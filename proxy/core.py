"""
proxy.core
~~~~~~~~~~
Non-blocking secure HTTP proxy with auth, ACL, block-list, and logging.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import Dict, Tuple, Optional

from .config import Config
from .auth import authenticate, AuthError, User
from .acls import ACLChecker
from .blocklist import Blocklist
from .logger import ProxyLogger

CRLF = b"\r\n"
BUFFER = 65536  # 64 KiB


# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #

def run_proxy(config: Config) -> None:
    """Entry point called by main.py"""
    proxy = ProxyServer(config)
    try:
        asyncio.run(proxy.serve_forever())
    except KeyboardInterrupt:
        print("\n▸ Proxy shut down.")


# --------------------------------------------------------------------------- #
#  Core Server
# --------------------------------------------------------------------------- #

class ProxyServer:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.blocklist = Blocklist(cfg.blocklist_path)
        self.acl = ACLChecker()
        self.logger = ProxyLogger(cfg.log_path)

    # ───────────────────────────────────────────────────────────────────── #
    #  AsyncIO Server
    # ───────────────────────────────────────────────────────────────────── #

    async def serve_forever(self) -> None:
        ssl_ctx = _server_ssl_context() if self.cfg.use_tls else None

        server = await asyncio.start_server(
            self._handle_client,
            host=self.cfg.listen_host,
            port=self.cfg.listen_port,
            ssl=ssl_ctx,
        )

        addr = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f"▸ Proxy listening on {addr}  (TLS={self.cfg.use_tls})")

        async with server:
            await server.serve_forever()

    # ───────────────────────────────────────────────────────────────────── #
    #  Per-connection handler
    # ───────────────────────────────────────────────────────────────────── #

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        request_started = time.time()

        try:
            req_line, headers = await _read_request_head(reader)
            method, target, version = _parse_request_line(req_line)

            # 1) AuthN/AuthZ
            user = await self._authenticate(headers)
            await self._authorize(user, method, target)

            # 2) Block-list
            host, port = _extract_host_port(method, target, headers)
            if self.blocklist.contains(host):
                await _send_simple_response(writer, 451, b"Blocked by policy")
                self.logger.log_block(user, method, host, port)
                return

            # 3) Processing
            self.logger.log_start(user, method, host, port, headers)
            if method.upper() == "CONNECT":
                await self._tunnel_https(reader, writer, host, port, user)
            else:
                await self._forward_http(reader, writer, req_line, headers, host, port, user)

            self.logger.log_end(user, method, host, port, ok=True,
                                 duration=time.time() - request_started)

        except ProxyError as e:
            await _send_simple_response(writer, e.status, e.msg.encode())
            self.logger.log_end(None, "-", "-", 0, ok=False,
                                 duration=time.time() - request_started,
                                 error=str(e))
        except Exception as e:
            await _send_simple_response(writer, 500, b"Internal Server Error")
            self.logger.log_end(None, "-", "-", 0, ok=False,
                                 duration=time.time() - request_started,
                                 error=repr(e))
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ───────────────────────────────────────────────────────────────── #
    #  Helpers
    # ───────────────────────────────────────────────────────────────── #

    async def _authenticate(self, headers: Dict[str, str]) -> Optional[User]:
        if not self.cfg.auth_enabled:
            return None
        try:
            return authenticate(headers)
        except AuthError as e:
            raise ProxyError(407, "Proxy Authentication Required") from e

    async def _authorize(self, user: Optional[User], method: str, target: str) -> None:
        if user and not self.acl.permit(user, method, target):
            raise ProxyError(403, "Forbidden")

    # ------------------------------------------------------------------ #
    #  Data pipelines
    # ------------------------------------------------------------------ #

    async def _tunnel_https(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        host: str,
        port: int,
        user: Optional[User],
    ) -> None:
        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            raise ProxyError(502, f"Upstream connect failed: {e}")

        # Acknowledge the tunnel
        await _send_simple_response(client_writer, 200, b"Connection Established")

        # If we later add MITM we would wrap remote_writer with ssl.create_default_context()

        await _pipe_bidirectional(client_reader, client_writer,
                                  remote_reader, remote_writer)

    async def _forward_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        req_line: bytes,
        headers: Dict[str, str],
        host: str,
        port: int,
        user: Optional[User],
    ) -> None:
        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            raise ProxyError(502, f"Upstream connect failed: {e}")

        # Remove Proxy-Authorization header before forwarding
        filtered_head = _rebuild_request_head(req_line, headers)

        remote_writer.write(filtered_head)
        await remote_writer.drain()

        # Stream client body → remote
        # We don’t know Content-Length here; just pipe until remote closes
        await asyncio.gather(
            _pipe_stream(client_reader, remote_writer),
            _pipe_stream(remote_reader, client_writer),
        )


# --------------------------------------------------------------------------- #
#  Low-level Utilities
# --------------------------------------------------------------------------- #

class ProxyError(Exception):
    """Raise to trigger an HTTP error back to the client."""
    def __init__(self, status: int, msg: str):
        self.status = status
        self.msg = msg
        super().__init__(f"{status} {msg}")


async def _read_request_head(reader: asyncio.StreamReader) -> Tuple[bytes, Dict[str, str]]:
    """
    Read until the blank line that ends the HTTP request head.
    Returns (request-line bytes, headers dict[str,str]).
    """
    head = b""
    while True:
        line = await reader.readline()
        if not line:
            raise ProxyError(400, "Bad Request: EOF before headers complete")
        head += line
        if line == CRLF:
            break

    # Split first line + headers
    lines = head.split(CRLF)[:-1]  # last element is b''
    if not lines:
        raise ProxyError(400, "Bad Request: empty head")

    req_line = lines[0]
    hdrs: Dict[str, str] = {}
    for raw in lines[1:]:
        if b":" not in raw:
            continue
        k, v = raw.split(b":", 1)
        hdrs[k.decode().strip().lower()] = v.decode().strip()

    return req_line, hdrs


def _parse_request_line(line: bytes) -> Tuple[str, str, str]:
    try:
        method, target, version = line.decode().strip().split()
        return method, target, version
    except ValueError:
        raise ProxyError(400, "Bad Request: malformed request-line")


def _extract_host_port(method: str, target: str, headers: Dict[str, str]) -> Tuple[str, int]:
    if method.upper() == "CONNECT":
        host, _, port = target.partition(":")
        return host, int(port or 443)

    # For regular HTTP, target may be absolute URI or relative
    if "host" in headers:
        host_header = headers["host"]
        if ":" in host_header:
            host, port = host_header.split(":", 1)
            return host, int(port)
        return host_header, 80

    # Last fallback: parse absolute URL
    if target.startswith("http://"):
        rest = target[7:]
        host_part, _, _ = rest.partition("/")
        if ":" in host_part:
            host, port = host_part.split(":", 1)
            return host, int(port)
        return host_part, 80

    raise ProxyError(400, "Bad Request: cannot determine Host")


def _rebuild_request_head(req_line: bytes, headers: Dict[str, str]) -> bytes:
    """Re-encode the request head, stripping hop-by-hop headers we don’t forward."""
    hop_by_hop = {"proxy-authorization", "proxy-connection", "connection", "keep-alive"}
    head = bytearray(req_line.rstrip() + CRLF)
    for k, v in headers.items():
        if k.lower() in hop_by_hop:
            continue
        head.extend(f"{k}: {v}".encode() + CRLF)
    head.extend(CRLF)
    return bytes(head)


async def _send_simple_response(writer: asyncio.StreamWriter,
                                status: int,
                                body: bytes = b"") -> None:
    reason = {
        200: "OK",
        403: "Forbidden",
        407: "Proxy Authentication Required",
        451: "Unavailable For Legal Reasons",
        502: "Bad Gateway",
    }.get(status, "Error")

    head = f"HTTP/1.1 {status} {reason}\r\n"

    if status == 407:
        head += 'Proxy-Authenticate: Basic realm="SecureProxy"\r\n'

    head += f"Content-Length: {len(body)}\r\n\r\n"
    writer.write(head.encode() + body)
    await writer.drain()


async def _pipe_stream(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while not src.at_eof():
            data = await src.read(BUFFER)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    finally:
        try:
            dst.close()
            await dst.wait_closed()
        except Exception:
            pass


async def _pipe_bidirectional(
    r1: asyncio.StreamReader,
    w1: asyncio.StreamWriter,
    r2: asyncio.StreamReader,
    w2: asyncio.StreamWriter,
) -> None:
    await asyncio.gather(
        _pipe_stream(r1, w2),
        _pipe_stream(r2, w1),
    )


def _server_ssl_context() -> ssl.SSLContext:
    """
    Return an SSLContext for client→proxy TLS.  
    For the first milestone we simply create a self-signed context pointing to
    `scripts/generate_ca.sh` output (server.pem / server.key). Adapt as needed.
    """
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain("server.pem", "server.key")  # ← generate later
    return ctx
