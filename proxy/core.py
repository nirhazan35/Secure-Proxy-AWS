"""
proxy.core
~~~~~~~~~~
Non-blocking secure HTTP proxy with auth, ACL, block-list, and logging.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import Dict, Optional, Tuple

from .acls import ACLChecker
from .auth import AuthError, User, authenticate
from .blocklist import Blocklist
from .config import Config
from .logger import ProxyLogger

CRLF = b"\r\n"
BUFFER = 65_536


def run_proxy(config: Config) -> None:
    proxy = ProxyServer(config)
    try:
        asyncio.run(proxy.serve_forever())
    except KeyboardInterrupt:
        print("\n▸ Proxy shut down.")


class ProxyServer:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.blocklist = Blocklist(cfg.blocklist_path)
        self.acl = ACLChecker()
        self.logger = ProxyLogger(cfg.log_path)

    async def serve_forever(self) -> None:
        ssl_ctx = _server_ssl_context() if self.cfg.use_tls else None
        server = await asyncio.start_server(
            self._handle_client,
            host=self.cfg.listen_host,
            port=self.cfg.listen_port,
            ssl=ssl_ctx,
        )

        bind_str = ", ".join(str(s.getsockname()) for s in server.sockets)
        print(f"▸ Proxy listening on {bind_str}  (TLS={self.cfg.use_tls})")

        async with server:
            await server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        start_ts = time.time()
        peer_ip, _ = writer.get_extra_info("peername")

        try:
            req_line, headers = await _read_request_head(reader)
            method, target, _ = _parse_request_line(req_line)
            try:
                user = await self._authenticate(headers)
            except AuthError as exc:
                if getattr(exc, "supplied_user", None):
                    self.logger.auth_fail(peer_ip, exc.supplied_user)
                raise ProxyError(407, "Proxy Authentication Required") from None
            await self._authorize(user, method, target)

            host, port = _extract_host_port(method, target, headers)
            if self.blocklist.contains(host):
                await _send_simple_response(writer, 451, b"Unauthorized website, blocked by policy.")
                self.logger.block(
                    user.username if user else "-",
                    method,
                    target,
                    "matched_blocklist",
                )
                return

            full_url = target if method.upper() != "CONNECT" else f"{host}:{port}"
            self.logger.start(
                user.username if user else "-",
                peer_ip,
                method,
                full_url,
                headers.get("user-agent", ""),
            )

            if method.upper() == "CONNECT":
                await self._tunnel_https(reader, writer, host, port)
            else:
                await self._forward_http(reader, writer, req_line, headers, host, port)

            self.logger.end(
                user.username if user else "-",
                method,
                full_url,
                200,
                0,
                int((time.time() - start_ts) * 1000),
            )

        except ProxyError as e:
            try:
                try:
                    await _send_simple_response(writer, e.status, e.msg.encode())
                except ConnectionResetError:
                    pass
            except Exception:
                pass
            if e.status != 407:
                self.logger.end(
                    "-",
                    method if "method" in locals() else "-",
                    full_url if "full_url" in locals() else "-",
                    e.status,
                    0,
                    int((time.time() - start_ts) * 1000)
                    if "start_ts" in locals() else 0,
                )
            return
        except Exception as e:
            await _send_simple_response(writer, 500, b"Internal Server Error")
            self.logger.end(
                "-",
                method if "method" in locals() else "-",
                target if "target" in locals() else "-",
                500,
                0,
                int((time.time() - start_ts) * 1000),
            )
        finally:
            try:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionResetError:
                    pass
            except Exception:
                pass

    async def _authenticate(self, headers: Dict[str, str]) -> Optional[User]:
        if not self.cfg.auth_enabled:
            return None
        return authenticate(headers)

    async def _authorize(
        self, user: Optional[User], method: str, target: str
    ) -> None:
        if user and not self.acl.permit(user, method, target):
            raise ProxyError(403, "Forbidden")
        
    async def _tunnel_https(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            raise ProxyError(502, f"Upstream connect failed: {e}") from e

        await _send_simple_response(client_writer, 200, b"Connection Established")
        await _pipe_bidirectional(
            client_reader, client_writer, remote_reader, remote_writer
        )

    async def _forward_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        req_line: bytes,
        headers: Dict[str, str],
        host: str,
        port: int,
    ) -> None:
        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            raise ProxyError(502, f"Upstream connect failed: {e}") from e

        remote_writer.write(_rebuild_request_head(req_line, headers))
        await remote_writer.drain()

        await asyncio.gather(
            _pipe_stream(client_reader, remote_writer),
            _pipe_stream(remote_reader, client_writer),
        )


class ProxyError(Exception):
    def __init__(self, status: int, msg: str):
        self.status = status
        self.msg = msg
        super().__init__(f"{status} {msg}")


async def _read_request_head(reader: asyncio.StreamReader) -> Tuple[bytes, Dict[str, str]]:
    head = b""
    while True:
        line = await reader.readline()
        if not line:
            raise ProxyError(400, "Bad Request: EOF before headers complete")
        head += line
        if line == CRLF:
            break

    lines = head.split(CRLF)[:-1]
    if not lines:
        raise ProxyError(400, "Bad Request: empty head")

    req_line = lines[0]
    hdrs = {}
    for raw in lines[1:]:
        if b":" in raw:
            k, v = raw.split(b":", 1)
            hdrs[k.decode().strip().lower()] = v.decode().strip()
    return req_line, hdrs


def _parse_request_line(line: bytes) -> Tuple[str, str, str]:
    try:
        return line.decode().strip().split()
    except ValueError:
        raise ProxyError(400, "Bad Request: malformed request-line")


def _extract_host_port(method: str, target: str, headers: Dict[str, str]) -> Tuple[str, int]:
    if method.upper() == "CONNECT":
        host, _, port = target.partition(":")
        return host, int(port or 443)
    if "host" in headers:
        host_hdr = headers["host"]
        if ":" in host_hdr:
            host, port = host_hdr.split(":", 1)
            return host, int(port)
        return host_hdr, 80
    if target.startswith("http://"):
        rest = target[7:]
        host_part, _, _ = rest.partition("/")
        if ":" in host_part:
            host, port = host_part.split(":", 1)
            return host, int(port)
        return host_part, 80
    raise ProxyError(400, "Bad Request: cannot determine Host")


_HOP_BY_HOP = {
    "proxy-authorization",
    "proxy-connection",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def _rebuild_request_head(req_line: bytes, headers: Dict[str, str]) -> bytes:
    head = bytearray(req_line.rstrip() + CRLF)
    for k, v in headers.items():
        if k.lower() not in _HOP_BY_HOP:
            head.extend(f"{k}: {v}".encode() + CRLF)
    head.extend(CRLF)
    return bytes(head)


async def _send_simple_response(writer: asyncio.StreamWriter, status: int, body: bytes = b"") -> None:
    reason = {200: "OK", 403: "Forbidden", 407: "Proxy Authentication Required",
              451: "Unavailable For Legal Reasons", 502: "Bad Gateway"}.get(status, "Error")
    head = f"HTTP/1.1 {status} {reason}\r\n"
    if status == 407:
        head += 'Proxy-Authenticate: Basic realm="SecureProxy"\r\n'
    head += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    writer.write(head.encode() + body)
    await writer.drain()


async def _pipe_stream(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while not src.at_eof():
            chunk = await src.read(BUFFER)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    finally:
        try:
            dst.close()
            await dst.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def _pipe_bidirectional(r1, w1, r2, w2) -> None:
    await asyncio.gather(_pipe_stream(r1, w2), _pipe_stream(r2, w1))


def _server_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain("server.pem", "server.key")
    return ctx
