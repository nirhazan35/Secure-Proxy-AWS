"""
proxy.logger
~~~~~~~~~~~~
Human-readable *and* JSON logs with daily rotation.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

_ISO = "%Y-%m-%dT%H:%M:%SZ"

def _now() -> str:  # RFC-3339 without microseconds
    return datetime.now(tz=timezone.utc).strftime(_ISO)


class _PlainFormatter(logging.Formatter):
    """ e.g. 2025-06-19T15:07:02Z alice 127.0.0.1 GET http://e.com/ 200 4 327B 89 ms """

    def format(self, record):  # type: ignore[override]
        d: Dict[str, Any] = record.msg if isinstance(record.msg, dict) else {}
        if record.levelno >= logging.ERROR:
            return super().format(record)

        parts = [
            d.get("ts", _now()),
            d.get("user", "-"),
            d.get("ip", "-"),
            d.get("method", "-"),
            d.get("url", "-"),
        ]
        if record.msg["event"] == "block":
            parts.extend(["BLOCKED", d.get("reason", "")])
        else:  # end
            parts.extend(
                [
                    str(d.get("status", "-")),
                    f'{d.get("bytes", 0):,}B',
                    f'{d.get("ms", 0)} ms',
                ]
            )
        return " ".join(parts)


class _JSONFormatter(logging.Formatter):
    def format(self, record):  # type: ignore[override]
        return json.dumps(record.msg, separators=(",", ":"))


class ProxyLogger:
    def __init__(self, basename: str | Path):
        root = logging.getLogger("proxy")
        root.setLevel(logging.INFO)
        root.propagate = False  # don’t spam the root logger

        basename = Path(basename).with_suffix("")  # proxy_access
        jsonl_file = basename.with_suffix(".jsonl")

        # json lines
        h = logging.handlers.TimedRotatingFileHandler(
            jsonl_file, when="midnight", backupCount=7, encoding="utf-8"
        )
        h.setFormatter(_JSONFormatter())
        root.addHandler(h)

        self.log = root

    def start(
        self,
        user: str,
        ip: str,
        method: str,
        url: str,
        ua: str,
    ):
        if user == "-":
            return
        self.log.info(
            {
                "event": "start",
                "ts": _now(),
                "user": user,
                "ip": ip,
                "method": method,
                "url": url,
                "ua": ua,
            }
        )

    def end(
        self,
        user: str,
        method: str,
        url: str,
        status: int,
        total_bytes: int,
        duration_ms: int,
    ):
        if user == "-":
            return
        self.log.info(
            {
                "event": "end",
                "ts": _now(),
                "user": user,
                "method": method,
                "url": url,
                "status": status,
                "bytes": total_bytes,
                "ms": duration_ms,
            }
        )

    def block(self, user: str, method: str, url: str, reason: str):
        self.log.info(
            {
                "event": "block",
                "ts": _now(),
                "user": user,
                "method": method,
                "url": url,
                "reason": reason,
            }
        )

    def auth_fail(self, ip: str, supplied_user: str | None):
        self.log.warning(
            {
                "event": "auth_fail",
                "ts": _now(),
                "ip": ip,
                "user": supplied_user or "-",
            }
        )
