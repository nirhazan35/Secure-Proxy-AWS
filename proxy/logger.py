"""
proxy.logger
~~~~~~~~~~~~
JSON-line rotating logger (daily).  Keeps dependencies minimal by
using stdlib logging.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_ISO = "%Y-%m-%dT%H:%M:%S.%fZ"


class ProxyLogger:
    def __init__(self, path: str | Path):
        self.log = logging.getLogger("proxy")
        self.log.setLevel(logging.INFO)
        handler = logging.handlers.TimedRotatingFileHandler(
            filename=Path(path),
            when="midnight",
            backupCount=7,
            encoding="utf-8",
        )
        handler.setFormatter(_JsonFormatter())  # type: ignore[arg-type]
        self.log.addHandler(handler)

    # ------------------------------------------------------------------ #
    # public helpers
    # ------------------------------------------------------------------ #

    def log_start(
        self,
        user,
        method,
        host,
        port,
        headers: Dict[str, str],
    ):
        self.log.info(
            {
                "event": "start",
                "ts": _now(),
                "user": _u(user),
                "method": method,
                "host": host,
                "port": port,
                "ua": headers.get("user-agent", ""),
            },
        )

    def log_end(
        self,
        user,
        method,
        host,
        port,
        ok: bool,
        duration: float,
        error: Optional[str] = None,
    ):
        self.log.info(
            {
                "event": "end",
                "ts": _now(),
                "user": _u(user),
                "method": method,
                "host": host,
                "port": port,
                "ok": ok,
                "ms": int(duration * 1000),
                "error": error,
            },
        )

    def log_block(self, user, method, host, port):
        self.log.info(
            {
                "event": "block",
                "ts": _now(),
                "user": _u(user),
                "method": method,
                "host": host,
                "port": port,
            },
        )


# ------------------------------------------------------------------ #
#  utilities
# ------------------------------------------------------------------ #

class _JsonFormatter(logging.Formatter):
    def format(self, record):  # type: ignore[override]
        if isinstance(record.msg, dict):
            return json.dumps(record.msg, separators=(",", ":"))
        return super().format(record)


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime(_ISO)


def _u(user) -> str:
    return getattr(user, "username", "")
