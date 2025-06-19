"""
proxy.auth
~~~~~~~~~~
Simple Basic-Auth user store.  Credentials are supplied via the
environment variable  PROXY_USERS="user1:pass1,user2:pass2"
or an optional JSON file (future extension).
"""

from __future__ import annotations

import base64
import hmac
import os
from dataclasses import dataclass
from typing import Dict

_USERS: Dict[str, str] = {}  # username -> plaintext password (demo only!)


def _load_users() -> None:
    """Populate _USERS from env var. Format:  'alice:secret,bob:1234'."""
    raw = os.getenv("PROXY_USERS", "admin:admin")
    for pair in filter(None, (p.strip() for p in raw.split(","))):
        if ":" in pair:
            user, pwd = pair.split(":", 1)
            _USERS[user] = pwd


_load_users()


class AuthError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class User:
    username: str


def _decode_basic(header_val: str) -> tuple[str, str]:
    if not header_val.lower().startswith("basic "):
        raise AuthError("Unsupported auth scheme")
    try:
        decoded = base64.b64decode(header_val.split(None, 1)[1]).decode()
        return decoded.split(":", 1)
    except Exception as e:  # noqa: BLE001
        raise AuthError("Bad Base64") from e


def authenticate(headers: Dict[str, str]) -> User:
    auth_hdr = headers.get("proxy-authorization")
    if not auth_hdr:
        raise AuthError("Missing Proxy-Authorization")

    username, password = _decode_basic(auth_hdr)

    stored = _USERS.get(username)
    if stored is None or not hmac.compare_digest(stored, password):
        raise AuthError("Bad credentials")

    return User(username=username)
