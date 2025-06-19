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

class AuthError(Exception):
    def __init__(self, msg: str, supplied_user: str | None = None):
        super().__init__(msg)
        self.supplied_user = supplied_user

def _load_users() -> None:
    """Populate _USERS from env"""
    raw = os.getenv("PROXY_USERS", "")
    if not raw:
        raise AuthError("no users found")
    for pair in filter(None, (p.strip() for p in raw.split(","))):
        if ":" in pair:
            user, pwd = pair.split(":", 1)
            _USERS[user] = pwd


_load_users()



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


def authenticate(headers):
    auth_hdr = headers.get("proxy-authorization")
    if not auth_hdr:
        raise AuthError("Missing header")
    user, pwd = _decode_basic(auth_hdr)
    if user not in _USERS or _USERS[user] != pwd:
        raise AuthError("Bad credentials", supplied_user=user)
    return User(username=user)
