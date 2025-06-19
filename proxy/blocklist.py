"""
proxy.blocklist
~~~~~~~~~~~~~~~
Simple host block-list with wildcard support:

blocklist.txt
-------------
# comment
example.com
*.ads.example.net
"""

from __future__ import annotations

import pathlib
import time
from typing import Set, Tuple


class Blocklist:
    def __init__(self, path: str | pathlib.Path):
        self.path = pathlib.Path(path)
        self._mtime: float = 0.0
        self._exact: Set[str] = set()
        self._suffixes: Set[str] = set()
        self._load()

    # ------------------------------------------------------------------ #
    # public
    # ------------------------------------------------------------------ #

    def contains(self, host: str) -> bool:
        """True if *host* is blocked (case-insensitive)."""
        self._maybe_reload()
        host = host.lower().rstrip(".")
        if host in self._exact:
            return True
        return any(host == s or host.endswith("." + s) for s in self._suffixes)

    # ------------------------------------------------------------------ #
    # private
    # ------------------------------------------------------------------ #

    def _maybe_reload(self) -> None:
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            return
        if mtime != self._mtime:
            self._mtime = mtime
            self._load()

    def _load(self) -> None:
        self._exact.clear()
        self._suffixes.clear()

        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return

        for ln in lines:
            ln = ln.strip().lower()
            if not ln or ln.startswith("#"):
                continue
            if ln.startswith("*."):
                self._suffixes.add(ln[2:])
            else:
                self._exact.add(ln)
