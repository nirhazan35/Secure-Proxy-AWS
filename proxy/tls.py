"""
proxy.tls
~~~~~~~~~
Placeholder for future MITM certificate minting.  Not required unless you
need full HTTPS inspection.  For now we only expose a helper that *could*
be called from core.py once you extend the proxy.
"""

from __future__ import annotations

from pathlib import Path


def ensure_local_ca(ca_dir: str | Path = "certs") -> None:  # noqa: D401
    """
    Ensure a local root-CA key+cert exist (lazy-creates with OpenSSL CLI).
    """
    # This is a no-op stub; implement with `cryptography` or subprocess
    # if your course later demands MITM HTTPS inspection.
    Path(ca_dir).mkdir(exist_ok=True)
