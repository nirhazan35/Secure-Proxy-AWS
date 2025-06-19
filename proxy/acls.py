"""
proxy.acls
~~~~~~~~~~
Tiny rule-engine for per-user allow/deny.  
For the first milestone every authenticated user is fully allowed.
Extend by reading a YAML file if you need finer rules.
"""

from __future__ import annotations

from .auth import User


class ACLChecker:
    def permit(self, user: User | None, method: str, target: str) -> bool:  # noqa: D401
        """Return True if the request is allowed."""
        # Demo policy: authenticated users = allow all,
        # unauthenticated (when auth is disabled) = allow.
        return True
