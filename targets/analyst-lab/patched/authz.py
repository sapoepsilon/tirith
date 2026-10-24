"""The only authorization rule in the demo: the caller must be the identity it asks to act as,
and only an admin identity may read the flag."""

from __future__ import annotations

ADMINS = frozenset({"demo-admin"})


def may_read(caller: str, requested: str) -> bool:
    """True only when the caller exists, is asking for its own identity, and is an admin."""
    if not caller or caller != requested:
        return False
    return caller in ADMINS


def deny(caller: str, requested: str) -> bool:
    return not may_read(caller, requested)