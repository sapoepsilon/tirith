"""Audit log helper. Every scope decision and state-changing action goes through here."""

from __future__ import annotations

from typing import Any

from .models import AuditEntry
from .store import get_store


def audit(
    action: str,
    target: str | None = None,
    allowed: bool = True,
    actor: str = "system",
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    return get_store().add_audit(
        AuditEntry(action=action, target=target, allowed=allowed, actor=actor, details=details)
    )
