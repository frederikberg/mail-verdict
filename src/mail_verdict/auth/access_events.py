"""
The audit trail of access keys (`access_key_events`): a key was created,
changed, revoked, or refused something.

Rows are written in the transaction of the change they record. A row names
its subject without a foreign key, so the history of a removed key stays; it
goes with its user.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from mail_verdict.database.models import AccessKeyEvent

AccessKeyEventKind = Literal["created", "changed", "revoked", "refused"]


def record_access_key_event(
    session: AsyncSession,
    subject: str,
    user_id: uuid.UUID,
    kind: AccessKeyEventKind,
    *,
    actor_user_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Add one event to `session`; it is stored when the session commits.

    Args:
        subject: The token subject the key signs in as.
        user_id: The user the subject belongs to.
        kind: What happened.
        actor_user_id: Who did it, when a person did.
        detail: What changed or was refused, JSON-serialisable.
    """
    session.add(
        AccessKeyEvent(
            subject=subject, user_id=user_id, kind=kind, actor_user_id=actor_user_id,
            detail=detail or {},
        )
    )
