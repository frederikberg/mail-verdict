"""
GET /api/me -- who the caller is.

What a client reads once it holds a token: which user it signed in as,
whether that user is admin (which decides whether admin screens are offered)
and what the token's own sign-in may do -- everything, or the scopes of an
access key (auth/grants.py).
"""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from mail_verdict.api.deps import require_principal
from mail_verdict.auth.grants import AccessMode
from mail_verdict.auth.principal import Principal
from mail_verdict.database.connection import get_db_connection
from mail_verdict.database.models import User

router = APIRouter(tags=["auth"])


class AccessResponse(BaseModel):
    """What the caller's own sign-in may do. `full` is everything its user
    may do; `scoped` is exactly `scopes` (a write scope implies its read
    scope), with writes confined to the listed calendars or address books
    when a limit is set (null: every one)."""

    mode: AccessMode
    scopes: list[str]
    calendar_write_ids: list[uuid.UUID] | None
    addressbook_write_ids: list[uuid.UUID] | None


class MeResponse(BaseModel):
    """The signed-in user. `role` is the effective one: the owner is admin
    whatever the users table says, and a scoped access key is never admin."""

    user_id: uuid.UUID
    email: str | None
    display_name: str
    role: Literal["admin", "user"]
    disabled: bool
    access: AccessResponse


@router.get("/me", response_model=MeResponse)
async def get_me(principal: Principal = Depends(require_principal)) -> MeResponse:
    """The signed-in user."""
    async with get_db_connection().session() as session:
        user = await session.get(User, principal.user_id)
    grant = principal.grant
    access = (
        AccessResponse(
            mode="full", scopes=[], calendar_write_ids=None, addressbook_write_ids=None,
        )
        if grant is None
        else AccessResponse(
            mode="scoped", scopes=sorted(grant.scopes),
            calendar_write_ids=(
                None if grant.calendar_write_ids is None else sorted(grant.calendar_write_ids)
            ),
            addressbook_write_ids=(
                None if grant.addressbook_write_ids is None
                else sorted(grant.addressbook_write_ids)
            ),
        )
    )
    return MeResponse(
        user_id=principal.user_id,
        email=user.email if user else None,
        display_name=user.display_name if user else principal.subject,
        role="admin" if principal.is_admin else "user",
        disabled=False,
        access=access,
    )
