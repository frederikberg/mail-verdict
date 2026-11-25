"""
Access keys -- the token subjects that sign in as a user, and what each may
do (auth/grants.py).

A key is a subject with a grant: `full` (everything its user may do) or
`scoped` to a list of scopes, optionally with the calendars and address books
its writes are confined to. The credential itself is made at the identity
provider; attaching it to a user, and narrowing, widening or removing what it
may do, is done here and takes effect within `auth.principal_cache_seconds`.

A subject is listed as a key when it is scoped, has a label, or has signed in
as a machine client.

GET   /api/admin/access-keys                            -- every key (?user_id=)
PATCH /api/admin/users/{user_id}/subjects/{subject}     -- change a key's label or grant
GET   /api/me/access-keys                               -- the caller's own keys, read-only

Attaching a key is POST /api/admin/users/{user_id}/subjects (api/admin.py);
signing one out is the sign-in revoke route (api/sign_ins.py), removing it is
DELETE on the subject (api/admin.py).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from mail_verdict.api.deps import require_admin, require_principal
from mail_verdict.auth.access_events import record_access_key_event
from mail_verdict.auth.grants import (
    CALENDAR_WRITE,
    CONTACTS_WRITE,
    AccessMode,
    GrantInvalid,
    ScopeName,
    check_fields,
)
from mail_verdict.auth.principal import Principal, get_principal_resolver
from mail_verdict.database.connection import get_db_connection
from mail_verdict.database.models import (
    AccessKeyEvent,
    DavAccountOwner,
    DavCollection,
    SignIn,
    User,
    UserIdentity,
)

router = APIRouter(prefix="/admin", tags=["access-keys"], dependencies=[Depends(require_admin)])
me_router = APIRouter(prefix="/me/access-keys", tags=["access-keys"])


class AccessKeyResponse(BaseModel):
    """One access key. `scopes` are the ones held (a write scope implies its
    read scope); a write limit of null means every collection. The sign-in
    fields are null until the key has been used."""

    subject: str
    label: str | None
    user_id: uuid.UUID
    user_display_name: str
    access: AccessMode
    scopes: list[str]
    calendar_write_ids: list[uuid.UUID] | None
    addressbook_write_ids: list[uuid.UUID] | None
    created_at: datetime
    sign_in_id: uuid.UUID | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    revoked_at: datetime | None
    last_refusal_at: datetime | None


class AccessKeyUpdateRequest(BaseModel):
    """The fields of a key to change; the rest stay as they are.

    Switching `access` to `full` without naming scopes or limits clears them,
    and dropping a write scope without naming its limit clears the limit.
    `label` and the write limits take null to clear them."""

    label: str | None = Field(default=None, min_length=1)
    access: AccessMode = "full"
    scopes: list[ScopeName] = Field(default_factory=list)
    calendar_write_ids: list[uuid.UUID] | None = None
    addressbook_write_ids: list[uuid.UUID] | None = None


async def ensure_collections(
    session: AsyncSession,
    user_id: uuid.UUID,
    kind: str,
    collection_ids: list[uuid.UUID] | None,
) -> None:
    """Refuse (422 `unknown_collection`) a write limit naming a calendar or
    address book that is not one of the user's own."""
    if not collection_ids:
        return
    found = set(
        (
            await session.execute(
                select(DavCollection.id)
                .join(DavAccountOwner, DavAccountOwner.dav_account_id == DavCollection.account_id)
                .where(
                    DavAccountOwner.user_id == user_id,
                    DavCollection.kind == kind,
                    DavCollection.deleted_at.is_(None),
                    DavCollection.id.in_(collection_ids),
                )
            )
        ).scalars()
    )
    if found != set(collection_ids):
        raise HTTPException(status_code=422, detail="unknown_collection")


def check_grant(
    access: AccessMode,
    scopes: Sequence[str],
    calendar_write_ids: list[uuid.UUID] | None,
    addressbook_write_ids: list[uuid.UUID] | None,
) -> list[str]:
    """The scopes to store (sorted, no repeats), or 422 with the reason."""
    try:
        return check_fields(access, scopes, calendar_write_ids, addressbook_write_ids)
    except GrantInvalid as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def grant_detail(
    label: str | None,
    access: str,
    scopes: list[str],
    calendar_write_ids: list[uuid.UUID] | None,
    addressbook_write_ids: list[uuid.UUID] | None,
) -> dict[str, Any]:
    """A key's label and grant as an audit-trail detail."""
    return {
        "label": label,
        "access": access,
        "scopes": scopes,
        "calendar_write_ids": (
            None if calendar_write_ids is None else sorted(str(i) for i in calendar_write_ids)
        ),
        "addressbook_write_ids": (
            None if addressbook_write_ids is None else sorted(str(i) for i in addressbook_write_ids)
        ),
    }


def _identity_detail(identity: UserIdentity) -> dict[str, Any]:
    return grant_detail(
        identity.label, identity.access, list(identity.scopes), identity.calendar_write_ids,
        identity.addressbook_write_ids,
    )


async def _keys(
    *conditions: ColumnElement[bool], only_keys: bool = True,
) -> list[AccessKeyResponse]:
    """The subjects matching `conditions`, with their user's name, their
    machine sign-in and their last refusal -- only those that count as keys,
    unless `only_keys` is false."""
    machine = (
        select(
            SignIn.handle, SignIn.id, SignIn.first_seen_at, SignIn.last_seen_at,
            SignIn.revoked_at,
        )
        .where(SignIn.kind == "machine")
        .subquery()
    )
    refusals = (
        select(AccessKeyEvent.subject, func.max(AccessKeyEvent.at).label("at"))
        .where(AccessKeyEvent.kind == "refused")
        .group_by(AccessKeyEvent.subject)
        .subquery()
    )
    query = (
        select(
            UserIdentity, User.display_name, machine.c.id, machine.c.first_seen_at,
            machine.c.last_seen_at, machine.c.revoked_at, refusals.c.at,
        )
        .join(User, User.id == UserIdentity.user_id)
        .outerjoin(machine, machine.c.handle == UserIdentity.subject)
        .outerjoin(refusals, refusals.c.subject == UserIdentity.subject)
        .where(*conditions)
        .order_by(UserIdentity.label.is_(None), UserIdentity.label, UserIdentity.subject)
    )
    if only_keys:
        query = query.where(
            or_(
                UserIdentity.access == "scoped",
                UserIdentity.label.is_not(None),
                machine.c.id.is_not(None),
            )
        )
    async with get_db_connection().session() as session:
        rows = (await session.execute(query)).all()
    return [
        AccessKeyResponse(
            subject=identity.subject, label=identity.label, user_id=identity.user_id,
            user_display_name=display_name, access=identity.access,  # type: ignore[arg-type]
            scopes=sorted(identity.scopes),
            calendar_write_ids=identity.calendar_write_ids,
            addressbook_write_ids=identity.addressbook_write_ids,
            created_at=identity.created_at, sign_in_id=sign_in_id,
            first_seen_at=first_seen, last_seen_at=last_seen, revoked_at=revoked,
            last_refusal_at=refused,
        )
        for identity, display_name, sign_in_id, first_seen, last_seen, revoked, refused in rows
    ]


@router.get("/access-keys", response_model=list[AccessKeyResponse])
async def list_access_keys(
    user_id: uuid.UUID | None = Query(default=None),
) -> list[AccessKeyResponse]:
    """Every access key, or one user's: label first, then subject."""
    conditions = [] if user_id is None else [UserIdentity.user_id == user_id]
    return await _keys(*conditions)


@me_router.get("", response_model=list[AccessKeyResponse])
async def list_own_access_keys(
    principal: Principal = Depends(require_principal),
) -> list[AccessKeyResponse]:
    """The caller's own access keys, read-only. A key is signed out with
    POST /api/me/sign-ins/{sign_in_id}/revoke."""
    return await _keys(UserIdentity.user_id == principal.user_id)


@router.patch("/users/{user_id}/subjects/{subject}", response_model=AccessKeyResponse)
async def update_access_key(
    user_id: uuid.UUID,
    subject: str,
    request: AccessKeyUpdateRequest,
    principal: Principal = Depends(require_principal),
) -> AccessKeyResponse:
    """Change a subject's label or grant. 404 if it is not this user's; 400
    for the subject this request signed in with, whose grant would change
    under the caller mid-request; 422 for a combination that cannot be
    stored (`unknown_scope`, `full_access_carries_no_scopes`,
    `calendar_limit_needs_calendar_write`,
    `addressbook_limit_needs_contacts_write`) or a write limit naming a
    collection that is not the user's own (`unknown_collection`)."""
    fields = request.model_fields_set
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    if user_id == principal.user_id and subject == principal.subject:
        raise HTTPException(
            status_code=400, detail="this is the subject you are signed in with",
        )
    async with get_db_connection().session() as session:
        identity = await session.get(UserIdentity, subject)
        if identity is None or identity.user_id != user_id:
            raise HTTPException(status_code=404, detail="Subject not found for this user")
        before = _identity_detail(identity)

        access: AccessMode = request.access if "access" in fields else identity.access  # type: ignore[assignment]
        scopes = list(request.scopes) if "scopes" in fields else list(identity.scopes)
        calendar_ids = (
            request.calendar_write_ids
            if "calendar_write_ids" in fields else identity.calendar_write_ids
        )
        addressbook_ids = (
            request.addressbook_write_ids
            if "addressbook_write_ids" in fields else identity.addressbook_write_ids
        )
        if access == "full" and not fields & {
            "scopes", "calendar_write_ids", "addressbook_write_ids",
        }:
            scopes, calendar_ids, addressbook_ids = [], None, None
        if "calendar_write_ids" not in fields and CALENDAR_WRITE not in scopes:
            calendar_ids = None
        if "addressbook_write_ids" not in fields and CONTACTS_WRITE not in scopes:
            addressbook_ids = None

        scopes = check_grant(access, scopes, calendar_ids, addressbook_ids)
        await ensure_collections(
            session, user_id, "calendar",
            request.calendar_write_ids if "calendar_write_ids" in fields else None,
        )
        await ensure_collections(
            session, user_id, "addressbook",
            request.addressbook_write_ids if "addressbook_write_ids" in fields else None,
        )

        if "label" in fields:
            identity.label = request.label
        identity.access = access
        identity.scopes = scopes
        identity.calendar_write_ids = calendar_ids
        identity.addressbook_write_ids = addressbook_ids
        after = _identity_detail(identity)
        if after != before:
            record_access_key_event(
                session, subject, user_id, "changed", actor_user_id=principal.user_id,
                detail={"before": before, "after": after},
            )
    resolver = get_principal_resolver()
    if resolver is not None:
        resolver.forget()
    return (await _keys(UserIdentity.subject == subject, only_keys=False))[0]
