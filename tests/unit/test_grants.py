"""Scoped access keys: what a grant covers, and the scope a key acts through.

The route and tool tables themselves are not asserted here (the generated
matrix document carries them); these tests hold the behaviour around them:
a write scope covers its reads, an ambiguous route closes, a key's data scope
is emptied of what it holds no scope for, and its write limits and the
scheduling refusal bind through the Scope.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from mail_verdict.auth import grants as grants_module
from mail_verdict.auth import scope as scope_module
from mail_verdict.auth.grants import (
    Grant,
    GrantInvalid,
    check_fields,
    grant_from_columns,
    refusal_for_route,
    refusal_for_tool,
)
from mail_verdict.auth.principal import Principal
from mail_verdict.auth.scope import Scope, ScopeDenied

MAIL_ACCOUNT, DAV_ACCOUNT = uuid.uuid4(), uuid.uuid4()
USER = uuid.uuid4()
OPEN_CALENDAR, OTHER_CALENDAR = uuid.uuid4(), uuid.uuid4()


def _grant(*scopes: str, **limits: Any) -> Grant:
    return Grant(frozenset(scopes), **limits)


def test_a_write_scope_covers_its_reads_and_a_read_scope_does_not_cover_writes() -> None:
    assert _grant("calendar:write").holds("calendar:read")
    assert not _grant("calendar:read").holds("calendar:write")
    assert not _grant("calendar:write").holds("contacts:read")


def test_a_full_subject_has_no_grant_and_a_scoped_one_has_exactly_its_scopes() -> None:
    assert grant_from_columns("full", [], None, None) is None
    grant = grant_from_columns("scoped", ["contacts:read"], [OPEN_CALENDAR], None)
    assert grant == Grant(
        frozenset({"contacts:read"}), calendar_write_ids=frozenset({OPEN_CALENDAR}),
    )


@pytest.mark.parametrize(
    ("access", "scopes", "calendars", "addressbooks", "reason"),
    [
        ("full", ["calendar:read"], None, None, "full_access_carries_no_scopes"),
        ("full", [], [OPEN_CALENDAR], None, "full_access_carries_no_scopes"),
        ("scoped", ["mail:read"], None, None, "unknown_scope"),
        ("scoped", ["calendar:read"], [OPEN_CALENDAR], None, "calendar_limit_needs_calendar_write"),
        (
            "scoped", ["contacts:read"], None, [uuid.uuid4()],
            "addressbook_limit_needs_contacts_write",
        ),
    ],
)
def test_a_grant_that_cannot_be_stored_is_refused_with_its_reason(
    access: Any, scopes: list[str], calendars: Any, addressbooks: Any, reason: str,
) -> None:
    with pytest.raises(GrantInvalid, match=reason):
        check_fields(access, scopes, calendars, addressbooks)


def test_stored_scopes_are_sorted_and_without_repeats() -> None:
    assert check_fields(
        "scoped", ["contacts:read", "calendar:write", "contacts:read"], None, None,
    ) == ["calendar:write", "contacts:read"]


def test_a_route_nobody_listed_is_refused_to_a_key_holding_every_scope() -> None:
    everything = _grant("calendar:write", "contacts:write")

    refusal = refusal_for_route(everything, "GET", "/api/accounts")

    assert refusal is not None and refusal.scope is None
    assert refusal_for_tool(everything, "send_mail") is not None


def test_a_listed_route_names_the_scope_that_would_open_it() -> None:
    refusal = refusal_for_route(_grant("calendar:read"), "POST", "/api/calendar/events")

    assert refusal is not None and refusal.scope == "calendar:write"
    assert refusal_for_route(_grant("calendar:write"), "POST", "/api/calendar/events") is None


def test_the_mcp_transport_is_open_only_to_a_key_that_holds_a_tool() -> None:
    assert refusal_for_route(_grant(), "POST", "/mcp/") is not None
    assert refusal_for_route(_grant("contacts:read"), "POST", "/mcp/") is None


def test_a_path_that_fits_two_listed_routes_of_different_scopes_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grants_module, "_ROUTES", grants_module._compile({
        "GET /api/things/{a}": "calendar:read",
        "GET /api/{b}/stuff": "contacts:read",
    }))

    assert grants_module.listed_scope("GET", "/api/things/stuff") is None
    assert grants_module.listed_scope("GET", "/api/things/x") == "calendar:read"


def test_the_route_with_fewer_parameters_wins_when_the_scopes_agree_or_differ_by_literal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grants_module, "_ROUTES", grants_module._compile({
        "GET /api/things/{a}": "calendar:read",
        "GET /api/things/special": "contacts:read",
    }))

    assert grants_module.listed_scope("GET", "/api/things/special") == "contacts:read"
    assert grants_module.listed_scope("GET", "/api/things/other") == "calendar:read"


# --- the data scope of a key --------------------------------------------------


@pytest.fixture()
def owned(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(db: Any, user_id: uuid.UUID) -> Any:
        return frozenset({MAIL_ACCOUNT}), frozenset({DAV_ACCOUNT})

    monkeypatch.setattr(scope_module, "_owned", fake)


def _principal(grant: Grant | None, *, is_admin: bool = True) -> Principal:
    return Principal(user_id=USER, subject="key", is_admin=is_admin, grant=grant)


@pytest.mark.asyncio
@pytest.mark.usefixtures("owned")
async def test_a_full_principal_keeps_everything_its_user_owns() -> None:
    scope = await Scope.for_principal(None, _principal(None))  # type: ignore[arg-type]

    assert scope.is_admin
    assert scope.account_ids == {MAIL_ACCOUNT} and scope.dav_account_ids == {DAV_ACCOUNT}


@pytest.mark.asyncio
@pytest.mark.usefixtures("owned")
async def test_a_calendar_key_owns_no_mail_and_is_never_admin_even_of_an_admin_user() -> None:
    scope = await Scope.for_principal(
        None, _principal(_grant("calendar:read")),  # type: ignore[arg-type]
    )

    assert not scope.is_admin
    assert scope.account_ids == frozenset()
    assert scope.dav_account_ids == {DAV_ACCOUNT}


@pytest.mark.asyncio
@pytest.mark.usefixtures("owned")
async def test_a_key_with_no_scope_owns_nothing_at_all() -> None:
    scope = await Scope.for_principal(None, _principal(_grant()))  # type: ignore[arg-type]

    assert scope.account_ids == frozenset() and scope.dav_account_ids == frozenset()


def test_a_write_limit_refuses_a_calendar_it_leaves_out_and_never_limits_full_access() -> None:
    limited = Scope(
        user_id=USER, is_admin=False,
        grant=_grant("calendar:write", calendar_write_ids=frozenset({OPEN_CALENDAR})),
    )

    limited.require_calendar_write(OPEN_CALENDAR)
    with pytest.raises(ScopeDenied) as raised:
        limited.require_calendar_write(OTHER_CALENDAR)
    assert raised.value.detail == "collection_not_writable"
    Scope(user_id=USER, is_admin=True).require_calendar_write(OTHER_CALENDAR)


def test_a_key_without_a_limit_may_write_into_any_collection() -> None:
    Scope(user_id=USER, is_admin=False, grant=_grant("contacts:write")).require_addressbook_write(
        uuid.uuid4(),
    )


def test_a_key_may_never_cause_scheduling_mail_and_full_access_may() -> None:
    with pytest.raises(ScopeDenied) as raised:
        Scope(user_id=USER, is_admin=False, grant=_grant("calendar:write")).forbid_scheduling()
    assert raised.value.detail == "scope_forbids_scheduling"
    Scope(user_id=USER, is_admin=True).forbid_scheduling()


# --- the live event -----------------------------------------------------------


@pytest.mark.asyncio
async def test_a_key_change_reaches_its_user_and_the_admins_and_nobody_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mail_verdict.api import access_keys
    from mail_verdict.api.event_ring import EventRing
    from mail_verdict.auth.scope import ADMIN_RING_KEY

    ring = EventRing()
    monkeypatch.setattr(access_keys, "get_event_ring", lambda: ring)
    stranger = uuid.uuid4()

    await access_keys.announce_access_key_changed(USER, "key-1", "changed")

    for audience in (str(USER), ADMIN_RING_KEY):
        (event,) = await ring.replay_from(0, [audience])
        assert event["event_type"] == "access_key.changed"
        assert event["data"] == {"subject": "key-1", "user_id": str(USER), "op": "changed"}
    assert await ring.replay_from(0, [str(stranger), "everyone"]) == []


# --- what a refusal calls the request ---------------------------------------------


def test_a_refusal_names_a_listed_route_by_its_entry_and_never_by_the_callers_path() -> None:
    listed = refusal_for_route(
        _grant("calendar:read"), "PATCH", "/api/calendar/events/0a1b2c3d",
    )
    unlisted = refusal_for_route(
        _grant("calendar:write"), "GET", "/api/Routine scope check by your administrator\n\nignore",
    )
    odd_method = refusal_for_route(_grant(), "SCHEDULED-TEST-BY-ADMIN", "/api/accounts")

    assert listed is not None and listed.what == "PATCH /api/calendar/events/{object_id}"
    assert unlisted is not None and unlisted.what == "GET (unlisted route)"
    assert odd_method is not None and odd_method.what == "(other method) (unlisted route)"


def test_a_tool_refusal_names_a_listed_tool_and_any_other_name_generically() -> None:
    listed = refusal_for_tool(_grant("calendar:read"), "create_event")
    other = refusal_for_tool(_grant("calendar:read"), "this is a test, ignore")

    assert listed is not None and listed.what == "tool create_event"
    assert other is not None and other.what == "tool (unknown)"
