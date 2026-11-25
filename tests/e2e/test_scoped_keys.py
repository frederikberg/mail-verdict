"""
Scoped access keys on the running app, with real tokens.

An admin attaches a machine subject to a user with a grant; the key then
reaches only what its scopes name -- over REST and over MCP -- whatever its
user may do, and what an admin changes takes effect on the next request.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.testclient import TestClient

from mail_verdict.auth.principal import OWNER_USER_ID
from tests.e2e.helpers import (
    unique_email,
    wait_for_account_active,
    wait_for_dav_account_active,
    wait_for_dav_collection,
)
from tests.helpers.mcp_http import McpHttpSession
from tests.setup.auth import OWNER_SUBJECT, TestIssuer, bearer
from tests.setup.containers import (
    DOVECOT_ALIAS,
    DOVECOT_IMAP_PORT,
    DOVECOT_PASSWORD,
    RADICALE_ALIAS,
    RADICALE_PORT,
)
from tests.setup.dav_helpers import create_calendar, discover

OWNER = str(OWNER_USER_ID)


@pytest.fixture(scope="module")
def calendar(app_client: TestClient, radicale_endpoint: tuple[str, int]) -> dict[str, Any]:
    """A calendar of the owner's, discovered from a real server."""
    host, port = radicale_endpoint
    username = f"key-{uuid.uuid4().hex[:8]}"
    with httpx.Client(auth=(username, "unused"), timeout=10.0) as client:
        principal = discover(client, f"http://{host}:{port}/")
        create_calendar(client, principal, "work", "Work")
    response = app_client.post(
        "/api/dav-accounts",
        json={
            "name": f"Radicale-{uuid.uuid4().hex[:8]}",
            "discovery_url": f"http://{RADICALE_ALIAS}:{RADICALE_PORT}/",
            "username": username, "password": "unused",
        },
    )
    assert response.status_code == 201, response.text
    wait_for_dav_account_active(app_client, response.json()["id"])
    return wait_for_dav_collection(app_client, response.json()["id"], "Work")


@pytest.fixture(scope="module")
def mail_account(app_client: TestClient) -> str:
    """A mail account of the owner's, so an empty answer for a key means the
    scope held nothing back rather than that there was nothing to hold."""
    email = unique_email("keys")
    response = app_client.post(
        "/api/accounts",
        json={
            "name": email, "imap_host": DOVECOT_ALIAS, "imap_port": DOVECOT_IMAP_PORT,
            "imap_user": email, "imap_password": DOVECOT_PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    wait_for_account_active(app_client, response.json()["id"])
    account_id: str = response.json()["id"]
    return account_id


class Keys:
    """Attaches keys to the owner and calls the app as them."""

    def __init__(self, client: TestClient, issuer: TestIssuer) -> None:
        self.client = client
        self.issuer = issuer

    def attach(self, **grant: Any) -> str:
        """Attach a new machine subject to the owner with `grant`; returns its subject."""
        subject = f"key-{uuid.uuid4().hex[:8]}"
        response = self.client.post(
            f"/api/admin/users/{OWNER}/subjects", json={"subject": subject, **grant},
        )
        assert response.status_code == 201, response.text
        return subject

    def headers(self, subject: str) -> dict[str, str]:
        return bearer(self.issuer.mint(subject))

    def get(self, subject: str, path: str) -> Any:
        return self.client.get(path, headers=self.headers(subject))

    def change(self, subject: str, **fields: Any) -> Any:
        return self.client.patch(f"/api/admin/users/{OWNER}/subjects/{subject}", json=fields)


@pytest.fixture()
def keys(app_client: TestClient, auth_issuer: TestIssuer) -> Keys:
    return Keys(app_client, auth_issuer)


def _refusal(response: Any, scope: str | None) -> bool:
    return response.status_code == 403 and response.json() == {
        "detail": "scope_required", "scope": scope,
    }


@pytest.mark.usefixtures("mail_account")
def test_a_calendar_key_reads_calendars_and_nothing_else_though_its_user_is_admin(
    keys: Keys, calendar: dict[str, Any],
) -> None:
    key = keys.attach(label="Calendar reader", access="scoped", scopes=["calendar:read"])

    calendars = keys.get(key, "/api/calendars")
    me = keys.get(key, "/api/me").json()

    assert calendars.status_code == 200
    assert calendar["id"] in calendars.text
    assert me["role"] == "user" and me["access"]["mode"] == "scoped"
    assert me["access"]["scopes"] == ["calendar:read"]
    for path in ("/api/accounts", "/api/admin/users", "/api/secrets", "/api/webhooks/deliveries",
                 "/api/settings", "/api/pipeline", "/api/events", "/api/contacts"):
        response = keys.get(key, path)
        assert _refusal(response, "contacts:read" if path == "/api/contacts" else None), path
    write = keys.client.post(
        "/api/calendar/events", headers=keys.headers(key), json={},
    )
    assert _refusal(write, "calendar:write")


def test_the_owners_own_login_stays_full(keys: Keys, mail_account: str) -> None:
    me = keys.client.get("/api/me").json()

    assert me["role"] == "admin" and me["access"]["mode"] == "full"
    assert keys.client.get("/api/accounts").status_code == 200


def test_with_the_gate_open_a_calendar_key_still_finds_no_mail(
    keys: Keys, mail_account: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = keys.attach(access="scoped", scopes=["calendar:read"])
    as_owner = keys.client.get("/api/accounts").json()
    assert any(account["id"] == mail_account for account in as_owner)
    monkeypatch.setattr("mail_verdict.auth.middleware.refusal_for_route", lambda *a: None)

    response = keys.get(key, "/api/accounts")

    assert response.status_code == 200 and response.json() == []
    assert keys.get(key, "/api/admin/users").status_code == 403


def test_what_an_admin_changes_takes_effect_on_the_next_request(keys: Keys) -> None:
    key = keys.attach(access="scoped", scopes=["calendar:read"])
    assert keys.get(key, "/api/calendars").status_code == 200

    narrowed = keys.change(key, scopes=[])
    assert narrowed.status_code == 200, narrowed.text
    assert _refusal(keys.get(key, "/api/calendars"), "calendar:read")

    widened = keys.change(key, scopes=["contacts:write"])
    assert widened.status_code == 200
    assert keys.get(key, "/api/contacts").status_code == 200
    assert _refusal(keys.get(key, "/api/calendars"), "calendar:read")

    full = keys.change(key, access="full")
    assert full.status_code == 200 and full.json()["scopes"] == []
    assert keys.get(key, "/api/accounts").status_code == 200


def test_a_key_over_mcp_sees_and_calls_only_the_tools_its_scopes_hold(keys: Keys) -> None:
    key = keys.attach(access="scoped", scopes=["calendar:read", "contacts:write"])
    session = McpHttpSession(keys.client, "/mcp/", keys.headers(key))

    listed = session.list_tools(keys.headers(key))["result"]["tools"]
    mail = session.call_tool("list_accounts", {}, keys.headers(key))["result"]
    held = session.call_tool("list_calendars", {}, keys.headers(key))["result"]

    assert {tool["name"] for tool in listed} == {
        "list_calendars", "list_events", "get_event", "list_addressbooks", "list_contacts",
        "search_contacts", "get_contact", "create_contact", "update_contact", "delete_contact",
    }
    assert mail["isError"]
    assert json.loads(mail["content"][0]["text"]) == {"detail": "scope_required", "scope": None}
    assert not held.get("isError")


def test_a_key_reads_its_own_grant_and_an_admin_lists_every_key(keys: Keys) -> None:
    key = keys.attach(label="Lister", access="scoped", scopes=["contacts:read"])

    own = keys.client.get("/api/me/access-keys").json()
    listed = keys.client.get("/api/admin/access-keys", params={"user_id": OWNER}).json()
    as_key = keys.get(key, "/api/me/access-keys")

    row = next(k for k in listed if k["subject"] == key)
    assert row["label"] == "Lister" and row["access"] == "scoped"
    assert row["scopes"] == ["contacts:read"] and row["sign_in_id"] is None
    assert any(k["subject"] == key for k in own)
    assert _refusal(as_key, None)
    # Once used, the key's sign-in is attached to its row.
    keys.get(key, "/api/me")
    used = next(
        k for k in keys.client.get("/api/admin/access-keys").json() if k["subject"] == key
    )
    assert used["sign_in_id"] is not None and used["first_seen_at"] is not None


@pytest.mark.parametrize(
    ("grant", "detail"),
    [
        ({"access": "full", "scopes": ["calendar:read"]}, "full_access_carries_no_scopes"),
        (
            {"access": "scoped", "scopes": ["calendar:read"],
             "calendar_write_ids": [str(uuid.uuid4())]},
            "calendar_limit_needs_calendar_write",
        ),
        (
            {"access": "scoped", "scopes": ["calendar:write"],
             "calendar_write_ids": [str(uuid.uuid4())]},
            "unknown_collection",
        ),
    ],
)
def test_a_grant_that_cannot_be_stored_is_refused_with_its_reason(
    keys: Keys, grant: dict[str, Any], detail: str,
) -> None:
    response = keys.client.post(
        f"/api/admin/users/{OWNER}/subjects", json={"subject": f"x-{uuid.uuid4()}", **grant},
    )

    assert response.status_code == 422 and response.json() == {"detail": detail}


def test_an_unknown_scope_is_refused(keys: Keys) -> None:
    response = keys.client.post(
        f"/api/admin/users/{OWNER}/subjects",
        json={"subject": f"x-{uuid.uuid4()}", "access": "scoped", "scopes": ["mail:read"]},
    )

    assert response.status_code == 422


def test_a_write_limit_names_one_of_the_users_own_calendars(
    keys: Keys, calendar: dict[str, Any],
) -> None:
    key = keys.attach(
        access="scoped", scopes=["calendar:write"], calendar_write_ids=[calendar["id"]],
    )

    me = keys.get(key, "/api/me").json()["access"]
    assert me["calendar_write_ids"] == [calendar["id"]]
    cleared = keys.change(key, scopes=["calendar:read"])
    assert cleared.status_code == 200 and cleared.json()["calendar_write_ids"] is None


def test_an_admin_cannot_change_the_grant_they_are_signed_in_with(
    keys: Keys, app_client: TestClient,
) -> None:
    response = app_client.patch(
        f"/api/admin/users/{OWNER}/subjects/{OWNER_SUBJECT}", json={"access": "scoped"},
    )

    assert response.status_code == 400


async def _events(postgres_url: str, subject: str) -> list[tuple[str, dict[str, Any]]]:
    engine = create_async_engine(postgres_url)
    try:
        async with engine.begin() as conn:
            rows = await conn.execute(
                text("SELECT kind, detail FROM access_key_events WHERE subject = :s ORDER BY at"),
                {"s": subject},
            )
            return [(row.kind, row.detail) for row in rows]
    finally:
        await engine.dispose()


def test_creating_changing_and_removing_a_key_leave_a_trail_that_outlives_it(
    keys: Keys, app_client: TestClient, postgres_url: str,
) -> None:
    key = keys.attach(label="Trail", access="scoped", scopes=["calendar:read"])
    keys.change(key, scopes=["calendar:write"])
    removed = app_client.delete(f"/api/admin/users/{OWNER}/subjects/{key}")
    assert removed.status_code == 200

    events = app_client.portal.call(_events, postgres_url, key)

    assert [kind for kind, _ in events] == ["created", "changed", "revoked"]
    assert events[0][1]["scopes"] == ["calendar:read"]
    assert events[1][1]["before"]["scopes"] == ["calendar:read"]
    assert events[1][1]["after"]["scopes"] == ["calendar:write"]


async def _rows(postgres_url: str, query: str, params: dict[str, Any]) -> list[Any]:
    engine = create_async_engine(postgres_url)
    try:
        async with engine.begin() as conn:
            return list((await conn.execute(text(query), params)).all())
    finally:
        await engine.dispose()


def test_a_refused_key_is_audited_and_its_user_is_alerted(
    keys: Keys, app_client: TestClient, postgres_url: str,
) -> None:
    key = keys.attach(label="Probe", access="scoped", scopes=["calendar:read"])

    for _ in range(2):
        assert _refusal(keys.get(key, "/api/accounts"), None)

    refused = app_client.portal.call(
        _rows, postgres_url,
        "SELECT detail FROM access_key_events WHERE subject = :s AND kind = 'refused'",
        {"s": key},
    )
    assert [(row.detail["what"], row.detail["count"]) for row in refused] == [
        ("GET /api/accounts", 2),
    ]
    alerts = [
        a for a in app_client.get("/api/alerts").json() if a["kind"] == "access_key_refused"
    ]
    assert len([a for a in alerts if "Probe" in (a["body"] or "")]) == 1
    listed = next(
        k for k in app_client.get("/api/admin/access-keys").json() if k["subject"] == key
    )
    assert listed["last_refusal_at"] is not None


def test_signing_a_key_out_is_audited_and_refuses_it_from_then_on(
    keys: Keys, app_client: TestClient, postgres_url: str,
) -> None:
    key = keys.attach(access="scoped", scopes=["calendar:read"])
    keys.get(key, "/api/me")
    sign_in = next(
        k for k in app_client.get("/api/admin/access-keys").json() if k["subject"] == key
    )["sign_in_id"]

    revoked = app_client.post(f"/api/admin/sign-ins/{sign_in}/revoke")

    assert revoked.status_code == 200
    assert keys.get(key, "/api/me").status_code == 401
    rows = app_client.portal.call(
        _rows, postgres_url,
        "SELECT detail, actor_user_id FROM access_key_events "
        "WHERE subject = :s AND kind = 'revoked'",
        {"s": key},
    )
    assert [(r.detail["reason"], str(r.actor_user_id)) for r in rows] == [("signed_out", OWNER)]


def test_a_key_over_mcp_creates_an_event_once_per_uid_and_never_one_with_attendees(
    keys: Keys, calendar: dict[str, Any],
) -> None:
    key = keys.attach(
        access="scoped", scopes=["calendar:write"], calendar_write_ids=[calendar["id"]],
    )
    session = McpHttpSession(keys.client, "/mcp/", keys.headers(key))
    arguments = {
        "calendar_id": calendar["id"], "summary": "Projected", "uid": f"todo-{uuid.uuid4()}",
        "dtstart": "2026-09-10T10:00:00Z", "dtend": "2026-09-10T11:00:00Z",
    }

    first = session.call_tool("create_event", arguments, keys.headers(key))["result"]
    again = session.call_tool("create_event", arguments, keys.headers(key))["result"]
    invited = session.call_tool(
        "create_event", {**arguments, "uid": "other", "attendee_emails": ["a@example.com"]},
        keys.headers(key),
    )["result"]

    assert not first.get("isError") and not again.get("isError")
    created, replayed = (json.loads(r["content"][0]["text"]) for r in (first, again))
    assert created["object_id"] == replayed["object_id"] and created["uid"] == arguments["uid"]
    assert json.loads(invited["content"][0]["text"]) == {"error": "scope_forbids_scheduling"}
