"""
A refused scoped key leaves a trail and tells its user, against a real
database: one audit row per key and route and hour with the repeats counted,
a cap on how many rows one key can write, and one alert per key and day for
the key's own user.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import text

from mail_verdict.alerts import access_key_refused
from mail_verdict.alerts.access_key_refused import record_refusal
from mail_verdict.auth.grants import Grant, Refusal
from mail_verdict.auth.principal import OWNER_USER_ID, Principal
from mail_verdict.database.connection import DatabaseConnection


async def _key(db: DatabaseConnection, label: str | None = "Calendar sync") -> Principal:
    subject = f"refused-key-{uuid.uuid4()}"
    async with db.session() as session:
        await session.execute(
            text(
                "INSERT INTO user_identities (subject, user_id, label, access, scopes) "
                "VALUES (:s, :u, :l, 'scoped', ARRAY['calendar:read'])"
            ),
            {"s": subject, "u": OWNER_USER_ID, "l": label},
        )
    return Principal(
        user_id=OWNER_USER_ID, subject=subject, is_admin=False,
        grant=Grant(frozenset({"calendar:read"})),
    )


async def _events(db: DatabaseConnection, subject: str) -> list[dict[str, Any]]:
    async with db.session() as session:
        rows = await session.execute(
            text(
                "SELECT detail FROM access_key_events "
                "WHERE subject = :s AND kind = 'refused' ORDER BY at"
            ),
            {"s": subject},
        )
        return [row.detail for row in rows]


async def _alerts(db: DatabaseConnection, subject: str) -> list[Any]:
    async with db.session() as session:
        rows = await session.execute(
            text(
                "SELECT kind, user_id, account_id, title, body FROM alerts "
                "WHERE dedupe_key LIKE :k"
            ),
            {"k": f"access-key-refused:{subject}:%"},
        )
        return list(rows)


@pytest.mark.asyncio
async def test_a_repeat_counts_on_the_same_row_and_another_route_gets_its_own(
    migrated_db: DatabaseConnection,
) -> None:
    key = await _key(migrated_db)

    for _ in range(3):
        await record_refusal(key, Refusal(None, "GET /api/accounts"))
    await record_refusal(key, Refusal("calendar:write", "POST /api/calendar/events"))

    assert await _events(migrated_db, key.subject) == [
        {"what": "GET /api/accounts", "scope": None, "count": 3},
        {"what": "POST /api/calendar/events", "scope": "calendar:write", "count": 1},
    ]


@pytest.mark.asyncio
async def test_a_name_longer_than_the_bound_is_cut_before_it_is_stored_or_shown(
    migrated_db: DatabaseConnection,
) -> None:
    key = await _key(migrated_db)

    await record_refusal(key, Refusal(None, "tool " + "x" * 5000))

    (event,) = await _events(migrated_db, key.subject)
    (alert,) = await _alerts(migrated_db, key.subject)
    assert len(event["what"]) == 200
    assert len(alert.body) < 400


@pytest.mark.asyncio
async def test_a_key_probing_many_routes_cannot_write_more_than_the_cap(
    migrated_db: DatabaseConnection, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(access_key_refused, "MAX_ROWS_PER_HOUR", 3)
    key = await _key(migrated_db)

    for number in range(6):
        await record_refusal(key, Refusal(None, f"GET /api/probe-{number}"))

    events = await _events(migrated_db, key.subject)
    assert len(events) == 3
    assert sum(e["count"] + e.get("suppressed", 0) for e in events) == 6


@pytest.mark.asyncio
async def test_the_alert_goes_to_the_keys_user_once_a_day_and_names_the_key(
    migrated_db: DatabaseConnection,
) -> None:
    key = await _key(migrated_db, label="Calendar sync")

    await record_refusal(key, Refusal(None, "GET /api/accounts"))
    await record_refusal(key, Refusal(None, "POST /api/outbox"))

    (alert,) = await _alerts(migrated_db, key.subject)
    assert alert.kind == "access_key_refused"
    assert alert.user_id == OWNER_USER_ID and alert.account_id is None
    assert "Calendar sync" in alert.body and "GET /api/accounts" in alert.body


@pytest.mark.asyncio
async def test_an_unlabelled_key_is_named_by_its_subject(migrated_db: DatabaseConnection) -> None:
    key = await _key(migrated_db, label=None)

    await record_refusal(key, Refusal(None, "GET /api/accounts"))

    (alert,) = await _alerts(migrated_db, key.subject)
    assert key.subject in alert.body


@pytest.mark.asyncio
async def test_a_failure_to_record_never_reaches_the_caller(
    migrated_db: DatabaseConnection, monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(*args: object) -> None:
        raise RuntimeError("database gone")

    monkeypatch.setattr(access_key_refused, "_record", broken)

    await record_refusal(await _key(migrated_db), Refusal(None, "GET /api/accounts"))
