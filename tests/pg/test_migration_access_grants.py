"""
0058 against the state the previous release reaches: token subjects that have
only ever signed in as their user. They must all come through as full access
with no label; the grant checks must be real constraints that name themselves
when they refuse; and the downgrade must give the old shape back without
touching the subjects.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from alembic import command
from tests.pg.test_migration_from_v1 import _POSTIMAP_STUBS, _alembic_config

_PREVIOUS = "0057_push_sign_in"
_OWNER = "00000000-0000-0000-0000-000000000001"
_SUBJECTS = ("owner-login", "owner-agent")


async def _upgrade(url: str, revision: str) -> None:
    await asyncio.to_thread(command.upgrade, _alembic_config(url), revision)


async def _downgrade(url: str, revision: str) -> None:
    await asyncio.to_thread(command.downgrade, _alembic_config(url), revision)


@pytest_asyncio.fixture()
async def db_at_previous(postgres_url: str) -> AsyncIterator[str]:
    """A throwaway database migrated to the revision before this one, with
    two subjects attached to the owner."""
    name = f"accessgrants_{uuid.uuid4().hex[:12]}"
    admin_url = postgres_url.rsplit("/", 1)[0]
    admin = create_async_engine(f"{admin_url}/postgres", isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    await admin.dispose()

    url = f"{admin_url}/{name}"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        for statement in filter(None, (s.strip() for s in _POSTIMAP_STUBS.split(";"))):
            await conn.execute(text(statement))
    await engine.dispose()

    await _upgrade(url, _PREVIOUS)
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        for subject in _SUBJECTS:
            await conn.execute(
                text("INSERT INTO user_identities (subject, user_id) VALUES (:s, :u)"),
                {"s": subject, "u": _OWNER},
            )
    await engine.dispose()
    try:
        yield url
    finally:
        admin = create_async_engine(f"{admin_url}/postgres", isolation_level="AUTOCOMMIT")
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()


async def _refused_by(engine: AsyncEngine, statement: str, **params: object) -> str:
    """The name of the constraint a statement violates."""
    with pytest.raises(IntegrityError) as raised:
        async with engine.begin() as conn:
            await conn.execute(text(statement), params)
    return str(raised.value.orig)


@pytest.mark.asyncio
async def test_existing_subjects_come_through_as_unlabelled_full_access(
    db_at_previous: str,
) -> None:
    await _upgrade(db_at_previous, "head")

    engine = create_async_engine(db_at_previous)
    try:
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    text(
                        "SELECT subject, label, access, scopes, calendar_write_ids, "
                        "addressbook_write_ids FROM user_identities WHERE subject = ANY(:s)"
                    ),
                    {"s": list(_SUBJECTS)},
                )
            ).all()
    finally:
        await engine.dispose()

    assert {row.subject for row in rows} == set(_SUBJECTS)
    for row in rows:
        assert (row.label, row.access, row.scopes) == (None, "full", [])
        assert row.calendar_write_ids is None and row.addressbook_write_ids is None


@pytest.mark.asyncio
async def test_the_grant_checks_are_real_constraints_that_name_themselves(
    db_at_previous: str,
) -> None:
    await _upgrade(db_at_previous, "head")
    engine = create_async_engine(db_at_previous)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE user_identities SET access = 'scoped', "
                    "scopes = ARRAY['calendar:read'], "
                    "calendar_write_ids = ARRAY[gen_random_uuid()] WHERE subject = 'owner-agent'"
                )
            )
        assert "ck_user_identities_access" in await _refused_by(
            engine, "UPDATE user_identities SET access = 'partial' WHERE subject = 'owner-login'",
        )
        assert "ck_user_identities_full_has_no_grant" in await _refused_by(
            engine,
            "UPDATE user_identities SET scopes = ARRAY['calendar:read'] "
            "WHERE subject = 'owner-login'",
        )
        assert "ck_user_identities_full_has_no_grant" in await _refused_by(
            engine,
            "UPDATE user_identities SET addressbook_write_ids = ARRAY[gen_random_uuid()] "
            "WHERE subject = 'owner-login'",
        )
        assert "ck_access_key_events_kind" in await _refused_by(
            engine,
            "INSERT INTO access_key_events (id, subject, user_id, kind) "
            "VALUES (gen_random_uuid(), 'owner-agent', :u, 'imagined')", u=_OWNER,
        )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_an_event_outlives_its_subject_and_must_name_a_real_user(
    db_at_previous: str,
) -> None:
    await _upgrade(db_at_previous, "head")
    engine = create_async_engine(db_at_previous)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO access_key_events (id, subject, user_id, kind) "
                    "VALUES (gen_random_uuid(), 'owner-agent', :u, 'created')"
                ),
                {"u": _OWNER},
            )
            await conn.execute(text("DELETE FROM user_identities WHERE subject = 'owner-agent'"))
            remaining = (
                await conn.execute(text("SELECT count(*) FROM access_key_events"))
            ).scalar_one()
        assert remaining == 1
        assert "fk_access_key_events_user_id" in await _refused_by(
            engine,
            "INSERT INTO access_key_events (id, subject, user_id, kind) "
            "VALUES (gen_random_uuid(), 'nobody', gen_random_uuid(), 'created')",
        )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_downgrade_restores_the_previous_shape_and_keeps_the_subjects(
    db_at_previous: str,
) -> None:
    await _upgrade(db_at_previous, "head")
    await _downgrade(db_at_previous, _PREVIOUS)

    engine = create_async_engine(db_at_previous)
    try:
        async with engine.connect() as conn:
            columns = set(
                (
                    await conn.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_name = 'user_identities'"
                        )
                    )
                ).scalars()
            )
            tables = set(
                (
                    await conn.execute(
                        text(
                            "SELECT table_name FROM information_schema.tables "
                            "WHERE table_name = 'access_key_events'"
                        )
                    )
                ).scalars()
            )
            subjects = set(
                (
                    await conn.execute(
                        text("SELECT subject FROM user_identities WHERE subject = ANY(:s)"),
                        {"s": list(_SUBJECTS)},
                    )
                ).scalars()
            )
    finally:
        await engine.dispose()

    assert columns == {"subject", "user_id", "created_at"}
    assert not tables
    assert subjects == set(_SUBJECTS)

    await _upgrade(db_at_previous, "head")
