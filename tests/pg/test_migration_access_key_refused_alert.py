"""
0059 admits the alert kind `access_key_refused` and nothing before it does;
the downgrade drops such alerts and gives the previous kinds back.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from tests.pg.test_migration_from_v1 import _POSTIMAP_STUBS, _alembic_config, _upgrade

_PREVIOUS = "0058_access_grants"
_REVISION = "0059_access_key_refused_alert"


@pytest_asyncio.fixture()
async def db_at_previous(postgres_url: str) -> AsyncIterator[str]:
    name = f"refusedalert_{uuid.uuid4().hex[:12]}"
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
    try:
        yield url
    finally:
        admin = create_async_engine(f"{admin_url}/postgres", isolation_level="AUTOCOMMIT")
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()


async def _insert_alert(url: str, kind: str) -> None:
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO alerts (kind, deliver_at, dedupe_key) VALUES (:k, now(), :d)"),
                {"k": kind, "d": f"{kind}:{uuid.uuid4()}"},
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_the_alert_kind_is_admitted_only_from_this_revision(db_at_previous: str) -> None:
    with pytest.raises(IntegrityError, match="ck_alerts_kind"):
        await _insert_alert(db_at_previous, "access_key_refused")

    await _upgrade(db_at_previous, _REVISION)
    await _insert_alert(db_at_previous, "access_key_refused")
    await _insert_alert(db_at_previous, "account_unowned")

    await asyncio.to_thread(command.downgrade, _alembic_config(db_at_previous), _PREVIOUS)

    engine = create_async_engine(db_at_previous)
    try:
        async with engine.connect() as conn:
            kinds = (await conn.execute(text("SELECT kind FROM alerts"))).scalars().all()
    finally:
        await engine.dispose()
    assert kinds == ["account_unowned"]
