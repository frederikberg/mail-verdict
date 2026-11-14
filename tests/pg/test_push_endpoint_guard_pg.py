"""
The Web Push routes against a real schema: a browser endpoint on an internal
address is refused at registration, and a test push to an endpoint that
cannot be reached -- refused by the guard, or not resolvable at all -- is the
documented 502, its row stamped failed, never a 500. webpush_async runs for
real here; nothing is mocked between the route and the connection attempt.
"""

from __future__ import annotations

import base64
import os
import uuid
from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from starlette.testclient import TestClient

from mail_verdict.api.alerts import router as alerts_router
from mail_verdict.auth.principal import OWNER_USER_ID
from mail_verdict.database.connection import DatabaseConnection
from mail_verdict.database.repository import PushSubscriptionRepository
from mail_verdict.push.vapid import VapidKeyRepository
from tests.helpers.auth import act_as_owner_of_everything

_ENCRYPTION_KEY = "00" * 32


def _browser_keys() -> dict[str, str]:
    """A real browser subscription's keys: pywebpush encrypts the payload
    with them before it connects anywhere."""
    public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()  # noqa: E731
    return {"p256dh": encode(public), "auth": encode(os.urandom(16))}


@pytest.fixture()
def client(
    migrated_db: DatabaseConnection, monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(alerts_router)
    act_as_owner_of_everything(app, migrated_db)
    monkeypatch.setattr(
        "mail_verdict.push.vapid._vapid_repo", VapidKeyRepository(migrated_db, _ENCRYPTION_KEY),
    )
    # A browser row never reaches the relay; this server has none configured.
    monkeypatch.setattr("mail_verdict.api.alerts.get_relay_client", lambda: None)
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize(
    "endpoint", ["http://127.0.0.1:2586/upAbc", "https://10.0.0.5/push", "https://[::1]/push"],
)
def test_a_browser_endpoint_on_an_internal_address_is_refused(
    client: TestClient, endpoint: str,
) -> None:
    response = client.post(
        "/alerts/subscriptions", json={"endpoint": endpoint, "keys": _browser_keys()},
    )

    assert response.status_code == 400
    assert "public address" in response.json()["detail"]


@pytest.mark.parametrize(
    "endpoint", ["http://127.0.0.1:2586/upAbc", "https://push.invalid/push"],
)
def test_a_test_push_that_cannot_be_delivered_is_502_and_marks_the_device_failed(
    client: TestClient, migrated_db: DatabaseConnection, endpoint: str,
) -> None:
    """The row is written past the registration check, as one stored before
    it existed would be."""
    keys = _browser_keys()
    repo = PushSubscriptionRepository(migrated_db)
    row = client.portal.call(
        lambda: repo.upsert(
            OWNER_USER_ID, endpoint=f"{endpoint}-{uuid.uuid4()}", p256dh=keys["p256dh"],
            auth=keys["auth"], label=None,
        )
    )

    response = client.post(f"/alerts/subscriptions/{row.id}/test")

    assert response.status_code == 502
    stored = [
        s for s in client.portal.call(repo.list_for_user, OWNER_USER_ID) if s.id == row.id
    ]
    assert stored and stored[0].failed_at is not None
