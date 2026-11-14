"""A Web Push send gives up after push.webpush_timeout_seconds.

pywebpush passes no timeout of its own, which aiohttp reads as none at all,
so a push service that never answers would hold the send forever. The
listener here is on loopback, which the send's address guard refuses, so the
guard is swapped for a plain connector: this is about the timeout alone.
"""

from __future__ import annotations

import asyncio
import base64
import os
import socket
import time
import uuid
from collections.abc import AsyncIterator
from types import SimpleNamespace

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from py_vapid import Vapid02

from mail_verdict.database.models import Alert, PushSubscription
from mail_verdict.push import send
from mail_verdict.push.relay import RelayOutcome


@pytest_asyncio.fixture()
async def silent_push_service() -> AsyncIterator[int]:
    """A push service on loopback that accepts the request and never answers."""

    async def handle(request: web.Request) -> web.Response:
        await asyncio.sleep(30)
        return web.Response(status=201)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    runner = web.AppRunner(app, shutdown_timeout=0.1)
    await runner.setup()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    await web.TCPSite(runner, "127.0.0.1", port).start()
    try:
        yield port
    finally:
        await runner.cleanup()


class _Vapid:
    def __init__(self) -> None:
        self._key = Vapid02()
        self._key.generate_keys()

    async def get_or_create(self) -> Vapid02:
        return self._key


def _subscription(endpoint: str) -> PushSubscription:
    public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()  # noqa: E731
    return PushSubscription(
        id=uuid.uuid4(), transport="webpush", endpoint=endpoint, p256dh=encode(public),
        auth=encode(os.urandom(16)),
    )


@pytest.mark.asyncio
async def test_a_push_service_that_never_answers_is_a_failed_send_after_the_timeout(
    silent_push_service: int, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(send, "PublicOnlyConnector", aiohttp.TCPConnector)
    config = SimpleNamespace(push=SimpleNamespace(webpush_timeout_seconds=0.5))
    monkeypatch.setattr(send, "get_config", lambda: config)
    alert = Alert(id=uuid.uuid4(), kind="mail", title="t")
    sub = _subscription(f"http://127.0.0.1:{silent_push_service}/push")

    started = time.monotonic()
    outcome = await send._send_webpush(_Vapid(), alert, sub)  # type: ignore[arg-type]

    assert outcome is RelayOutcome.FAILED
    assert time.monotonic() - started < 5
