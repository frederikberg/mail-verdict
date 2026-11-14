"""Web Push endpoints on non-public addresses, refused at registration and at
send time.

The send-time cases go through a real aiohttp connection attempt against a
listener on loopback, so a refusal is proven by the listener never seeing a
request, not by a mocked call.
"""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web

from mail_verdict.push.endpoint_guard import (
    EndpointRefused,
    PublicOnlyConnector,
    check_push_endpoint,
    is_public_address,
)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
        "0.0.0.0", "224.0.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "not-an-ip",
    ],
)
def test_internal_and_special_addresses_are_not_public(address: str) -> None:
    assert not is_public_address(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_global_unicast_addresses_are_public(address: str) -> None:
    assert is_public_address(address)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:2586/up123",
        "https://10.0.0.5/push",
        "https://[fd00::1]/push",
        "https://169.254.169.254/latest",
        "https://[::ffff:127.0.0.1]/push",
        "https://localhost/push",
        "ftp://push.example/x",
        "not a url",
    ],
)
async def test_an_endpoint_that_is_or_resolves_to_an_internal_address_is_refused(
    url: str,
) -> None:
    with pytest.raises(EndpointRefused):
        await check_push_endpoint(url)


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["https://8.8.8.8/push", "https://push.invalid/push"])
async def test_a_public_or_not_yet_resolvable_endpoint_is_accepted(url: str) -> None:
    await check_push_endpoint(url)


@pytest_asyncio.fixture()
async def listener() -> AsyncIterator[tuple[int, list[str]]]:
    """An HTTP server on loopback, recording every request it is sent."""
    hits: list[str] = []

    async def handle(request: web.Request) -> web.Response:
        hits.append(request.path)
        return web.Response(status=201)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    try:
        yield port, hits
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_the_connector_refuses_a_loopback_address_before_connecting(
    listener: tuple[int, list[str]],
) -> None:
    port, hits = listener
    async with aiohttp.ClientSession(connector=PublicOnlyConnector()) as session:
        with pytest.raises(aiohttp.ClientConnectorError):
            await session.post(f"http://127.0.0.1:{port}/push")
    assert hits == []


@pytest.mark.asyncio
async def test_a_name_resolving_to_loopback_at_send_time_is_refused(
    listener: tuple[int, list[str]],
) -> None:
    """DNS rebinding: whatever a name pointed at when it was registered, the
    connection checks what it points at now."""
    port, hits = listener

    class Rebound(aiohttp.abc.AbstractResolver):
        async def resolve(self, host: str, port: int = 0, family: Any = 0) -> list[Any]:
            return [{
                "hostname": host, "host": "127.0.0.1", "port": port,
                "family": socket.AF_INET, "proto": 0, "flags": 0,
            }]

        async def close(self) -> None:
            pass

    connector = PublicOnlyConnector(resolver=Rebound())
    async with aiohttp.ClientSession(connector=connector) as session:
        with pytest.raises(aiohttp.ClientConnectorError):
            await session.post(f"http://push.example.com:{port}/push")
    assert hits == []


@pytest.mark.asyncio
async def test_without_the_guard_the_same_request_reaches_the_listener(
    listener: tuple[int, list[str]],
) -> None:
    """The control: the listener is reachable, so the refusals above are the
    guard's and not a dead port."""
    port, hits = listener
    async with aiohttp.ClientSession() as session:
        response = await session.post(f"http://127.0.0.1:{port}/push")
    assert response.status == 201
    assert hits == ["/push"]
