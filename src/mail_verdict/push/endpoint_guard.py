"""
Keeping Web Push sends on the public internet.

A browser hands this server the URL of its push service, and the server
POSTs to it from wherever it runs -- inside a cluster, next to its database
and every other internal service. So the URL is a client-chosen target, and
only public addresses are acceptable: an endpoint that is, or resolves to, a
loopback, private, link-local, unique-local, shared (carrier-grade NAT) or
otherwise non-global address is refused.

The check runs twice. At registration, `check_push_endpoint` refuses what
is visibly wrong now. At send time, `PublicOnlyConnector` checks the
address it is about to connect to, after resolution and for every
connection the request makes, redirects included -- so a name that
resolved to a public address at registration and to an internal one later
(DNS rebinding) is still refused. Native push is unaffected: its relays are
configuration (push.relay_urls), not client input.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Sequence
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import aiohttp

if TYPE_CHECKING:
    from aiohttp.abc import ResolveResult
    from aiohttp.tracing import Trace


class EndpointRefused(ValueError):
    """A push endpoint this server will not send to; the message says why."""


class PrivateAddressRefused(OSError):
    """A connection to a non-public address, refused before it was made."""


def is_public_address(address: str) -> bool:
    """Whether an IP address is one a push may be sent to: globally routable
    unicast, an IPv4-mapped IPv6 address judged by its IPv4 part."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def check_push_endpoint(url: str) -> None:
    """
    Refuse a push endpoint that is not an http(s) URL, or whose host is or
    resolves to a non-public address. A name that does not resolve now is
    accepted: nothing is sent to it until it does, and the send checks again.

    Raises:
        EndpointRefused: The endpoint may not be registered.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise EndpointRefused("the endpoint is not an http(s) URL")
    host = parts.hostname
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        addresses = [host]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, parts.port or 443, type=socket.SOCK_STREAM,
            )
        except OSError:
            return
        addresses = [str(info[4][0]) for info in infos]
    if not all(is_public_address(address) for address in addresses):
        raise EndpointRefused("the endpoint is not on a public address")


class PublicOnlyConnector(aiohttp.TCPConnector):
    """A TCP connector that refuses to connect to any non-public address.

    Every connection aiohttp makes resolves its host here first -- a literal
    address as well as a name, the first request as well as a redirect --
    so checking the resolved addresses is checking what is connected to.
    """

    async def _resolve_host(
        self, host: str, port: int, traces: Sequence[Trace] | None = None,
    ) -> list[ResolveResult]:
        hosts = await super()._resolve_host(host, port, traces=traces)
        if not hosts or not all(is_public_address(entry["host"]) for entry in hosts):
            raise PrivateAddressRefused(f"{host} is not on a public address")
        return hosts
