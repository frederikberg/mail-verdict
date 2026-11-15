"""
Access tokens for webhook headers from a stored OAuth2 client.

A receiver behind an identity provider takes only short-lived tokens, which a
value typed into a header once cannot supply. A rule's header instead names a
client as `{{oauth:NAME}}`; the secret NAME holds the client's credentials as
one JSON object,

    {"token_url": "https://idp.example/oauth/v2/token",
     "client_id": "...", "client_secret": "...", "scope": "..."}

(`scope` optional), and the token is fetched with the client-credentials grant
when a delivery needs one. A token is kept in memory until shortly before it
expires and fetched again after that; replacing the secret drops it at once,
since the cache is keyed by the document's hash.

Nothing here logs or returns a credential, a token, a response body or
transport error text: a failure carries the class of the problem and an HTTP
status only, and the worker stores that as the delivery's error.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

_RETRYABLE_STATUSES = frozenset({408, 429})


class ClientTokenError(Exception):
    """A token could not be had. `permanent` says whether asking again with
    the same credentials would change anything; the text names no value."""

    def __init__(self, detail: str, *, permanent: bool) -> None:
        super().__init__(detail)
        self.detail = detail
        self.permanent = permanent


@dataclass(frozen=True)
class _Client:
    token_url: str
    client_id: str
    client_secret: str
    scope: str | None


def _parse_client(name: str, document: str) -> _Client:
    try:
        raw: Any = json.loads(document)
    except ValueError:
        raise ClientTokenError(
            f"secret {name} is not a JSON document of OAuth2 client credentials", permanent=True,
        ) from None
    if not isinstance(raw, dict):
        raise ClientTokenError(
            f"secret {name} is not a JSON object of OAuth2 client credentials", permanent=True,
        )
    fields = {}
    for key in ("token_url", "client_id", "client_secret"):
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            raise ClientTokenError(f"secret {name} has no {key}", permanent=True)
        fields[key] = value
    scope = raw.get("scope")
    if scope is not None and not isinstance(scope, str):
        raise ClientTokenError(f"secret {name} has a scope that is not a string", permanent=True)
    if not fields["token_url"].startswith(("https://", "http://")):
        raise ClientTokenError(f"secret {name} has a token_url that is not http(s)", permanent=True)
    return _Client(scope=scope or None, **fields)


class ClientTokenCache:
    """Fetches and remembers the access tokens of stored OAuth2 clients."""

    def __init__(
        self, *, request_timeout_seconds: float, refresh_margin_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._timeout = request_timeout_seconds
        self._margin = refresh_margin_seconds
        self._clock = clock
        self._transport = transport
        self._tokens: dict[tuple[str, str], tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    async def token(self, name: str, document: str) -> str:
        """The access token of the client the secret `name` describes.

        Raises:
            ClientTokenError: the document is unusable, the provider refused
                the client, or it could not be reached
        """
        key = (name, hashlib.sha256(document.encode()).hexdigest())
        async with self._lock:
            cached = self._tokens.get(key)
            if cached is not None and self._clock() < cached[1]:
                return cached[0]
            # A replaced document leaves its old token behind otherwise.
            self._tokens = {k: v for k, v in self._tokens.items() if k[0] != name}
            token, lifetime = await self._fetch(name, _parse_client(name, document))
            refresh_in = lifetime - min(self._margin, lifetime / 2)
            self._tokens[key] = (token, self._clock() + refresh_in)
            return token

    async def _fetch(self, name: str, client: _Client) -> tuple[str, float]:
        form = {"grant_type": "client_credentials"}
        if client.scope:
            form["scope"] = client.scope
        try:
            async with httpx.AsyncClient(
                follow_redirects=False, timeout=httpx.Timeout(self._timeout),
                transport=self._transport,
            ) as http:
                response = await asyncio.wait_for(
                    http.post(
                        client.token_url, data=form, auth=(client.client_id, client.client_secret),
                    ),
                    timeout=self._timeout,
                )
        except asyncio.TimeoutError:
            raise ClientTokenError(
                f"token request for {name} timed out", permanent=False,
            ) from None
        except httpx.HTTPError as exc:
            raise ClientTokenError(
                f"token request for {name} failed: {type(exc).__name__}", permanent=False,
            ) from None
        status = response.status_code
        if status != 200:
            raise ClientTokenError(
                f"token request for {name} answered HTTP {status}",
                permanent=not (status >= 500 or status in _RETRYABLE_STATUSES),
            )
        try:
            body: Any = response.json()
            token = body["access_token"]
            lifetime = float(body["expires_in"])
        except (ValueError, KeyError, TypeError):
            raise ClientTokenError(
                f"token response for {name} has no access_token and expires_in", permanent=False,
            ) from None
        if not isinstance(token, str) or not token or lifetime <= 0:
            raise ClientTokenError(
                f"token response for {name} has no usable access_token", permanent=False,
            )
        return token, lifetime
