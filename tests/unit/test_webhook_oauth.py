"""Access tokens for webhook headers: fetched with a stored OAuth2 client's
credentials, kept until shortly before they expire, never echoed in an error."""

from __future__ import annotations

import json
from base64 import b64decode
from urllib.parse import parse_qs

import httpx
import pytest

from mail_verdict.pipeline.effect_codec import EffectConfigError, parse_effect
from mail_verdict.webhooks.oauth import ClientTokenCache, ClientTokenError
from mail_verdict.webhooks.spec import referenced_oauth_clients, render_headers

_SECRET = "client-secret-NOT-REAL"
_DOCUMENT = json.dumps({
    "token_url": "https://idp.example/oauth/v2/token", "client_id": "forwarder",
    "client_secret": _SECRET, "scope": "openid audience",
})


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Provider:
    """Answers token requests from a scripted list of (status, body) and records them."""

    def __init__(self, *answers: tuple[int, dict[str, object] | str]) -> None:
        self.answers = list(answers)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(body, str):
            return httpx.Response(status, text=body)
        return httpx.Response(status, json=body)


def _cache(provider: _Provider, clock: _Clock) -> ClientTokenCache:
    return ClientTokenCache(
        request_timeout_seconds=5, refresh_margin_seconds=60, clock=clock,
        transport=httpx.MockTransport(provider),
    )


def _ok(token: str, lifetime: int = 43200) -> tuple[int, dict[str, object]]:
    return 200, {"access_token": token, "expires_in": lifetime}


@pytest.mark.asyncio
class TestFetch:
    async def test_asks_with_the_client_credentials_grant_and_basic_auth(self) -> None:
        provider = _Provider(_ok("at-1"))

        assert await _cache(provider, _Clock()).token("RECEIVER", _DOCUMENT) == "at-1"

        request = provider.requests[0]
        assert str(request.url) == "https://idp.example/oauth/v2/token"
        assert parse_qs(request.content.decode()) == {
            "grant_type": ["client_credentials"], "scope": ["openid audience"],
        }
        scheme, _, encoded = request.headers["authorization"].partition(" ")
        assert scheme == "Basic"
        assert b64decode(encoded).decode() == f"forwarder:{_SECRET}"

    async def test_a_token_is_reused_until_its_refresh_margin(self) -> None:
        provider = _Provider(_ok("at-1", 600), _ok("at-2", 600))
        clock = _Clock()
        cache = _cache(provider, clock)

        assert await cache.token("RECEIVER", _DOCUMENT) == "at-1"
        clock.now += 539
        assert await cache.token("RECEIVER", _DOCUMENT) == "at-1"
        assert len(provider.requests) == 1
        clock.now += 2
        assert await cache.token("RECEIVER", _DOCUMENT) == "at-2"
        assert len(provider.requests) == 2

    async def test_a_short_lived_token_is_refreshed_at_half_its_life(self) -> None:
        provider = _Provider(_ok("at-1", 100), _ok("at-2", 100))
        clock = _Clock()
        cache = _cache(provider, clock)

        await cache.token("RECEIVER", _DOCUMENT)
        clock.now += 49
        assert await cache.token("RECEIVER", _DOCUMENT) == "at-1"
        clock.now += 2
        assert await cache.token("RECEIVER", _DOCUMENT) == "at-2"

    async def test_replacing_the_secret_drops_the_token_at_once(self) -> None:
        provider = _Provider(_ok("at-1"), _ok("at-2"))
        cache = _cache(provider, _Clock())
        other = json.dumps({**json.loads(_DOCUMENT), "client_secret": "rotated"})

        assert await cache.token("RECEIVER", _DOCUMENT) == "at-1"
        assert await cache.token("RECEIVER", other) == "at-2"

    async def test_a_scope_is_optional(self) -> None:
        provider = _Provider(_ok("at-1"))
        document = json.dumps({
            key: value for key, value in json.loads(_DOCUMENT).items() if key != "scope"
        })

        await _cache(provider, _Clock()).token("RECEIVER", document)

        assert parse_qs(provider.requests[0].content.decode()) == {
            "grant_type": ["client_credentials"],
        }


@pytest.mark.asyncio
class TestFailures:
    @pytest.mark.parametrize(
        ("answer", "permanent"),
        [((401, {"error": "invalid_client"}), True), ((400, "bad"), True),
         ((503, "down"), False), ((429, "slow"), False), ((408, "late"), False)],
    )
    async def test_a_refusal_is_permanent_and_a_busy_provider_is_not(
        self, answer: tuple[int, dict[str, object] | str], permanent: bool,
    ) -> None:
        with pytest.raises(ClientTokenError) as raised:
            await _cache(_Provider(answer), _Clock()).token("RECEIVER", _DOCUMENT)

        assert raised.value.permanent is permanent
        assert f"HTTP {answer[0]}" in raised.value.detail
        assert _SECRET not in raised.value.detail

    async def test_an_answer_without_a_token_is_retried(self) -> None:
        with pytest.raises(ClientTokenError) as raised:
            cache = _cache(_Provider((200, {"expires_in": 10})), _Clock())
            await cache.token("RECEIVER", _DOCUMENT)

        assert raised.value.permanent is False

    async def test_a_transport_error_is_retried_and_names_no_value(self) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"cannot connect, sent {request.headers['authorization']}")

        cache = ClientTokenCache(
            request_timeout_seconds=5, refresh_margin_seconds=60,
            transport=httpx.MockTransport(refuse),
        )
        with pytest.raises(ClientTokenError) as raised:
            await cache.token("RECEIVER", _DOCUMENT)

        assert raised.value.permanent is False
        assert "ConnectError" in raised.value.detail
        assert _SECRET not in raised.value.detail
        assert "Basic" not in raised.value.detail

    @pytest.mark.parametrize(
        "document",
        [
            "not json", "[]",
            json.dumps({"client_id": "a", "client_secret": "b"}),
            json.dumps({"token_url": "ftp://x", "client_id": "a", "client_secret": "b"}),
            json.dumps({"token_url": "https://x", "client_id": "a", "client_secret": "b",
                        "scope": 1}),
        ],
    )
    async def test_an_unusable_document_is_permanent_and_asks_nobody(self, document: str) -> None:
        provider = _Provider(_ok("at-1"))

        with pytest.raises(ClientTokenError) as raised:
            await _cache(provider, _Clock()).token("RECEIVER", document)

        assert raised.value.permanent is True
        assert provider.requests == []
        assert "client-secret" not in raised.value.detail


class TestHeaders:
    def test_an_oauth_reference_satisfies_a_credential_header(self) -> None:
        effect = parse_effect({"webhook": {
            "name": "inbox", "url": "https://receiver.example/api/inboxes/x/mails",
            "headers": {"Authorization": "Bearer {{oauth:RECEIVER}}"},
        }})

        assert effect is not None

    def test_a_literal_credential_is_still_refused_and_names_both_references(self) -> None:
        with pytest.raises(EffectConfigError, match=r"\{\{oauth:NAME\}\}"):
            parse_effect({"webhook": {
                "name": "inbox", "url": "https://receiver.example/x",
                "headers": {"Authorization": "Bearer literal"},
            }})

    def test_references_are_listed_and_rendered_in_one_pass(self) -> None:
        headers = {"Authorization": "Bearer {{oauth:RECEIVER}}", "X-Api-Key": "{{secret:KEY}}"}

        assert referenced_oauth_clients(headers) == ["RECEIVER"]
        # A token that looks like a reference is not substituted again.
        rendered = render_headers(headers, {"KEY": "k"}, {"RECEIVER": "{{secret:KEY}}"})
        assert rendered == {"Authorization": "Bearer {{secret:KEY}}", "X-Api-Key": "k"}

    def test_a_missing_token_names_the_client_only(self) -> None:
        with pytest.raises(KeyError, match="RECEIVER"):
            render_headers({"Authorization": "Bearer {{oauth:RECEIVER}}"}, {}, {})
