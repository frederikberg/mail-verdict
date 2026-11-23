"""
Unit tests for embeddings/provider.py's FakeEmbeddingProvider and provider
resolution -- the real OpenAIEmbeddingProvider is exercised in the `llm`
layer, which needs a real key.
"""

from __future__ import annotations

import httpx
import openai
import pytest

from mail_verdict.core.errors import ProviderUnavailableError
from mail_verdict.database.models import EMBEDDING_DIMENSIONS
from mail_verdict.embeddings.provider import (
    EmbeddingProvider,
    FakeEmbeddingProvider,
    FallbackEmbeddingProvider,
    OpenAIEmbeddingProvider,
    resolve_active_embedding_model,
    resolve_active_embedding_provider,
    resolve_embedding_provider,
    resolve_embedding_provider_for_model,
)


@pytest.mark.asyncio
async def test_fake_provider_produces_correct_dimensions() -> None:
    """Every vector must be exactly EMBEDDING_DIMENSIONS long -- pgvector's
    column type would reject anything else."""
    provider = FakeEmbeddingProvider()
    vectors = await provider.embed_batch(["hello world"], model="fake")
    assert len(vectors) == 1
    assert len(vectors[0]) == EMBEDDING_DIMENSIONS


@pytest.mark.asyncio
async def test_fake_provider_is_deterministic() -> None:
    """The same text must always produce the same vector, so tests
    asserting on distance/ordering are reproducible."""
    provider = FakeEmbeddingProvider()
    a = await provider.embed_batch(["same text"], model="fake")
    b = await provider.embed_batch(["same text"], model="fake")
    assert a[0] == b[0]


@pytest.mark.asyncio
async def test_fake_provider_differs_for_different_text() -> None:
    """Different inputs must not collide on the same vector."""
    provider = FakeEmbeddingProvider()
    a = await provider.embed_batch(["alpha"], model="fake")
    b = await provider.embed_batch(["beta"], model="fake")
    assert a[0] != b[0]


@pytest.mark.asyncio
async def test_fake_provider_embeds_a_whole_batch() -> None:
    """One call can embed several texts, each getting its own vector in order."""
    provider = FakeEmbeddingProvider()
    vectors = await provider.embed_batch(["one", "two", "three"], model="fake")
    assert len(vectors) == 3
    assert vectors[0] != vectors[1] != vectors[2]


def test_resolve_openai_provider() -> None:
    """The 'openai' name resolves to the real provider class."""
    provider = resolve_embedding_provider("openai", cred_repo=None)  # type: ignore[arg-type]
    assert isinstance(provider, OpenAIEmbeddingProvider)


def test_resolve_fake_provider() -> None:
    """The 'fake' name resolves to the deterministic test provider."""
    provider = resolve_embedding_provider("fake", cred_repo=None)  # type: ignore[arg-type]
    assert isinstance(provider, FakeEmbeddingProvider)


def test_resolve_unknown_provider_raises() -> None:
    """An unrecognized provider name is a configuration error, not a
    silent fallback to something else."""
    with pytest.raises(ValueError, match="Unknown embedding provider"):
        resolve_embedding_provider("anthropic", cred_repo=None)  # type: ignore[arg-type]


def test_resolve_custom_provider() -> None:
    """The 'custom' name resolves to the same class as 'openai', carrying
    its own base_url."""
    provider = resolve_embedding_provider(  # type: ignore[arg-type]
        "custom", cred_repo=None, base_url="https://example.test/v1",
    )
    assert isinstance(provider, OpenAIEmbeddingProvider)
    assert provider._provider == "custom"  # noqa: SLF001
    assert provider._base_url == "https://example.test/v1"  # noqa: SLF001


class TestResolveActiveEmbeddingModel:
    """resolve_active_embedding_model: which model actually serves search."""

    def test_falls_back_to_model_when_unset(self) -> None:
        assert resolve_active_embedding_model({"model": "text-embedding-3-small"}) == (
            "text-embedding-3-small"
        )

    def test_frozen_active_model_wins_over_the_migration_target(self) -> None:
        """Mid-migration, active_model differs from model -- and it is
        the one search must keep using."""
        settings = {"model": "new-model", "active_model": "old-model"}
        assert resolve_active_embedding_model(settings) == "old-model"


class TestResolveActiveEmbeddingProvider:
    def test_falls_back_to_current_provider_and_base_url(self) -> None:
        settings = {"provider": "custom", "base_url": "https://example.test/v1"}
        assert resolve_active_embedding_provider(settings) == (
            "custom", "https://example.test/v1",
        )

    def test_defaults_to_openai_with_no_provider_set(self) -> None:
        assert resolve_active_embedding_provider({}) == ("openai", None)

    def test_frozen_active_provider_wins_over_the_migration_target(self) -> None:
        """Mid-migration, the frozen provider/base_url -- not the new
        target -- is what a fresh search query must be embedded through,
        to land in the vector space active_model actually names."""
        settings = {
            "provider": "custom", "base_url": "https://new.example.test/v1",
            "active_provider": "openai", "active_base_url": None,
        }
        assert resolve_active_embedding_provider(settings) == ("openai", None)


def _status_error(cls: type[openai.APIStatusError], status: int) -> openai.APIStatusError:
    request = httpx.Request("POST", "https://example.test/v1/embeddings")
    response = httpx.Response(status, request=request)
    return cls("boom", response=response, body=None)  # type: ignore[arg-type, unused-ignore]


class _Scripted(EmbeddingProvider):
    """Answers with a vector or raises, and remembers what it was asked."""

    def __init__(self, *, error: Exception | None = None, width: int = EMBEDDING_DIMENSIONS):
        self.error = error
        self.width = width
        self.calls: list[tuple[list[str], str]] = []

    async def embed_batch(
        self, texts: list[str], *, model: str, timeout: float | None = None,
    ) -> list[list[float]]:
        self.calls.append((texts, model))
        if self.error is not None:
            raise self.error
        return [[0.5] * self.width for _ in texts]


class TestFallbackEmbeddingProvider:
    @pytest.mark.asyncio
    async def test_primary_answer_is_used_without_touching_the_fallback(self) -> None:
        primary, fallback = _Scripted(), _Scripted()
        provider = FallbackEmbeddingProvider(primary, fallback, fallback_model="other-name")
        await provider.embed_batch(["a"], model="m")
        assert primary.calls == [(["a"], "m")]
        assert fallback.calls == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "error",
        [
            _status_error(openai.RateLimitError, 429),
            _status_error(openai.InternalServerError, 503),
            _status_error(openai.AuthenticationError, 401),
            ProviderUnavailableError("No custom API key configured"),
        ],
    )
    async def test_provider_failure_goes_to_the_fallback_under_its_own_model_name(
        self, error: Exception,
    ) -> None:
        primary, fallback = _Scripted(error=error), _Scripted()
        provider = FallbackEmbeddingProvider(primary, fallback, fallback_model="other-name")
        vectors = await provider.embed_batch(["a", "b"], model="m", timeout=3.0)
        assert len(vectors) == 2
        assert fallback.calls == [(["a", "b"], "other-name")]

    @pytest.mark.asyncio
    async def test_a_request_the_primary_rejected_as_malformed_is_not_retried_elsewhere(
        self,
    ) -> None:
        error = _status_error(openai.BadRequestError, 400)
        primary, fallback = _Scripted(error=error), _Scripted()
        provider = FallbackEmbeddingProvider(primary, fallback, fallback_model="other-name")
        with pytest.raises(openai.BadRequestError):
            await provider.embed_batch(["a"], model="m")
        assert fallback.calls == []

    @pytest.mark.asyncio
    async def test_a_bug_in_this_process_is_not_an_outage(self) -> None:
        primary, fallback = _Scripted(error=KeyError("x")), _Scripted()
        provider = FallbackEmbeddingProvider(primary, fallback, fallback_model="other-name")
        with pytest.raises(KeyError):
            await provider.embed_batch(["a"], model="m")
        assert fallback.calls == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "fallback",
        [
            _Scripted(error=ProviderUnavailableError("no key")),
            _Scripted(error=_status_error(openai.InternalServerError, 500)),
            _Scripted(width=EMBEDDING_DIMENSIONS + 1),
        ],
    )
    async def test_when_the_fallback_cannot_answer_the_primary_error_surfaces(
        self, fallback: _Scripted,
    ) -> None:
        error = _status_error(openai.RateLimitError, 429)
        provider = FallbackEmbeddingProvider(
            _Scripted(error=error), fallback, fallback_model="other-name",
        )
        with pytest.raises(openai.RateLimitError):
            await provider.embed_batch(["a"], model="m")


class _StoredKeys:
    """Credential repository stand-in holding only the keys it is given."""

    def __init__(self, **keys: str) -> None:
        self._keys = keys

    async def resolve_key(self, provider: str) -> str | None:
        return self._keys.get(provider)


class TestFallbackResolution:
    SETTINGS = {
        "provider": "custom", "base_url": "https://primary.test/v1", "model": "Qwen/Q",
        "fallback_base_url": "https://fallback.test/v1", "fallback_model": "Q",
    }

    def _resolve(self, settings: dict, **overrides: object) -> EmbeddingProvider:
        args = {
            "provider_name": "custom", "base_url": "https://primary.test/v1", "model": "Qwen/Q",
            **overrides,
        }
        return resolve_embedding_provider_for_model(
            settings, None, **args,  # type: ignore[arg-type]
        )

    def test_a_fallback_is_attached_when_configured(self) -> None:
        assert isinstance(self._resolve(self.SETTINGS), FallbackEmbeddingProvider)

    @pytest.mark.parametrize(
        "unset", [{"fallback_base_url": None}, {"fallback_model": None}, {}],
    )
    def test_unconfigured_means_no_fallback(self, unset: dict) -> None:
        settings = {k: v for k, v in self.SETTINGS.items() if not k.startswith("fallback_")}
        settings.update(unset)
        assert isinstance(self._resolve(settings), OpenAIEmbeddingProvider)

    @pytest.mark.parametrize(
        "other",
        [{"model": "previous-model"}, {"base_url": "https://previous.test/v1"}],
    )
    def test_a_call_for_another_vector_space_gets_no_fallback(self, other: dict) -> None:
        assert isinstance(self._resolve(self.SETTINGS, **other), OpenAIEmbeddingProvider)

    @pytest.mark.asyncio
    async def test_the_fallback_endpoint_reads_its_own_key_and_never_the_primarys(self) -> None:
        provider = OpenAIEmbeddingProvider(
            _StoredKeys(custom="primary-key"),  # type: ignore[arg-type]
            provider="custom", base_url="https://fallback.test/v1",
            credential="embedding_fallback",
        )
        with pytest.raises(ProviderUnavailableError, match="embedding_fallback"):
            await provider.embed_batch(["a"], model="Q")
