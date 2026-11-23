"""
Embedding providers.

Mirrors spam/analyst.py's SpamAnalyst / LiveSpamAnalyst / FakeSpamAnalyst
shape: an abstract provider, a live implementation that resolves the
provider's API key fresh on every call rather than capturing it at
construction, and a deterministic fake for tests and API-key-free local
development.

Anthropic has no embedding model of its own and is not going to grow one --
its own documentation points at a third-party partner for this -- so it is
never one of the names `semantic.provider` accepts. "custom" is any
OpenAI-compatible embeddings endpoint (settings.semantic.base_url), the
same request shape as "openai" -- both are OpenAIEmbeddingProvider,
differing only in which client the resolved base_url points at. An optional
second endpoint serving the same model (settings.semantic.fallback_*) is
tried when the first fails, see FallbackEmbeddingProvider. Each of
its responses is recorded with its token count (usage/recorder.py) by the
recorder its caller hands in.
"""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from mail_verdict.core.errors import ProviderUnavailableError
from mail_verdict.core.openai_provider import get_openai_client
from mail_verdict.core.structured_llm import resolve_client
from mail_verdict.database.models import EMBEDDING_DIMENSIONS
from mail_verdict.usage.tokens import from_embeddings

if TYPE_CHECKING:
    from mail_verdict.settings.credentials import ProviderCredentialRepository
    from mail_verdict.usage.recorder import UsageRecorder

logger = logging.getLogger(__name__)

def resolve_active_embedding_model(settings: Mapping[str, Any]) -> str:
    """
    The embedding model actually serving search and neighbour hints right
    now, as opposed to `settings.semantic.model` -- the migration target a
    re-embed fills toward, which may still have incomplete coverage.

    `active_model` starts unset (None), meaning "whatever `model` currently
    is" -- the steady state where no migration is in flight. It is frozen
    to the previously-active model the moment `model` changes
    (api/settings_api.py's update_settings) and advanced to match `model`
    only once the reconciler observes full coverage under it
    (embeddings/worker.py's `_maybe_cutover`), which is what keeps search
    answering from a complete vector space throughout a migration.

    Args:
        settings: The "semantic" settings category

    Returns:
        The model name to embed a search query or neighbour lookup with
    """
    return str(settings.get("active_model") or settings["model"])


def resolve_active_embedding_provider(settings: Mapping[str, Any]) -> tuple[str, str | None]:
    """
    The provider and base_url a fresh search query must be embedded
    through, to land in the vector space `resolve_active_embedding_model`
    names -- which can differ from `settings.provider`/`base_url` mid
    migration if the switch changed provider as well as model (moving to
    a different compatible server, say). Frozen and advanced in the same
    write as `active_model` (see that function's docstring); falls back to
    the live provider/base_url exactly when `active_model` does, for the
    same reason.

    Args:
        settings: The "semantic" settings category

    Returns:
        (provider name, base_url or None)
    """
    active_provider = settings.get("active_provider")
    if active_provider:
        return str(active_provider), (settings.get("active_base_url") or None)
    return str(settings.get("provider") or "openai"), (settings.get("base_url") or None)


class EmbeddingProvider(ABC):
    """Abstract base for turning text into vectors."""

    @abstractmethod
    async def embed_batch(
        self, texts: list[str], *, model: str, timeout: float | None = None,
    ) -> list[list[float]]:
        """
        Embed a batch of texts in one request.

        Args:
            texts: Texts to embed, in order
            model: Provider model name to embed with
            timeout: Seconds to wait for the response; None keeps the
                client's own timeout

        Returns:
            One vector per input text, same order, each of
            EMBEDDING_DIMENSIONS length

        Raises:
            ProviderUnavailableError: No API key configured
            RuntimeError: The request failed after retries
        """


class OpenAIEmbeddingProvider(EmbeddingProvider):
    """
    Embeds via an OpenAI-compatible embeddings endpoint, truncated to
    EMBEDDING_DIMENSIONS via the API's own `dimensions` parameter.

    Serves both "openai" and "custom" (settings.semantic.provider): the
    request shape is identical, so only which client `resolve_client`
    hands back -- pointed at api.openai.com or at base_url -- differs.

    Every `text-embedding-3-*` model, and Infomaniak's own
    `Qwen/Qwen3-Embedding-8B`, supports Matryoshka truncation this way,
    which is what lets the vector column stay a single fixed width
    regardless of which model produced a given row -- the model itself is
    recorded per row instead (message_embeddings.model), so a model change
    is a visible coverage change rather than a validation the dimensions
    setting would otherwise need.
    """

    def __init__(
        self, cred_repo: ProviderCredentialRepository,
        *, provider: str = "openai", base_url: str | None = None,
        usage: UsageRecorder | None = None, credential: str | None = None,
    ) -> None:
        """
        Args:
            cred_repo: Provider API key repository, read fresh per call
            provider: "openai" or "custom" -- which credential to resolve
            base_url: Required when provider is "custom"; ignored otherwise
            usage: Records each response's tokens; None records nothing
            credential: A credential of its own to send, for a "custom"
                endpoint that is not the one `provider` names (the
                fallback endpoint); None resolves `provider`'s credential
        """
        self._cred_repo = cred_repo
        self._provider = provider
        self._base_url = base_url
        self._usage = usage
        self._credential = credential

    async def _client(self) -> Any:
        """The client for this endpoint, with its key read fresh."""
        if self._credential is None:
            return await resolve_client(self._provider, self._cred_repo, base_url=self._base_url)
        api_key = await self._cred_repo.resolve_key(self._credential)
        if not api_key:
            raise ProviderUnavailableError(f"No {self._credential} API key configured")
        return get_openai_client(api_key, base_url=self._base_url)

    async def embed_batch(
        self, texts: list[str], *, model: str, timeout: float | None = None,
    ) -> list[list[float]]:
        """
        Embed a batch, resolving the API key fresh.

        Raises whatever the client raises on failure -- rate limits,
        connection errors, and auth rejections are all `openai` exception
        types the worker's caller inspects directly, matching how
        core/structured_llm.py leaves provider exceptions to its callers
        rather than wrapping them here.
        """
        client = await self._client()
        response = await client.embeddings.create(
            model=model, input=texts, dimensions=EMBEDDING_DIMENSIONS,
            **({} if timeout is None else {"timeout": timeout}),
        )
        if self._usage is not None:
            await self._usage.record(
                provider=self._provider, base_url=self._base_url, model=model,
                tokens=from_embeddings(response),
            )
        logger.debug(
            "Embedded batch",
            extra={"provider": self._provider, "model": model, "count": len(texts)},
        )
        return [item.embedding for item in response.data]


# What the fallback is not tried for: a request the endpoint rejected as
# malformed is about this text, and the other endpoint would reject it too.
_ITEM_SPECIFIC_ERRORS = frozenset({"BadRequestError", "UnprocessableEntityError"})

FALLBACK_CREDENTIAL = "embedding_fallback"


def _fallback_applies(exc: Exception) -> bool:
    """Whether a failure of the first endpoint is one the second may answer:
    an unconfigured key, or a provider-side error (rate limit, connection,
    timeout, 5xx, rejected key, spent allowance). Matched on the exception's
    origin and class name so a bug in this process never reads as an outage."""
    if isinstance(exc, ProviderUnavailableError):
        return True
    return (
        type(exc).__module__.split(".")[0] == "openai"
        and type(exc).__name__ not in _ITEM_SPECIFIC_ERRORS
    )


class FallbackEmbeddingProvider(EmbeddingProvider):
    """
    Tries the primary endpoint and, when it fails in a way `_fallback_applies`
    names, a second endpoint serving the same model.

    The caller keeps filing the vectors under the model it asked for: the
    second endpoint is declared to serve the same weights (only its name for
    them differs, `fallback_model`), so both land in one vector space. A
    vector of the wrong width from it is refused rather than stored. When the
    fallback fails too, or has no key stored, the primary's own error is what
    propagates, so queue retry, the circuit breaker and search's 503 behave
    exactly as without a fallback.
    """

    def __init__(
        self, primary: EmbeddingProvider, fallback: EmbeddingProvider, *, fallback_model: str,
    ) -> None:
        """
        Args:
            primary: The configured provider
            fallback: The provider of the second endpoint
            fallback_model: The model's name at the second endpoint
        """
        self._primary = primary
        self._fallback = fallback
        self._fallback_model = fallback_model

    async def embed_batch(
        self, texts: list[str], *, model: str, timeout: float | None = None,
    ) -> list[list[float]]:
        """Embed with the primary, then the fallback if the primary failed."""
        try:
            return await self._primary.embed_batch(texts, model=model, timeout=timeout)
        except Exception as exc:
            if not _fallback_applies(exc):
                raise
            primary_error = exc
        try:
            vectors = await self._fallback.embed_batch(
                texts, model=self._fallback_model, timeout=timeout,
            )
            if len(vectors) != len(texts) or any(
                len(vector) != EMBEDDING_DIMENSIONS for vector in vectors
            ):
                raise RuntimeError("fallback endpoint returned vectors of the wrong shape")
        except ProviderUnavailableError:
            logger.debug("Embedding fallback has no key configured")
            raise primary_error from None
        except Exception as exc:
            logger.warning(
                "Embedding fallback failed too",
                extra={"model": model, "error": type(exc).__name__},
            )
            raise primary_error from None
        logger.warning(
            "Embedded through the fallback endpoint",
            extra={"model": model, "primary_error": type(primary_error).__name__},
        )
        return vectors


class FakeEmbeddingProvider(EmbeddingProvider):
    """
    Deterministic, hash-derived vectors -- the test workhorse.

    Never calls out to a real provider: each text's vector is derived from
    a SHA-256 hash of the text, so the same input always produces the same
    output and different inputs produce different (if meaningless) ones.
    Good enough to exercise storage, claim/complete, and cosine-distance
    ordering in tests without an API key.
    """

    async def embed_batch(
        self, texts: list[str], *, model: str, timeout: float | None = None,
    ) -> list[list[float]]:
        """Derive a deterministic vector per text from its hash."""
        return [_fake_vector(text) for text in texts]


def _fake_vector(text: str) -> list[float]:
    """A deterministic unit-ish vector derived from a text's hash, long
    enough to fill EMBEDDING_DIMENSIONS by repeating the digest bytes."""
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return [
        (digest[i % len(digest)] / 255.0) * 2 - 1 for i in range(EMBEDDING_DIMENSIONS)
    ]


def resolve_embedding_provider(
    provider_name: str, cred_repo: ProviderCredentialRepository, *, base_url: str | None = None,
    usage: UsageRecorder | None = None,
) -> EmbeddingProvider:
    """
    Resolve a provider instance by name.

    Args:
        provider_name: "openai", "custom" or "fake"
        cred_repo: Provider API key repository
        base_url: Required when provider_name is "custom"; ignored
            otherwise
        usage: Records each response's tokens; None records nothing

    Returns:
        A provider instance

    Raises:
        ValueError: provider_name is not recognized
    """
    if provider_name in ("openai", "custom"):
        return OpenAIEmbeddingProvider(
            cred_repo, provider=provider_name, base_url=base_url, usage=usage,
        )
    if provider_name == "fake":
        return FakeEmbeddingProvider()
    raise ValueError(f"Unknown embedding provider {provider_name!r}")


def resolve_embedding_provider_for_model(
    settings: Mapping[str, Any], cred_repo: ProviderCredentialRepository, *,
    provider_name: str, base_url: str | None, model: str, usage: UsageRecorder | None = None,
) -> EmbeddingProvider:
    """
    The provider to embed with `model` through `provider_name`/`base_url`,
    with the configured fallback endpoint behind it when there is one and it
    serves this very model.

    The fallback is attached only when `semantic.fallback_base_url` and
    `fallback_model` are set and the call is for the configured live
    identity: mid-migration a query for the previous model, or a row of
    another model, is a different vector space the fallback does not serve.

    Args:
        settings: The "semantic" settings category
        cred_repo: Provider API key repository
        provider_name: "openai", "custom" or "fake"
        base_url: The custom endpoint, when provider_name is "custom"
        model: The model the vectors are for
        usage: Records each response's tokens; None records nothing

    Raises:
        ValueError: provider_name is not recognized
    """
    primary = resolve_embedding_provider(
        provider_name, cred_repo, base_url=base_url, usage=usage,
    )
    fallback_url = settings.get("fallback_base_url")
    fallback_model = settings.get("fallback_model")
    serves_live_identity = (
        model == str(settings["model"])
        and provider_name == str(settings.get("provider") or "openai")
        and (base_url or None) == (settings.get("base_url") or None)
    )
    if not (fallback_url and fallback_model and serves_live_identity) or provider_name == "fake":
        return primary
    fallback = OpenAIEmbeddingProvider(
        cred_repo, provider="custom", base_url=str(fallback_url), usage=usage,
        credential=FALLBACK_CREDENTIAL,
    )
    return FallbackEmbeddingProvider(primary, fallback, fallback_model=str(fallback_model))


__all__ = [
    "EmbeddingProvider",
    "FallbackEmbeddingProvider",
    "FakeEmbeddingProvider",
    "OpenAIEmbeddingProvider",
    "ProviderUnavailableError",
    "resolve_active_embedding_model",
    "resolve_active_embedding_provider",
    "resolve_embedding_provider",
    "resolve_embedding_provider_for_model",
]
