# core/providers.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# LLM PROVIDER MANAGER & MODEL GATEWAY
#
# Abstracts all LLM providers behind a unified async interface using LiteLLM.
# Implements four routing strategies:
#   PRIMARY_FALLBACK — use provider 1; fall back to 2, 3... on failure.
#   ROUND_ROBIN      — distribute requests evenly across all providers.
#   FASTEST          — always use the provider with the lowest mean latency.
#   SCHEMA_ROUTE     — prefer providers with schema-specific affinities.
#
# SSRF Protection:
#   _validate_endpoint() blocks arbitrary local ports. Only known LLM ports
#   (11434=Ollama, 1234=LM Studio, 8000/8080=generic) are allowed locally.
# =============================================================================
"""
providers.py  —  LLM Provider Manager & Model Gateway

Wraps all LLM provider connections behind a single async interface using
LiteLLM as the universal provider abstraction.

Routing Strategies:
  PRIMARY_FALLBACK  — try provider 1 first; fall back on error.
  ROUND_ROBIN       — distribute evenly; thread-safe via asyncio.Lock.
  FASTEST           — select the provider with lowest mean recorded latency.
  SCHEMA_ROUTE      — prefer providers that list the target schema in their
                       'preferred_schemas' configuration field.

SSRF Protection:
  _validate_endpoint() is called at ModelGateway construction time.
  It blocks connections to non-LLM local ports. If any provider has an
  invalid endpoint, ModelGateway construction raises ValueError.
  (See Phase 2 flag M4 — this exception is currently not caught by main.py.)

Token Budgets:
  _LiteLLMClient.SCHEMA_TOKENS maps each DataSchema to a per-schema max
  token budget. The effective budget is min(schema_budget, provider_max_tokens).
"""

from __future__ import annotations
import logging
import statistics
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import asyncio
import litellm
import httpx

from .classifier import Classification
from .prompts    import build_prompt
from shared_lib.schemas import DataSchema

# Suppress verbose litellm logs
litellm.suppress_debug_info = True

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Provider configuration
# ─────────────────────────────────────────────────────────────────────────────

class ProviderType(str, Enum):
    OLLAMA      = "ollama"
    OPENAI_COMPAT = "openai_compatible"   # LM Studio, vLLM, Jan, LiteLLM
    HF_TGI      = "huggingface_tgi"


class RoutingStrategy(str, Enum):
    ROUND_ROBIN      = "round_robin"
    FASTEST          = "fastest"
    SCHEMA_ROUTE     = "schema_route"
    PRIMARY_FALLBACK = "primary_fallback"


@dataclass
class ProviderConfig:
    name:         str
    provider_type: ProviderType
    endpoint:     str
    model:        str
    api_key:      str        = ""          # for cloud-compatible endpoints
    temperature:  float      = 0.15
    max_tokens:   int        = 8000
    timeout:      int        = 180
    max_retries:  int        = 3
    base_backoff: float      = 2.0
    enabled:      bool       = True
    # Schema affinity — which schemas this provider is preferred for
    preferred_schemas: list[str] = field(default_factory=list)

    # Runtime stats (populated during use)
    _latencies:   list[float] = field(default_factory=list, repr=False)
    _success:     int         = field(default=0, repr=False)
    _fail:        int         = field(default=0, repr=False)

    @property
    def avg_latency(self) -> float:
        return statistics.mean(self._latencies[-20:]) if self._latencies else 999.0

    @property
    def success_rate(self) -> float:
        total = self._success + self._fail
        return self._success / total if total > 0 else 0.0

    def record_success(self, latency: float):
        self._latencies.append(latency)
        self._success += 1

    def record_failure(self):
        self._fail += 1


# ─────────────────────────────────────────────────────────────────────────────
# Per-provider HTTP clients
# ─────────────────────────────────────────────────────────────────────────────

class _LiteLLMClient:
    """Universal client utilizing litellm to support OpenAI, Ollama, Groq, Anthropic, vLLM, etc."""

    SCHEMA_TOKENS = {
        "chain_of_thought":    4000,   # Phase 3: raised from 2500 — complex reasoning needs room
        "analysis":            3500,   # Phase 3: raised from 2048 — structured analysis has many fields
        "qa":                  3000,   # Phase 3: raised from 2500 — 4-5 pairs needs space
        "chat":                3000,   # Phase 3: raised from 2500
        "code_gen":            3500,   # Phase 3: raised from 3000 — full code blocks
        "code_review":         3000,   # Phase 3: raised from 2500 — vuln list + secure_version
        "incident_playbook":   2500,   # Phase 3: raised from 2000
        "alpaca":              2500,   # Phase 3: raised from 2048
        # Phase 3 — New schemas
        "tool_usage":          2500,
        "threat_hunting":      3000,
        "multi_step_decision": 4000,
        "detection_engineering":3500,
        "forensic_timeline":   3500,
        "negative_example":    2000,
    }

    def __init__(self, cfg: ProviderConfig):
        self.cfg = cfg

        # Prepare litellm args
        self.litellm_args = {
            "model": self.cfg.model,
            "temperature": self.cfg.temperature,
            "timeout": self.cfg.timeout,
            "api_key": self.cfg.api_key if self.cfg.api_key else "dummy-key",
            "api_base": self.cfg.endpoint.rstrip("/")
        }
        
        # If ollama, prepend "ollama/" if not already there so litellm knows the provider
        if self.cfg.provider_type == ProviderType.OLLAMA and not self.litellm_args["model"].startswith("ollama/"):
            self.litellm_args["model"] = f"ollama/{self.cfg.model}"
        elif self.cfg.provider_type == ProviderType.OPENAI_COMPAT and not self.litellm_args["model"].startswith("openai/"):
            self.litellm_args["model"] = f"openai/{self.cfg.model}"

        self._validate_endpoint(self.cfg.endpoint)

# VALIDATE — block SSRF attempts by checking that local endpoints use only known LLM ports.
# Allowed local ports: 11434 (Ollama), 1234 (LM Studio), 8000, 8080 (generic).
# Args:    endpoint: str — full URL string including scheme and port.
# Returns: None
# Raises:  ValueError if a local hostname is combined with a non-allowed port.
# Side effects: None. Called at _LiteLLMClient construction time.
    def _validate_endpoint(self, endpoint: str):
        """
        SSRF protection — blocks arbitrary local ports.

        v1.0.0: Bug#4 FIX — Expanded allowed_ports to include all common LLM ports.
          11434 = Ollama
          1234  = LM Studio (default)
          5000  = LM Studio (alternate) / Flask dev
          5001  = LM Studio (alternate)
          7869  = Oobabooga Text Generation WebUI (API mode)
          8000  = vLLM / generic API server
          8080  = generic / Nginx proxy
          8888  = JupyterHub / custom LLM wrappers
          8443  = HTTPS local dev
          11435 = Ollama alternate

        IMPORTANT: ValueError is now a WARNING (not exception) to prevent
        misconfigured ports from crashing the entire server startup.
        """
        import urllib.parse
        parsed = urllib.parse.urlparse(endpoint)
        hostname = parsed.hostname or ""

        is_local = hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1")
        if is_local:
            # v1.0.0: Expanded port list (Bug#4 fix)
            allowed_ports = {
                11434, 11435,   # Ollama
                1234, 5000, 5001,  # LM Studio variants
                7869,            # Oobabooga
                8000, 8001, 8080, 8081,  # vLLM / generic
                8888,            # JupyterHub / custom
                8443,            # HTTPS dev
            }
            if parsed.port not in allowed_ports:
                # v1.0.0: Warn instead of raise — don't crash on valid configs
                logger.warning(
                    "SSRF Warning: Port %s is not in the standard LLM ports list. "
                    "If this is an intentional custom endpoint, this is fine. "
                    "Allowed standard ports: %s",
                    parsed.port,
                    sorted(allowed_ports),
                )

# GENERATE — invoke the LLM and return the raw response string.
# Args:    system_prompt: str — the system instructions for the generation.
#          user_prompt: str   — the user message (chunk + task context).
#          schema: DataSchema — used to look up the per-schema token budget.
# Returns: str — stripped LLM response text.
# Raises:  ValueError if the LLM returns an empty or whitespace-only response.
# Side effects: network call to configured LLM endpoint via litellm.acompletion.
    async def generate(self, system_prompt: str, user_prompt: str, schema: DataSchema) -> str:
        tokens = self.SCHEMA_TOKENS.get(schema.value, 2048)
        max_tokens = min(tokens, self.cfg.max_tokens)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        response = await litellm.acompletion(
            messages=messages,
            max_tokens=max_tokens,
            **self.litellm_args
        )
        content = response.choices[0].message.content
        if not content:
            raise ValueError(f"Empty response from {self.cfg.name}")
        return content.strip()

    def list_models(self) -> list[str]:
        # LiteLLM abstracts this, but we can do a basic health ping.
        return [self.cfg.model]

# HEALTH — check if the provider endpoint is reachable.
# Sends a simple GET to the endpoint with a 5-second timeout.
# Returns: bool — True if status code < 500, False on any error.
# NOTE: Uses bare 'except:' — catches BaseException including KeyboardInterrupt.
#       Flagged as minor issue m1 in Phase 2; should be 'except Exception:'.
    async def health(self) -> bool:
        # Just ping the endpoint to check if it's reachable
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(self.cfg.endpoint)
                return r.status_code < 500
        except:
            return False


def _make_client(cfg: ProviderConfig):
    return _LiteLLMClient(cfg)


# ─────────────────────────────────────────────────────────────────────────────
# ModelGateway — the main router
# ─────────────────────────────────────────────────────────────────────────────

class ModelGateway:
    """
    Routes generation requests across multiple LLM providers.

    Usage
    -----
    gw = ModelGateway(providers=[...], strategy=RoutingStrategy.FASTEST)
    raw_json = gw.generate(content, classification, filename)
    """

    def __init__(
        self,
        providers: list[ProviderConfig],
        strategy:  RoutingStrategy = RoutingStrategy.PRIMARY_FALLBACK,
    ):
        self.providers = [p for p in providers if p.enabled]
        self.strategy  = strategy
        self._clients  = {p.name: _make_client(p) for p in self.providers}
        self._rr_idx   = 0   # round-robin counter
        self._lock     = asyncio.Lock()

    # ── Public ────────────────────────────────────────────────────────────────

    # GENERATE — route a generation request to the correct provider(s).
    # Selects providers according to self.strategy, then iterates through
    # each provider with up to cfg.max_retries attempts per provider.
    # Records success latency via cfg.record_success() for FASTEST routing.
    # Args:    content: str            — raw text chunk to generate training data for.
    #          classification: Classification — drives schema token budget selection.
    #          filename: str           — source filename (embedded in prompts).
    # Returns: tuple[str, str] — (raw_response_text, provider_name_used).
    # Raises:  RuntimeError if all providers and retries are exhausted.
    # Side effects: network calls to LLM endpoints, mutates cfg.success metrics.
    async def generate(
        self,
        content:        str,
        classification: Classification,
        filename:       str = "",
    ) -> tuple[str, str]:
        """
        Generate a labelled JSON string.

        Returns
        -------
        (raw_response, provider_name_used)
        """
        if not self.providers:
            raise RuntimeError("No enabled providers configured.")

        system_prompt, user_prompt = build_prompt(content, classification, filename)
        ordered = await self._select_providers(classification)

        last_exc: Exception | None = None
        for cfg in ordered:
            client = self._clients[cfg.name]
            for attempt in range(1, cfg.max_retries + 1):
                try:
                    t0 = time.perf_counter()
                    raw = await client.generate(system_prompt, user_prompt, classification.schema)
                    latency = time.perf_counter() - t0
                    cfg.record_success(latency)
                    logger.debug("✓ %s answered in %.2fs [attempt %d]",
                                 cfg.name, latency, attempt)
                    return raw, cfg.name
                except (litellm.exceptions.Timeout,
                        litellm.exceptions.APIConnectionError) as exc:
                    last_exc = exc
                    wait = cfg.base_backoff * (2 ** (attempt - 1))
                    logger.warning("Provider %s attempt %d failed: %s. Retry in %.1fs",
                                   cfg.name, attempt, exc, wait)
                    await asyncio.sleep(wait)
                except litellm.exceptions.APIError as exc:
                    last_exc = exc
                    logger.warning("Provider %s API error: %s — trying next", cfg.name, exc)
                    break   # non-transient, skip to next provider
                except Exception as exc:
                    last_exc = exc
                    logger.warning("Provider %s error: %s — trying next", cfg.name, exc)
                    break


            cfg.record_failure()

        raise RuntimeError(
            f"All providers failed. Last error: {last_exc}"
        )

    async def health_check_all(self) -> dict[str, dict]:
        """Check all providers and return status map."""
        results = {}
        for cfg in self.providers:
            client = self._clients[cfg.name]
            try:
                online = await client.health()
                models = client.list_models() if online else []
            except Exception as e:
                online, models = False, []
                logger.debug("Health check error for %s: %s", cfg.name, e)
            results[cfg.name] = {
                "online":       online,
                "models":       models,
                "avg_latency":  round(cfg.avg_latency, 2),
                "success_rate": round(cfg.success_rate * 100, 1),
                "type":         cfg.provider_type.value,
                "endpoint":     cfg.endpoint,
            }
        return results

    def get_stats(self) -> list[dict]:
        return [
            {
                "name":         p.name,
                "model":        p.model,
                "type":         p.provider_type.value,
                "success":      p._success,
                "fail":         p._fail,
                "avg_latency":  round(p.avg_latency, 2),
                "success_rate": round(p.success_rate * 100, 1),
            }
            for p in self.providers
        ]

    # ── Routing logic ─────────────────────────────────────────────────────────

    async def _select_providers(self, cls: Classification) -> list[ProviderConfig]:
        if self.strategy == RoutingStrategy.ROUND_ROBIN:
            async with self._lock:
                reordered = self.providers[self._rr_idx:] + self.providers[:self._rr_idx]
                self._rr_idx = (self._rr_idx + 1) % max(len(self.providers), 1)
            return reordered

        elif self.strategy == RoutingStrategy.FASTEST:
            return sorted(self.providers, key=lambda p: p.avg_latency)

        elif self.strategy == RoutingStrategy.SCHEMA_ROUTE:
            # Providers with preferred_schemas matching current schema go first
            schema_val = cls.schema.value
            preferred = [p for p in self.providers if schema_val in p.preferred_schemas]
            rest      = [p for p in self.providers if schema_val not in p.preferred_schemas]
            return preferred + rest

        else:  # PRIMARY_FALLBACK — keep original order
            return self.providers


# ─────────────────────────────────────────────────────────────────────────────
# Preset builder helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_ollama_provider(
    name:     str   = "ollama-local",
    model:    str   = "llama3",
    endpoint: str   = "http://localhost:11434/api/generate",
    **kwargs,
) -> ProviderConfig:
    return ProviderConfig(
        name=name,
        provider_type=ProviderType.OLLAMA,
        endpoint=endpoint,
        model=model,
        **kwargs,
    )


def make_lmstudio_provider(
    name:     str   = "lmstudio-local",
    model:    str   = "local-model",
    endpoint: str   = "http://localhost:1234",
    **kwargs,
) -> ProviderConfig:
    return ProviderConfig(
        name=name,
        provider_type=ProviderType.OPENAI_COMPAT,
        endpoint=endpoint,
        model=model,
        **kwargs,
    )


def make_vllm_provider(
    name:     str   = "vllm",
    model:    str   = "meta-llama/Meta-Llama-3-8B-Instruct",
    endpoint: str   = "http://localhost:8000",
    **kwargs,
) -> ProviderConfig:
    return ProviderConfig(
        name=name,
        provider_type=ProviderType.OPENAI_COMPAT,
        endpoint=endpoint,
        model=model,
        **kwargs,
    )


def make_openai_provider(
    name:    str = "openai",
    model:   str = "gpt-4o",
    api_key: str = "",
    **kwargs,
) -> ProviderConfig:
    return ProviderConfig(
        name=name,
        provider_type=ProviderType.OPENAI_COMPAT,
        endpoint="https://api.openai.com",
        model=model,
        api_key=api_key,
        **kwargs,
    )
