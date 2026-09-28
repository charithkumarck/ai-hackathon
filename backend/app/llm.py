"""
LLM layer.

Provider-agnostic on purpose: the pipeline asks for "this pydantic schema,
filled in" and does not care who fills it. Three backends, tried in order:

    gemini   Google GenAI — API key (AI Studio) or Vertex AI (ADC)
    claude   Anthropic
    offline  deterministic lexical heuristic, so the demo never dies on stage

Whichever runs, the contract is identical and the guardrail upstream is
unchanged: the model may only *choose* technique IDs from the candidate pool
retrieval handed it.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, TypeVar

from pydantic import BaseModel, Field

try:
    from dotenv import load_dotenv

    # override=True on purpose. This machine has a GEMINI_API_KEY set globally
    # in the user profile for an unrelated project; without override it wins
    # over backend/.env and the app authenticates as the wrong thing.
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"), override=True)
except ImportError:  # dotenv is optional
    pass

PROVIDER = os.environ.get("LLM_PROVIDER", "auto").lower()
# Pin the model. The `-latest` aliases route to whatever is newest, which is
# also whatever is busiest -- gemini-flash-latest 503s while the pinned model
# behind it answers fine.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
# Tried in order when the primary is overloaded, so a demo never dies on a 503.
GEMINI_FALLBACKS = [
    m.strip()
    for m in os.environ.get(
        "GEMINI_FALLBACK_MODELS", "gemini-3.5-flash,gemini-3.1-flash-lite-preview"
    ).split(",")
    if m.strip()
]
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-opus-5")
MAX_TOKENS = 8000
THINKING_BUDGET = int(os.environ.get("GEMINI_THINKING_BUDGET", "512"))

T = TypeVar("T", bound=BaseModel)


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class RejectedCandidate(BaseModel):
    technique_id: str = Field(description="An ATT&CK ID from the candidate list that was considered and rejected")
    why: str = Field(description="One short sentence on why it does not fit")


class MappingResult(BaseModel):
    """Step 5: pick the technique and critique the rule."""

    abstain: bool = Field(
        description="True when no candidate is a defensible match, or two are equally plausible"
    )
    technique_id: str = Field(
        description="The chosen parent technique ID, exactly as given in the candidate list. Empty string if abstaining."
    )
    sub_technique_id: str = Field(
        description="The chosen sub-technique ID if one clearly applies, else an empty string"
    )
    confidence: float = Field(description="0.0 to 1.0")
    behaviour: str = Field(description="One sentence: the attacker behaviour this rule is looking for")
    what_it_observes: str = Field(description="One sentence: what the query literally matches in the logs")
    reasoning: str = Field(description="Two or three sentences justifying the choice over the alternatives")
    rejected: list[RejectedCandidate] = Field(description="1-3 candidates considered and ruled out")
    blind_spots: list[str] = Field(
        description="3-5 concrete things this rule cannot establish. Be specific to the query, "
                    "not generic advice. Each one a single sentence."
    )
    telemetry_upgrades: list[str] = Field(
        description="2-4 additional log sources or fields that would materially improve this rule, "
                    "each with what it would newly catch"
    )
    ambiguity_note: str = Field(
        description="If abstaining, the question that would resolve it. Otherwise an empty string."
    )


class SuggestedRule(BaseModel):
    technique_id: str = Field(description="ATT&CK ID from the gap candidate list")
    title: str = Field(description="Short imperative name for the detection rule to build")
    why: str = Field(description="One sentence: what an attacker does here that you currently cannot see")
    priority: str = Field(description="One of: critical, high, medium")


class GapResult(BaseModel):
    narrative: str = Field(
        description="Two sentences naming what the current rule catches and what stage of the "
                    "intrusion it stops being useful at"
    )
    suggestions: list[SuggestedRule] = Field(description="3-5 next detections, most urgent first")


class GeneratedRule(BaseModel):
    language: str
    query: str = Field(description="The detection query itself, no prose, no markdown fences")
    explanation: str = Field(description="Two sentences on how it works")
    required_telemetry: list[str] = Field(description="Log sources this rule needs to be onboarded")


# ---------------------------------------------------------------------------
# Provider resolution
# ---------------------------------------------------------------------------

_provider: str | None = None
_client: Any = None
_error: str | None = None
_model: str | None = None


VERTEX_MODEL = os.environ.get("VERTEX_MODEL", "gemini-2.5-flash")

# Vertex is kept alongside the API-key client, not just as a startup
# alternative. The free-tier key is 20 requests/day/model; Vertex bills the GCP
# project and has real quota. When every API-key model is spent we escalate
# here rather than dropping straight to the offline heuristic.
_vertex_client: Any = None
_vertex_checked = False


def get_vertex() -> Any:
    """Lazily build a Vertex client. None when ADC is missing or expired."""
    global _vertex_client, _vertex_checked
    if _vertex_checked:
        return _vertex_client
    _vertex_checked = True
    project = os.environ.get("GCP_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        return None
    try:
        from google import genai

        client = genai.Client(
            vertexai=True, project=project,
            location=os.environ.get("GCP_LOCATION", "global"),
        )
        client.models.generate_content(model=VERTEX_MODEL, contents="ok")
        _vertex_client = client
    except Exception:
        _vertex_client = None  # ADC expired, or no Vertex access on this project
    return _vertex_client


def _try_gemini() -> tuple[Any, str, str] | None:
    """Returns (client, model, mode) or None. API key first, then Vertex."""
    try:
        from google import genai
    except ImportError:
        return None

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if api_key:
        try:
            client = genai.Client(api_key=api_key)
            # Cheap liveness probe -- an invalid key fails here, not mid-demo.
            next(iter(client.models.list()), None)
            return client, GEMINI_MODEL, "api-key"
        except Exception:
            pass  # fall through to Vertex

    vertex = get_vertex()
    if vertex is not None:
        loc = os.environ.get("GCP_LOCATION", "global")
        return vertex, VERTEX_MODEL, f"vertex:{loc}"
    return None


def _try_claude() -> tuple[Any, str, str] | None:
    try:
        import anthropic
    except ImportError:
        return None
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return None
    try:
        return anthropic.Anthropic(), CLAUDE_MODEL, "api-key"
    except Exception:
        return None


def _resolve() -> None:
    global _provider, _client, _error, _model
    if _provider is not None or _error is not None:
        return

    order = {
        "auto": [("gemini", _try_gemini), ("claude", _try_claude)],
        "gemini": [("gemini", _try_gemini)],
        "claude": [("claude", _try_claude)],
        "offline": [],
    }.get(PROVIDER, [("gemini", _try_gemini), ("claude", _try_claude)])

    for name, probe in order:
        found = probe()
        if found:
            _client, _model, mode = found
            _provider = f"{name}:{mode}"
            return

    _error = (
        "no working LLM credentials. Set GEMINI_API_KEY (aistudio.google.com/apikey), "
        "or run `gcloud auth application-default login` for Vertex, "
        "or set ANTHROPIC_API_KEY."
    )


def llm_available() -> bool:
    _resolve()
    return _client is not None


def llm_status() -> dict[str, Any]:
    _resolve()
    return {
        "available": _client is not None,
        "provider": _provider,
        "model": _model,
        "reason": None if _client is not None else _error,
        "exhausted_models": sorted(_exhausted),
        "free_tier_note": "Gemini free tier is 20 requests/day/model",
    }


# ---------------------------------------------------------------------------
# The one call the pipeline makes
# ---------------------------------------------------------------------------

_RETRY_DELAY_RE = re.compile(r"'retryDelay':\s*'(\d+)s'")


def call_structured(system: str, user: str, schema: type[T], attempts: int = 3) -> T:
    """Fill `schema` with the model. Raises if no provider is available.

    Retries on rate limits. Free-tier Gemini throttles hard, and two pipeline
    steps fire back to back, so without this the second one always loses and
    silently degrades to the heuristic.
    """
    _resolve()
    if _client is None:
        raise RuntimeError(f"LLM unavailable: {_error}")

    last: Exception | None = None
    for attempt in range(attempts):
        try:
            if _provider and _provider.startswith("gemini"):
                return _call_gemini(system, user, schema)
            return _call_claude(system, user, schema)
        except Exception as exc:
            last = exc
            text = str(exc)
            retryable = (
                not _is_daily_quota(exc)
                and (
                    "429" in text or "RESOURCE_EXHAUSTED" in text
                    or "rate_limit" in text or _is_overloaded(exc)
                )
            )
            if not retryable or attempt == attempts - 1:
                raise
            hinted = _RETRY_DELAY_RE.search(text)
            delay = int(hinted.group(1)) + 1 if hinted else 5 * (2 ** attempt)
            time.sleep(min(delay, 30))
    raise last or RuntimeError("LLM call failed")


def provider_label() -> str:
    """Short name for the UI chip: 'gemini', 'claude', or 'offline'."""
    _resolve()
    return _provider.split(":")[0] if _provider else "offline"


def _is_overloaded(exc: Exception) -> bool:
    text = str(exc)
    return "503" in text or "UNAVAILABLE" in text or "high demand" in text


def _is_daily_quota(exc: Exception) -> bool:
    """Daily quota exhausted -- fatal for this model until tomorrow.

    Critically different from a per-minute throttle. Retrying a per-minute
    limit is correct; retrying a *daily* limit spends more of a quota that is
    already gone. The free tier is 20 requests/day/model, so an amplifying
    retry drains it in two rules.
    """
    return "PerDay" in str(exc)


# Models whose daily quota is gone. Skipped for the rest of the process.
_exhausted: set[str] = set()


def _call_gemini(system: str, user: str, schema: type[T]) -> T:
    from google.genai import types

    config = types.GenerateContentConfig(
        system_instruction=system,
        response_mime_type="application/json",
        response_schema=schema,
        max_output_tokens=MAX_TOKENS,
        temperature=0.2,
        # Capped, not disabled. Unbounded thinking on a classification task
        # doubles latency without improving the answer; 512 still gets the
        # spraying-vs-guessing discrimination right.
        thinking_config=types.ThinkingConfig(thinking_budget=THINKING_BUDGET),
    )

    client, chain = _client, [m for m in [_model, *GEMINI_FALLBACKS] if m not in _exhausted]
    if not chain:
        # Free-tier key is spent for today. Vertex bills the GCP project and
        # has its own quota, so escalate there before giving up.
        vertex = get_vertex()
        if vertex is None:
            raise RuntimeError(
                "every Gemini model has spent its free-tier daily quota "
                f"({', '.join(sorted(_exhausted))}), and Vertex is unavailable. "
                "Run `gcloud auth application-default login` to use the GCP "
                "project's quota, or wait for the free tier to reset."
            )
        client, chain = vertex, [VERTEX_MODEL]

    last: Exception | None = None
    for model in chain:
        try:
            response = client.models.generate_content(
                model=model, contents=user, config=config
            )
        except Exception as exc:
            last = exc
            if _is_daily_quota(exc):
                # Burn nothing further on this model today.
                _exhausted.add(model)
                continue
            if _is_overloaded(exc):
                continue  # that model is busy; try the next one
            raise

        parsed = getattr(response, "parsed", None)
        if isinstance(parsed, schema):
            return parsed
        # Schema mode occasionally hands back a dict instead of the instance.
        if isinstance(parsed, dict):
            return schema.model_validate(parsed)
        if response.text:
            return schema.model_validate_json(response.text)
        last = RuntimeError(f"{model} returned no parsable output")

    raise last or RuntimeError("Gemini returned no parsable output")


def _call_claude(system: str, user: str, schema: type[T]) -> T:
    response = _client.messages.parse(
        model=_model,
        max_tokens=MAX_TOKENS,
        thinking={"type": "adaptive"},
        system=system,
        messages=[{"role": "user", "content": user}],
        output_format=schema,
    )
    parsed = response.parsed_output
    if parsed is None:
        raise RuntimeError("Claude returned no parsable output")
    return parsed
