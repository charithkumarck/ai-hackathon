"""
FastAPI surface for the detection-coverage analyser.

    POST /api/analyze          one rule  -> TTP + critique + gaps
    POST /api/analyze/bulk     many      -> per-rule results + coverage + replay
    POST /api/generate-rule    a gap     -> a query you can paste into the SIEM
    GET  /api/replay/{id}      scenario  -> what your rules would have caught
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import pipeline, replay as replay_mod
from .attack_kb import get_kb
from .coverage import build_coverage
from .llm import llm_status, provider_label
from .retrieve import get_index
from .seed_rules import seed_queries

app = FastAPI(title="ATT&CK Coverage X-Ray", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # hackathon demo; lock down before anything real
    allow_methods=["*"],
    allow_headers=["*"],
)

# Analyses are a pure function of (rule text, provider), so cache them on disk.
# On free-tier Gemini a cold 30-rule sweep takes ~9 minutes; warm it once before
# a demo and the same sweep returns instantly, across restarts.
_CACHE: dict[str, dict[str, Any]] = {}
_SESSIONS: dict[str, dict[str, Any]] = {}
MAX_BULK = 60
WORKERS = int(os.environ.get("ANALYZE_WORKERS", "3"))
CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "analysis_cache.json")
_cache_lock = threading.Lock()


def _load_cache() -> None:
    try:
        with open(CACHE_FILE, encoding="utf-8") as fh:
            _CACHE.update(json.load(fh))
    except (FileNotFoundError, json.JSONDecodeError):
        pass


def _save_cache() -> None:
    try:
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_CACHE, fh)
        os.replace(tmp, CACHE_FILE)
    except OSError:
        pass  # a cache that cannot be written is not worth failing a request over


def _cache_key(text: str, with_gaps: bool) -> str:
    # Provider is part of the key: an offline-mode answer must not be served
    # once a real model is configured.
    stamp = f"{provider_label()}:{int(with_gaps)}:{text}"
    return hashlib.sha256(stamp.encode()).hexdigest()


def _analyze_cached(text: str, with_gaps: bool) -> dict[str, Any]:
    key = _cache_key(text, with_gaps)
    hit = _CACHE.get(key)
    if hit is not None:
        return {**hit, "cached": True}
    result = pipeline.analyze(text, include_gaps=with_gaps)
    # Never cache a degraded answer -- it would outlive the outage.
    if result.get("ok") and result.get("engine") != "offline-heuristic":
        with _cache_lock:
            _CACHE[key] = result
            _save_cache()
    return {**result, "cached": False}


_load_cache()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    rule: str = Field(min_length=3, max_length=20000)
    include_gaps: bool = True


class BulkRule(BaseModel):
    name: str = ""
    query: str
    language: str = ""


class BulkRequest(BaseModel):
    rules: list[BulkRule] = []
    use_seed: bool = False


class GenerateRequest(BaseModel):
    technique_id: str
    language: str = "SPL"
    context: str = ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _mount_ui() -> None:
    """Serve the built frontend from the API when it exists.

    One container, one origin, no CORS -- and the UI's relative /api calls
    just work. Skipped in dev, where Vite serves the UI and proxies /api here.
    """
    dist = os.path.join(os.path.dirname(__file__), "..", "..", "UI", "dist")
    index = os.path.join(dist, "index.html")
    if not os.path.exists(index):
        return

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    app.mount("/assets", StaticFiles(directory=os.path.join(dist, "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        # Anything not under /api is the single-page app.
        candidate = os.path.join(dist, full_path)
        if full_path and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(index)


@app.get("/api/health")
def health() -> dict[str, Any]:
    kb = get_kb()
    index = get_index()
    return {
        "status": "ok",
        "attack": kb.stats(),
        "retrieval": {"indexed_techniques": index.n, "vocabulary": len(index.idf)},
        "llm": llm_status(),
        "guardrail": {
            "hallucinated_ids_blocked": pipeline.HALLUCINATION_BLOCKS,
            "policy": "technique IDs must come from the retrieved candidate pool",
        },
        "scenario_validation": replay_mod.VALIDATION_ERRORS or "all scenario technique IDs valid",
        "cached_analyses": len(_CACHE),
        "cache_file": os.path.abspath(CACHE_FILE),
    }


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest) -> dict[str, Any]:
    result = _analyze_cached(req.rule, req.include_gaps)
    if not result.get("ok"):
        raise HTTPException(status_code=422, detail=result.get("error", "analysis failed"))
    return result


@app.get("/api/seed-rules")
def seed() -> dict[str, Any]:
    rules = seed_queries()
    return {"count": len(rules), "rules": rules}


@app.post("/api/analyze/bulk")
def analyze_bulk(req: BulkRequest) -> dict[str, Any]:
    rules = (
        [BulkRule(name=r["name"], query=r["query"], language=r.get("language", ""))
         for r in seed_queries()]
        if req.use_seed
        else req.rules
    )
    if not rules:
        raise HTTPException(status_code=422, detail="No rules supplied")
    if len(rules) > MAX_BULK:
        raise HTTPException(status_code=422, detail=f"Maximum {MAX_BULK} rules per request")

    # Gaps are per-rule and expensive; the coverage view supersedes them.
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        analyses = list(pool.map(lambda r: _analyze_cached(r.query, False), rules))

    results = []
    detected_ids: set[str] = set()
    for rule, analysis in zip(rules, analyses):
        mapping = analysis.get("mapping") or {}
        tech = mapping.get("technique")
        sub = mapping.get("sub_technique")
        if tech:
            detected_ids.add(tech["id"])
        if sub:
            detected_ids.add(sub["id"])
        results.append({
            "name": rule.name or "(unnamed rule)",
            "query": rule.query,
            "language": (analysis.get("parsed") or {}).get("language"),
            "domain": (analysis.get("parsed") or {}).get("domain"),
            "ok": analysis.get("ok", False),
            "technique": tech,
            "sub_technique": sub,
            "tactic": mapping.get("tactic"),
            "confidence": mapping.get("confidence"),
            "abstained": mapping.get("abstain", False),
        })

    coverage = build_coverage(analyses)
    replays = [
        replay_mod.replay(s["id"], detected_ids) for s in replay_mod.list_scenarios()
    ]

    session_id = uuid.uuid4().hex[:12]
    _SESSIONS[session_id] = {"detected_ids": detected_ids, "coverage": coverage}

    return {
        "session_id": session_id,
        "rules": results,
        "coverage": coverage,
        "replays": replays,
        "engine": analyses[0].get("engine") if analyses else "unknown",
    }


@app.get("/api/eval")
def eval_results() -> dict[str, Any]:
    """Last accuracy run, plus the retrieval-recall curve behind it."""
    path = os.path.join(os.path.dirname(__file__), "..", "eval", "results.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        raise HTTPException(
            status_code=404,
            detail="No eval run found. Run: python -m eval.run_eval --n 20",
        )
    data.setdefault("recall_curve", [])
    data.setdefault("recall_sample", 0)
    return data


@app.get("/api/scenarios")
def scenarios() -> dict[str, Any]:
    return {"scenarios": replay_mod.list_scenarios()}


@app.get("/api/replay/{scenario_id}")
def get_replay(scenario_id: str, session: str = "") -> dict[str, Any]:
    detected = _SESSIONS.get(session, {}).get("detected_ids", set())
    result = replay_mod.replay(scenario_id, detected)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@app.post("/api/generate-rule")
def generate(req: GenerateRequest) -> dict[str, Any]:
    result = pipeline.generate_rule(req.technique_id, req.language, req.context)
    if not result.get("ok"):
        raise HTTPException(status_code=422, detail=result.get("error"))
    return result


@app.get("/api/technique/{technique_id}")
def technique(technique_id: str) -> dict[str, Any]:
    tech = get_kb().get(technique_id.upper())
    if not tech:
        raise HTTPException(status_code=404, detail=f"Unknown technique {technique_id}")
    return {
        **tech.brief(),
        "description": tech.description,
        "platforms": tech.platforms,
        "log_sources": tech.log_sources[:20],
        "detection_notes": tech.detection_notes[:3],
        "sub_techniques": [
            get_kb().get(s).brief() for s in tech.sub_ids if get_kb().get(s)
        ],
    }


# Registered last so it never shadows an /api route.
_mount_ui()
