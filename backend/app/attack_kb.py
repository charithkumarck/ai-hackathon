"""
Loads the MITRE ATT&CK STIX bundle into a flat, query-friendly knowledge base.

This is the "brain" the rest of the app reasons over. Nothing here talks to an
LLM -- it is pure data. The LLM is only ever allowed to pick IDs that came out
of this file, which is what stops it inventing technique numbers.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "enterprise-attack.json")

# Attack order. ATT&CK v18 split the old "Defense Evasion" tactic into
# "Defense Impairment" and "Stealth", so both appear here.
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-impairment",
    "stealth",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Which security domain a platform belongs to. Used for the coverage dashboard.
PLATFORM_DOMAIN = {
    "Identity Provider": "Identity",
    "Windows": "Endpoint",
    "Linux": "Endpoint",
    "macOS": "Endpoint",
    "Containers": "Endpoint",
    "ESXi": "Endpoint",
    "Network Devices": "Network",
    "IaaS": "Cloud",
    "SaaS": "Cloud",
    "Office Suite": "Cloud",
    "PRE": "Network",
}

DOMAINS = ["Identity", "Endpoint", "Network", "Cloud"]

_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(https?://[^)]+\)")


def _clean(text: str) -> str:
    """ATT&CK descriptions are markdown with inline citations. Strip the noise."""
    text = _CITATION_RE.sub("", text or "")
    text = _MD_LINK_RE.sub(r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _external_url(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


@dataclass
class Technique:
    id: str
    name: str
    description: str
    tactics: list[str]
    tactic_names: list[str]
    platforms: list[str]
    domains: list[str]
    is_sub: bool
    parent_id: str | None
    url: str
    sub_ids: list[str] = field(default_factory=list)
    # Detection guidance, straight from ATT&CK's detection strategies / analytics.
    detection_notes: list[str] = field(default_factory=list)
    log_sources: list[str] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return self.name

    @property
    def primary_tactic(self) -> str:
        """The earliest tactic in kill-chain order.

        STIX lists kill_chain_phases in its own order, which is not attack
        order -- T1556 arrives as [defense-impairment, persistence,
        credential-access]. Taking tactics[0] would put the technique late in
        the chain and make every downstream lookup wrong.
        """
        if not self.tactics:
            return "unknown"
        return min(
            self.tactics,
            key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else len(TACTIC_ORDER),
        )

    def search_text(self) -> str:
        """Everything BM25 should match against for this technique."""
        parts = [
            self.name,
            self.name,  # weight the name
            " ".join(self.tactic_names),
            self.description[:1500],
            " ".join(self.detection_notes)[:1500],
            " ".join(self.log_sources),
            " ".join(self.platforms),
        ]
        return " ".join(parts)

    def brief(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic_names[0] if self.tactic_names else "Unknown",
            "tactics": self.tactic_names,
            "is_sub": self.is_sub,
            "parent_id": self.parent_id,
            "url": self.url,
            "domains": self.domains,
        }


class AttackKB:
    def __init__(self, path: str = DATA_FILE):
        self.path = os.path.abspath(path)
        self.techniques: dict[str, Technique] = {}
        self.tactic_names: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        with open(self.path, encoding="utf-8") as fh:
            bundle = json.load(fh)
        objects = bundle["objects"]
        by_stix = {o["id"]: o for o in objects}

        for obj in objects:
            if obj["type"] == "x-mitre-tactic":
                self.tactic_names[obj["x_mitre_shortname"]] = obj["name"]

        # --- techniques -------------------------------------------------
        patterns = [
            o
            for o in objects
            if o["type"] == "attack-pattern"
            and not o.get("revoked")
            and not o.get("x_mitre_deprecated")
        ]
        stix_to_attack: dict[str, str] = {}
        for obj in patterns:
            tid = _external_id(obj)
            if not tid:
                continue
            stix_to_attack[obj["id"]] = tid
            tactics = [
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            platforms = obj.get("x_mitre_platforms", [])
            domains = sorted({PLATFORM_DOMAIN[p] for p in platforms if p in PLATFORM_DOMAIN})
            self.techniques[tid] = Technique(
                id=tid,
                name=obj["name"],
                description=_clean(obj.get("description", "")),
                tactics=tactics,
                tactic_names=[self.tactic_names.get(t, t.replace("-", " ").title()) for t in tactics],
                platforms=platforms,
                domains=domains or ["Endpoint"],
                is_sub=bool(obj.get("x_mitre_is_subtechnique")),
                parent_id=None,
                url=_external_url(obj) or "",
            )

        # --- parent / child links --------------------------------------
        for obj in objects:
            if obj["type"] == "relationship" and obj["relationship_type"] == "subtechnique-of":
                child = stix_to_attack.get(obj["source_ref"])
                parent = stix_to_attack.get(obj["target_ref"])
                if child in self.techniques and parent in self.techniques:
                    self.techniques[child].parent_id = parent
                    self.techniques[parent].sub_ids.append(child)

        # --- detection strategies -> analytics -> log sources -----------
        analytics = {o["id"]: o for o in objects if o["type"] == "x-mitre-analytic"}
        strategies = {o["id"]: o for o in objects if o["type"] == "x-mitre-detection-strategy"}

        for obj in objects:
            if obj["type"] != "relationship" or obj["relationship_type"] != "detects":
                continue
            strategy = strategies.get(obj["source_ref"])
            tid = stix_to_attack.get(obj["target_ref"])
            if not strategy or tid not in self.techniques:
                continue
            tech = self.techniques[tid]
            for aref in strategy.get("x_mitre_analytic_refs", []):
                analytic = analytics.get(aref)
                if not analytic:
                    continue
                note = _clean(analytic.get("description", ""))
                if note and note not in tech.detection_notes:
                    tech.detection_notes.append(note)
                for ls in analytic.get("x_mitre_log_source_references", []):
                    name = ls.get("name")
                    channel = ls.get("channel")
                    label = f"{name}:{channel}" if name and channel else (name or "")
                    if label and label not in tech.log_sources:
                        tech.log_sources.append(label)

        # Children inherit nothing, but parents borrow their children's log
        # sources so a parent-level match still knows what telemetry it needs.
        for tech in self.techniques.values():
            if tech.sub_ids:
                for sid in tech.sub_ids:
                    for ls in self.techniques[sid].log_sources:
                        if ls not in tech.log_sources:
                            tech.log_sources.append(ls)

    # ------------------------------------------------------------------
    def get(self, tid: str) -> Technique | None:
        return self.techniques.get(tid)

    def exists(self, tid: str) -> bool:
        return tid in self.techniques

    def in_tactics(self, tactics: list[str]) -> list[Technique]:
        want = set(tactics)
        return [t for t in self.techniques.values() if want & set(t.tactics)]

    def downstream_tactics(self, tactic: str) -> list[str]:
        """Tactics that come after this one in a real intrusion."""
        if tactic not in TACTIC_ORDER:
            return TACTIC_ORDER
        idx = TACTIC_ORDER.index(tactic)
        return TACTIC_ORDER[idx + 1 :]

    def tactic_label(self, shortname: str) -> str:
        return self.tactic_names.get(shortname, shortname.replace("-", " ").title())

    def stats(self) -> dict[str, Any]:
        subs = sum(1 for t in self.techniques.values() if t.is_sub)
        return {
            "techniques": len(self.techniques) - subs,
            "sub_techniques": subs,
            "total": len(self.techniques),
            "tactics": len(self.tactic_names),
            "with_detection_guidance": sum(
                1 for t in self.techniques.values() if t.detection_notes
            ),
        }


@lru_cache(maxsize=1)
def get_kb() -> AttackKB:
    return AttackKB()
