"""
Coverage engine: many rules -> one picture of the organisation's posture.

The scoring formula is deliberately simple and stated in the output, because a
coverage number nobody can explain is a number nobody trusts:

    breadth(domain) = tactics with at least one detection / tactics in scope
    depth(domain)   = min(1, rules per covered tactic / DEPTH_TARGET)
    score(domain)   = 100 * (0.7 * breadth + 0.3 * depth)
    posture         = weighted mean of domain scores

Breadth dominates on purpose: five brute-force rules and nothing else is not
good coverage, it is one detection written five times.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .attack_kb import DOMAINS, TACTIC_ORDER, get_kb

DEPTH_TARGET = 3          # rules per tactic before depth is considered full
DOMAIN_WEIGHTS = {"Identity": 0.30, "Endpoint": 0.30, "Cloud": 0.20, "Network": 0.20}

# How much an uncovered tactic hurts. Post-compromise stages are what turn an
# incident into a breach, so they carry more weight than reconnaissance.
TACTIC_RISK = {
    "reconnaissance": 0.3,
    "resource-development": 0.2,
    "initial-access": 1.0,
    "execution": 0.9,
    "persistence": 1.0,
    "privilege-escalation": 1.0,
    "defense-impairment": 0.8,
    "stealth": 0.7,
    "credential-access": 1.0,
    "discovery": 0.6,
    "lateral-movement": 1.0,
    "collection": 0.7,
    "command-and-control": 0.8,
    "exfiltration": 1.0,
    "impact": 1.0,
}


def _score_domain(covered_tactics: set[str], rule_count: int, in_scope: int) -> dict[str, Any]:
    breadth = (len(covered_tactics) / in_scope) if in_scope else 0.0
    depth = min(1.0, (rule_count / max(1, len(covered_tactics)) / DEPTH_TARGET)) if covered_tactics else 0.0
    score = 100 * (0.7 * breadth + 0.3 * depth)
    return {
        "score": round(score),
        "breadth_pct": round(breadth * 100),
        "depth_pct": round(depth * 100),
        "tactics_covered": len(covered_tactics),
        "tactics_in_scope": in_scope,
        "rules": rule_count,
    }


def build_coverage(analyses: list[dict[str, Any]]) -> dict[str, Any]:
    """`analyses` is a list of results from pipeline.analyze()."""
    kb = get_kb()

    # tactic -> set of technique ids we detect
    tactic_hits: dict[str, set[str]] = defaultdict(set)
    # domain -> tactic -> rule count
    domain_tactic_rules: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    domain_rules: dict[str, int] = defaultdict(int)
    covered_techniques: set[str] = set()
    unmapped = 0

    for item in analyses:
        mapping = (item or {}).get("mapping") or {}
        tech = mapping.get("technique")
        if not tech:
            unmapped += 1
            continue
        tid = tech["id"]
        full = kb.get(tid)
        if not full:
            unmapped += 1
            continue
        covered_techniques.add(tid)
        sub = mapping.get("sub_technique")
        if sub:
            covered_techniques.add(sub["id"])

        domain = (item.get("parsed") or {}).get("domain") or (full.domains[0] if full.domains else "Endpoint")
        if domain not in DOMAINS:
            domain = full.domains[0] if full.domains else "Endpoint"
        domain_rules[domain] += 1
        for tactic in full.tactics:
            tactic_hits[tactic].add(tid)
            domain_tactic_rules[domain][tactic] += 1

    # --- per-domain scores ---------------------------------------------
    domain_scores: dict[str, Any] = {}
    for domain in DOMAINS:
        in_scope = sum(
            1 for t in TACTIC_ORDER
            if any(domain in tech.domains and t in tech.tactics for tech in kb.techniques.values())
        )
        covered = {t for t, n in domain_tactic_rules[domain].items() if n > 0}
        domain_scores[domain] = _score_domain(covered, domain_rules[domain], in_scope or len(TACTIC_ORDER))

    posture = round(
        sum(domain_scores[d]["score"] * DOMAIN_WEIGHTS[d] for d in DOMAINS)
        / sum(DOMAIN_WEIGHTS.values())
    )

    # --- the matrix ------------------------------------------------------
    matrix = []
    for tactic in TACTIC_ORDER:
        hits = tactic_hits.get(tactic, set())
        matrix.append({
            "tactic": tactic,
            "label": kb.tactic_label(tactic),
            "techniques_detected": len(hits),
            "technique_ids": sorted(hits),
            "risk": TACTIC_RISK.get(tactic, 0.5),
            "status": "none" if not hits else ("thin" if len(hits) < 2 else "covered"),
        })

    # --- ranked gaps -----------------------------------------------------
    # Zero coverage is the worst case, but a tactic held up by a single
    # technique is nearly as bad -- one detection is one variation away from
    # blind. Both are reported, blank first, then thin, each by risk.
    gaps = []
    for row in matrix:
        if row["techniques_detected"] > 1:
            continue
        blank = row["techniques_detected"] == 0
        blind_domains = [
            d for d in DOMAINS if domain_tactic_rules[d].get(row["tactic"], 0) == 0
        ]
        gaps.append({
            "tactic": row["tactic"],
            "label": row["label"],
            "risk": row["risk"],
            "kind": "blank" if blank else "thin",
            "detected": row["techniques_detected"],
            "blind_domains": blind_domains,
            "impact": (
                _gap_impact(row["tactic"])
                if blank
                else _thin_impact(row["tactic"], row["technique_ids"])
            ),
        })
    gaps.sort(key=lambda g: (g["kind"] != "blank", -g["risk"]))

    projected = _project(domain_scores, gaps[:3], domain_tactic_rules)

    return {
        "rules_analysed": len(analyses),
        "rules_mapped": len(analyses) - unmapped,
        "unmapped": unmapped,
        "unique_techniques": len(covered_techniques),
        "posture_score": posture,
        "posture_band": _band(posture),
        "projected_score": projected,
        "domains": domain_scores,
        "matrix": matrix,
        "top_gaps": gaps[:6],
        "formula": (
            "score = 100 x (0.7 x tactics_covered/tactics_in_scope + "
            f"0.3 x min(1, rules_per_covered_tactic/{DEPTH_TARGET}))"
        ),
    }


def _band(score: int) -> str:
    if score >= 70:
        return "strong"
    if score >= 45:
        return "moderate"
    if score >= 25:
        return "weak"
    return "high risk"


def _project(domain_scores, top_gaps, domain_tactic_rules) -> int:
    """What the posture score becomes if the top 3 gaps each get one rule."""
    bumped = {d: dict(v) for d, v in domain_scores.items()}
    for gap in top_gaps:
        for domain in gap["blind_domains"][:1]:
            s = bumped[domain]
            # A blank tactic gains breadth; a thin one only gains depth, since
            # that tactic already counts as covered.
            if gap["kind"] == "blank":
                s["tactics_covered"] = min(s["tactics_in_scope"], s["tactics_covered"] + 1)
            s["rules"] += 1
    total = 0.0
    for domain, s in bumped.items():
        breadth = s["tactics_covered"] / max(1, s["tactics_in_scope"])
        depth = min(1.0, s["rules"] / max(1, s["tactics_covered"]) / DEPTH_TARGET)
        total += (100 * (0.7 * breadth + 0.3 * depth)) * DOMAIN_WEIGHTS[domain]
    return round(total / sum(DOMAIN_WEIGHTS.values()))


def _thin_impact(tactic: str, technique_ids: list[str]) -> str:
    kb = get_kb()
    names = [kb.get(t).name for t in technique_ids if kb.get(t)]
    only = names[0] if names else "a single technique"
    return (
        f"Held up by one detection ({only}). An attacker using any other route through "
        f"{kb.tactic_label(tactic).lower()} is invisible."
    )


def _gap_impact(tactic: str) -> str:
    return {
        "initial-access": "You cannot see how an attacker gets in.",
        "execution": "Malicious code runs without an alert.",
        "persistence": "An attacker who is evicted comes straight back.",
        "privilege-escalation": "A normal user becoming an admin is silent.",
        "defense-impairment": "Tampering with your own security controls is invisible.",
        "stealth": "Attacker activity is being hidden and you would not know.",
        "credential-access": "Credential theft goes unnoticed.",
        "discovery": "An attacker maps your environment unobserved.",
        "lateral-movement": "Once inside, an attacker moves freely and invisibly.",
        "collection": "Data being staged for theft raises nothing.",
        "command-and-control": "Attacker channels out of the network are unmonitored.",
        "exfiltration": "Data can leave the organisation without an alert.",
        "impact": "Ransomware or destruction would be detected only by its effects.",
        "reconnaissance": "External scanning and profiling is unmonitored.",
        "resource-development": "Attacker infrastructure build-up is unmonitored.",
    }.get(tactic, "This stage of an intrusion is unmonitored.")
