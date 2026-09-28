"""
Accuracy eval against SigmaHQ.

SigmaHQ ships thousands of real detection rules that already carry their
correct ATT&CK technique as a tag (`tags: attack.t1110.003`). That is free,
human-authored ground truth. We strip the tags, run the rule through our
pipeline, and compare.

What the rule is shown: title, logsource, detection. That is what a SIEM rule
actually contains. We deliberately drop `description`, `references` and
`falsepositives`, because those often name the technique in prose and would
turn the test into reading comprehension instead of query analysis.

    python -m eval.run_eval --n 20

Results are cached, so a re-run costs no API calls.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.attack_kb import get_kb  # noqa: E402
from app.llm import llm_status, provider_label  # noqa: E402
from app.pipeline import HALLUCINATION_BLOCKS, analyze  # noqa: E402

HERE = Path(__file__).resolve().parent
CACHE_FILE = HERE / "eval_cache.json"
RESULTS_FILE = HERE / "results.json"
TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)

# Fields a real SIEM rule carries. Everything else is stripped.
KEEP_FIELDS = ("title", "logsource", "detection")


def find_rules(root: Path) -> list[Path]:
    return sorted(root.rglob("*.yml"))


def load_rule(path: Path) -> dict[str, Any] | None:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(doc, dict) or "detection" not in doc:
        return None

    truth = [
        m.group(1).upper()
        for tag in (doc.get("tags") or [])
        if isinstance(tag, str) and (m := TAG_RE.match(tag.strip()))
    ]
    if not truth:
        return None

    stripped = {k: doc[k] for k in KEEP_FIELDS if k in doc}
    return {
        "path": str(path.relative_to(root_of(path))),
        "title": doc.get("title", ""),
        "truth": truth,
        "text": yaml.safe_dump(stripped, sort_keys=False, default_flow_style=False),
    }


def root_of(path: Path) -> Path:
    for parent in path.parents:
        if parent.name == "rules":
            return parent.parent
    return path.parent


def parent_of(tid: str) -> str:
    return tid.split(".")[0]


def recall_curve(rules: list[dict], ks: tuple[int, ...] = (10, 20, 30, 50)) -> list[dict]:
    """Does retrieval even surface the right technique?

    No model involved, so this is free and exact. It is the ceiling on
    accuracy -- the model cannot choose what retrieval never found.
    """
    from app.parser import parse_rule
    from app.pipeline import CANDIDATE_POOL, _retrieval_query
    from app.retrieve import get_index

    index = get_index()
    parsed = [(parse_rule(r["text"]), r["truth"]) for r in rules]
    out = []
    for k in ks:
        exact = parent = 0
        for p, truth in parsed:
            ids = [c.technique.id for c in index.search(_retrieval_query(p), top_k=k)]
            parents = {i.split(".")[0] for i in ids}
            if any(t in ids for t in truth):
                exact += 1
            if any(parent_of(t) in parents for t in truth):
                parent += 1
        n = len(parsed) or 1
        row = {"k": k, "exact": round(100 * exact / n, 1), "parent": round(100 * parent / n, 1)}
        if k == CANDIDATE_POOL:
            row["current"] = True
        out.append(row)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--rules-dir",
        default=os.environ.get("SIGMA_DIR", str(HERE.parent / "data" / "sigma" / "rules")),
    )
    ap.add_argument("--n", type=int, default=20, help="sample size")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--recall-n", type=int, default=200,
                    help="rules used for the retrieval-recall curve (free, no model)")
    args = ap.parse_args()

    if not args.rules_dir:
        print("Pass --rules-dir <path to sigma rules/> or set SIGMA_DIR")
        return 2
    root = Path(args.rules_dir)
    if not root.exists():
        print(f"No such directory: {root}")
        return 2

    status = llm_status()
    if not status["available"]:
        print(f"No model configured: {status['reason']}")
        return 1

    kb = get_kb()
    cache: dict[str, Any] = {}
    if CACHE_FILE.exists():
        cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))

    print(f"Provider: {status['provider']} ({status['model']})")
    print(f"Scanning {root} ...")

    candidates = []
    for path in find_rules(root):
        rule = load_rule(path)
        if rule:
            candidates.append(rule)
    print(f"{len(candidates)} Sigma rules carry an ATT&CK technique tag.")

    # Only score against techniques that exist in the ATT&CK version we ship.
    # Sigma still tags the pre-v18 numbering (t1562.001), and penalising the
    # pipeline for an ID that no longer exists would be measuring the wrong
    # thing. Count them, report them, exclude them.
    scoreable, renumbered = [], []
    for rule in candidates:
        if any(kb.exists(t) for t in rule["truth"]):
            scoreable.append(rule)
        else:
            renumbered.append(rule)
    print(
        f"{len(scoreable)} scoreable against ATT&CK v18; "
        f"{len(renumbered)} excluded (technique renumbered or retired since tagging)."
    )

    random.seed(args.seed)
    recall_sample = random.sample(scoreable, min(args.recall_n, len(scoreable)))
    print()
    print(f"Measuring retrieval recall on {len(recall_sample)} rules (no model) ...")
    curve = recall_curve(recall_sample)
    for row in curve:
        mark = "  <- current" if row.get("current") else ""
        print(f"   pool {row['k']:<3} exact {row['exact']:5.1f}%   parent {row['parent']:5.1f}%{mark}")

    random.seed(args.seed)
    sample = random.sample(scoreable, min(args.n, len(scoreable)))
    print(f"\nEvaluating {len(sample)} held-out rules (seed {args.seed})\n")

    rows = []
    before_blocks = HALLUCINATION_BLOCKS
    for i, rule in enumerate(sample, 1):
        key = f"{provider_label()}:{rule['path']}"
        if key in cache:
            row = cache[key]
            mark = "cached"
        else:
            try:
                result = analyze(rule["text"], include_gaps=False)
            except Exception as exc:
                print(f"  [{i:2}/{len(sample)}] ERROR  {rule['title'][:46]}  ({str(exc)[:50]})")
                continue
            if result.get("engine") == "offline-heuristic":
                print(f"  [{i:2}/{len(sample)}] SKIP   {rule['title'][:46]}  (model unavailable)")
                continue
            mapping = result["mapping"]
            tech = mapping.get("technique") or {}
            sub = mapping.get("sub_technique") or {}
            row = {
                "title": rule["title"],
                "truth": rule["truth"],
                "predicted": sub.get("id") or tech.get("id") or "",
                "predicted_parent": tech.get("id") or "",
                "predicted_tactic": mapping.get("tactic") or "",
                "confidence": mapping.get("confidence", 0),
                "abstained": bool(mapping.get("abstain")),
            }
            cache[key] = row
            CACHE_FILE.write_text(json.dumps(cache, indent=1), encoding="utf-8")
            mark = "live"

        truth_parents = {parent_of(t) for t in row["truth"]}
        row["exact"] = row["predicted"] in row["truth"]
        row["technique_ok"] = row["predicted_parent"] in truth_parents
        truth_tactics = set()
        for t in row["truth"]:
            tech_obj = kb.get(t) or kb.get(parent_of(t))
            if tech_obj:
                truth_tactics.update(tech_obj.tactic_names)
        row["tactic_ok"] = row["predicted_tactic"] in truth_tactics
        rows.append(row)

        verdict = (
            "ABSTAIN" if row["abstained"]
            else "EXACT  " if row["exact"]
            else "TECH   " if row["technique_ok"]
            else "TACTIC " if row["tactic_ok"]
            else "MISS   "
        )
        print(
            f"  [{i:2}/{len(sample)}] {verdict} {row['title'][:40]:42} "
            f"truth {','.join(row['truth']):12} got {row['predicted'] or '-':12} ({mark})"
        )

    if not rows:
        print("\nNo rules evaluated.")
        return 1

    n = len(rows)
    answered = [r for r in rows if not r["abstained"]]
    exact = sum(r["exact"] for r in rows)
    tech_ok = sum(r["technique_ok"] for r in rows)
    tactic_ok = sum(r["tactic_ok"] for r in rows)
    abstained = sum(r["abstained"] for r in rows)
    hallucinated = HALLUCINATION_BLOCKS - before_blocks

    def pct(x: int, d: int = n) -> str:
        return f"{100 * x / d:5.1f}%" if d else "  n/a"

    print("\n" + "=" * 66)
    print(f"  EVALUATED ON {n} HELD-OUT SIGMAHQ RULES")
    print("=" * 66)
    print(f"  Exact match (incl. sub-technique)   {pct(exact)}   {exact}/{n}")
    print(f"  Correct technique (parent level)    {pct(tech_ok)}   {tech_ok}/{n}")
    print(f"  Correct tactic                      {pct(tactic_ok)}   {tactic_ok}/{n}")
    print(f"  Abstained (declined to guess)       {pct(abstained)}   {abstained}/{n}")
    if answered:
        ans_tech = sum(r["technique_ok"] for r in answered)
        print(f"  Technique accuracy when answering   {pct(ans_tech, len(answered))}"
              f"   {ans_tech}/{len(answered)}")
    print(f"  Hallucinated technique IDs          {hallucinated:>6}   "
          f"(retrieval-constrained)")
    print("=" * 66)

    misses = [r for r in rows if not r["technique_ok"] and not r["abstained"]]
    if misses:
        print("\n  Misses:")
        for r in misses[:8]:
            print(f"    {r['title'][:44]:46} truth {','.join(r['truth']):12} "
                  f"got {r['predicted']:12} conf {r['confidence']}")
        tactic_saves = sum(r["tactic_ok"] for r in misses)
        print(f"\n  {tactic_saves}/{len(misses)} misses still landed the right tactic.")

    RESULTS_FILE.write_text(
        json.dumps(
            {
                "provider": status["provider"],
                "model": status["model"],
                "sample_size": n,
                "seed": args.seed,
                "exact": exact,
                "technique": tech_ok,
                "tactic": tactic_ok,
                "abstained": abstained,
                "hallucinated": hallucinated,
                "recall_sample": len(recall_sample),
                "recall_curve": curve,
                "rows": rows,
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    print(f"\nWritten to {RESULTS_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
