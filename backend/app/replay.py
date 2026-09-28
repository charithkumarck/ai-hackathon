"""
Attack replay.

A percentage does not frighten anybody. A timeline does. These are real-world
intrusion chains in ATT&CK order; we walk each step against the techniques the
customer actually detects and mark it SEEN or MISSED.

No LLM involved -- it is a set lookup. Every technique ID is validated against
the live KB at import, so an ATT&CK renumbering shows up as a loud warning
rather than a silently broken demo.
"""
from __future__ import annotations

from typing import Any

from .attack_kb import get_kb

SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "cloud-identity-takeover",
        "name": "Cloud identity takeover",
        "summary": "A sprayed password works, and the attacker owns the tenant two hours later.",
        "steps": [
            ("09:14", "T1110.003", "Sprays 400 common passwords across the tenant"),
            ("09:47", "T1078.004", "One password works -- signs in as a real employee"),
            ("09:51", "T1556.006", "Registers their own MFA device on the account"),
            ("10:02", "T1098.003", "Grants the account an additional cloud admin role"),
            ("10:30", "T1114.002", "Bulk-downloads the executive mailbox"),
            ("11:15", "T1070.008", "Clears mailbox audit data to cover the theft"),
        ],
    },
    {
        "id": "ransomware-phish",
        "name": "Ransomware from a phishing email",
        "summary": "Attachment to full domain encryption in under a working day.",
        "steps": [
            ("08:32", "T1566.001", "Employee receives a weaponised invoice attachment"),
            ("08:36", "T1204.002", "Employee opens it and enables macros"),
            ("08:36", "T1059.001", "Macro launches obfuscated PowerShell"),
            ("08:41", "T1547.001", "Adds a Run key so the implant survives reboot"),
            ("09:20", "T1003.001", "Dumps LSASS to harvest cached admin credentials"),
            ("10:05", "T1021.002", "Moves to the file server over SMB admin shares"),
            ("11:40", "T1685", "Disables endpoint protection across the estate"),
            ("12:15", "T1490", "Deletes volume shadow copies"),
            ("12:20", "T1486", "Encrypts every reachable file share"),
        ],
    },
    {
        "id": "insider-exfil",
        "name": "Insider data theft",
        "summary": "A legitimate account quietly walks out with the customer database.",
        "steps": [
            ("14:02", "T1078", "Logs in with their own valid credentials, out of hours"),
            ("14:11", "T1087.002", "Enumerates domain accounts and groups"),
            ("14:26", "T1039", "Browses and copies from finance network shares"),
            ("15:03", "T1560.001", "Archives the collected files with 7-Zip"),
            ("15:31", "T1567.002", "Uploads the archive to personal cloud storage"),
        ],
    },
]


def _validate() -> list[str]:
    kb = get_kb()
    problems = []
    for scenario in SCENARIOS:
        for _, tid, _ in scenario["steps"]:
            if not kb.exists(tid):
                problems.append(f"{scenario['id']}: unknown technique {tid}")
    return problems


def list_scenarios() -> list[dict[str, str]]:
    return [
        {"id": s["id"], "name": s["name"], "summary": s["summary"], "steps": len(s["steps"])}
        for s in SCENARIOS
    ]


def replay(scenario_id: str, detected_ids: set[str]) -> dict[str, Any]:
    """Walk one scenario against the set of technique IDs the customer detects."""
    kb = get_kb()
    scenario = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if scenario is None:
        return {"ok": False, "error": f"Unknown scenario {scenario_id}"}

    # A parent-level detection covers its sub-techniques and vice versa: if you
    # detect T1110 you would see T1110.003 fire.
    expanded: set[str] = set()
    for tid in detected_ids:
        expanded.add(tid)
        tech = kb.get(tid)
        if not tech:
            continue
        if tech.parent_id:
            expanded.add(tech.parent_id)
        expanded.update(tech.sub_ids)

    steps = []
    seen_count = 0
    first_miss_index = None
    for i, (clock, tid, description) in enumerate(scenario["steps"]):
        tech = kb.get(tid)
        detected = tid in expanded
        if detected:
            seen_count += 1
        elif first_miss_index is None:
            first_miss_index = i
        steps.append({
            "time": clock,
            "technique_id": tid,
            "technique": tech.name if tech else tid,
            "tactic": tech.tactic_names[0] if tech and tech.tactic_names else "Unknown",
            "action": description,
            "detected": detected,
            "url": tech.url if tech else "",
        })

    total = len(steps)
    blind_from = steps[first_miss_index]["time"] if first_miss_index is not None else None

    return {
        "ok": True,
        "id": scenario["id"],
        "name": scenario["name"],
        "summary": scenario["summary"],
        "steps": steps,
        "seen": seen_count,
        "missed": total - seen_count,
        "total": total,
        "verdict": _verdict(seen_count, total, steps, first_miss_index, blind_from),
    }


def _verdict(seen: int, total: int, steps: list[dict], first_miss: int | None,
             blind_from: str | None) -> str:
    if seen == total:
        return "Every stage of this intrusion would raise an alert."
    if seen == 0:
        return "This entire intrusion runs start to finish without raising a single alert."
    missed = total - seen
    if first_miss == 0:
        return (
            f"You catch {seen} of {total} stages, but not the way in -- the intrusion is "
            f"already underway before your first alert fires. {missed} stages raise nothing."
        )
    duration = f"{steps[0]['time']} to {blind_from}"
    return (
        f"Your SIEM sees the first {first_miss} stage{'s' if first_miss != 1 else ''} "
        f"({duration}). After that the attacker goes dark: {missed} of {total} stages "
        f"raise nothing at all."
    )


VALIDATION_ERRORS = _validate()
