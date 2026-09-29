
# Coverage X-Ray

Problem Statement: 

Any security engineer cannot know all 100+ TTPs (tactic, technique, and procedure) of MITRE ATT&CK (framework for understanding and mapping cyberattacker behavior)
MITRE ATT&CK = Adversarial Tactics, Techniques, and Common Knowledge. --> It documents how attackers typically operate during a cyberattack, based on real-world observations.

Intend is to help security engineers or security analysts can use this built site to know about the TTPs.
SIEM engineer builds detection logic, like brute force or impossible travel use cases, and he does not
know the TTPs. TTP are required for documnetation and to understand the current security posture of the organization and to konw in which domian the security they need to focus
and start writing secuirty usecases on it. To konw the MITRE mapping either the engineer Googles or use any AI tool to know the TTPs and add this to his
documentation or the analytical rule list.  

Coverage X-Ray is built to bridge this gap and save time and focus on deveopment work

Paste a SIEM detection rule → get its MITRE ATT&CK technique, what the rule
**cannot** see, and the detections you are missing further down the attack chain.

---

## How it works

```
paste
  ↓  parse      detect SPL/KQL/YARA-L, extract what the query observes
  ↓             …and strip comments — this is the injection boundary
  ↓  enrich     indicator lexicon: 445→SMB, 1102→log clearing, 4769+0x17→kerberoasting
  ↓  retrieve   mitre over 697 ATT&CK techniques → 10 candidates
  ↓  reason     ai model picks from those candidates ONLY, and justifies it
  ↓  critique   blind spots + telemetry that would close them
  ↓  walk       downstream tactics → the rules you don't have
```

### The two guarantees

**1. No invented technique IDs.** Retrieval builds the candidate pool; the model
may only *choose* from it. Anything else is dropped, counted, as `hallucinated_ids_blocked`. This is why you can trust the
coverage grid

**2. A pasted rule is untrusted input.** Comments are stripped before the text
reaches a prompt, and the model receives the parsed IR rather than raw text.
Try the "injection test" example.

## SOP
**Functionality1:** Paste you individual detection queries in SINGLE RULE of Coverage X-Ray and get your TTPs
**Functionality2:** Shows the blind spot of the that single rule query and what can be made stronger
**Functionality3:** You can generate the detection rules for other TTPs related to that rule and post sanity check in you environment can implement and increase the coverage
**Functionality4:** Can make use of the FULL SWEEP feature in Coverage X-Ray to dump your detection rules and know the security posture of your organization
Gives you the percentage of security coverage based on scoring defined below along with the coverage by security domains.
It also gives attack matrix right from recon to impact like how many detection rules are there.

---

## Data

`backend/data/enterprise-attack.json` — MITRE's Enterprise STIX bundle
(697 techniques, 475 sub-techniques, 15 tactics, plus v18 detection strategies
and analytics with real log-source names).

Refresh:

```bash
curl -L -o backend/data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

**Heads-up:** ATT&CK v18 renumbered things. "Impair Defenses" `T1562` is now
`T1685` *Disable or Modify Tools*, and "Defense Evasion" split into *Defense
Impairment* and *Stealth*. Never hardcode an ID from memory — `replay.py`
validates all of its IDs against the live KB at import and reports breakage on
`/api/health`.

---

## Scoring

```
breadth(domain) = tactics with ≥1 detection / tactics in scope
depth(domain)   = min(1, rules per covered tactic / 3)
score(domain)   = 100 × (0.7 × breadth + 0.3 × depth)
posture         = weighted mean  (Identity .3, Endpoint .3, Cloud .2, Network .2)
```

Breadth dominates deliberately: five brute-force rules and nothing else is not
coverage, it is one detection written five times.

---

## Status

Built:

- [x] ATT&CK ingest 
- [x] Parser for SPL / KQL / YARA-L  / plain English
- [x] Retrieval-constrained mapping with confidence + abstention
- [x] Blind spots + telemetry upgrades
- [x] Gap walk down the kill chain
- [x] Rule generation for a named gap
- [x] Bulk sweep → posture score, domain scores, ATT&CK matrix
- [x] Attack replay over 3 real intrusion chains
- [x] Prompt-injection stripping, demoed in the UI
- [x] Offline mode so the demo cannot die on stage

---
## Tech Stack
Backend: python/fastapi Frontend: react/typescript LLM_AI: gemini 3.8 flash

### Results — 20 held-out rules, gemini-3.8-flash, seed 7

| Metric | |
|---|---|
| Exact match (incl. sub-technique) | **45%** |
| Correct technique (parent level) | **55%** |
| Correct tactic | **60%** |
| Abstained (declined to guess) | **15%** |
| Technique accuracy when it answers | **65%** |
| **Hallucinated technique IDs** | **0** |

Zero is not luck. The model can only choose from the IDs retrieval handed it;
anything else is dropped and counted (`hallucinated_ids_blocked` on
`/api/health`). Wrong-but-real is possible; invented is not.


