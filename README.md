---
title: Coverage X-Ray
emoji: 🛡️
colorFrom: green
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Paste a SIEM rule, get its ATT&CK technique and what you're blind to
---

# Coverage X-Ray

Paste a SIEM detection rule → get its MITRE ATT&CK technique, what the rule
**cannot** see, and the detections you are missing further down the attack chain.

Not a MITRE lookup tool. The T-number is step one; the product is the gap.

---

## Run it

Two terminals.

**Backend**

```bash
cd HACK/backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

**Frontend**

```bash
cd HACK/UI
npm install
npm run dev
```

Open <http://localhost:5173>.

> Vite binds IPv6 on this machine — use `localhost`, not `127.0.0.1`.

### The model

Config lives in `backend/.env`:

```
GEMINI_API_KEY=...
GEMINI_MODEL=gemini-3.8-flash
GEMINI_FALLBACK_MODELS=gemini-3.5-flash,gemini-3.1-flash-lite-preview
GEMINI_THINKING_BUDGET=512
LLM_PROVIDER=auto          # auto | gemini | claude | offline
```

Providers are tried in order: **Gemini** (API key, then Vertex AI via ADC) →
**Claude** (`ANTHROPIC_API_KEY`) → **offline**.

Three things learned the hard way, all encoded in `llm.py`:

- **Pin the model.** `gemini-flash-latest` routes to whatever is newest, which
  is also whatever is busiest — it 503s while the pinned `gemini-3.8-flash`
  behind it answers fine.
- **Pro is quota-zero on free tier.** `gemini-pro-latest` returns
  `RESOURCE_EXHAUSTED ... limit: 0`. Flash is the tier that works.
- **`load_dotenv(override=True)`.** This machine has a `GEMINI_API_KEY` set
  globally in the user profile for an unrelated project. Without `override`
  it silently wins over `backend/.env` and you authenticate as the wrong thing.

On overload the call walks the fallback chain, then retries with backoff
(honouring Google's `retryDelay`), then degrades to the offline heuristic
rather than erroring. `engine` in every response says which path ran.

### Offline mode

With no working credentials the app still runs on a lexical heuristic, so a
demo cannot die on stage. It maps and critiques but **cannot generate rules**,
and its mappings are unreasoned — it calls the brute-force example
*Password Spraying*, where the model correctly says *Password Guessing*
(grouping by user + a high threshold is guessing; spraying is many accounts,
few attempts each). That contrast is the cleanest proof the model is doing
real work.

---

## How it works

```
paste
  ↓  parse      detect SPL/KQL/YARA-L, extract what the query observes
  ↓             …and strip comments — this is the injection boundary
  ↓  enrich     indicator lexicon: 445→SMB, 1102→log clearing, 4769+0x17→kerberoasting
  ↓  retrieve   BM25 over 697 ATT&CK techniques → 10 candidates
  ↓  reason     Claude picks from those candidates ONLY, and justifies it
  ↓  critique   blind spots + telemetry that would close them
  ↓  walk       downstream tactics → the rules you don't have
```

### The two guarantees

**1. No invented technique IDs.** Retrieval builds the candidate pool; the model
may only *choose* from it. Anything else is dropped, counted, and surfaced on
`/api/health` as `hallucinated_ids_blocked`. This is why you can trust the
coverage grid — one wrong ID silently corrupts it.

**2. A pasted rule is untrusted input.** Comments are stripped before the text
reaches a prompt, and the model receives the parsed IR rather than raw text.
Try the "injection test" example.

---

## API

| Endpoint | Does |
|---|---|
| `GET /api/health` | KB stats, LLM status, guardrail counter |
| `POST /api/analyze` | one rule → mapping + critique + gaps + trace |
| `POST /api/analyze/bulk` | many rules → coverage + posture + replays (`{"use_seed": true}` for the 30-rule demo set) |
| `POST /api/generate-rule` | a gap → a query to paste into the SIEM |
| `GET /api/replay/{id}?session=` | one intrusion replayed against your coverage |
| `GET /api/technique/{id}` | raw ATT&CK detail |

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

- [x] ATT&CK ingest + BM25 retrieval, no vector DB to stand up
- [x] Parser for SPL / KQL / YARA-L / Sigma / plain English
- [x] Retrieval-constrained mapping with confidence + abstention
- [x] Blind spots + telemetry upgrades
- [x] Gap walk down the kill chain
- [x] Rule generation for a named gap
- [x] Bulk sweep → posture score, domain scores, ATT&CK matrix
- [x] Attack replay over 3 real intrusion chains
- [x] Prompt-injection stripping, demoed in the UI
- [x] Offline mode so the demo cannot die on stage

- [x] **SigmaHQ accuracy eval** (`python -m eval.run_eval`)

Not built yet:

- [ ] Sigma → SPL/KQL conversion to generate multi-dialect test data for free
- [ ] Export the coverage layer as an ATT&CK Navigator JSON


---

## Measured accuracy

SigmaHQ publishes ~2,800 real detection rules that already carry their correct
ATT&CK technique as a tag. That is free, human-authored ground truth. The eval
strips the tags, feeds the rule through the pipeline, and compares.

The rule is shown only `title`, `logsource` and `detection` — what a SIEM rule
actually contains. `description`, `references` and `falsepositives` are dropped
because they often name the technique in prose, which would make this a reading
test rather than a query-analysis test.

```
python -m eval.run_eval --rules-dir <sigma>/rules --n 20
```

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

### Retrieval recall is the ceiling

The model cannot pick what retrieval never surfaced, so recall bounds accuracy.
Measured over 200 Sigma rules — no LLM involved, so this is free to re-run:

| pool size | exact in pool | parent in pool |
|---|---|---|
| 10 | 52.5% | 66.5% |
| 20 | 61.5% | 75.5% |
| **30** (default) | **67.5%** | **79.0%** |
| 50 | 74.0% | 84.5% |

Widening the pool from 10 to 30 cut the abstention rate from 75% to 15% and
doubled parent-level accuracy. The remaining gap is a retrieval problem, not a
reasoning problem — embeddings in place of BM25 is the obvious next step.

### On the misses

Several are defensible alternative mappings rather than errors — ATT&CK mapping
is genuinely ambiguous and a Sigma tag is one author's opinion:

| Rule | Sigma says | We said | |
|---|---|---|---|
| Guest → Member state change | T1078.004 Cloud Accounts | T1098 Account Manipulation | changing a user's state *is* account manipulation |
| PowerShell installed as service | T1569.002 Service Execution | T1543.003 Windows Service | near-twins |
| ScreenConnect web shell | T1190 Exploit Public-Facing App | T1505.003 Web Shell | the rule detects the web shell |
| CrackMapExec | 6 techniques tagged | T1021.002 SMB Shares | correct, just not in their list |

Scored strictly against the tag, these count as misses. That is the honest
number and it is the one reported above.
