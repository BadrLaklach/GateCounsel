# Planner Agent — File-by-File Guide & Integration Manual

Standalone delivery of the Planner Agent (spec §6.2). Your recon agent is
already built and stays untouched — this folder contains ONLY what the
planner adds, plus one reference copy of the recon data contract so the
folder runs by itself.

---

## 1. Where the planner sits in the flow

```
   YOUR SIDE (already built)
   ─────────────────────────────────────────────────────────────────────
   target URL ─► Recon Agent ─► SiteMap ─► sitemap.json
                                (agents/recon/core/models.py — DATA CONTRACT)

   THIS DELIVERY (planner only)
   ─────────────────────────────────────────────────────────────────────
                                 │
                                 ▼
                    ┌─ RuleEngine.generate(sitemap) ──► list[PlanTask]
                    │        deterministic, no network,
                    │        every task carries its recon evidence
                    │
                    ├─ AttackPlanner.plan(sitemap)
                    │        │  filter (min_priority) + cap (max_tasks)
                    │        ▼
                    │  optional LLMClient (Gemini, OpenAI-compatible)
                    │        re-rank / drop / reword rationales
                    │        CANNOT add tasks; failure ⇒ rules-only plan
                    │        ▼
                    └─► AttackPlan  ──►  plan.json  (plan_models.py)
                                 │
                                 ▼
   NEXT MILESTONE          expert agents consume plan.tasks
   (not in this delivery)  keyed by task.expert_route,
                           gated by task.risk_tier
```

One sentence: **recon answers "what does the app look like", the planner
answers "what should we test, in what order, and how dangerous is each
test"** — as a JSON plan your expert agents will consume.

---

## 2. The files

| File | One-line role |
|---|---|
| `agents/planner/__init__.py` | Public API: `AttackPlanner`, `planner_node` |
| `agents/planner/planner.py` | Orchestrator + LangGraph node |
| `agents/planner/models/plan_models.py` | Output contract: `PlanTask`, `AttackPlan` |
| `agents/planner/engine/rule_engine.py` | Deterministic SiteMap → scored tasks |
| `agents/planner/client/llm_client.py` | OpenAI-compatible chat client (httpx) |
| `run_planner.py` | CLI: `sitemap.json → plan.json` |
| `orchestration/graph.py` | `START → recon → planner → END` |
| `tests/test_planner.py` | Rules, LLM mocks, CLI, recon integration |

### 2.1 `agents/planner/models/plan_models.py` — the output contract

Defines what a plan IS. Three models:

- **`PlanTask`** — one attack hypothesis:
  - `id` (`T-001`…), `vuln_class` (7 literals: sqli, xss_reflected,
    jwt_misconfig, auth_bypass, idor, ssrf, open_redirect)
  - `expert_route` — which expert agent should run it (e.g. `sqli_expert`)
  - `endpoint_url` / `method` / `target_params` — where & what to test
  - `signals` — the recon evidence that justified the task (audit trail)
  - `rationale` — one-line human-readable reason
  - `priority` 0–100 + `band` (critical ≥80, high ≥60, medium ≥40, low)
  - `risk_tier` — `safe_probe` (benign GET verification) vs
    `needs_review` (mutating method / SSRF side effects / active bypass)
- **`PlanSummary`** — counts by class / band / risk (dashboarding)
- **`AttackPlan`** — the whole plan + `llm_used`, `llm_model`, `notes`

`band_from_priority()` is the shared band mapping — import it wherever you
re-score tasks so bands stay consistent.

### 2.2 `agents/rule_engine.py` — the deterministic brain

`RuleEngine.generate(sitemap) → list[PlanTask]`, no LLM, no network. Three
rule families:

1. **Per-endpoint parameter rules** (`_endpoint_tasks`): matches each
   `Param` against hint tables (`SQLI_PARAM_HINTS`, `ID_PARAM_HINTS`,
   `OPEN_REDIRECT_HINTS`, `SSRF_PARAM_HINTS`) and observed properties
   (reflected value, numeric/UUID examples) → emits sqli / xss_reflected /
   idor / open_redirect / ssrf tasks. Signals for the same
   `(vuln_class, method, url)` accumulate into ONE task (`_TaskAccum`) —
   that is the dedup mechanism.
2. **Auth-wide rules** (`_auth_tasks`):
   - `token_type == "jwt"` → one `jwt_misconfig` task scored from decoded
     sample claims (privileged claims, PII claims, missing `exp`,
     localStorage storage).
   - `auth_bypass` → one task per protected URL, sources merged from
     `auth.protected_endpoints` ∪ endpoints flagged `auth_required`.
3. **Finalization** (`_finalize`): score, sort, assign sequential IDs.

Scoring model (important for your report/defence):

```
priority = round(100 × impact(vuln_class) × likelihood)
likelihood = 0.30 floor, +0.05..0.30 per signal, capped at 0.95
impact: sqli .95 | jwt .90 | auth_bypass .90 | ssrf .85 | idor .80
        | xss_reflected .55 | open_redirect .50
risk:   auth_bypass & ssrf ⇒ needs_review; any non-GET method ⇒ needs_review
```

Tuning surface: edit the hint tables / `CLASS_IMPACT` / `CLASS_RISK` dicts
at the top — no logic changes needed.

### 2.3 `agents/llm_client.py` — the optional LLM layer

Deliberately dependency-light (httpx, not the `openai` package). Works with
any OpenAI-compatible endpoint; defaults point at Gemini:

```
GEMINI_API_KEY (or LLM_API_KEY / OPENAI_API_KEY)   auth token
LLM_BASE_URL   default https://generativelanguage.googleapis.com/v1beta/openai/
LLM_MODEL      default gemini-2.0-flash
```

`llm_config_from_env()` returns `None` when no key is found → the planner
runs rules-only. `extract_json_object()` tolerates code fences and prose
around the JSON reply.

### 2.4 `agents/planner.py` — the orchestrator + LangGraph node

- `AttackPlanner(config).plan(sitemap)`:
  1. `RuleEngine().generate(sitemap)` → candidates
  2. filter by `min_priority`, cap by `max_tasks`
  3. if an LLM client exists → `_llm_rerank()`; **any** exception appends a
     note and keeps the deterministic plan (LLM can never break planning)
  4. build `AttackPlan` with `PlanSummary` + notes
- `_llm_rerank()` safety contract:
  - sends only a digest (top 30 candidates) + auth summary
  - accepts back `{"tasks":[{"id","keep","priority","rationale"}]}`
  - unknown/hallucinated `id` → ignored; `keep:false` → priority 0 → dropped;
    valid priority → re-scored and re-banded; rationale capped at 400 chars
  - after LLM: tasks re-sorted and re-numbered `T-001…`
- `planner_node(state)` — the LangGraph adapter:
  reads `state["sitemap"]` (+ optional `state["planner_config"]`), returns
  `{"plan": plan.model_dump(), "planner_done": True}`. It imports NOTHING
  from recon — this is why it drops into your graph unchanged.

### 2.5 `run_planner.py` — the CLI

```
python run_planner.py sitemap.json --out plan.json            # auto LLM if key present
python run_planner.py sitemap.json --no-llm                   # rules only
python run_planner.py sitemap.json --max-tasks 20 --min-priority 40
```

Prints a rich table (plain fallback without rich) and the plan notes.
Useful for debugging your integration independently of LangGraph.

### 2.6 `orchestration/graph_snippet.py` — wiring reference (read me)

Shows both integration options:
- **Option A**: you already have a LangGraph graph → 3 edits (import,
  state keys, `add_node` + `recon→planner` edge).
- **Option B**: plain Python call, no LangGraph.

Also documents the state contract and how the future expert stage will
dispatch on `expert_route` / `risk_tier`.

---

## 3. The data contract — what your recon must emit

The rule engine reads exactly these fields (all optional-safe: empty
fields just produce fewer tasks, never errors):

| Field | Used by | If missing |
|---|---|---|
| `SiteMap.target`, `base_url` | plan metadata | plan shows blank target |
| `SiteMap.endpoints[]` | all per-endpoint rules | only auth rules fire |
| `Endpoint.url`, `method` | task identity (dedup key) | — |
| `Endpoint.params[]` | sqli/xss/idor/redirect/ssrf matching | no param tasks |
| `Param.name` | hint-table matching | — |
| `Param.reflected` / `Endpoint.reflected_params` | XSS task + sqli boost | no XSS tasks |
| `Param.examples`, `type_hint` | numeric/UUID boosts | lower likelihood |
| `Endpoint.status_codes` | reachability boost (+0.05) | no boost |
| `Endpoint.auth_required` | auth_bypass source ∪ + idor boost | fewer auth tasks |
| `AuthInfo.token_type == "jwt"` | jwt_misconfig task | no JWT task |
| `AuthInfo.jwt_sample_claims` | claim-based signals | generic JWT task |
| `AuthInfo.token_storage` | localStorage stealability signal | no signal |
| `AuthInfo.login_candidates` | JWT task target URL (`"<METHOD> <url>"`) | falls back to base_url |
| `AuthInfo.protected_endpoints` | auth_bypass tasks | falls back to auth_required endpoints |
| `AuthInfo.authenticated` | comparison signal | no signal |

If your own recon agent emits different field names, the ONLY file you may
need to touch is `rule_engine.py` (or write a small mapper
`your_sitemap → SiteMap` before calling `planner.plan()` — recommended,
keeps the planner stock).

---

## 4. Integration checklist

1. **Copy** `agents/plan_models.py`, `rule_engine.py`, `llm_client.py`,
   `planner.py` into your existing `agents/` package (skip `models.py` —
   it is the recon contract you already have).
2. **Contract check**: your recon output must validate as `SiteMap`
   (`SiteMap.model_validate(your_dict)`) — it does if you use the recon
   from this project.
3. **Wire the node**: apply Option A from `orchestration/graph_snippet.py`
   (3 edits). Or skip LangGraph entirely and call `AttackPlanner` directly.
4. **Optional LLM**: `export GEMINI_API_KEY=...` → planner auto-enables
   re-ranking. `--no-llm` / `use_llm: False` forces rules-only.
5. **Verify**: run the tests (below), then
   `python run_planner.py your_sitemap.json --out plan.json` and inspect
   the table + `plan.notes`.

---

## 5. Running the tests

From this folder's root:

```
python -m unittest tests.test_planner -v        # 20 run + 3 skip here*
```

*In the planner-only folder the 3 recon→planner integration tests skip
(they import `agents.recon_agent`); run the full suite from your main
GateCounsel repo where recon lives — there all 23 pass.

Dependencies: `pydantic`, `httpx` (both already required by recon).
Optional: `rich` (pretty CLI table), `langgraph` (only for Option A).
The LLM layer is tested with mocks — no network, no key needed.

---

## 6. Design guarantees (for your writeup)

- **Deterministic-first**: the plan is always valid with zero LLM/network.
- **LLM is capped**: re-rank/drop/reword only — cannot invent tasks,
  cannot change IDs, cannot exceed the candidate set, cannot break the run.
- **Auditable**: every task carries `signals` (raw recon evidence) and the
  plan records `notes` (what the rules/LLM did) — you can always answer
  "why was this task planned?".
- **Safety-tiered**: `safe_probe` tasks are benign GET probes an exploit
  agent may auto-run; `needs_review` tasks (auth bypass attempts, SSRF,
  any mutating method) queue for human/operator approval.
