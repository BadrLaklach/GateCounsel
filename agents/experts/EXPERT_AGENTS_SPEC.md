# Hackbot — Vulnerability Expert Agents: Build Specification

**Purpose of this document:** a precise, implementation-ready spec for building the
Expert Agents stage of the Hackbot pipeline (spec §6.3 / §8). Hand this file directly
to an AI coding agent as the task brief. It assumes the Recon Agent (`SiteMap` /
`sitemap.json`) and Planner Agent (`AttackPlan` / `plan.json`, with `PlanTask` objects)
already exist and are stable — **do not modify recon or planner code.** This spec
covers only what sits between the Planner's output and the (not-yet-built) Exploit
Agent's input.

---

## 1. Where this component sits

```
Planner Agent ──► plan.json (AttackPlan, list[PlanTask])
                        │
                        ▼
        ┌───────────────────────────────┐
        │   EXPERT AGENTS (this spec)    │
        │   one per vulnerability class   │
        │   input:  one PlanTask          │
        │   output: one ExpertVerdict     │
        │   (reasoning only — NO network   │
        │    calls to the target, ever)   │
        └───────────────┬────────────────┘
                         │ ExpertVerdict (attack plan, not yet executed)
                         ▼
              Exploit Agent (not in this delivery)
```

One sentence: **the Planner answers "what should we test"; the Expert Agent answers
"exactly how would I test it, and what would prove it worked"** — producing a
structured, unexecuted attack plan that a separate Exploit Agent will later carry out.

**Hard constraint, non-negotiable:** Expert Agents never send a request to the target
application and never call sqlmap/nuclei/Playwright/etc. directly. They only reason
over text (the task, retrieved documentation, and the LLM's response) and emit a
structured verdict object. Network execution is exclusively the Exploit Agent's job
(future milestone). This separation is a core architectural guarantee of the whole
Hackbot system — do not blur it for convenience.

---

## 2. Scope — which experts to build

Build experts for all seven classes the Planner already emits (`PlanTask.vuln_class`
literals), so every task the Planner produces has a matching expert:

| `vuln_class` literal | Expert module | Tier |
|---|---|---|
| `sqli` | `sqli_expert.py` | 1 now, Tier 2 candidate later |
| `xss_reflected` | `xss_expert.py` | 1 now, Tier 2 candidate later |
| `idor` | `idor_expert.py` | 1 only |
| `ssrf` | `ssrf_expert.py` | 1 only |
| `open_redirect` | `open_redirect_expert.py` | 1 only |
| `jwt_misconfig` | `jwt_expert.py` | 1 only |
| `auth_bypass` | `auth_bypass_expert.py` | 1 only |

**Build order:** implement `xss_expert.py` first, end-to-end, including its RAG
knowledge base and tests. Only once it passes its own test suite, use it as the
template to build the remaining six — they share the same base class and interface,
differing only in their knowledge base content and a few class-specific hint fields.

---

## 3. Shared input contract (do not redefine — import from planner)

Every expert receives one `PlanTask` (already defined in `agents/plan_models.py` —
import it, do not duplicate it). Relevant fields the expert must read:

```python
PlanTask:
    id: str                      # "T-001"
    vuln_class: str              # one of the 7 literals above
    expert_route: str            # e.g. "xss_expert" — used for dispatch
    endpoint_url: str
    method: str
    target_params: list[str]
    signals: list[str]           # recon evidence, e.g. "param reflected=true"
    rationale: str                # Planner's one-line justification
    priority: int                 # 0-100
    band: str                     # critical/high/medium/low
    risk_tier: str                # "safe_probe" | "needs_review"
```

The expert must **not** re-derive or second-guess `vuln_class` or `risk_tier` — those
are the Planner's job. The expert's job is to go one level deeper on the *how*.

---

## 4. Output contract — define this new model

Create `agents/expert_models.py` with a new pydantic model, `ExpertVerdict`. This is
the contract the (future) Exploit Agent will consume — keep it stable and documented,
the same way `plan_models.py` is documented for the Planner.

```python
class ExpertVerdict(BaseModel):
    task_id: str                       # must match the originating PlanTask.id
    vuln_class: str                    # copied from the PlanTask, not re-decided
    endpoint_url: str
    method: str
    target_param: str                  # the ONE parameter this verdict targets
                                        # (if a task has multiple params, emit
                                        # one ExpertVerdict per param)
    payload: str                       # the exact string/value to send
    payload_encoding: str | None       # e.g. "url", "base64", "none"
    injection_point: str               # "query" | "body" | "header" | "cookie"
    expected_success_signal: str       # plain-language description of what
                                        # the Exploit Agent should look for to
                                        # confirm this worked (e.g. "script
                                        # executes in headless browser",
                                        # "response contains SQL error string",
                                        # "response returns 200 with another
                                        # user's data instead of 403")
    confidence: float                  # 0.0-1.0, the expert's own estimate
    reasoning: str                     # short, human-readable justification
    alternate_payloads: list[str]      # 0-3 fallback payloads if the primary fails
    requires_auth_context: bool        # true if this needs an authenticated session
    tier: str                          # "tier1_rag" | "tier2_finetuned" — which
                                        # model variant produced this verdict
    model_name: str                    # exact model/adapter identifier used
    retrieved_sources: list[str]       # knowledge-base doc IDs/titles used as
                                        # context (audit trail, mirrors the
                                        # Planner's `signals` field)
```

Design rule, same as the Planner: **every verdict must carry its own audit trail**
(`retrieved_sources`, `reasoning`) so "why did the expert suggest this payload?" is
always answerable without re-running anything.

---

## 5. Shared base class — build once, reuse per expert

Create `agents/experts/base_expert.py` with a `BaseExpert` class that every
per-class expert subclasses. This is where almost all the real logic lives —
subclasses should be small.

```python
class BaseExpert:
    vuln_class: str                 # set by subclass
    knowledge_base_path: str        # set by subclass, e.g. "knowledge/xss/"

    def __init__(self, llm_client, retriever, lora_adapter_path: str | None = None):
        ...

    def retrieve_context(self, task: PlanTask) -> list[RetrievedChunk]:
        """Query the vuln-class knowledge base using task.signals + task.rationale
        as the search query. Return top-k (k=3 default) chunks."""

    def build_prompt(self, task: PlanTask, context: list[RetrievedChunk]) -> str:
        """Assemble system prompt + retrieved context + task details into the
        final LLM prompt. MUST instruct the model to return ONLY a JSON object
        matching ExpertVerdict's schema — no prose, no markdown fences."""

    def call_model(self, prompt: str) -> str:
        """Send to the LLM (Tier 1: base model + prompt; Tier 2: base model +
        LoRA adapter loaded if self.lora_adapter_path is set). Reuse the
        existing `agents/llm_client.py` pattern from the Planner (same
        OpenAI-compatible httpx client) rather than writing a new one — add a
        local-inference branch (Ollama/local HF model) alongside it, since
        Tier 2 experts run on a self-hosted fine-tuned model, not a hosted API."""

    def parse_response(self, raw: str, task: PlanTask) -> ExpertVerdict:
        """Parse + validate the model's JSON reply into ExpertVerdict. Must be
        at least as tolerant as the Planner's `extract_json_object()` (handles
        code fences / stray prose). On parse failure: retry once with a
        stricter 'return ONLY valid JSON' reminder; on second failure, return
        a verdict with confidence=0.0 and reasoning explaining the parse
        failure — NEVER raise an unhandled exception out of this stage."""

    def run(self, task: PlanTask) -> list[ExpertVerdict]:
        """Full pipeline for one task: retrieve -> prompt -> call -> parse.
        Returns one ExpertVerdict per target_param in task.target_params."""
```

**Per-class subclasses only need to provide:**
- `vuln_class` and `knowledge_base_path`.
- A short, class-specific system-prompt fragment (how this vulnerability class is
  reasoned about, written once per class).
- Any class-specific hint logic worth adding on top of retrieval (optional — keep
  this thin; most specialization should live in the knowledge base content, not in
  branching code).

---

## 6. The RAG knowledge base — build this before any expert logic

For each vulnerability class, create `knowledge/<vuln_class>/` containing small,
focused Markdown or JSON chunks, one technique/context per file. Minimum content
per class (expand over time, this is the floor, not the ceiling):

- **xss_reflected:** reflected-in-HTML-body bypasses, reflected-in-attribute
  bypasses, reflected-in-`<script>`-context bypasses, common filter-evasion
  techniques, encoding tricks (derived from PortSwigger's XSS Academy labs).
- **sqli:** error-based, blind boolean-based, blind time-based, UNION-based
  techniques, common WAF-bypass encodings (derived from PortSwigger's SQLi labs).
- **ssrf:** basic SSRF, bypassing allow-lists (DNS rebinding, redirect chains,
  decimal/octal IP encoding), cloud-metadata-endpoint targeting.
- **idor:** horizontal vs. vertical access-control bypass patterns, common ID
  obfuscation bypass techniques (sequential IDs, UUIDs, encoded IDs).
- **open_redirect:** common redirect-parameter bypass techniques, protocol-relative
  URL tricks, encoding-based filter evasion.
- **jwt_misconfig:** `alg:none` attack, weak-secret brute-forceability, `kid`
  header injection, missing signature verification patterns.
- **auth_bypass:** common auth-bypass patterns (direct object access, parameter
  tampering on auth state, forced browsing).

**Each chunk file should be short** (one technique, 100-300 words) so retrieval
returns precise, relevant context rather than entire lab write-ups. Store alongside
each chunk a short title and source attribution (e.g. `source: PortSwigger XSS
Academy — reflected XSS into attribute`) — this becomes the `retrieved_sources`
field in the output.

**Ingestion:** write `rag/ingest.py` (or extend the Planner's, if one already exists)
to embed and load these chunks into ChromaDB, one collection per vuln class
(`chroma_collection = f"knowledge_{vuln_class}"`), so retrieval queries stay scoped
to the right expert's domain and never leak cross-class context.

---

## 7. Model configuration — Tier 1 vs Tier 2

**Tier 1 (build this first, for all seven classes):**
- Single shared open-weight base model (e.g. `Qwen2.5-7B-Instruct` or similar —
  confirm exact model with the project owner before hardcoding), accessed via the
  existing `llm_client.py` pattern (Groq free tier for dev, Ollama local as
  fallback — both OpenAI-compatible, same client code).
- No fine-tuning. Specialization comes entirely from the system prompt + RAG
  context per class.
- `tier` field in `ExpertVerdict` = `"tier1_rag"`.

**Tier 2 (stretch goal, XSS and SQLi only, build only after Tier 1 is fully
working and tested for all seven classes):**
- A LoRA adapter fine-tuned per class, trained **outside** this codebase (separate
  offline training scripts, not part of this delivery — see `finetuning/` in the
  main project structure).
- `BaseExpert` must accept an optional `lora_adapter_path`; when set, `call_model()`
  loads the base model + adapter locally (e.g. via `transformers` + `peft`, or
  Unsloth's inference path) instead of calling the hosted API.
- `tier` field = `"tier2_finetuned"` when an adapter is active.
- **Do not block Tier 1 completion on Tier 2 readiness.** The system must be fully
  functional and demoable with Tier 1 alone.

---

## 8. Prompt template (shared skeleton — fill in class-specific pieces)

```
SYSTEM:
You are a specialist security researcher focused exclusively on {vuln_class}
vulnerabilities. You reason carefully about a single endpoint/parameter and
produce ONE precise, testable attack plan. You never guess broadly — you use
the provided reference material and the recon evidence given to you.

Output ONLY a single JSON object matching this exact schema, with no prose,
no markdown code fences, no explanation outside the JSON:
{ExpertVerdict JSON schema, pasted explicitly}

REFERENCE MATERIAL (retrieved for this specific case):
{top-k retrieved chunks, each with its source title}

TASK:
Endpoint: {method} {endpoint_url}
Target parameter(s): {target_params}
Recon evidence: {signals}
Planner's rationale: {rationale}

Produce your attack plan now.
```

Keep this skeleton identical across all seven experts — only the system-prompt's
first paragraph (what this class is, how to reason about it) should differ,
and that difference should live in each subclass, not be duplicated per call.

---

## 9. File structure to produce

```
agents/
├── expert_models.py              # ExpertVerdict (new, this spec)
└── experts/
    ├── base_expert.py            # BaseExpert (new, this spec)
    ├── xss_expert.py             # build + test first
    ├── sqli_expert.py
    ├── idor_expert.py
    ├── ssrf_expert.py
    ├── open_redirect_expert.py
    ├── jwt_expert.py
    ├── auth_bypass_expert.py
    └── dispatch.py                # maps PlanTask.expert_route -> expert instance
knowledge/
    ├── xss_reflected/*.md
    ├── sqli/*.md
    ├── ssrf/*.md
    ├── idor/*.md
    ├── open_redirect/*.md
    ├── jwt_misconfig/*.md
    └── auth_bypass/*.md
rag/
    ├── ingest.py                  # extend or reuse if planner already has one
    └── retriever.py               # per-class ChromaDB query helper
orchestration/
    └── experts_node.py            # LangGraph node: consumes state["plan"],
                                     # dispatches each task to its expert via
                                     # dispatch.py, returns state["verdicts"]
tests/
    └── test_experts.py            # see §11
```

---

## 10. LangGraph integration (`experts_node.py`)

```python
def experts_node(state: dict) -> dict:
    """Reads state['plan'] (AttackPlan from the Planner), dispatches each
    PlanTask to its matching expert via dispatch.py, collects all
    ExpertVerdicts, returns {'verdicts': [...], 'experts_done': True}.
    Imports NOTHING from recon — mirrors planner_node's isolation pattern.
    A failure in ONE expert (bad LLM response, retrieval error) must be
    caught and logged per-task; it must never abort the whole batch."""
```

Wire it as `planner -> experts -> END` (until the Exploit Agent exists), following
the same pattern already used in `graph.py` for `recon -> planner`.

---

## 11. Required tests (`tests/test_experts.py`)

Mirror the Planner's testing discipline (23 tests, no network calls, LLM mocked):

- Each expert's `retrieve_context()` returns non-empty results for a task with
  clear signals (e.g. `reflected=true` for XSS).
- `build_prompt()` output contains the task's endpoint, params, and retrieved
  source titles.
- `parse_response()` correctly parses a well-formed JSON reply.
- `parse_response()` handles a reply wrapped in markdown code fences.
- `parse_response()` returns a `confidence=0.0` verdict (not an exception) on
  unparseable input.
- `run()` produces exactly one `ExpertVerdict` per `target_param`.
- `dispatch.py` correctly routes each of the 7 `expert_route` values to the
  right expert class.
- `experts_node()` processes a multi-task plan and continues past a single
  failed task rather than aborting.
- Integration test (skippable without a live LLM key, same pattern as planner's
  `--no-llm` option): run the full pipeline against a tiny fixture `plan.json`
  with 2-3 tasks and assert the shape of `state["verdicts"]`.

---

## 12. Design guarantees to preserve (for the project write-up)

- **No direct network access from any expert.** Verified by: experts' test suite
  mocks the LLM client only — there is no HTTP client import in any expert module
  pointed at anything other than the configured LLM endpoint.
- **Per-class knowledge isolation.** XSS retrieval must never return SQLi chunks
  and vice versa — enforced by separate ChromaDB collections per class.
- **Graceful degradation.** A single bad LLM response or a single bad task must
  degrade to a low-confidence verdict, never crash the batch.
- **Full audit trail.** Every verdict traces back to the retrieved sources and
  reasoning that produced it — no verdict should be unexplainable after the fact.
- **Tier 1 always works standalone.** Tier 2 (LoRA) is strictly additive; removing
  all adapters must leave a fully functional Tier 1 system.

---

## 13. Explicit non-goals for this delivery

- Do **not** implement the Exploit Agent, Scope Guard, or any tool wrapper
  (sqlmap/nuclei/Playwright) — those are separate milestones.
- Do **not** train any LoRA adapter as part of this task — Tier 2 wiring (the
  `lora_adapter_path` plumbing) should exist, but no actual training run is in
  scope here.
- Do **not** modify `agents/plan_models.py`, `rule_engine.py`, `planner.py`, or
  anything in the recon package — this delivery only adds new files.
