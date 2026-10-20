# GateCounsel — Full Project Roadmap

## 1. Project definition

### Proposed title

**GateCounsel: An Agentic DevSecOps Platform for Continuous, Scope-Constrained Web Application Security Testing**

### Core objective

Build and evaluate a system that deploys a sanctioned web application into an isolated environment, maps its attack surface, selects relevant web-security tests through vulnerability-specialized agents, executes only approved tests through deterministic tooling, verifies the evidence, and feeds the result back into the CI/CD delivery process.

This is not an unrestricted hacking tool. It is a **continuous application-security verifier for controlled lab environments**. Its contribution is the combination of:

- DevOps: reproducible environments, CI/CD, versioned policies, test artifacts, and deployment gates.
- Agentic AI: stateful orchestration, specialist reasoning, retrieval, and structured outputs.
- Cybersecurity: web vulnerability testing, evidence validation, secure reporting, and hard scope control.

### Research questions

1. Does routing a test task to a vulnerability-class specialist improve the useful finding rate over one generalist agent?
2. Does retrieval from curated OWASP/PortSwigger material improve plan quality over prompting alone?
3. Can a deterministic scope and policy layer safely integrate agent-led testing into a CI/CD workflow?
4. Can change-aware planning reduce testing time without reducing coverage of known benchmark cases?

## 2. Architecture to implement

The design should have three layers. Keep the boundaries explicit in code and in the thesis.

```text
                     Control plane
Developer / CI -> Run API -> Orchestrator -> Policy gate -> CI result
                                  |
                     Testing plane
                                  v
 Recon -> Planner -> Expert Agents -> Exploit Agent -> Verifier -> Findings
             |                           |                         |
             |                           v                         +--> Policy gate
             |                 fixed operation allowlist                       |
             |                           |                              GateDecision
             |                           v                                   |
             +-----------------> RequestBroker / Scope Guard                  v
                                         |                             Report Agent
                                         v                                   |
                              constrained tool wrappers                     v
                                         |                           report.json / .md
                                         v
                                    Lab target

                     Platform plane
       Docker Compose - isolated networks - CI workflow - artifacts - logs
```

### Non-negotiable rule

Models have no direct tool or target-network capability. They may return only constrained, typed data for a defined stage, such as `ReconSuggestion`, `PlannerReview`, or `ExpertVerdict`. Provider API calls are made only by an audited `ModelClient` over a separately controlled model-service path; they are not target requests. Every target-bound request must use the `RequestBroker`, which invokes the Scope Guard immediately before action.

This avoids the central architectural weakness in the original diagram: placing the Scope Guard only as a graph node is insufficient if a tool wrapper can call the network directly.

### Execution sequence

1. A developer, operator, or CI workflow creates a run with a versioned `ScopePolicy`.
2. The environment manager starts the sanctioned demo target and lab-only SSRF sentinel on an isolated Docker network, then waits for health checks. Target-side SSRF is restricted to the sentinel; public egress is denied.
3. Recon creates a typed site map using bounded deterministic discovery. It may also request constrained AI path suggestions from a sanitized structural inventory; every accepted target path still goes through the request broker.
4. Deterministic planner rules generate candidate `TestTask` objects from the site map. AI may review only those known candidates and adjust ranking or rationale within policy bounds.
5. The matching class-specific expert for reflected XSS, IDOR, SQLi, SSRF, or open redirect receives only the task, sanitized recon/auth context, and retrieved knowledge. It returns an `ExpertVerdict` per target parameter, including a proposed test input, placement, expected success signal, reasoning, and source audit fields; it has no tool access.
6. The Exploit Agent validates the verdict against the originating task and fixed harmless test allowlist, then selects only a fixed class-specific operation. A controlled executor asks the RequestBroker and Scope Guard for permission before every request or browser navigation, then calls the approved wrapper.
7. The verifier evaluates raw evidence against class-specific success criteria and emits `confirmed`, `rejected`, or `inconclusive`.
8. The deterministic policy gate evaluates verified findings. The Report Agent then creates canonical JSON and renders Markdown/HTML from verified findings, evidence references, run metadata, and the gate decision. It cannot invent findings or alter verdicts.
9. CI receives the separate deterministic gate result: `pass`, `warn`, `manual_review`, or `fail`.
10. The workflow uploads the evidence as artifacts and destroys the temporary environment.

## 3. Shared data contracts

Create Pydantic models before agents or tools. These are the real interfaces of the system.

| Contract | Required purpose |
|---|---|
| `ScopePolicy` | Allowed schemes, hosts, resolved CIDRs, ports, methods, run expiry, maximum requests, redirect rule, and authorization record. |
| `RunRequest` / `RunMetadata` | Run ID, commit SHA, requester, timestamps, target profile, provider/model and prompt versions, AI mode, fallback state. |
| `Endpoint` / `SiteMap` | URL template, method, parameters, auth state, source of discovery, technology hints. |
| `TestTask` | Endpoint, vulnerability class, priority, change-impact reason, and required auth context. |
| `AttackPlan` | Planner output containing the validated vulnerability-class task candidates. |
| `ExpertVerdict` | One typed, unexecuted expert proposal per task parameter: target location, proposed payload/encoding, injection point, expected success signal, confidence, reasoning, alternatives, auth requirement, model tier/name, and retrieved-source audit trail. No arbitrary command or network capability. |
| `ExecutionRequest` | Finite, allowlisted operation selected by the Exploit Agent for the controlled executor. |
| `Evidence` / `Finding` | Sanitized observation and verifier-produced result, including evidence references and remediation. |
| `GateDecision` | Deterministic CI result, rule ID, affected findings, and exit code. |
| `ReportPackage` | Canonical sanitized JSON and rendered Markdown/HTML from verified findings, run context, and gate decision. |

Persist each contract as JSON per run. This makes the workflow auditable, testable, and easy to evaluate later.

## 4. Repository layout

```text
gatecounsel/
├── apps/
│   ├── api/                       # FastAPI control plane
│   └── dashboard/                 # React UI; add after the API is stable
├── core/
│   ├── models.py                  # Pydantic contracts
│   ├── config.py
│   ├── logging.py
│   └── errors.py
├── orchestration/
│   ├── graph.py                   # LangGraph state graph
│   ├── state.py
│   └── run_service.py
├── agents/
│   ├── recon.py
│   ├── planner.py
│   ├── exploit_agent.py           # fixed operation dispatch, no arbitrary tools
│   ├── report_agent.py            # verified findings to report package
│   └── experts/
├── execution/
│   ├── request_broker.py          # only outbound network gateway
│   ├── executor.py
│   ├── verifier.py
│   └── wrappers/
├── safety/
│   ├── scope_guard.py
│   ├── policy_gate.py
│   └── redaction.py
├── rag/
│   ├── sources/                   # reviewed, licensed source material
│   ├── ingest.py
│   └── retriever.py
├── reports/
│   ├── renderers/
│   └── schemas/
├── lab/
│   ├── compose.yaml
│   ├── target-profiles/
│   └── demo-target/
├── evaluation/
│   ├── ground_truth/
│   ├── baselines/
│   └── run_evaluation.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── safety/
│   └── e2e/
├── .github/workflows/
├── docs/
└── pyproject.toml
```

## 5. Technology decisions

Pin every dependency in a lock file and record tested versions in `docs/technology-decisions.md`; do not rely on an unpinned “latest”.

| Concern | Recommendation | How it is used |
|---|---|---|
| Runtime | Python with `pyproject.toml`, a virtual environment, `pytest`, and Ruff | Core services, agents, tool wrappers, tests, formatting/linting. |
| Typed contracts | Pydantic | Validate all agent output and API input before it reaches another component. |
| Orchestration | LangGraph | Implement a small explicit state graph with retries, checkpoints, and terminal states. |
| HTTP/API | FastAPI | Expose run creation, status, reports, and health endpoints. Do not run long scans in a request handler. |
| Browser automation | Playwright for Python | Recon, authenticated navigation, screenshots, and browser-based confirmation. Use one isolated context per run. |
| Retrieval | Chroma locally plus a local embedding model | Store reviewed documents with class, source, version, and license metadata. |
| Model provider | Provider interface; local model runtime for the demo, optional hosted provider for development | Require JSON-schema-compatible structured output. Keep prompts and model IDs versioned. |
| Lab/infrastructure | Docker Compose Specification | Define targets, GateCounsel, storage, and isolated networks as code. |
| CI/CD | GitHub Actions | Build, test, start the lab, run safe end-to-end tests, upload reports, and clean up. |
| Security reporting | JSON + Markdown/HTML; SARIF as a later integration | JSON is the source of truth; human reports and CI annotations are generated from it. |

Use Docker Compose, not Kubernetes, for the core thesis. Kubernetes adds operations work without strengthening the central research question. Treat it as future work.

## 6. Full implementation roadmap

### Phase 0 — Governance, scope, and thesis protocol

**Deliverables:** `docs/scope.md`, `docs/threat-model.md`, `docs/research-protocol.md`, `lab/target-profiles/`.

1. Define sanctioned targets and explicitly prohibit external, production, or third-party targets.
2. Define the maximum test intensity: request budget, concurrency, timeout, body-size limit, ports, and methods.
3. Decide which data may appear in reports. Redact cookies, tokens, passwords, authorization headers, and personal data by default.
4. Write the ground truth for every benchmark case before implementation. A benchmark case needs an ID, target version, endpoint, class, expected verdict, and safe evidence criterion.
5. Obtain institution/supervisor approval for the isolated lab and document it.

**Exit condition:** the project can demonstrate precisely what it is authorized to test and how it will measure correctness.

### Phase 1 — Repository foundation and development standards

**Deliverables:** Python project, pre-commit hooks, test command, CI lint/test workflow, decision log.

1. Initialize Git, `.gitignore`, `pyproject.toml`, and an `.env.example` with no secrets.
2. Add unit-test, lint, format, and type-check commands. Run them in CI from the first day.
3. Add structured JSON logging with `run_id`, `component`, `event`, and timestamp fields.
4. Create the Pydantic contracts listed above and unit-test validation failures.
5. Add a `Makefile` or PowerShell task script for common commands such as test, lab-up, lab-down, and run-demo.

**Exit condition:** a clean clone can create an environment, run unit tests, and start a placeholder service using documented commands.

### Phase 2 — Reproducible laboratory

**Deliverables:** `lab/compose.yaml`, target profile, health checks, seed data, reset procedure.

1. Start with one custom deliberately vulnerable demo target because it provides stable ground truth.
2. Add OWASP Juice Shop later as a realistic integration target, not as the only benchmark source.
3. Put GateCounsel and the target on a private Compose network. Expose ports to the host only for local development.
4. Add health checks and a reset/seed command so every test run begins from a known state.
5. Confirm that the executor container cannot reach the public internet; use network design and an egress-blocking rule where available.

**Exit condition:** `docker compose up` starts a reproducible target; `docker compose down -v` returns it to a clean state.

### Phase 3 — Scope Guard and request broker

**Deliverables:** `ScopeGuard`, `RequestBroker`, audit log, adversarial safety tests.

1. Parse and canonicalize every requested URL.
2. Allow only the run-specific scheme, hostname, resolved address range, port, and path constraints from `ScopePolicy`.
3. Re-check redirects and DNS resolution before each resulting request. Reject unexpected protocols, private metadata endpoints, and encoded host tricks.
4. Enforce request/time/concurrency budgets and stop a run when it expires.
5. Ensure Playwright navigation and direct HTTP wrappers use the same broker policy.
6. Unit-test allowed requests, blocked hosts, redirects, malformed URLs, expired policies, and request-budget exhaustion.

**Exit condition:** no execution wrapper can make an outbound request without an auditable Scope Guard decision.

### Phase 4 — Bounded recon and evidence capture

**Deliverables:** `SiteMap` JSON, screenshots/HAR references, endpoint-discovery tests, bounded AI path suggestions with deterministic fallback.

1. Build a deterministic bounded crawler: start URL, depth limit, page limit, same-origin only, and allowed navigation methods.
2. Capture forms, query parameters, links, known API calls, cookies/auth state names, and technology hints.
3. Use Playwright request/response events to observe JavaScript-driven routes and APIs.
4. Store only sanitized metadata; secrets are redacted before persistence.
5. Optionally ask AI for up to eight additional relative GET paths from a sanitized structural inventory. Validate each path and fetch it only through the Scope Guard and request broker. Never send credentials, parameter values, raw response bodies, or personal data.
6. Add fixtures from the demo target to test discovery deterministically, including malformed/out-of-scope model suggestions and deterministic fallback.

**Exit condition:** deterministic recon produces the expected typed site map for a known target version; AI suggestions are bounded, validated, and safely optional.

### Phase 5 — Planner, experts, and structured outputs

**Deliverables:** planner rules, expert interface, prompt registry, invalid-output handling.

1. Implement deterministic task-generation rules for the five MVP classes: reflected input for XSS, object ownership context for IDOR, known database-backed input for SQLi, a controlled server-side URL-fetch input for SSRF, and a redirect destination parameter for open redirect.
2. Define a common `Expert` interface: `run(task, recon_context, retrieved_context) -> list[ExpertVerdict]`, with one verdict per target parameter.
3. Add one shared `ModelClient` provider interface and a deterministic fake provider. For the MVP, use it for bounded recon suggestions, planner review, and Tier 1 expert calls for all five MVP classes.
4. Validate every model response with strict typed schemas and field/count limits. Invalid, unsafe, unknown, or out-of-scope output is rejected; expert failures result in no execution, while recon/planning retain their deterministic fallback. Never repair a response by executing raw text.
5. Record provider/model name, prompt/schema version, retrieval IDs where applicable, AI mode, fallback state, and output-validation result in run metadata without secrets or sensitive prompts.

**Exit condition:** the graph can route tasks to experts and safely handle valid, invalid, and unavailable-model responses.

### Phase 6 — Tool wrappers, verification, and first vulnerability classes

**Deliverables:** bounded Exploit Agent, class-specific deterministic wrappers and verifiers for reflected XSS, IDOR, SQLi, SSRF, and open redirect, including a lab-only SSRF sentinel.

1. Implement the Exploit Agent as a dispatcher over a finite operation allowlist, then implement one wrapper and verifier at a time. A wrapper accepts a validated execution request; it does not accept model-generated shell commands.
2. Define success criteria per class before coding. A response error alone is not confirmation.
3. Capture reproducible evidence: sanitized request/response metadata, browser screenshot or trace, timing result where relevant, target and tool versions.
4. Implement the verdict triad: `confirmed`, `rejected`, `inconclusive`.
5. Add a manual-review queue for inconclusive findings.

**Exit condition:** each selected class has at least several known positive and negative lab cases with reproducible evidence.

### Phase 7 — Expand and evaluate the RAG knowledge base

**Deliverables:** source manifest, ingestion job, retrieval tests, cited expert output.

The MVP starts with a small reviewed local collection for each of its five class-specific expert profiles. This phase establishes provenance and evaluation for those collections, then expands the corpus after the five-class safety and evidence pipeline is stable.

1. Curate only materials you may store and use: OWASP resources, public guidance, and your own summaries. Record source URL, version/date, license, vulnerability class, and checksum.
2. Chunk documents by concept, not arbitrary large blocks. Preserve title, section, class, and source metadata.
3. Use metadata filtering so an IDOR expert does not receive irrelevant SQLi content.
4. Test retrieval independently with a small question set before connecting it to agents.
5. Include retrieved source identifiers in each `ExpertVerdict` and final report.

**Exit condition:** retrieval returns relevant, traceable material for benchmark questions and does not expose raw unreviewed web content to the agent.

### Phase 8 — Reporting and DevSecOps feedback

**Deliverables:** Report Agent, finding JSON schema, Markdown/HTML report, CI summary, initial SARIF exporter.

1. Make verifier-produced `Finding` JSON the canonical record. The Report Agent renders all other formats from that record plus run metadata and the gate result.
2. Include run/commit ID, target profile, scope-policy ID, verdict, evidence, remediation, confidence, and ASVS reference.
3. Use a deterministic severity rubric initially; label any LLM severity suggestions as recommendations and never let the Report Agent alter verified severity or verdicts.
4. Upload reports, sanitized logs, screenshots, and test results as CI artifacts.
5. Add SARIF only after the JSON model is stable. It can surface compatible findings in GitHub code-scanning views, but do not depend on it for the core demo.

**Exit condition:** a CI run produces one auditable report package that a developer can understand without reading agent logs.

### Phase 9 — CI/CD and policy gate

**Deliverables:** GitHub Actions workflow, environment lifecycle, gate tests, artifacts.

1. Begin with `workflow_dispatch` and a scheduled run; add pull-request checks after the lab is reliable.
2. In CI, build images, start Compose, wait for health checks, run only the in-container target profile, collect artifacts, and always tear down with an `always` cleanup step.
3. Gate only on confirmed findings with adequate evidence. Use `warn` mode before enabling `fail` mode.
4. Store the policy as versioned YAML and test it as code.
5. Add change-aware prioritization later: map changed files or service labels to vulnerability classes, but retain a periodic full scan.

**Exit condition:** a sanctioned CI run has no dependency on a developer laptop and returns a transparent pass/warn/fail decision.

### Phase 10 — API and dashboard

**Deliverables:** FastAPI endpoints, run status, report download, optional React dashboard.

1. Implement API endpoints for creating a permitted run, listing runs, viewing status, and downloading reports.
2. Use a durable job mechanism for long runs; FastAPI background tasks are acceptable only for the small MVP, not for a restart-safe worker architecture.
3. Add authentication if the API is exposed beyond local use.
4. Build the dashboard last. It should visualize run state, scope decisions, findings, and artifacts; it must not be required to start a run.

**Exit condition:** API and UI are thin control/visibility layers over tested core services.

### Phase 11 — Evaluation and dissertation evidence

**Deliverables:** frozen benchmark set, experiment scripts, metrics tables, reproducibility package.

1. Freeze target image versions, benchmark cases, prompts, model IDs, RAG source manifest, and policies for each experiment.
2. Compare at least a generalist baseline and a specialized-agent configuration on identical cases.
3. Report precision, recall, false-positive rate, false-negative rate, confirmation rate, run time, tool actions, and scope violations blocked.
4. Repeat runs where LLM variability matters and report variance.
5. Separate claims supported by measurements from qualitative observations.

**Exit condition:** another student can reproduce the evaluation using the documented lab images, configuration, and scripts.

### Phase 12 — Stretch goals only

- LoRA/QLoRA comparison for one class after the RAG baseline is working.
- Additional classes: CSRF and authentication/JWT.
- Change-aware test prioritization from Git diffs.
- React dashboard polish, notifications, and issue-tracker integration.
- A second external lab target such as Juice Shop or WebGoat.

## 7. Testing strategy

| Test level | What to test |
|---|---|
| Unit | URL canonicalization, policy rules, redaction, schema validation, report rendering, ranking. |
| Contract | Each agent and wrapper accepts/returns the shared Pydantic models. |
| Integration | Request broker with a Compose target; recon; RAG retrieval; executor/verifier pairs. |
| End-to-end | Full run against a reset lab and expected final report/gate outcome. |
| Safety | Forbidden host, redirect, invalid scheme, expired scope, tool bypass attempt, request budget, secret redaction. |
| Regression | A fixed benchmark set runs in CI on every relevant change. |

## 8. Risks and controls

| Risk | Design control |
|---|---|
| Scope bypass | One request broker, URL/DNS/redirect validation, isolated network, and adversarial tests. |
| False positives | Evidence-based verifier and an `inconclusive` state; do not gate on unconfirmed agent opinions. |
| LLM instability | Typed output, deterministic fallbacks, prompt/model versioning, and baseline measurements. |
| Too much scope | Three classes and one lab target are the core; all other components are staged extensions. |
| Secret leakage | Redaction before logs/reports/artifacts; never commit `.env` or test credentials. |
| Non-reproducible results | Pinned images/dependencies, seed data, target profiles, and experiment manifests. |
| CI false failures | Health checks, bounded timeouts, artifact collection, and always-run cleanup. |

## 9. Things to pay special attention to

1. **Safety is a code property, not a prompt.** Validate it at the actual network boundary.
2. **Do not confuse a plan with a finding.** An AI proposal needs deterministic evidence before it is reported as confirmed.
3. **Use a custom lab for ground truth.** Public training applications are excellent demos but not always stable experimental benchmarks.
4. **Avoid arbitrary model-generated commands and payload execution.** Translate a validated plan into narrowly defined wrapper operations.
5. **Treat RAG as a dataset.** Keep provenance, versions, metadata, and evaluation questions.
6. **Keep the CI gate conservative.** Begin in audit/warn mode and gate only confirmed, high-confidence, evidence-backed results.
7. **Do not build a dashboard first.** The invisible contracts, safety layer, lab, and tests are the project.
8. **Fine-tuning is not required for a successful thesis.** A rigorous RAG-versus-generalist evaluation is already a meaningful contribution.

## 10. Authoritative learning resources

- LangGraph overview and concepts: <https://langchain-ai.github.io/langgraph/>
- FastAPI documentation: <https://fastapi.tiangolo.com/>
- Pydantic documentation: <https://docs.pydantic.dev/>
- Playwright for Python: <https://playwright.dev/python/docs/intro>
- Docker Compose Specification: <https://docs.docker.com/reference/compose-file/>
- GitHub Actions documentation: <https://docs.github.com/en/actions>
- GitHub workflow artifacts: <https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts>
- GitHub SARIF integration: <https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file>
- Chroma documentation: <https://docs.trychroma.com/>
- OWASP Juice Shop: <https://owasp.org/www-project-juice-shop/>
- OWASP ASVS: <https://owasp.org/www-project-application-security-verification-standard/>

## 11. Final full-project definition of done

The project is complete when a clean CI job can start a controlled lab target, run GateCounsel under a recorded scope policy, generate a typed site map and specialist tasks, route approved tests through the bounded Exploit Agent, verify selected findings with sanitized evidence, have the Report Agent publish a reproducible package from verified results, return a deterministic policy decision, clean up its environment, and produce evaluation data comparing at least one specialist configuration against a baseline.
