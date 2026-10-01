# Hackbot MVP Roadmap — Fast, Safe, End-to-End

## 1. MVP objective

In the shortest practical time, build a demonstrable DevSecOps pipeline that tests one deliberately vulnerable application inside Docker, blocks all out-of-scope traffic, runs two specialized testing paths, confirms evidence, writes a report, and returns a CI-friendly decision.

The MVP proves the architecture. It does **not** need a full dashboard, six vulnerability classes, a large RAG corpus, fine-tuning, or public-target scanning.

## 2. Fixed MVP scope

| Area | MVP decision |
|---|---|
| Target | One custom deliberately vulnerable demo application in Docker. OWASP Juice Shop is optional only after the MVP passes. |
| Classes | XSS and IDOR. Add SQL injection only after both are reliably end-to-end. |
| Agent logic | Rule-based planner plus two specialist components with typed output. One local/optional LLM adapter may enrich explanations but cannot execute tools. |
| Recon | Bounded same-origin browser crawl of known routes/forms/API calls. |
| Execution | One Python/Playwright executor behind one request broker. |
| Safety | Docker private network, explicit `ScopePolicy`, request/timeout budget, redirect validation, audit log. |
| Output | JSON finding file, Markdown report, screenshots/logs as artifacts. |
| DevOps | Docker Compose plus a GitHub Actions workflow that starts, tests, collects artifacts, and destroys the lab. |
| UI | No dashboard. Use FastAPI OpenAPI docs or a CLI command. |
| RAG/fine-tuning | Deferred. Use a small, reviewed local guidance file only if needed. |

## 3. MVP architecture

```text
GitHub Actions / local command
             │
             ▼
      Docker Compose starts
      demo-target + hackbot
             │
             ▼
 ScopePolicy → RequestBroker → Recon → RulePlanner
                                      ├─ XSS specialist
                                      └─ IDOR specialist
                                              │
                                              ▼
                                    Executor → Verifier
                                              │
                                              ▼
                               JSON + Markdown report + gate result
             │
             ▼
       collect artifacts and remove containers
```

## 4. MVP repository layout

```text
hackbot/
├── app/
│   ├── models.py
│   ├── scope_guard.py
│   ├── request_broker.py
│   ├── recon.py
│   ├── planner.py
│   ├── experts.py
│   ├── executor.py
│   ├── verifier.py
│   ├── reporter.py
│   └── cli.py
├── demo-target/
│   ├── Dockerfile
│   ├── app/                       # intentionally vulnerable, documented lab only
│   └── ground_truth.json
├── lab/
│   ├── compose.yaml
│   └── scope-policy.yaml
├── tests/
│   ├── unit/
│   ├── safety/
│   └── e2e/
├── artifacts/                     # ignored by Git
├── .github/workflows/mvp.yml
├── docs/
├── pyproject.toml
└── README.md
```

## 5. The two-person work split

Both people review contracts together before coding. Keep all integration through Pydantic models, never through informal dictionaries.

| Owner | Primary responsibility | First integration hand-off |
|---|---|---|
| Person A | Docker lab, custom demo target, Scope Guard, request broker, CI workflow, safety tests | Working `ScopePolicy` and a reachable in-network target. |
| Person B | Pydantic models, recon, rule planner, specialists, executor/verifier, report renderer | A `SiteMap` fixture and sample `Finding` JSON. |
| Both | Contract review, end-to-end test, report wording, demo, benchmark labels | A successful `run-demo` command and CI artifact. |

Do not divide the project into two separate applications. Integrate every two or three days.

## 6. Implementation plan — ten working days

### Day 1 — Agree the contracts and safety rules

Create these models first:

- `ScopePolicy`
- `Endpoint` and `SiteMap`
- `TestTask`
- `AttackPlan`
- `Evidence`
- `Finding`
- `GateDecision`

Write `docs/mvp-scope.md` stating:

- only the Compose service hostname is allowed;
- no public IPs, external DNS names, or production targets;
- the run has a small request/depth/time budget;
- test evidence and logs are sanitized;
- the target is intentionally vulnerable and locally owned.

**Done when:** invalid schemas fail unit tests and the scope document is accepted by both teammates.

### Day 2 — Build the laboratory

Person A creates `lab/compose.yaml` with:

- `demo-target` service;
- `hackbot` service;
- one internal network;
- a target health check;
- no external target required;
- an output volume for sanitized artifacts.

Person B creates the project shell, CLI skeleton, test setup, and sample data contracts.

The demo target must include two seeded, documented cases:

- one reflected-input scenario for the XSS path;
- one object-ownership scenario for the IDOR path.

Record expected safe evidence criteria in `demo-target/ground_truth.json`; do not rely on memory.

**Done when:** Compose starts the target, health checks pass, and the Hackbot container can resolve only the Compose target name.

### Day 3 — Make scope enforcement real

Implement `ScopeGuard.authorize()` and make the request broker the only allowed outbound client.

Minimum checks:

- scheme and hostname exactly match policy;
- resolved destination belongs to the expected internal network/address range;
- port and HTTP method are permitted;
- redirects are checked again;
- request count and run timeout are bounded;
- every allow/block decision is logged with its reason.

Add tests for a valid in-network URL, an external URL, an invalid scheme, a redirect, and budget exhaustion.

**Done when:** the safety-test suite proves that disallowed destinations are rejected before a request is made.

### Day 4 — Deterministic recon

Use Playwright for Python to visit only allowed pages and collect:

- URLs and HTTP methods observed;
- links and forms;
- parameter names and source (path/query/form);
- basic authentication-state labels;
- browser screenshots/trace references when useful.

Keep it bounded: one host, small depth, page limit, short timeout. Write a `SiteMap` JSON artifact.

**Done when:** the demo target produces a stable expected `SiteMap` in an end-to-end test.

### Day 5 — Planner and specialist interfaces

Build a deterministic planner that creates tasks such as:

- reflected user-controlled input → XSS specialist candidate;
- numeric/object-like identifier plus authorization context → IDOR specialist candidate.

Each specialist returns a Pydantic `AttackPlan` with a class, target location, planned safe test family, expected success signal, and rationale. It must not return shell commands or directly operate tools.

Add an optional LLM adapter behind the same interface, but use a deterministic fake adapter in tests. This keeps the MVP reliable even if a local model is unavailable.

**Done when:** fixture site maps produce predictable task and plan JSON.

### Day 6 — Executor and verifier

Implement one controlled operation per class through the request broker/Playwright.

The verifier must use class-specific, explicit rules:

- XSS is confirmed only by an agreed browser-side execution signal in the controlled lab.
- IDOR is confirmed only by evidence that an unauthorized test identity accessed an object it should not own in the controlled lab.

Response status codes or model confidence alone never confirm a finding.

Store sanitized request metadata, response metadata, timestamps, and a screenshot/trace reference as `Evidence`.

**Done when:** positive demo cases return `confirmed`; equivalent negative controls return `rejected` or `inconclusive`.

### Day 7 — Report and policy gate

Implement:

- `report.json` as the canonical output;
- `report.md` for humans;
- a simple gate: `fail` only for a confirmed finding with complete evidence, otherwise `warn` or `pass`.

Include run ID, target profile, scope-policy ID, class, verdict, evidence files, remediation summary, and ASVS reference where suitable.

Redact authentication headers, cookies, passwords, and tokens before writing files.

**Done when:** one CLI run produces a readable report that links findings to evidence.

### Day 8 — End-to-end local workflow

Create one command, for example `python -m app.cli run --profile lab/mvp`, that:

1. validates policy;
2. waits for the target health check;
3. performs recon;
4. plans tasks;
5. executes permitted tests;
6. verifies evidence;
7. writes report and gate decision.

Run it against a reset lab several times. Fix nondeterminism before adding features.

**Done when:** the same clean lab produces the intended findings and artifacts reliably.

### Day 9 — CI/CD workflow

Add `.github/workflows/mvp.yml` with these jobs/steps:

1. checkout and install dependencies;
2. lint and unit-test;
3. build/start Compose services;
4. wait for health check;
5. run the Hackbot end-to-end command;
6. upload sanitized reports/logs/screenshots as workflow artifacts;
7. always stop and remove the Compose environment.

Start with a manually triggered workflow and scheduled runs. Enable pull-request checks only after it is stable.

**Done when:** a fresh CI runner produces the same report package without access to any external target.

### Day 10 — Stabilize and present

1. Run every unit, safety, integration, and end-to-end test.
2. Verify that the blocked-host test is visible in logs but contains no secret data.
3. Write a two-minute demo script: commit/change → CI run → report artifact → gate result.
4. Record the MVP limitations honestly: two classes, one target, deterministic planner, no fine-tuning, no dashboard.
5. Tag the MVP release in Git.

**Done when:** both teammates can clone the repository and reproduce the demo using only the README.

## 7. MVP acceptance checklist

- [ ] Compose starts an intentionally vulnerable target and Hackbot in one isolated environment.
- [ ] The target policy is explicit, versioned, and enforced at every outbound request.
- [ ] Recon creates a typed site map.
- [ ] The planner routes tasks to XSS and IDOR specialist interfaces.
- [ ] Specialists return schema-valid plans and never perform network actions.
- [ ] Executor activity is behind the request broker.
- [ ] Positive and negative controls exist for both classes.
- [ ] Findings require evidence and use confirmed/rejected/inconclusive verdicts.
- [ ] JSON and Markdown reports are produced and sanitized.
- [ ] GitHub Actions uploads artifacts and cleans up containers even after failure.
- [ ] Safety tests demonstrate blocking of an out-of-scope request.

## 8. Explicitly postpone these items

- React dashboard.
- Large RAG corpus and vector database.
- Fine-tuning/LoRA.
- sqlmap, nuclei, SSRF, CSRF, JWT, and additional target applications.
- Kubernetes, cloud deployment, production access, issue-tracker automation.
- Automatic blocking of real production releases.

The first extension after MVP should be SQL injection **only if** the core safety and evidence pipeline is stable. The next major extension should be the curated RAG baseline, followed by the specialist-versus-generalist evaluation.

## 9. Essential references

- Docker Compose: <https://docs.docker.com/compose/>
- Playwright Python: <https://playwright.dev/python/docs/intro>
- FastAPI: <https://fastapi.tiangolo.com/>
- LangGraph: <https://langchain-ai.github.io/langgraph/>
- GitHub Actions artifacts: <https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts>
- OWASP ASVS: <https://owasp.org/www-project-application-security-verification-standard/>

## 10. MVP definition of done

The MVP is complete when one command or CI workflow can create an isolated lab, execute a scope-constrained run through the typed pipeline, confirm or reject the two controlled vulnerability scenarios using evidence, publish a sanitized report, return a deterministic gate decision, and remove the environment afterward.
