# GateCounsel: Current Project State and MVP Next Steps

**Review date:** 13 October 2026  
**Repository snapshot:** `main` at `6e8ca76`  
**Compared with:** `GATECOUNSEL_MVP_ROADMAP.md`, `GATECOUNSEL_FULL_PROJECT_ROADMAP.md`, and `GateCounsel_Project_Detailed.md` in this folder.

> **Historical snapshot:** this audit records the repository and two-class MVP plan as reviewed on 13 October 2026. The agreed MVP scope was expanded on 16 October 2026 to reflected XSS, IDOR, SQLi, SSRF, and open redirect. See the current [MVP Roadmap](GATECOUNSEL_MVP_ROADMAP.md) and [Target MVP Architecture](TARGET_MVP_ARCHITECTURE.md) for the active scope; the implementation findings below remain a snapshot of the reviewed code.

## Executive summary

GateCounsel currently has two substantial working areas: a reconnaissance pipeline and a deterministic-first planning pipeline. They share Pydantic data models and can be joined in a small LangGraph flow. The repository also has a Docker Compose file for OWASP Juice Shop, a local mock application used by tests, a Juice Shop validation script, and example fine-tuning data generation code.

The repository does **not** yet demonstrate the MVP described in the roadmap. There is no custom Docker target with recorded ground truth, no complete request broker, no XSS or IDOR specialist implementation, no controlled executor or evidence verifier, no report renderer or policy gate, and no GitHub Actions workflow. Consequently, the current project is best described as an early recon-and-planning prototype, not an end-to-end DevSecOps security testing system.

The largest issue to resolve before adding execution is the gap between the documented safety guarantee and the current network paths: the HTTPX recon client checks scope, but the Playwright callback only observes requests after they are initiated, and Katana runs in a separate process. The CLI also treats the operator-supplied target as allowed without restricting it to the local lab. The current Compose network is a regular bridge network, not a network with outbound access disabled.

## What exists today

### Reconnaissance

`agents/recon/` implements a multi-stage reconnaissance pipeline. Its main components are:

- `agents/recon/core/models.py`: Pydantic contracts for `SiteMap`, endpoints, parameters, forms, authentication observations, technology hints, and crawl statistics.
- `agents/recon/core/http_client.py`: an HTTPX wrapper that checks URLs with `ScopeGuard`, manually validates redirect destinations, rate limits its own requests, and caps response bodies.
- `agents/recon/crawlers/crawler.py`: bounded breadth-first HTTP crawling, link and form extraction, JavaScript endpoint pattern extraction, and JSON/OpenAPI-related inventory support.
- `agents/recon/scanners/param_probe.py`: common API-path checks and benign reflection-marker probes.
- `agents/recon/scanners/auth_detector.py`: login-surface detection, optional operator-supplied credential attempts, JWT/session observations, and protected-endpoint checks.
- `agents/recon/scanners/fingerprint.py`: rule-based technology hints from response headers and page content.
- Optional integrations: Playwright for browser-driven pages and request observations, Katana for additional route discovery, and Gemini for suggested GET paths.
- `run_recon.py`: a command-line entry point that writes a site map JSON file.

The HTTPX portion has useful bounds such as page/depth limits, a per-client request rate, per-request timeouts, body caps, and redirect re-checks. These are not yet a run-wide request or time budget, and they do not automatically apply to Playwright or Katana.

### Planning

`agents/planner/` turns a `SiteMap` into a typed `AttackPlan`:

- `agents/planner/engine/rule_engine.py` creates and scores candidates from reflected parameters, parameter names and examples, JWT observations, and protected-endpoint observations.
- `agents/planner/models/plan_models.py` defines `PlanTask`, `PlanSummary`, and `AttackPlan`, including priority bands, vulnerability class, expert route, evidence signals, and a `safe_probe` / `needs_review` label.
- `agents/planner/planner.py` applies task limits and can call an optional LLM to adjust or drop rule-generated tasks. The LLM response is matched to existing task IDs, so it cannot introduce a new task.
- `agents/planner/client/llm_client.py` implements an HTTPX OpenAI-compatible chat client. Gemini is the default provider configuration; another compatible endpoint can be set manually.
- `run_planner.py` reads a site map JSON file and writes a plan JSON file.

The rule engine currently recognizes seven classes: SQL injection, reflected XSS, JWT misconfiguration, authentication bypass, IDOR, SSRF, and open redirect. That is broader than the two-class MVP.

### Orchestration, lab, tests, and training data

- `orchestration/graph.py` can wire recon alone or recon followed by planning. The “full graph” is currently a stub with the same two stages; expert, execution, reporting, and gate nodes are absent.
- `lab/docker-compose.yml` starts OWASP Juice Shop on host port `127.0.0.1:3000`. It does not define the custom target or a GateCounsel service. The image uses the mutable `latest` tag; the Compose network is a normal bridge network and has no health check or `internal: true` setting.
- `tests/mock_app.py` is a small local HTTP server fixture used to exercise recon and planner behavior. It is not the custom Docker target and ground-truth benchmark described in the MVP plan.
- `tests/test_recon.py` and `tests/test_planner.py` contain 51 test methods in total, including unit, CLI, mock-app integration, and optional LangGraph checks. They were inspected but not run for this review.
- `training_data/` contains hand-authored example scenarios for SQLi, SSRF, IDOR, and open redirect, plus a JSONL generator. It does not contain a model training pipeline, trained adapter, RAG corpus, or retrieval implementation.
- `scripts/validate_juiceshop.py` is a manual integration-check script. It is not an automated CI workflow.

## Technologies currently present

| Technology | Current use | Declared dependency / status |
|---|---|---|
| Python | Recon, planner, CLIs, tests, and data generation | No Python version or packaged project metadata is declared. |
| Pydantic | Site map and plan data models | `pydantic>=2.7` in `requirements.txt`. |
| HTTPX | Recon HTTP client and LLM API calls | `httpx>=0.27`. |
| Beautiful Soup 4 | HTML form and link parsing | `beautifulsoup4>=4.12`. |
| Playwright for Python | Optional browser-based recon | `playwright>=1.45`; browser installation/setup is not documented in a supported setup guide. |
| LangGraph | Optional recon and recon-to-planner state graphs | `langgraph>=0.2`; graph functions explicitly fail with an install hint if unavailable. |
| Rich | Optional CLI tables | `rich>=13.0`; CLIs have a plain-text fallback. |
| Gemini / OpenAI-compatible chat APIs | Optional recon path suggestions and planner reranking | Calls are made directly over HTTPX. There is no RAG or local model runtime packaged with the repository. |
| Docker Compose | Local Juice Shop container | One Compose service only; image version is not pinned. |
| Python `unittest` | Current test suite | Tests use the standard library; there is no declared test/lint/type-check command. |
| Katana | Optional external crawler process | Binary is not a Python dependency and is skipped if missing. |

There is no `pyproject.toml`, lock file, `.env.example`, Makefile/task script, FastAPI service, React dashboard, ChromaDB integration, RAG ingestion/retrieval code, report package, or `.github/workflows/` directory. `requirements.txt` uses minimum-version ranges rather than exact pins. In addition, `run_recon.py` imports `urllib3`, but `urllib3` is not declared directly in `requirements.txt`.

## Comparison with the MVP roadmap

| MVP requirement | Current state | Assessment |
|---|---|---|
| One custom deliberately vulnerable Docker target, with Juice Shop only as a later optional target | Compose starts Juice Shop only. The mock app exists under tests but is not a Docker target. | Not met |
| XSS and IDOR as the two initial classes | The planner includes seven classes. There are no XSS or IDOR specialist modules. | Partially aligned; scope has drifted |
| Typed contracts and deterministic planner | Typed site-map and plan models and deterministic ranking exist. | Partially met |
| Bounded, same-origin recon | HTTPX crawl has bounds; optional Playwright/Katana paths are not controlled through one enforceable broker. | Partially met |
| One request broker and explicit scope policy | A host allow-list guard and an HTTPX wrapper exist. There is no shared broker/policy model for every network tool. | Not met |
| Private lab network, request/time budget, redirect checks, audit | HTTPX redirects and optional audit logging exist. The Compose network is not egress-isolated; no run-wide budget or versioned policy exists. | Partially met |
| XSS and IDOR specialists return typed plans and do not access the target | Only a future expert specification exists; expert code and dispatch do not. | Not met |
| Controlled executor and evidence-based verifier | No executor, evidence model, or class-specific verifier exists. | Not met |
| Sanitized JSON and Markdown report plus deterministic gate | No report renderer, redaction stage, or gate implementation exists. | Not met |
| Compose lifecycle plus GitHub Actions artifacts and cleanup | Compose exists for Juice Shop, but no GateCounsel runner service or Actions workflow exists. | Not met |
| Reproducible documented local setup | README says a supported setup command is absent; dependency and browser versions are not locked. | Not met |

The MVP is not end-to-end yet. Recon and planning provide a useful starting segment, but the MVP definition of done requires the target, enforcement, execution, verification, reporting, gate, and cleanup to work together in one repeatable local command or CI run.

## Comparison with the full-project roadmap

The full roadmap is a later destination, not the current build target. The present code mainly covers part of Phase 4 (recon) and part of Phase 5 (planner). The lab in Phase 2 is only a basic Juice Shop Compose service. Phase 3 (a comprehensive request broker and policy), Phase 6 (tool wrappers and verifiers), Phase 7 (RAG), Phase 8 (reports), Phase 9 (CI gate), Phase 10 (API/dashboard), and Phase 11 (reproducible evaluation) are not implemented.

The current training-data generator is not the full roadmap's RAG or fine-tuning milestone: there is no source manifest, license/version/checksum tracking, retrieval store, training command, adapter, or evaluation protocol. Keep those items behind a stable, evidence-producing MVP as the roadmap recommends.

## Inconsistencies and issues to resolve

### 1. The README understates and misstates the repository contents

The root README says the repository contains only the public project overview and that the Docker lab is not implemented. The repository already contains recon and planner code, tests, training-data modules, and a Compose file. At the same time, the README is right that the complete app and CI workflow are not implemented. Update the status wording when code changes are next authorized so it distinguishes these partial components from the missing end-to-end pipeline.

### 2. Scope enforcement is not yet a single, non-bypassable boundary

`BrowserCrawler._on_request()` calls `is_allowed()` from Playwright's request event, but it does not abort a disallowed request. A Playwright request event is an observation callback; `page.goto()` scope-checks the initial URL, but that alone does not prevent off-scope subresources or redirected navigations. Katana runs as a separate subprocess; GateCounsel checks its starting URL and filters returned endpoints, but its requests do not pass through the Python `ScopeGuard` or a shared broker.

`ScopeGuard` stores hosts and optional ports, not a complete `ScopePolicy`. With no explicit port, its documented behavior is to allow any port for that host. The decision check accepts either HTTP or HTTPS even if the registration used only one scheme. DNS pinning is disabled by default; when enabled, it compares DNS answers in the guard but does not bind the eventual HTTPX connection to the checked address. There is no run-wide request/time budget, method allow-list, expiry, or recorded authorization declaration.

The CLI also puts the supplied target directly into the allow-list. This checks that later HTTPX URLs match that input; it does not limit targets to the local Docker lab or independently establish authorization. `scripts/validate_juiceshop.py` makes a direct HTTPX reachability request before creating the recon agent, outside the Scope Guard.

### 3. The lab is not isolated in the way the plans require

The Compose file binds the Juice Shop port to localhost on the host, which limits remote access to that published port. Its container network is still the ordinary Docker bridge network, which does not itself disable outbound access. There is no GateCounsel service, internal-only network, custom target, health check, reset procedure, or pinned image version. This does not meet the MVP/full-roadmap lab boundary yet.

### 4. A tracked plan artifact names an external-looking target

`plan.json` is a plan generated for `https://server.vulnapp.id` and includes HTTP and HTTPS endpoints for that host. It is a static artifact, not an execution command, and this review did not contact it. The repository contains no scope/authorization record for it, while project documentation says testing is for controlled, sanctioned lab targets only. Treat it as unverified historical data: do not execute its tasks; replace it with a synthetic local fixture or document its authorization and purpose before using it as a sample.

### 5. MVP scope and implementation work have diverged

The MVP roadmap fixes the first milestone to XSS and IDOR and defers SQLi, other classes, RAG, and fine-tuning. The planner already ranks seven classes, and `training_data/generate.py` prepares fine-tuning examples for SQLi, SSRF, IDOR, and open redirect. This data is not wired into execution, but it expands effort beyond the MVP and does not match the expert specification's stated Tier 2 candidates (XSS and SQLi). The MVP should explicitly gate which classes are active; the other data should remain a later research track.

### 6. Data sanitization is a requirement without an implementation boundary

The site-map contract can retain query-value examples, hidden form values (including CSRF tokens), and response snippets. No central redaction stage exists before serialization. The optional LLM features also send target URLs, endpoint paths, parameter names, and planning signals to the configured provider (Gemini by default); the README does not yet describe that data flow. Define what may be persisted or sent to an LLM before adding reports or running against data-bearing applications.

### 7. Safety and run statistics can be misleading

The HTTPX client increments its own blocked counter and the `ScopeGuard` increments another counter for the same denied request. `ReconAgent` adds both counters, so HTTPX blocks can be counted twice. `requests_made` counts only the HTTPX client, not browser or Katana traffic. These fields should not be treated as total run activity until the accounting model is unified.

The planner's `_TaskAccum.add()` avoids adding duplicate signal text but still adds the signal's likelihood boost every time. For example, the same endpoint-reachable signal may be added once per parameter, inflating the score without adding new evidence.

Also, `safe_probe` is a planner label, not an execution authorization. A GET-based IDOR check can still read another user's data; the later executor must apply policy and evidence requirements to the specific operation.

### 8. Documentation, naming, and dependency setup need alignment

Several implementation modules, test names, Compose container names, and loggers still call the system “Hackbot,” while the project and roadmap call it “GateCounsel.” The expert specification describes future modules and uses a schema that does not match the existing training-data generator. `agents/planner/INTEGRATION.md` is a planner hand-off guide, not an up-to-date overall project status. The README also says Markdown files are ignored throughout the repository except for itself, but `.gitignore` has no general Markdown ignore rule and the agent Markdown documents are tracked; only the local planning folder is excluded. The local roadmaps and this status note therefore will not appear in Git history unless that folder policy changes.

The dependency manifest is not locked, lacks an explicit Python version, and omits the direct `urllib3` import in `run_recon.py`. The browser binary installation and the commands to create an environment and run the suite are not documented as a clean-clone workflow.

## Recommended next steps for the MVP

Work in this order so that later execution is built on a controlled, reviewable boundary:

1. **Freeze the MVP contract.** Confirm the first target is a custom local Docker app, with only XSS and IDOR, known positive and negative cases, and explicit safe success signals. Keep the other planner classes and model training out of the MVP run.
2. **Define and enforce scope before execution.** Add a versioned policy with scheme, host, port/address, methods, redirect behavior, expiry, request/time limits, and authorization metadata. Route HTTPX and browser actions through enforceable controls. Keep Katana disabled for MVP unless its traffic can be constrained at the network boundary. Add tests proving rejected requests never leave the runner.
3. **Build a reproducible isolated lab.** Add the custom target, health check, reset/seed data, and GateCounsel runner to Compose. Use a network with egress disabled for the test runner, pin target images, and verify the runner can reach only the intended target.
4. **Make recon safe and deterministic.** Keep recon bounded; remove or redact secret values from examples, hidden fields, and snippets before writing JSON; verify that discovered absolute URLs remain in scope; make request counts cover every enabled network tool.
5. **Constrain planning to the two MVP classes.** Keep deterministic rules as the baseline. Define typed specialist interfaces for XSS and IDOR and make risk labels advisory only; the executor must independently validate every action.
6. **Implement controlled execution and verification.** Add a narrow request broker and class-specific operations. Confirm XSS only with a controlled browser-side signal and IDOR only with a two-user ownership check. Store sanitized evidence and distinguish `confirmed`, `rejected`, and `inconclusive`.
7. **Produce reports and a conservative gate.** Generate canonical JSON plus Markdown from verified findings, redact secrets, and make the gate deterministic. Only evidence-backed confirmed findings should affect the gate.
8. **Make the whole run reproducible.** Document Python/browser/Docker setup, pin versions, add the GitHub Actions workflow with artifact upload and unconditional lab cleanup, then demonstrate the same result on a clean local checkout and CI runner.
9. **After MVP acceptance, expand the research.** Add SQLi if the baseline remains safe and reliable, then curate RAG data with provenance and compare specialist runs with a generalist baseline. Treat LoRA, more vulnerability classes, APIs, and dashboards as later phases.

## Review limits

This was a static repository and documentation review. No tests were run, no Docker services were started, and no target URLs were contacted. Code changes were not made during the audit. This requested status document was created afterward in the existing local plan folder, `Document_Plans_GitIgnored/`; that folder is excluded by `.gitignore`.
