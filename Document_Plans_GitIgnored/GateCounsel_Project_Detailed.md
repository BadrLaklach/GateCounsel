# GATECOUNSEL
### A Multi-Agent, Vulnerability-Class-Specialized Autonomous Pentesting Assistant

**Author:** Taha Benahmadi
**Institution:** ENSAM Meknès — Génie Logiciel & Systèmes Intelligents
**Type:** Semester Project

---

## Table of Contents

1. [Overview](#1-overview)
2. [Motivation & Context](#2-motivation--context)
3. [Objectives](#3-objectives)
4. [Scope](#4-scope)
5. [System Architecture](#5-system-architecture)
6. [Detailed Component Breakdown](#6-detailed-component-breakdown)
7. [Data Flow — End to End](#7-data-flow--end-to-end)
8. [Vulnerability Expert Agents](#8-vulnerability-expert-agents)
9. [Safety & Scope Enforcement](#9-safety--scope-enforcement)
10. [Technology Stack](#10-technology-stack)
11. [Project Structure (Repository Layout)](#11-project-structure-repository-layout)
12. [Evaluation Plan](#12-evaluation-plan)
13. [Development Timeline](#13-development-timeline)
14. [Risks & Mitigations](#14-risks--mitigations)
15. [Expected Contribution](#15-expected-contribution)
16. [Future Work](#16-future-work)

---

## 1. Overview

**GateCounsel** is an autonomous, multi-agent system that performs web application penetration testing the way a human security researcher would: it explores a target application, decides which vulnerabilities are worth investigating, attempts to actually exploit them, confirms whether the exploit genuinely worked, and produces a structured, professional report — all while staying inside a strictly enforced, human-approved scope.

What distinguishes GateCounsel from a generic "AI hacking agent" is **specialization by vulnerability class**. Instead of a single general-purpose agent trying to reason about every possible attack with one shallow system prompt, GateCounsel routes each testing opportunity to a dedicated **expert agent** — one per vulnerability class (XSS, SQL Injection, SSRF, IDOR, CSRF, Auth/JWT flaws, etc.). Each expert is strengthened with retrieval-augmented generation (RAG) over real security documentation (PortSwigger Web Security Academy, OWASP references) and, for the best-documented classes, a lightweight fine-tuned model adapter (LoRA).

GateCounsel is designed as the **offensive counterpart** to a prior project, MANTIS (an AI cybersecurity copilot that finds and *fixes* vulnerable code via multi-agent orchestration). Where MANTIS is defensive, GateCounsel is offensive — together they form a coherent specialization: **AI-driven offensive and defensive security automation.**

---

## 2. Motivation & Context

- **Manual pentesting is slow and expert-dependent.** A skilled human tester takes days to thoroughly cover even a moderately sized application. Automation cannot replace human judgment, but it can dramatically extend coverage and speed for well-understood vulnerability classes, freeing human testers to focus on business-logic flaws and novel attack chains.
- **LLM-based agents are increasingly capable of structured reasoning + tool use**, making autonomous, multi-step security testing workflows realistic for the first time — this is an active research area (autonomous pentesting agents, "PentestGPT"-style tools, LLM red-teaming).
- **Natural extension of existing skills and prior work.** The author has completed the full PortSwigger Web Security Academy curriculum, is an active CTF/HackTheBox participant, and previously built MANTIS — a LangGraph-orchestrated, multi-agent AI system for vulnerability remediation. GateCounsel reuses the same architectural pattern (multi-agent orchestration via LangGraph) applied to the opposite side of the security lifecycle.
- **Specialization by vulnerability class is a genuinely novel angle** compared to typical student security projects (scanners, WAFs, antivirus tools), and is closer to real mixture-of-experts research than a single generalist agent would be.

---

## 3. Objectives

### 3.1 Primary Objective
Design, implement, and evaluate an autonomous multi-agent system capable of performing an end-to-end penetration test — reconnaissance, planning, exploitation, and reporting — against a sanctioned, deliberately vulnerable web application, using vulnerability-class-specialized agents.

### 3.2 Secondary Objectives
- Demonstrate that splitting "reasoning" (deciding *what* to try) from "execution" (actually *doing* it) produces a safer, more measurable, and more maintainable system than a single monolithic agent.
- Quantify whether specializing agents per vulnerability class (via RAG and/or fine-tuning) meaningfully improves detection accuracy compared to a single generalist agent handling all classes.
- Produce a reusable, extensible architecture: adding a new vulnerability class should mean adding one new expert agent, not rewriting the pipeline.
- Enforce a hard, testable safety boundary so that the system can only ever act against explicitly sanctioned targets.
- Build the entire system on free / open-source components, so it has no recurring cost and does not depend on a paid API to run or demo.

---

## 4. Scope

### 4.1 In Scope — Vulnerability Classes
| Class | Status |
|---|---|
| SQL Injection (SQLi) | Full pipeline + candidate for fine-tuned expert |
| Cross-Site Scripting (XSS) | Full pipeline + candidate for fine-tuned expert |
| Server-Side Request Forgery (SSRF) | Full pipeline, RAG-only expert |
| Insecure Direct Object Reference (IDOR) | Full pipeline, RAG-only expert |
| Cross-Site Request Forgery (CSRF) | Full pipeline, RAG-only expert |
| Authentication / JWT flaws | Full pipeline, RAG-only expert |

### 4.2 In Scope — Targets
- OWASP Juice Shop (self-hosted, Docker)
- DVWA — Damn Vulnerable Web Application (self-hosted, Docker)
- WebGoat (self-hosted, Docker)
- A custom-built deliberately vulnerable application, for controlled, known-ground-truth benchmarking

### 4.3 Explicitly Out of Scope
- Zero-day vulnerability discovery
- Binary / native exploitation (memory corruption, etc.)
- Any live, external, third-party, or production target
- Fully unsupervised exploitation without a human-approved scope declaration
- Network-layer or infrastructure attacks (this project is strictly web-application-layer)

---

## 5. System Architecture

GateCounsel is organized as a directed pipeline of specialized agents, orchestrated with **LangGraph**, where state (recon data, findings, attack plans, confirmed results) flows through each stage.

```
                        ┌────────────────────┐
                        │   Target App (lab)  │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌────────────────────┐
                        │    Recon Agent      │
                        │  crawls, maps       │
                        │  endpoints/params   │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌────────────────────┐
                        │   Planner Agent     │
                        │  decides which      │
                        │  vuln classes to    │
                        │  test per endpoint  │
                        └──────────┬───────────┘
                                   │  routes by vulnerability class
                 ┌─────────────┬──┴──┬─────────────┬─────────────┐
                 ▼             ▼     ▼             ▼             ▼
            ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐
            │  XSS   │   │  SQLi  │   │  SSRF  │   │  IDOR  │   │  ...   │
            │ Expert │   │ Expert │   │ Expert │   │ Expert │   │ Expert │
            │(RAG+   │   │(RAG+   │   │ (RAG)  │   │ (RAG)  │   │ (RAG)  │
            │ LoRA)  │   │ LoRA)  │   │        │   │        │   │        │
            └───┬────┘   └───┬────┘   └───┬────┘   └───┬────┘   └───┬────┘
                └────────────┴─────────────┴─────────────┴───────────┘
                                   │   structured attack plan
                                   ▼   (vuln class, param, payload, success signal)
                        ┌────────────────────┐
                        │   Exploit Agent     │
                        │  executes plan,     │
                        │  interprets result  │
                        └──────────┬───────────┘
                                   │  every action passes through
                                   ▼
                        ┌────────────────────┐
                        │    Scope Guard      │
                        │  allow-list check   │
                        │  before any firing  │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌────────────────────┐
                        │   Exploit Tools     │
                        │ sqlmap, nuclei,     │
                        │ Playwright, custom  │
                        └──────────┬───────────┘
                                   │  confirmed / rejected + evidence
                                   ▼
                        ┌────────────────────┐
                        │  Reporting Agent    │
                        │  CVSS-scored PoC    │
                        │  report             │
                        └────────────────────┘
```

---

## 6. Detailed Component Breakdown

### 6.1 Recon Agent
**Purpose:** Build a complete map of the target application's attack surface.

**Responsibilities:**
- Crawl the application (headless browser via Playwright) to discover pages, forms, and client-side routes.
- Enumerate API endpoints, HTTP methods, and parameters (query string, body, headers, cookies).
- Detect authentication flows (login, session tokens, JWT usage) and identify which endpoints require authentication.
- Fingerprint technologies in use (framework, server headers) to help experts tailor payloads.

**Output:** A structured "site map" object — list of endpoints, each annotated with parameters, auth requirements, and detected technology hints.

---

### 6.2 Planner Agent
**Purpose:** Act as the router/dispatcher of the whole system.

**Responsibilities:**
- Read the Recon Agent's site map.
- For each endpoint, decide which vulnerability class(es) are plausible candidates (e.g., a search parameter reflected in HTML → candidate for XSS; a numeric ID in a URL → candidate for IDOR).
- Prioritize testing order (e.g., authentication-related endpoints first, since a successful auth bypass can unlock further testing).
- Dispatch each (endpoint, vulnerability class) pair to the matching Expert Agent.

**Output:** A prioritized queue of testing tasks, each tagged with an endpoint and a target vulnerability class.

---

### 6.3 Vulnerability Expert Agents
**Purpose:** Provide deep, class-specific reasoning about *how* to test a given endpoint for a given vulnerability class — without ever touching the network directly.

See [Section 8](#8-vulnerability-expert-agents) for full detail.

**Output (per task):** A structured **attack plan**:
```json
{
  "vuln_class": "XSS",
  "endpoint": "/search",
  "parameter": "q",
  "payload": "<script>...</script>",
  "expected_success_signal": "script executes in headless browser (alert hook fires)",
  "confidence": 0.82,
  "reasoning": "parameter reflected unescaped in response body"
}
```

---

### 6.4 Exploit Agent
**Purpose:** The single component authorized to take real action against the target. Bridges reasoning (experts) and execution (tools).

**Responsibilities:**
- Receive a structured attack plan from an expert.
- Pass the plan through the **Scope Guard** before doing anything else.
- Select and invoke the correct deterministic tool (sqlmap, nuclei, Playwright, or a custom script) to actually send the payload.
- Capture raw evidence: HTTP request/response pair, status code, timing, screenshot, or error string.
- Interpret that evidence against the expert's "expected success signal" to produce a verdict: **confirmed**, **rejected**, or **inconclusive** (flagged for manual review).

**Output:** A verdict object with full evidence, forwarded to the Reporting Agent if confirmed.

---

### 6.5 Scope Guard
**Purpose:** The single, non-bypassable safety checkpoint of the entire system.

**Responsibilities:**
- Maintain an explicit allow-list of sanctioned targets (hostnames/IPs, defined before any run starts).
- Intercept every single action the Exploit Agent attempts to take.
- Reject and log any action whose target falls outside the allow-list — regardless of what any upstream agent "decided."
- Provide an audit trail of every attempted action (allowed or blocked) for post-run review.

**Design principle:** This is implemented as plain, deterministic code — not an LLM call — so its behavior is guaranteed and independently testable, not just "probably safe."

---

### 6.6 Exploit Tools Layer
**Purpose:** The actual mechanisms that interact with the target over the network.

| Tool | Used for |
|---|---|
| **sqlmap** | Automated SQL injection detection and confirmation |
| **nuclei** (community templates) | Fast, broad coverage across several vulnerability classes |
| **Playwright** (headless browser) | XSS confirmation (does the script actually execute?), general UI-driven interaction |
| **Custom Python scripts** | IDOR, SSRF, CSRF, and auth/JWT tests not well covered by the tools above |

---

### 6.7 Reporting Agent
**Purpose:** Turn confirmed findings into a professional, actionable deliverable.

**Responsibilities:**
- Aggregate all confirmed findings from a run.
- Assign a CVSS-style severity score to each.
- Attach proof-of-concept evidence (request/response, screenshot).
- Generate remediation guidance per finding (drawing on the same RAG knowledge base used by the experts).
- Export the final report (Markdown/HTML/PDF).

---

## 7. Data Flow — End to End

1. **Input:** A human operator declares a target (URL) and confirms it is in-scope; this is registered with the Scope Guard.
2. **Recon:** The Recon Agent crawls the target and produces a site map.
3. **Planning:** The Planner Agent consumes the site map and produces a prioritized list of (endpoint, vulnerability class) testing tasks.
4. **Expert reasoning:** Each task is dispatched to its matching Expert Agent, which produces a structured attack plan.
5. **Scope check:** Every attack plan is checked against the Scope Guard's allow-list before execution.
6. **Exploitation:** The Exploit Agent executes the plan via the appropriate tool and captures evidence.
7. **Verdict:** The Exploit Agent interprets the evidence and marks the finding as confirmed, rejected, or inconclusive.
8. **Reporting:** All confirmed findings are compiled by the Reporting Agent into the final report.
9. **Human review:** The operator reviews the report; inconclusive findings are flagged for manual follow-up.

---

## 8. Vulnerability Expert Agents

Each expert agent shares the same interface (input: endpoint + context from recon; output: structured attack plan) but differs in how "expert" it actually is:

### 8.1 Tier 1 — RAG-only experts (baseline, guaranteed to work)
- Built on a single shared open-weight base model (e.g., Qwen2.5-7B or Llama-3.1-8B).
- Strengthened with retrieval-augmented generation over a curated knowledge base per vulnerability class: PortSwigger Web Security Academy write-ups, OWASP Testing Guide entries, public CTF write-ups.
- No model training required — fast to build, reliable, and the guaranteed working baseline for the whole project.
- Covers: SSRF, IDOR, CSRF, Auth/JWT (and XSS/SQLi if the Tier 2 stretch goal is not reached).

### 8.2 Tier 2 — Fine-tuned experts (stretch goal)
- For the 1–2 best-documented classes (candidates: XSS, SQLi), a lightweight **LoRA adapter** is fine-tuned on top of the same shared base model.
- Training data: curated (vulnerable context → correct payload/reasoning) pairs derived from PortSwigger labs, disclosed bug bounty reports, and CTF write-ups.
- Training performed with **Unsloth** (QLoRA, 4-bit) on a free Colab/Kaggle GPU (T4).
- At inference, the same base model is reused; only the relevant adapter is hot-swapped in — cheap to serve.
- **Evaluation goal:** directly compare the fine-tuned expert against its Tier-1 (RAG-only) counterpart on identical test cases, to measure whether fine-tuning meaningfully improves detection accuracy over strong prompting + retrieval alone.

---

## 9. Safety & Scope Enforcement

Because this system performs real exploitation attempts, safety is treated as a first-class design requirement, not an afterthought:

- **Sandboxed targets only.** All testing runs against self-hosted, deliberately vulnerable applications inside Docker containers on an isolated network — never live or external systems.
- **Hard-coded allow-list.** The Scope Guard is deterministic code, not an LLM decision, so its enforcement cannot be reasoned or prompted around.
- **Single choke-point.** Because the Exploit Agent is the *only* component that acts on the network, and every one of its actions passes through the Scope Guard, there is exactly one place to audit and test for safety — not four scattered ones.
- **Human sign-off.** No run begins without an operator explicitly declaring and confirming the target scope.
- **Full audit trail.** Every attempted action, allowed or blocked, is logged for post-run review.

---

## 10. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Agent orchestration | **Python + LangGraph** | Stateful multi-agent routing; same framework proven in MANTIS |
| RAG plumbing | **LangChain** | Standard retrieval integration |
| LLM inference (dev/demo) | **Groq API** (free tier) | Fast, free inference on open models |
| LLM inference (fallback/offline) | **Ollama** (local) | Zero cost, no live-API dependency during defense |
| Fine-tuning (stretch goal) | **Unsloth + QLoRA** | Fast, low-VRAM adapter training on free Colab/Kaggle GPUs |
| Vector store | **ChromaDB** | Local, free, zero hosted-service dependency |
| Exploit execution | **sqlmap, nuclei, Playwright, custom scripts** | Proven, deterministic tools rather than LLM-generated raw exploit code |
| Backend API | **FastAPI** | Lightweight, async-friendly, integrates cleanly with LangGraph |
| Frontend dashboard | **React.js** | Submit targets, track live agent progress, view reports |
| Infrastructure | **Docker Compose** | Runs the whole system plus vulnerable lab targets in one isolated, controlled network |

The entire stack is built on free and open-source components end to end — no recurring cost, and no dependency on a paid API to run or demo the system.

---

## 11. Project Structure (Repository Layout)

```
gatecounsel/
├── agents/
│   ├── recon_agent.py
│   ├── planner_agent.py
│   ├── exploit_agent.py
│   ├── reporting_agent.py
│   └── experts/
│       ├── base_expert.py
│       ├── xss_expert.py
│       ├── sqli_expert.py
│       ├── ssrf_expert.py
│       ├── idor_expert.py
│       ├── csrf_expert.py
│       └── auth_jwt_expert.py
├── safety/
│   └── scope_guard.py
├── tools/
│   ├── sqlmap_wrapper.py
│   ├── nuclei_wrapper.py
│   ├── playwright_runner.py
│   └── custom_payloads/
├── rag/
│   ├── knowledge_base/          # PortSwigger / OWASP reference docs per class
│   ├── ingest.py
│   └── retriever.py
├── finetuning/                  # Tier 2 stretch goal
│   ├── datasets/
│   ├── train_lora_xss.py
│   ├── train_lora_sqli.py
│   └── adapters/
├── orchestration/
│   └── graph.py                 # LangGraph pipeline definition
├── api/
│   └── main.py                  # FastAPI backend
├── frontend/
│   └── (React dashboard)
├── lab/
│   └── docker-compose.yml       # Juice Shop, DVWA, WebGoat, custom app
├── evaluation/
│   ├── benchmark_cases/
│   └── run_eval.py
└── reports/
    └── (generated PoC reports)
```

---

## 12. Evaluation Plan

| Metric | What it measures |
|---|---|
| Detection / confirmation rate per vulnerability class | How often a real, known vulnerability in the lab targets is correctly found and confirmed |
| False-positive rate | Cases where an expert's plan looked promising but the Exploit Agent's evidence did not confirm it |
| Fine-tuned vs. RAG-only comparison (Tier 2) | Whether fine-tuning a class-specific adapter meaningfully improves accuracy over prompting + retrieval alone |
| Time-to-first-finding | Speed of the automated pipeline, as a sanity check against a manual baseline |
| Scope Guard integrity | Adversarial testing: attempt to make an agent target something outside scope, confirm it is always blocked |

Benchmarking will use a curated set of ~20–30 known test cases across the lab targets, with documented ground truth (known vulnerabilities and their locations), so precision/recall-style metrics can be computed reliably.

---

## 13. Development Timeline (14 Weeks)

| Weeks | Milestone |
|---|---|
| 1–2 | State of the art review (autonomous pentesting agents), finalize scope, set up lab targets |
| 3–5 | Recon Agent + site-mapping pipeline |
| 6–8 | Planner Agent + Tier 1 (RAG-only) Expert Agents for 3 vulnerability classes |
| 9–10 | Exploit Agent + Scope Guard + exploit tools integration |
| 11 | Remaining expert agents (full class coverage) |
| 12 | Tier 2 stretch goal: LoRA fine-tuning for XSS/SQLi experts, benchmarking |
| 13 | Reporting Agent, dashboard, end-to-end integration |
| 14 | Evaluation write-up, demo preparation, final defense |

---

## 14. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| LLM-generated exploit reasoning is unreliable on the first try | Hybrid design: experts only *plan*, proven deterministic tools *execute* — reduces reliance on raw LLM-generated exploit code |
| Fine-tuning (Tier 2) underdelivers or runs out of time | Scoped as a stretch goal on top of a fully working Tier 1 baseline — the project remains complete and demoable either way |
| Free GPU/API tiers have rate limits | Ollama fallback for fully local, unlimited inference during development and defense |
| Safety concerns from running real exploits | Strict Docker-isolated lab targets, deterministic Scope Guard, no external targets ever |
| Curating quality fine-tuning data is time-consuming | Limited to 1–2 vulnerability classes with the richest public documentation (PortSwigger labs), not all classes |

---

## 15. Expected Contribution

A working, end-to-end prototype that autonomously pentests a sanctioned lab target and produces a structured, evidence-backed report — with measurable results on detection accuracy, false-positive rate, and the concrete value (or lack thereof) of per-class model specialization. Positioned alongside MANTIS, it forms a coherent "AI-driven offensive and defensive security automation" specialization, and the reasoning/execution split plus deterministic Scope Guard give the project a genuine, defensible safety story rather than just an offensive capability demo.

---

## 16. Future Work

- Extending expert coverage to additional vulnerability classes (Web Cache Poisoning, Request Smuggling, GraphQL-specific flaws).
- Business-logic vulnerability detection — a class that is inherently harder to automate and would be a natural next research direction.
- Integrating the system as a CI/CD pipeline step (pre-deployment automated pentesting), bridging toward a DevSecOps use case.
- Multi-target / continuous scanning mode with historical trend reporting.
- Open-sourcing the framework (agents, prompts, RAG knowledge base) as a community resource, similar in spirit to nuclei's template ecosystem.
