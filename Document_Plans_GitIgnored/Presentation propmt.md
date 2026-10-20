Create a clear, professional 12-slide presentation for our first meeting with project supervisors.

PROJECT
GateCounsel is a scope-constrained, AI-assisted web application security testing system designed to connect controlled security checks with a DevOps CI/CD workflow. Its goal is to run approved tests against an isolated application, verify results from evidence, and return a clear CI decision with a report.

AUDIENCE AND PURPOSE
The audience is academic supervisors who need to understand:
1. the project idea and its research value;
2. the full-project destination;
3. the smaller MVP we are building first;
4. what is implemented today versus still planned;
5. the next technical steps and decisions where supervisor feedback would help.

SOURCE RULES
- Treat “Current Implementation Architecture” and “Current Project State and MVP Next Steps” as authoritative for what is implemented today.
- Treat “Target MVP Architecture” and “GateCounsel MVP Roadmap” as authoritative for the intended MVP.
- Treat “GateCounsel Full Project Roadmap” as the longer-term destination.
- Use “EXPERT_AGENTS_SPEC” for the exact expert-to-exploit handoff: experts return a typed ExpertVerdict.
- Clearly label implemented, MVP target, and future/full-project work. Never present planned components as already implemented.
- If sources conflict, point out the conflict in a brief speaker note rather than inventing a resolution.
- Do not describe GateCounsel as an unrestricted autonomous hacking tool. Emphasize authorized scope, controlled execution, evidence-based verification, and deterministic CI policy.
- Do not imply that the existing project already has an end-to-end exploit, verification, reporting, gate, or CI pipeline.

DESIGN
- 16:9 widescreen, bright and clean academic engineering style.
- Use a white or very light background, dark navy text, and restrained teal/blue accents.
- Use amber for warnings/review, green for pass, and red for fail.
- Use a small visual legend consistently: solid outline = implemented today; teal outline = MVP target; gray dashed outline = future work.
- Use vector-style diagrams, simple icons, clear arrows, and generous whitespace. Avoid hacker clichés, neon effects, decorative code, and stock photos.
- Give every slide one clear takeaway title and one main visual. Use short labels and no more than 3–5 concise bullets per slide.
- Define technical terms on first use. Add brief presenter notes with the key point to say aloud.
- Add small source labels where technical or status claims appear.

SLIDE PLAN

1. TITLE
   Title: “GateCounsel: Scope-Constrained Security Testing for CI/CD”
   Subtitle: “From reconnaissance to evidence-backed delivery decisions”
   Include placeholders for presenter names, supervisors, institution, and meeting date. Use a simple pipeline motif.

2. THE PROBLEM
   Explain the project motivation: security testing can be manual and time-consuming; automated results need evidence and context; delivery pipelines need a repeatable way to act on security results.
   Visual: a simple “code change → security check → delivery decision” problem flow.

3. PROJECT OBJECTIVE AND RESEARCH QUESTIONS
   State the objective: build and evaluate a system that safely tests an authorized application in an isolated environment and returns verified, reportable results to CI/CD.
   Present the research questions from the full roadmap:
   - Do vulnerability-class specialists improve useful findings versus a generalist?
   - Does curated retrieval improve expert plan quality?
   - Can deterministic scope controls safely constrain agent-led testing?
   - Can change-aware planning reduce time without reducing known-case coverage?
   Visual: objective in the center, four research questions around it.

4. FULL-PROJECT DESTINATION
   Show the intended end-to-end system:
   developer/CI → run coordinator and scope policy → recon → planner → specialist experts → bounded Exploit Agent → controlled executor and broker → verifier → policy gate and Report Agent → CI result.
   Label this as the full-project destination, not the current implementation.
   Visual: one clean left-to-right architecture diagram.

5. SYSTEM MODULES
   Group the full design into clear layers:
   - Control plane: run configuration, orchestrator, scope policy.
   - Reasoning plane: recon, planner, XSS/IDOR experts.
   - Execution and safety plane: Exploit Agent, executor, RequestBroker, Scope Guard.
   - Evidence and decision plane: verifier, findings, policy gate.
   - Reporting and delivery plane: Report Agent, artifacts, CI status.
   Visual: layered architecture with arrows between layers.

6. WHAT THE AI DOES
   Explain the three bounded AI roles planned for the MVP:
   - Recon: suggests additional relative paths from sanitized structure.
   - Planner: ranks or drops existing rule-generated candidates.
   - Experts: produce an unexecuted ExpertVerdict with a proposed test and expected success signal.
   State that deterministic code controls scope, allowed operations, verification, and gate decisions. AI does not get direct target access or choose arbitrary tools.
   Visual: three AI-assist boxes feeding into deterministic validation.

7. SAFETY AND TRUST BOUNDARIES
   Explain the isolated target, versioned ScopePolicy, one RequestBroker, request checks, harmless allowlisted MVP tests, sanitized evidence, and deterministic verifier.
   Visual: show a protected boundary around the target and broker; show model services on a separate plane from target traffic.

8. MVP SCOPE
   Present the first demonstrable release:
   - One custom, deliberately vulnerable Docker application.
   - Reflected XSS and IDOR only.
   - AI-assisted recon, planning, and XSS/IDOR expert reasoning.
   - Bounded exploit operations, evidence verification, JSON/Markdown reports, and a deterministic gate.
   - GitHub Actions workflow with artifacts and cleanup.
   Also list what is deferred: public-target scanning, additional vulnerability classes, large RAG corpus, fine-tuning, dashboard, and cloud deployment.
   Visual: “MVP now” versus “later” two-column scope.

9. MVP LOGIC AND DATA HANDOFFS
   Show the MVP chain:
   PlanTask → ExpertVerdict JSON → Exploit Agent → ExecutionRequest JSON → executor/RequestBroker/Scope Guard → ExecutionResult and Evidence → Verifier → Finding → GateDecision → ReportInput → ReportPackage.
   Explain briefly that a finding is based on verifier evidence; an expert proposal alone is not a finding.
   Visual: compact flow diagram with contract names on arrows or boxes.

10. CI/CD DECISION
    Show how the final GateDecision reaches the workflow:
    - pass: exit code 0; continue.
    - warn: exit code 0 in the MVP’s default non-blocking mode; display review guidance.
    - fail: nonzero exit code; fail the check. A required check can block merge, and a deployment job can depend on it.
    Explain that the run summary and uploaded reports inform reviewers. Targeted email/chat/PR notifications are later integrations.
    Show report upload and lab cleanup running even after gate failure.
    Visual: three branches from GateDecision: pass, warn, fail.

11. CURRENT IMPLEMENTATION STATUS
    Be precise and use the current-state audit:
    - Implemented prototype: recon to planner.
    - Existing technologies include Python, Pydantic, HTTPX, Beautiful Soup, optional Playwright, LangGraph, optional Gemini/OpenAI-compatible model calls, Docker Compose, and unittest.
    - Existing output includes a typed site map and candidate plan.
    - The current run stops at planning. Experts, exploit execution, evidence verification, report generation, policy gate, and full GitHub Actions workflow are not implemented.
    - The current Compose lab uses Juice Shop; the MVP target is a custom isolated lab.
    Mention that some existing scope-aware controls are partial and do not yet form one universal non-bypassable broker.
    Visual: “Implemented today” and “Still to build” side-by-side, with different visual styles.

12. ROADMAP, EVALUATION, AND SUPERVISOR FEEDBACK
    Show the MVP build order: contracts and scope → custom lab → broker/guard → AI-assisted recon/planning and experts → exploit/verifier → reporting/gate → CI integration.
    Summarize evaluation measures from the full roadmap: precision, recall, false positives/negatives, confirmation rate, run time, tool actions, and blocked scope violations.
    End with questions for supervisors:
    - Is the two-class MVP scope appropriate?
    - Are the isolated lab and safety boundaries sufficient?
    - Which baseline and evaluation metrics should be prioritized?
    - Should the MVP warn by default and block only on well-evidenced confirmed findings?
    Visual: milestone timeline plus a small “feedback requested” panel.

FINAL QUALITY CHECK
Before presenting the result, confirm:
- Current implementation and planned architecture are visibly distinguished.
- The MVP is clearly smaller than the full-project destination.
- No slide claims the complete pipeline already exists.
- The diagrams show the path from a code change to a CI decision.
- Text remains readable when projected in a meeting room.