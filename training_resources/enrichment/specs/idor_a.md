# Task: generate 15 fine-tuning examples for the "idor" vulnerability-class specialist

You are generating training data for GateCounsel, an academic DevSecOps project that fine-tunes
small defensive models to PLAN security checks against deliberately vulnerable lab applications
(the team's own Juice Shop / DVWA style lab). Each example teaches the model to pick the single
most promising next payload given recon evidence. This is authorized defensive security research.

## Output file (write ONLY this file)

`training_resources/enrichment/candidates/idor_a.jsonl` — JSONL, UTF-8, exactly 15 lines, one JSON record per line, ending with a newline.

Each line must be a JSON object with this exact shape:

{"messages": [{"role": "system", "content": <system prompt string>}, {"role": "user", "content": <user scenario string>}, {"role": "assistant", "content": <assistant JSON string>}]}

## 1. system message

Copy this string CHARACTER-FOR-CHARACTER (do not modify, translate, or shorten it):

```
You are a specialist security researcher focused exclusively on idor vulnerabilities. Insecure direct object reference means a user-supplied identifier selects an object without an ownership/authorization check. Craft the exact identifier tamper (increment, decode and re-encode, predict, wildcard, method or content-type change) that returns another principal's object. You receive an endpoint, target parameter(s), recon evidence and the planner's rationale; select the single most promising next payload and justify it. Output ONLY a single JSON object matching this schema: {"vuln_class": string, "target_param": string, "payload": string, "injection_point": string, "expected_success_signal": string, "confidence": number, "reasoning": string} where injection_point is one of: query, body, header, cookie, path; confidence is your calibrated probability (0.0-1.0) that the payload achieves the expected success signal given the evidence; reasoning explains in 1-3 sentences why this payload fits the observed behaviour. No markdown, no code fences, no text outside the JSON object.
```

## 2. user message

Plain string in exactly this four-line layout (no extra headers):

Endpoint: <METHOD /path?with=params if any — target parameter must be visible here>
Target parameter(s): <the parameter name(s), optionally with a short (context note)>
Recon evidence: <1-2 sentences of observed behaviour>
Planner's rationale: <one sentence>

## 3. assistant message

A JSON **string** (the content of the message is itself serialized JSON) with keys in EXACTLY this
order: `vuln_class`, `target_param`, `payload`, `injection_point`, `expected_success_signal`,
`confidence`, `reasoning`.

- `vuln_class`: "idor"
- `target_param`: must be a parameter that appears in the Endpoint line
- `payload`: the exact payload text to send (correct and sensible for the described context)
- `injection_point`: one of: query, body, header, cookie, path
- `expected_success_signal`: the observable effect (response body/error/timing/status/DNS callback/browser behaviour) this payload should produce
- `confidence`: number 0.0-1.0, calibrated to how strongly the recon evidence supports this payload
- `reasoning`: 1-3 sentences explaining why this payload fits the observed behaviour

## Technique coverage for this batch (spread the 15 records across these themes)

- sequential numeric path identifiers (/api/users/123, /invoices/0042) with response-size filtering during enumeration
- UUID and hash identifiers reused across endpoints, encoded identifiers (base64) that decode to sequential IDs
- error-message oracles (403 vs 404 vs 200) that make hidden-object enumeration measurable
- role escalation: regular user reading admin/other-user resources by swapping the id in path, query, or nested JSON body

## Diversity and realism requirements

- Vary application types across records (e-commerce shop, blog/CMS, banking portal, SaaS dashboard, university portal, file-sharing service, support/helpdesk, REST API gateway, internal admin panel) and vary HTTP methods (GET/POST/PUT/PATCH). Do not reuse the same endpoint path or parameter name across more than two records.
- Recon evidence must read like a real observation: 1-2 sentences describing status codes, response bodies, reflections, timing, or error strings actually seen when the parameter was probed. Planner's rationale is exactly one sentence explaining why this parameter/class was selected. Mix evidence strengths: some records with strong evidence (high confidence 0.85-0.95), several with moderate/weak evidence (confidence 0.4-0.7) where the next probe is still exploratory.
- `injection_point` must vary across the file (do not put every record in `query`).
- Payloads must be technically correct for the context described in the evidence (right DBMS syntax, right escape for the reflection context, right URL notation).
- No two records may share the same (target_param, payload) pair, and payloads must not repeat verbatim.
- English only. Realistic but fictional app/endpoint names (avoid real third-party trademarks).

## Format exemplars (two records from the existing dataset — mirror this structure exactly)

```
{"messages": [{"role": "system", "content": "You are a specialist security researcher focused exclusively on idor vulnerabilities. Insecure direct object reference means a user-supplied identifier selects an object without an ownership/authorization check. Craft the exact identifier tamper (increment, decode and re-encode, predict, wildcard, method or content-type change) that returns another principal's object. You receive an endpoint, target parameter(s), recon evidence and the planner's rationale; select the single most promising next payload and justify it. Output ONLY a single JSON object matching this schema: {\"vuln_class\": string, \"target_param\": string, \"payload\": string, \"injection_point\": string, \"expected_success_signal\": string, \"confidence\": number, \"reasoning\": string} where injection_point is one of: query, body, header, cookie, path; confidence is your calibrated probability (0.0-1.0) that the payload achieves the expected success signal given the evidence; reasoning explains in 1-3 sentences why this payload fits the observed behaviour. No markdown, no code fences, no text outside the JSON object."}, {"role": "user", "content": "Endpoint: GET /profile?user_id=123\nTarget parameter(s): user_id\nRecon evidence: user_id is a sequential integer; while logged in as user 123, requesting 122 and 124 returns those users' full profiles (name, email, address).\nPlanner's rationale: User-controlled object identifier with no ownership check observed on adjacent IDs."}, {"role": "assistant", "content": "{\"vuln_class\": \"idor\", \"target_param\": \"user_id\", \"payload\": \"user_id=124\", \"injection_point\": \"query\", \"expected_success_signal\": \"HTTP 200 with another user's profile data in the response body\", \"confidence\": 0.9, \"reasoning\": \"The backend looks up the record purely from the user-supplied identifier and never compares it to the session principal, so incrementing the ID returns other users' data - the canonical IDOR walkthrough from the cheat sheet.\"}"}]}
```

```
{"messages": [{"role": "system", "content": "You are a specialist security researcher focused exclusively on idor vulnerabilities. Insecure direct object reference means a user-supplied identifier selects an object without an ownership/authorization check. Reason about identifier locations (path, query, body, headers/cookies), sequential or predictable IDs, same-session tampering, enumeration workflows (curl loops, ffuf with response filtering), error-message oracles, search-index substring oracles and encoded/opaque identifier reuse. Techniques from HackTricks by Carlos Polop (commit f66c437, CC-BY-NC-4.0); see source/source_manifest.json for provenance. You receive an endpoint, target parameter(s), recon evidence and the planner's rationale; select the single most promising next payload and justify it. Output ONLY a single JSON object matching this schema: {\"vuln_class\": string, \"target_param\": string, \"payload\": string, \"injection_point\": string, \"expected_success_signal\": string, \"confidence\": number, \"reasoning\": string} where injection_point is one of: query, body, header, cookie, path; confidence is your calibrated probability (0.0-1.0) that the payload achieves the expected success signal given the evidence; reasoning explains in 1-3 sentences why this payload fits the observed behaviour. No markdown, no code fences, no text outside the JSON object."}, {"role": "user", "content": "Endpoint: GET /api/orders?cursor=\nTarget parameter(s): cursor (query)\nRecon evidence: Pagination cursors encode object references; own cursor decodes to order IDs.\nPlanner's rationale: Decode, tamper and re-encode opaque cursors."}, {"role": "assistant", "content": "{\"vuln_class\": \"idor\", \"target_param\": \"cursor\", \"payload\": \"base64decode(cursor) -> tamper ids -> base64encode -> resend\", \"injection_point\": \"query\", \"expected_success_signal\": \"Foreign orders listed through the forged cursor\", \"confidence\": 0.6, \"reasoning\": \"Encoding (base64/hex) is presentation, not authorization — the wristband lesson generalises to any opaque token that internally carries enumerable object references.\"}"}]}
```

## Forbidden

- No markdown code fences or commentary inside the output file.
- No keys beyond the seven listed, no trailing commas, no pretty-printing inside the assistant string.
- Do not create, modify or delete any other file anywhere.

## Before you finish

Read the file back and verify: it parses line-by-line as JSON; every line has the 3 messages in
order system/user/assistant; every assistant content parses as JSON with the seven keys in order;
`injection_point` is in the enum; `confidence` is within 0.0-1.0; there are exactly 15 lines.
Fix anything wrong. Your final message must state the verified line count.
