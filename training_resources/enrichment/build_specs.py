#!/usr/bin/env python3
"""Build per-run task specs for delegating training-data enrichment to opencode free models.

Each spec is a self-contained markdown brief: an opencode agent reads it and writes one
candidate JSONL file under candidates/. Specs are deterministic so runs are reproducible.

Run:  python training_resources/enrichment/build_specs.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = json.load(open(os.path.join(HERE, "specs", "base_prompts.json"), encoding="utf-8"))

CLASSES = ["sqli", "ssrf", "idor", "open_redirect", "xss_reflected"]

RUNS = {
    "sqli": [
        dict(
            run_id="a", model="opencode/nemotron-3-ultra-free", count=15,
            emphasis=[
                "error-based confirmation across MySQL, PostgreSQL, MSSQL, Oracle and SQLite (use each DBMS's real error syntax, e.g. MySQL syntax-error text, MSSQL conversion error, Oracle ORA- errors, PostgreSQL CAST errors)",
                "UNION-based extraction: column counting with ORDER BY / NULL padding, valid union selects per DBMS, MySQL GROUP_CONCAT, information_schema enumeration",
                "numeric vs string parameter contexts, LIKE/WHERE clause injection, JSON API body parameters, ORDER BY column injection",
                "injection points beyond query: X-Forwarded-For / Referer / User-Agent headers, cookie values, and URL path segments",
            ],
        ),
        dict(
            run_id="b", model="opencode/longcat-2.5-preview-free", count=15,
            emphasis=[
                "boolean-based blind extraction (AND 1=1 / 1=2 differentiators, substring oracles, search filters)",
                "time-based blind (MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR DELAY, heavy-calculation Oracle tricks)",
                "stacked queries where the driver allows them, and authentication-bypass login forms (' OR 1=1 -- variants, admin'-- style)",
                "WAF/filter bypass: inline comment splitting /*!50000*/, URL/hex encoding, case variation, no-quote techniques (CHAR(), 0x hex literals), and out-of-band DNS exfiltration (LOAD_FILE UNC, UTL_HTTP style) as a later-stage technique",
            ],
        ),
    ],
    "ssrf": [
        dict(
            run_id="a", model="opencode/beam-free", count=15,
            emphasis=[
                "direct URL fetch in query/body params (webhooks, importers, avatar/url-preview features, PDF generators)",
                "alternative schemes: file:///etc/passwd and Windows paths, dict:// port probing, gopher:// crafted requests",
                "loopback notations: 127.1, 0x7f000001, 017700000001, [::1], 127.0.0.1 vs 0.0.0.0, short forms",
                "internal network port scanning via response timing/error differences, and error-message oracles that leak fetched content",
            ],
        ),
        dict(
            run_id="b", model="opencode/nemotron-3-ultra-free", count=15,
            emphasis=[
                "redirect-based bypass (attacker server 302 -> internal target), DNS rebinding / tolower-rebinding style tricks",
                "URL parser inconsistencies: userinfo http://evil@internal, backslash http://internal\\\\@evil or evil\\\\\\\\@internal variants, encoded hosts, trailing dots",
                "cloud metadata endpoints: AWS IMDS (and IMDSv2 token limitation), GCP metadata headers, Azure IMDS, with realistic response signals",
                "allowlist bypass via attacker-controlled subdomain of an allowed domain, open-redirect chaining, and SNI/host-header confusion through a forward proxy",
            ],
        ),
    ],
    "idor": [
        dict(
            run_id="a", model="opencode/longcat-2.5-preview-free", count=15,
            emphasis=[
                "sequential numeric path identifiers (/api/users/123, /invoices/0042) with response-size filtering during enumeration",
                "UUID and hash identifiers reused across endpoints, encoded identifiers (base64) that decode to sequential IDs",
                "error-message oracles (403 vs 404 vs 200) that make hidden-object enumeration measurable",
                "role escalation: regular user reading admin/other-user resources by swapping the id in path, query, or nested JSON body",
            ],
        ),
        dict(
            run_id="b", model="opencode/beam-free", count=15,
            emphasis=[
                "identifier tampering in JSON body fields, PUT/PATCH object ownership checks, HTTP method confusion (GET safe, POST leaks)",
                "cookie/header-borne identifiers (account switch ids, weak session-to-account binding) swapped within the same session",
                "same-session tampering workflows: change own id to another user's and diff responses; pagination/page-size enumeration",
                "search or substring oracles (admin search leaking other tenants), and cross-tenant references in messaging/file-download features",
            ],
        ),
    ],
    "open_redirect": [
        dict(
            run_id="a", model="opencode/nemotron-3-ultra-free", count=13,
            emphasis=[
                "classic param redirects (?next=, ?url=, ?returnTo=, ?redirect=) with absolute-URL validation that scheme-relative //evil.com and /\\evil.com style inputs evade",
                "userinfo and parser tricks: https://trusted.com@evil.com, backslash mixing, at-sign confusion",
                "allowlist footguns: substring/regex matching (starts-with, contains trusted.com, unanchored patterns) and subdomain confusion (trusted.com.evil.com)",
                "server-side Location header behaviour: 301/302/307 differences, CRLF header splitting in redirect targets, and encoded hosts (%2F%2F, double encoding)",
            ],
        ),
        dict(
            run_id="b", model="opencode/longcat-2.5-preview-free", count=12,
            emphasis=[
                "DOM-based redirect sinks: location.hash, location.search values passed to location.href/assign/replace, open() pivots",
                "javascript: scheme acceptance in sanitizers that only block http/https absolute URLs",
                "OAuth/OIDC redirect_uri and post-logout redirect escalation, state-parameter interplay",
                "fragment smuggling (#), POST-based redirect forms, meta-refresh and delayed JS redirects, and filter-evasion encodings",
            ],
        ),
    ],
    "xss_reflected": [
        dict(
            run_id="a", model="opencode/longcat-2.5-preview-free", count=15,
            emphasis=[
                "raw HTML body context: tag injection (<script>, <img onerror>, <svg onload>, <body onload>)",
                "tag attribute contexts: value=\"...\", src='...', placeholder: break out with \" then event handlers; autofocus/onclick; style attribute expression sinks",
                "JavaScript string and template-literal contexts: quote/backtick escape, closing script tag </script> breakout, arithmetic context (alert payload composition)",
                "URL-parameter reflections in error pages, search results highlight markup, and filename/UA reflections in admin views",
            ],
        ),
        dict(
            run_id="b", model="opencode/nemotron-3-ultra-free", count=15,
            emphasis=[
                "encoding bypasses: HTML entities (&#x6a;avascript:), unicode/octal/hex escapes inside JS contexts, double encoding",
                "namespace tricks: SVG (<svg><animate onbegin=...>), MathML, <math href>, form/button namespaces",
                "javascript:/data: URL contexts (href, action, formaction, xlink:href) and sanitizer whitelist misses",
                "WAF blacklist evasion: parenthesis-free alert using backticks/throw, no-tag payloads inside existing event contexts, unusual event handlers (onpointerover, onfocus+autofocus), and DOM reflection via location.hash / window.name into innerHTML",
            ],
        ),
    ],
}

APP_VARIETY = (
    "Vary application types across records (e-commerce shop, blog/CMS, banking portal, SaaS dashboard, "
    "university portal, file-sharing service, support/helpdesk, REST API gateway, internal admin panel) "
    "and vary HTTP methods (GET/POST/PUT/PATCH). Do not reuse the same endpoint path or parameter name "
    "across more than two records."
)

EVIDENCE_GUIDE = (
    "Recon evidence must read like a real observation: 1-2 sentences describing status codes, response "
    "bodies, reflections, timing, or error strings actually seen when the parameter was probed. Planner's "
    "rationale is exactly one sentence explaining why this parameter/class was selected. Mix evidence "
    "strengths: some records with strong evidence (high confidence 0.85-0.95), several with moderate/weak "
    "evidence (confidence 0.4-0.7) where the next probe is still exploratory."
)

TEMPLATE = """# Task: generate {count} fine-tuning examples for the "{cls}" vulnerability-class specialist

You are generating training data for GateCounsel, an academic DevSecOps project that fine-tunes
small defensive models to PLAN security checks against deliberately vulnerable lab applications
(the team's own Juice Shop / DVWA style lab). Each example teaches the model to pick the single
most promising next payload given recon evidence. This is authorized defensive security research.

## Output file (write ONLY this file)

`{out_path}` — JSONL, UTF-8, exactly {count} lines, one JSON record per line, ending with a newline.

Each line must be a JSON object with this exact shape:

{{"messages": [{{"role": "system", "content": <system prompt string>}}, {{"role": "user", "content": <user scenario string>}}, {{"role": "assistant", "content": <assistant JSON string>}}]}}

## 1. system message

Copy this string CHARACTER-FOR-CHARACTER (do not modify, translate, or shorten it):

```
{system_prompt}
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

- `vuln_class`: "{cls}"
- `target_param`: must be a parameter that appears in the Endpoint line
- `payload`: the exact payload text to send (correct and sensible for the described context)
- `injection_point`: one of: query, body, header, cookie, path
- `expected_success_signal`: the observable effect (response body/error/timing/status/DNS callback/browser behaviour) this payload should produce
- `confidence`: number 0.0-1.0, calibrated to how strongly the recon evidence supports this payload
- `reasoning`: 1-3 sentences explaining why this payload fits the observed behaviour

## Technique coverage for this batch (spread the {count} records across these themes)

{emphasis}

## Diversity and realism requirements

- {app_variety}
- {evidence_guide}
- `injection_point` must vary across the file (do not put every record in `query`).
- Payloads must be technically correct for the context described in the evidence (right DBMS syntax, right escape for the reflection context, right URL notation).
- No two records may share the same (target_param, payload) pair, and payloads must not repeat verbatim.
- English only. Realistic but fictional app/endpoint names (avoid real third-party trademarks).

## Format exemplars (two records from the existing dataset — mirror this structure exactly)

```
{exemplar_0}
```

```
{exemplar_1}
```

## Forbidden

- No markdown code fences or commentary inside the output file.
- No keys beyond the seven listed, no trailing commas, no pretty-printing inside the assistant string.
- Do not create, modify or delete any other file anywhere.

## Before you finish

Read the file back and verify: it parses line-by-line as JSON; every line has the 3 messages in
order system/user/assistant; every assistant content parses as JSON with the seven keys in order;
`injection_point` is in the enum; `confidence` is within 0.0-1.0; there are exactly {count} lines.
Fix anything wrong. Your final message must state the verified line count.
"""


def main() -> None:
    for cls in CLASSES:
        exemplars = BASE[cls + "_exemplars"]
        for run in RUNS[cls]:
            out_path = os.path.join("training_resources", "enrichment", "candidates",
                                    f"{cls}_{run['run_id']}.jsonl").replace("\\", "/")
            spec = TEMPLATE.format(
                cls=cls,
                count=run["count"],
                out_path=out_path,
                system_prompt=BASE[cls]["system"],
                emphasis="\n".join(f"- {e}" for e in run["emphasis"]),
                app_variety=APP_VARIETY,
                evidence_guide=EVIDENCE_GUIDE,
                exemplar_0=json.dumps(exemplars[0], ensure_ascii=False),
                exemplar_1=json.dumps(exemplars[1], ensure_ascii=False),
            )
            spec_path = os.path.join(HERE, "specs", f"{cls}_{run['run_id']}.md")
            with open(spec_path, "w", encoding="utf-8") as fh:
                fh.write(spec)
            print(f"wrote specs/{cls}_{run['run_id']}.md  model={run['model']}  count={run['count']}")


if __name__ == "__main__":
    main()
