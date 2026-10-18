#!/usr/bin/env python3
"""Generate full-scale SLM fine-tuning data (chat-format JSONL) for the five MVP classes.

Mirrors the generator style of training_resources/payloads_all_the_things/training_data/generate.py,
with techniques sourced from the pinned HackTricks checkout (see ../source/source_manifest.json,
upstream commit f66c437539916b7e87d35c17252a26f90878b40f, CC-BY-NC-4.0).

Each JSONL line is a single training conversation:
  {"messages": [{"role": "system", ...}, {"role": "user", ...}, {"role": "assistant", ...}]}

Run:  python generate_full.py
"""

import importlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

SCHEMA_HINT = (
    '{"vuln_class": string, "target_param": string, "payload": string, '
    '"injection_point": string, "expected_success_signal": string, '
    '"confidence": number, "reasoning": string}'
)

INJECTION_POINTS = "query, body, header, cookie, path"

SOURCE_ATTRIBUTION = (
    "Techniques from HackTricks by Carlos Polop (commit f66c437, CC-BY-NC-4.0); "
    "see source/source_manifest.json for provenance."
)

CLASS_BRIEF = {
    "sqli": (
        "SQL injection means user input reaches a SQL interpreter and changes query semantics. "
        "Reason about entry-point contexts, comment syntax, logical/arithmetic confirmation, "
        "DBMS identification, union/error/boolean/time-based extraction, stacked queries, "
        "out-of-band exfiltration and WAF/filter bypasses, respecting DBMS differences "
        "(MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MS Access)."
    ),
    "xss_reflected": (
        "Reflected XSS means a value you control is echoed into HTML or JavaScript and executed. "
        "Identify the reflection context (raw HTML, tag attribute, JS string, template literal), "
        "then choose context-matched payloads: tag injection, event handlers, javascript:/data: "
        "schemes, encoding bypasses (HTML entities, unicode, hex/octal), parenthesis-free "
        "execution, template interpolation, DOM sinks and WAF blacklist evasion."
    ),
    "ssrf": (
        "Server-side request forgery means the server fetches a URL you influence. "
        "Reason about interaction capture, alternative schemes (file, dict, sftp, tftp, ldap, "
        "gopher), redirect-based and DNS-rebinding bypasses, URL parser inconsistencies, "
        "loopback/integer/hex/octal IP notations, domain confusion tricks, infrastructure "
        "gadgets (PDF renderers, proxies, SNI, filename mini-languages) and cloud metadata "
        "endpoints (AWS, GCP, Azure, Oracle, Alibaba, IBM, Kubernetes, Docker)."
    ),
    "idor": (
        "Insecure direct object reference means a user-supplied identifier selects an object "
        "without an ownership/authorization check. Reason about identifier locations (path, "
        "query, body, headers/cookies), sequential or predictable IDs, same-session tampering, "
        "enumeration workflows (curl loops, ffuf with response filtering), error-message "
        "oracles, search-index substring oracles and encoded/opaque identifier reuse."
    ),
    "open_redirect": (
        "Open redirect means a user-controllable value makes the application or browser "
        "navigate to an attacker-controlled destination. Reason about loopback notations, "
        "scheme-relative URLs, userinfo and backslash parser tricks, whitelist/regex footguns, "
        "javascript: pivots and CRLF/scheme-splitting filters, DOM redirect sinks, fragment "
        "smuggling, parameter discovery and OAuth redirect_uri escalation."
    ),
}


def system_prompt(vuln_class: str) -> str:
    return (
        f"You are a specialist security researcher focused exclusively on {vuln_class} vulnerabilities. "
        f"{CLASS_BRIEF[vuln_class]} "
        f"{SOURCE_ATTRIBUTION} "
        "You receive an endpoint, target parameter(s), recon evidence and the planner's rationale; "
        "select the single most promising next payload and justify it. "
        f"Output ONLY a single JSON object matching this schema: {SCHEMA_HINT} "
        f"where injection_point is one of: {INJECTION_POINTS}; "
        "confidence is your calibrated probability (0.0-1.0) that the payload achieves the expected "
        "success signal given the evidence; reasoning explains in 1-3 sentences why this payload fits "
        "the observed behaviour. No markdown, no code fences, no text outside the JSON object."
    )


def user_prompt(endpoint: str, params: str, evidence: str, rationale: str) -> str:
    return (
        f"Endpoint: {endpoint}\n"
        f"Target parameter(s): {params}\n"
        f"Recon evidence: {evidence}\n"
        f"Planner's rationale: {rationale}"
    )


def build_example(vuln_class: str, row: tuple) -> dict:
    endpoint, params, evidence, rationale, payload, injection_point, signal, confidence, reasoning = row
    assistant_obj = {
        "vuln_class": vuln_class,
        "target_param": params.split(",")[0].split(" (")[0].strip(),
        "payload": payload,
        "injection_point": injection_point,
        "expected_success_signal": signal,
        "confidence": confidence,
        "reasoning": reasoning,
    }
    return {
        "messages": [
            {"role": "system", "content": system_prompt(vuln_class)},
            {"role": "user", "content": user_prompt(endpoint, params, evidence, rationale)},
            {"role": "assistant", "content": json.dumps(assistant_obj, ensure_ascii=False)},
        ]
    }


def validate(examples, vuln_class):
    seen = set()
    for ex in examples:
        msgs = ex["messages"]
        assert len(msgs) == 3 and [m["role"] for m in msgs] == ["system", "user", "assistant"]
        assert SOURCE_ATTRIBUTION.split(";")[0] in msgs[0]["content"], "system prompt lost its HackTricks attribution"
        obj = json.loads(msgs[2]["content"])
        expected_keys = [
            "vuln_class", "target_param", "payload", "injection_point",
            "expected_success_signal", "confidence", "reasoning",
        ]
        assert list(obj.keys()) == expected_keys, f"bad keys: {list(obj.keys())}"
        assert obj["vuln_class"] == vuln_class
        assert obj["injection_point"] in {"query", "body", "header", "cookie", "path"}
        assert 0.0 <= obj["confidence"] <= 1.0
        assert obj["payload"] and obj["expected_success_signal"] and obj["reasoning"]
        key = (obj["target_param"], obj["payload"])
        assert key not in seen, f"duplicate example: {key}"
        seen.add(key)


def main():
    datasets = {
        "sqli": "data_sqli_full",
        "ssrf": "data_ssrf_full",
        "xss_reflected": "data_xss_reflected_full",
        "idor": "data_idor_full",
        "open_redirect": "data_open_redirect_full",
    }
    sys.path.insert(0, HERE)
    out_dir = os.path.join(HERE, "generated")
    os.makedirs(out_dir, exist_ok=True)
    total = 0
    for vuln_class, module_name in datasets.items():
        module = importlib.import_module(module_name)
        examples = [build_example(vuln_class, row) for row in module.EXAMPLES]
        validate(examples, vuln_class)
        out_path = os.path.join(out_dir, f"{vuln_class}_full_training_data.jsonl")
        with open(out_path, "w", encoding="utf-8") as fh:
            for ex in examples:
                fh.write(json.dumps(ex, ensure_ascii=False) + "\n")
        size_kb = os.path.getsize(out_path) / 1024
        print(f"{vuln_class:<14} {len(examples):>4} examples -> {out_path} ({size_kb:.1f} KB)")
        total += len(examples)
    print(f"TOTAL: {total} examples")
    print(SOURCE_ATTRIBUTION)


if __name__ == "__main__":
    main()
