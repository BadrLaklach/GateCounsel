#!/usr/bin/env python3
"""Generate SLM fine-tuning data (chat-format JSONL) for SQLi, SSRF, IDOR and Open Redirect.

Each JSONL line is a single training conversation:
  {"messages": [{"role": "system", ...}, {"role": "user", ...}, {"role": "assistant", ...}]}

Payload choices and techniques are based on PayloadsAllTheThings. The
resource-specific fine-tuning examples are kept in this folder.
Run:  python generate.py
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

CLASS_BRIEF = {
    "sqli": (
        "SQL injection means user input reaches a SQL interpreter and changes query semantics. "
        "Choose the technique the evidence supports: error-based, boolean-based, time-based, "
        "union-based, stacked queries or out-of-band exfiltration; respect DBMS fingerprints "
        "(MySQL, PostgreSQL, MSSQL, Oracle, SQLite) and any filter constraints (blocked chars, WAF)."
    ),
    "ssrf": (
        "Server-side request forgery means the server fetches a URL you influence. Target internal "
        "services, cloud instance metadata endpoints, alternative schemes (file, gopher, dict, sftp, "
        "tftp) and filter bypasses (IP encodings, DNS names, redirects, parser discrepancies)."
    ),
    "idor": (
        "Insecure direct object reference means a user-supplied identifier selects an object without "
        "an ownership/authorization check. Craft the exact identifier tamper (increment, decode and "
        "re-encode, predict, wildcard, method or content-type change) that returns another principal's object."
    ),
    "open_redirect": (
        "Open redirect means a user-controllable value makes the application or browser navigate to an "
        "attacker-controlled host. Craft the URL value that survives the observed validation "
        "(whitelist, scheme, slash, dot, character filters) and still points at the attacker host."
    ),
}


def system_prompt(vuln_class: str) -> str:
    return (
        f"You are a specialist security researcher focused exclusively on {vuln_class} vulnerabilities. "
        f"{CLASS_BRIEF[vuln_class]} "
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
        obj = json.loads(msgs[2]["content"])
        expected_keys = [
            "vuln_class", "target_param", "payload", "injection_point",
            "expected_success_signal", "confidence", "reasoning",
        ]
        assert list(obj.keys()) == expected_keys, f"bad keys: {list(obj.keys())}"
        assert obj["vuln_class"] == vuln_class
        assert obj["injection_point"] in {"query", "body", "header", "cookie", "path"}
        assert 0.0 <= obj["confidence"] <= 1.0
        key = (obj["target_param"], obj["payload"])
        assert key not in seen, f"duplicate example: {key}"
        seen.add(key)


def main():
    datasets = {
        "sqli": "data_sqli",
        "ssrf": "data_ssrf",
        "idor": "data_idor",
        "open_redirect": "data_open_redirect",
    }
    sys.path.insert(0, HERE)
    total = 0
    for vuln_class, module_name in datasets.items():
        module = importlib.import_module(module_name)
        examples = [build_example(vuln_class, row) for row in module.EXAMPLES]
        validate(examples, vuln_class)
        out_path = os.path.join(HERE, f"{vuln_class}_training_data.jsonl")
        with open(out_path, "w", encoding="utf-8") as fh:
            for ex in examples:
                fh.write(json.dumps(ex, ensure_ascii=False) + "\n")
        size_kb = os.path.getsize(out_path) / 1024
        print(f"{vuln_class:<14} {len(examples):>4} examples -> {out_path} ({size_kb:.1f} KB)")
        total += len(examples)
    print(f"TOTAL: {total} examples")


if __name__ == "__main__":
    main()
