#!/usr/bin/env python3
"""Create cross-model review briefs for each class's filtered candidates.

Run AFTER qa/validate.py. Writes specs/review_<cls>.md; the reviewer model (always a
different free model than the two generators for that class) writes
reviews/<cls>_review.json with a strict verdict schema.

Run:  python training_resources/enrichment/qa/make_review_briefs.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ENRICH = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))

REVIEWERS = {
    "sqli": "opencode/beam-free",
    "ssrf": "opencode/longcat-2.5-preview-free",
    "idor": "opencode/nemotron-3-ultra-free",
    "open_redirect": "opencode/beam-free",
    "xss_reflected": "opencode/beam-free",
}

CLASS_FOCUS = {
    "sqli": ("SQL syntax must match the claimed DBMS exactly (MySQL/PostgreSQL/MSSQL/Oracle/SQLite errors, "
             "SLEEP vs pg_sleep vs WAITFOR DELAY, information_schema vs pg_catalog). UNION payloads need a "
             "plausible column count story. Check comment syntax -- vs # and quoting context (string vs numeric)."),
    "ssrf": ("URL notations must be valid (hex/octal IP forms, IPv6, scheme syntax). Metadata endpoints must be "
             "realistic (AWS IMDS paths, required headers). gopher/dict/file schemes must be used where the "
             "described backend plausibly supports them. Redirect/DNS-rebind reasoning must be coherent."),
    "idor": ("The evidence must describe an authorization gap, not just object access. Enumeration reasoning must "
             "be measurable (status codes, size diffs). Identifier formats must match the endpoint style."),
    "open_redirect": ("Payload must actually evade the filter described in the evidence (scheme-relative, userinfo, "
                      "backslash, encoding tricks must be syntactically valid). DOM cases must name a real sink. "
                      "OAuth cases must keep redirect_uri semantics plausible."),
    "xss_reflected": ("The payload must break out of the exact reflection context described in the evidence "
                      "(attribute quotes, JS string, template literal, raw HTML). Event handlers must be real HTML. "
                      "Encoding/namespace bypasses must be syntactically correct."),
}

BRIEF = """# Review task: vet {n} candidate training records for "{cls}"

You are the independent reviewer in a data-quality pipeline for GateCounsel, an academic
defensive-security project. Another model generated the file below; your job is to find
records that are technically wrong, unrealistic, or duplicated, so only sound examples
reach the training set.

## File under review (read it fully)

`training_resources/enrichment/filtered/{cls}_candidates.jsonl` — {n} lines, one JSON record per line.

Each record: messages=[system, user, assistant]; the assistant content is a JSON string with
vuln_class, target_param, payload, injection_point, expected_success_signal, confidence, reasoning.

## Class-specific technical bar

{focus}

## General bar (apply to every line)

1. **Payload correctness** — the payload is technically valid and is the right move for the context the evidence describes. A payload that cannot work as described is a reject.
2. **Signal realism** — expected_success_signal describes an observable effect (response body, status, timing, error, DNS/browser behaviour) that this payload would plausibly produce.
3. **Evidence realism & consistency** — recon evidence reads like a real observation and is consistent with the endpoint, parameter and injection_point; nothing self-contradictory.
4. **Confidence calibration** — strong evidence carries high confidence, weak/exploratory evidence carries lower; a 0.9 on vague evidence is a reject-level miscalibration.
5. **Reasoning accuracy** — no technical falsehoods; 1-3 sentences, actually justifies the payload.
6. **Duplication** — near-duplicate payloads or the same scenario re-hashed across lines (flag the weaker copy).
7. **Safety framing** — records describe testing of fictional/lab applications; reject any record naming real third-party targets or real credentials.

Reject only with a concrete technical justification. If something is minor (typo-level) or you
are simply unsure, put it in `concerns` instead of rejecting.

## Output file (write ONLY this file)

`training_resources/enrichment/reviews/{cls}_review.json` — JSON object, exactly:

{{"line": <int>, "verdict": "accept"|"reject", "reason": "<one sentence>", "issues": ["<optional short issue tags>"]}}

One entry per input line (all {n} lines, in order). Write compact JSON (one entry per line is fine).
Then finish with a one-paragraph summary of overall quality in your final message.
"""


def main() -> None:
    os.makedirs(os.path.join(ENRICH, "reviews"), exist_ok=True)
    for cls, model in REVIEWERS.items():
        path = os.path.join(ENRICH, "filtered", f"{cls}_candidates.jsonl")
        if not os.path.exists(path):
            print(f"skip {cls}: no filtered file yet")
            continue
        with open(path, encoding="utf-8") as fh:
            n = sum(1 for line in fh if line.strip())
        if n == 0:
            print(f"skip {cls}: 0 records")
            continue
        brief = BRIEF.format(cls=cls, n=n, focus=CLASS_FOCUS[cls])
        out = os.path.join(ENRICH, "specs", f"review_{cls}.md")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(brief)
        print(f"wrote specs/review_{cls}.md  lines={n}  reviewer={model}")


if __name__ == "__main__":
    main()
