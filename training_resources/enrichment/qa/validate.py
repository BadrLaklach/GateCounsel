#!/usr/bin/env python3
"""QA gate for opencode-generated enrichment candidates.

Stages:
  1. Structure: every line must be a valid 3-message record; assistant content must parse
     as JSON with the exact 7-key contract (order enforced), enum + confidence range checks.
  2. Normalization: the system prompt is replaced with the canonical per-class prompt
     (constant per class, so normalizing cannot lose scenario information).
  3. Dedup: exact (target_param, payload) and fuzzy payload token-Jaccard >= 0.8 against
     the same-class existing merged data, earlier accepted candidates, and within-file.

Outputs (under training_resources/enrichment/):
  filtered/<cls>_candidates.jsonl  — records that passed, one per line (line numbers are
                                     what the cross-model review references)
  qa_report.json                   — per-class counts + every rejection with reason
  provenance.json                  — source run id per accepted line number

Run:  python training_resources/enrichment/qa/validate.py
"""

import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENRICH = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
MERGED = os.path.join(REPO, "training_resources", "Merged_training_data")
CAND = os.path.join(ENRICH, "candidates")
OUT = os.path.join(ENRICH, "filtered")

KEYS = ["vuln_class", "target_param", "payload", "injection_point",
        "expected_success_signal", "confidence", "reasoning"]
ENUM = {"query", "body", "header", "cookie", "path"}
JACCARD_LIMIT = 0.8

BASE = json.load(open(os.path.join(ENRICH, "specs", "base_prompts.json"), encoding="utf-8"))
CANON = {c: BASE[c]["system"] for c in ["sqli", "ssrf", "idor", "open_redirect", "xss_reflected"]}


def tokens(text: str) -> set:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def load_class_existing(cls: str) -> list:
    path = os.path.join(MERGED, f"{cls}_merged_training_data.jsonl")
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            obj = json.loads(rec["messages"][2]["content"])
            out.append(obj)
    return out


def check_record(rec: dict, cls: str):
    """Return (assistant_obj, errors, warnings)."""
    errs, warns = [], []
    msgs = rec.get("messages")
    if not isinstance(msgs, list) or len(msgs) != 3:
        return None, ["messages must be a list of 3"], warns
    if [m.get("role") for m in msgs] != ["system", "user", "assistant"]:
        return None, ["role sequence must be system,user,assistant"], warns
    for m in msgs:
        if not isinstance(m.get("content"), str) or not m["content"].strip():
            return None, ["every message content must be a non-empty string"], warns
    user = msgs[1]["content"]
    for label in ["Endpoint:", "Target parameter(s):", "Recon evidence:", "Planner's rationale:"]:
        if label not in user:
            errs.append(f"user message missing '{label}'")
    try:
        obj = json.loads(msgs[2]["content"])
    except Exception as e:
        return None, [f"assistant content is not valid JSON: {e}"], warns
    if list(obj.keys()) != KEYS:
        errs.append(f"assistant keys/order wrong: {list(obj.keys())}")
        return obj, errs, warns
    if obj["vuln_class"] != cls:
        errs.append(f"vuln_class={obj['vuln_class']!r} != {cls!r}")
    if obj["injection_point"] not in ENUM:
        errs.append(f"injection_point {obj['injection_point']!r} not in enum")
    if not isinstance(obj["confidence"], (int, float)) or not (0.0 <= obj["confidence"] <= 1.0):
        errs.append(f"confidence {obj['confidence']!r} out of range")
    for k in ["target_param", "payload", "expected_success_signal", "reasoning"]:
        if not str(obj.get(k, "")).strip():
            errs.append(f"{k} empty")
    if obj.get("target_param") and obj["target_param"].split()[0] not in user:
        warns.append("target_param not visible in user message")
    if "```" in msgs[2]["content"] or "```" in user:
        errs.append("markdown fence leaked into record")
    return obj, errs, warns


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    report = {}
    provenance = {}
    grand = {"accepted": 0, "rejected": 0}
    for cls in ["sqli", "ssrf", "idor", "open_redirect", "xss_reflected"]:
        existing = load_class_existing(cls)
        existing_payload_tokens = [tokens(o["payload"]) for o in existing]
        existing_keys = {(o["target_param"], o["payload"].strip().lower()) for o in existing}
        accepted, rejects, fixed_sys = [], [], 0
        seen_in_class = list(existing_keys)
        seen_tokens = list(existing_payload_tokens)
        for cand_path in sorted(glob.glob(os.path.join(CAND, f"{cls}_[ab].jsonl"))):
            run_id = re.search(r"_(a|b)\.jsonl$", cand_path).group(1)
            if not os.path.exists(cand_path):
                continue
            with open(cand_path, encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    tag = f"{cls}_{run_id}:{lineno}"
                    if not line.strip():
                        rejects.append({"src": tag, "reason": "blank line"})
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception as e:
                        rejects.append({"src": tag, "reason": f"line not valid JSON: {e}"})
                        continue
                    obj, errs, warns = check_record(rec, cls)
                    if obj is None or errs:
                        rejects.append({"src": tag, "reason": "; ".join(errs)})
                        continue
                    key = (obj["target_param"], obj["payload"].strip().lower())
                    if key in seen_in_class:
                        rejects.append({"src": tag, "reason": f"duplicate (target_param,payload) {key[0]}"})
                        continue
                    ptok = tokens(obj["payload"])
                    sim = max((jaccard(ptok, t) for t in seen_tokens), default=0.0)
                    if sim >= JACCARD_LIMIT:
                        rejects.append({"src": tag, "reason": f"near-duplicate payload (jaccard {sim:.2f})"})
                        continue
                    if rec["messages"][0]["content"] != CANON[cls]:
                        fixed_sys += 1
                        rec["messages"][0]["content"] = CANON[cls]
                    accepted.append(rec)
                    seen_in_class.add(key)
                    seen_tokens.append(ptok)
                    provenance[f"{cls}:{len(accepted)}"] = {
                        "run": f"{cls}_{run_id}", "file_line": lineno,
                        "warnings": warns,
                    }
        out_path = os.path.join(OUT, f"{cls}_candidates.jsonl")
        with open(out_path, "w", encoding="utf-8") as fh:
            for rec in accepted:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        report[cls] = {
            "accepted": len(accepted),
            "rejected": len(rejects),
            "system_prompts_normalized": fixed_sys,
            "existing_examples": len(existing),
            "rejects": rejects,
        }
        grand["accepted"] += len(accepted)
        grand["rejected"] += len(rejects)
        print(f"{cls:<14} accepted={len(accepted):>3}  rejected={len(rejects):>2}  "
              f"(existing={len(existing)}, sys-normalized={fixed_sys})")
    json.dump(report, open(os.path.join(ENRICH, "qa_report.json"), "w", encoding="utf-8"),
              indent=2, ensure_ascii=False)
    json.dump(provenance, open(os.path.join(ENRICH, "provenance.json"), "w", encoding="utf-8"),
              indent=2, ensure_ascii=False)
    print(f"TOTAL accepted={grand['accepted']} rejected={grand['rejected']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
