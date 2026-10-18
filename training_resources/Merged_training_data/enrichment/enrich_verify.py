#!/usr/bin/env python3
"""Gate 1 for enrichment candidates: mechanical verification.

- payload must be VERBATIM member of the class's existing verified payload set
- schema/enum/confidence sanity
- dedup vs existing merged rows and within candidates
Outputs accepted_candidates.json + a review dump.
"""
import glob
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
MERGED = os.path.dirname(HERE)

CLASS_FILE = {
    "sqli": "sqli_merged_training_data.jsonl",
    "ssrf": "ssrf_merged_training_data.jsonl",
    "idor": "idor_merged_training_data.jsonl",
    "open_redirect": "open_redirect_merged_training_data.jsonl",
    "xss_reflected": "xss_reflected_merged_training_data.jsonl",
}
ASSISTANT_KEYS = ["vuln_class", "target_param", "payload", "injection_point",
                  "expected_success_signal", "confidence", "reasoning"]
VARIANT_KEYS = ["endpoint", "target_param", "recon_evidence", "planner_rationale",
                "vuln_class", "payload", "injection_point",
                "expected_success_signal", "confidence", "reasoning"]
INJ = {"query", "body", "header", "cookie", "path"}

def load_existing(cls):
    rows = [json.loads(l) for l in open(os.path.join(MERGED, CLASS_FILE[cls]), encoding="utf-8") if l.strip()]
    payloads = set()
    keys = set()
    for r in rows:
        a = json.loads(r["messages"][2]["content"])
        payloads.add(a["payload"])
        keys.add((a["target_param"], a["payload"]))
    return rows, payloads, keys

def user_msg(v):
    return (f"Endpoint: {v['endpoint']}\n"
            f"Target parameter(s): {v['target_param']}\n"
            f"Recon evidence: {v['recon_evidence']}\n"
            f"Planner's rationale: {v['planner_rationale']}")

def check(v, cls, payloads, seen_keys):
    errs = []
    if sorted(v.keys()) != sorted(VARIANT_KEYS):
        errs.append(f"keys mismatch: {list(v.keys())}")
        return errs, None
    if v["vuln_class"] != cls:
        errs.append(f"vuln_class={v['vuln_class']}")
    if v["payload"] not in payloads:
        errs.append("PAYLOAD NOT IN WHITELIST")
    if v["injection_point"] not in INJ:
        errs.append(f"injection_point={v['injection_point']}")
    if not isinstance(v["confidence"], (int, float)) or not (0.5 <= v["confidence"] <= 0.95):
        errs.append(f"confidence={v['confidence']}")
    for f, lo in (("endpoint", 6), ("recon_evidence", 30), ("planner_rationale", 15),
                  ("expected_success_signal", 10), ("reasoning", 60)):
        if not isinstance(v[f], str) or len(v[f].strip()) < lo:
            errs.append(f"{f} too short/empty")
    if re.search(r"^(as an ai|i cannot|sorry)", str(v["reasoning"]), re.I):
        errs.append("refusal text")
    key = (v["target_param"], v["payload"])
    if key in seen_keys:
        errs.append("duplicate (target_param,payload)")
    return errs, key

def main():
    stats = {}
    accepted = []
    seen_keys_all = {}
    review_lines = []
    for cls in CLASS_FILE:
        _, payloads, keys = load_existing(cls)
        seen = set(keys)
        n_raw = n_ok = 0
        for path in sorted(glob.glob(os.path.join(HERE, "raw", f"{cls}_*.json"))):
            rec = json.load(open(path, encoding="utf-8"))
            for v in rec.get("variants", []):
                n_raw += 1
                errs, key = check(v, cls, payloads, seen)
                if errs:
                    review_lines.append(f"REJECT {rec['key']} | {'; '.join(errs)[:120]} | payload={str(v.get('payload'))[:60]}")
                    continue
                seen.add(key)
                accepted.append({"class": cls, "batch": rec["key"], "model": rec["model"], "variant": v})
                review_lines.append(
                    f"OK    {rec['key']:<18} {v['endpoint'][:40]:<42} param={v['target_param'][:18]:<18} "
                    f"conf={v['confidence']:.2f} payload={v['payload'][:55]}")
                n_ok += 1
        stats[cls] = (n_raw, n_ok)
        print(f"{cls:<14} raw variants: {n_raw:>3} | passed gates: {n_ok:>3}")

    json.dump(accepted, open(os.path.join(HERE, "accepted_candidates.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    with open(os.path.join(HERE, "review_dump.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(review_lines) + "\n")
    total_raw = sum(a for a, _ in stats.values())
    total_ok = sum(b for _, b in stats.values())
    print(f"\nTOTAL raw: {total_raw} | passed: {total_ok} -> accepted_candidates.json + review_dump.txt")

if __name__ == "__main__":
    main()
