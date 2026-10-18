#!/usr/bin/env python3
"""Apply reviewed enrichment: append accepted variants to the merged JSONLs,
drop review-rejected candidates, and remove three defective seed rows found
during review (documented in ENRICHMENT.md)."""
import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
MERGED = os.path.dirname(HERE)

# review rejections (identified by stable content signatures)
def rejected(cls, v):
    p = v["payload"]
    if cls == "sqli" and "AND SELECT SUBSTR" in p:
        return "invalid SQL payload (AND SELECT ...)"
    if cls == "sqli" and v["injection_point"] == "cookie" and "EXTRACTVALUE(1337,CONCAT" in p:
        return "evidence contradicts error-based choice (generic 500 handler)"
    if cls == "ssrf" and p.startswith("GET @evildomain"):
        return "raw request-line payload mismatched with parameter scenario"
    if cls == "ssrf" and "chain: 302" in p:
        return "payload is descriptive prose, not a URL"
    if cls == "ssrf" and "%2561dmin" in p:
        return "evidence states the encoded form was blocked (contradiction)"
    if cls == "idor" and p == "/api/user/1233":
        return "payload path does not match the scenario endpoint"
    return None

# defective seed rows discovered in the existing merged data during review
BAD_SEEDS = {
    "ssrf": [
        lambda p: p.startswith("GET @evildomain") or "chain: 302" in p,
    ],
    "sqli": [
        lambda p: "AND SELECT SUBSTR" in p,
    ],
}

def main():
    accepted = json.load(open(os.path.join(HERE, "accepted_candidates.json"), encoding="utf-8"))
    per_class = {}
    n_rej = 0
    for a in accepted:
        r = rejected(a["class"], a["variant"])
        if r:
            n_rej += 1
            print(f"review-reject {a['class']:<14} {a['variant']['endpoint'][:45]:<47} {r}")
            continue
        per_class.setdefault(a["class"], []).append(a)

    summary = []
    for cls, items in per_class.items():
        path = os.path.join(MERGED, f"{cls}_merged_training_data.jsonl")
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        system = rows[0]["messages"][0]["content"]
        existing_keys = set()
        kept = []
        removed_seeds = 0
        for row in rows:
            a = json.loads(row["messages"][2]["content"])
            if cls in BAD_SEEDS and any(f(a["payload"]) for f in BAD_SEEDS[cls]):
                removed_seeds += 1
                continue
            existing_keys.add((a["target_param"], a["payload"]))
            kept.append(row)
        added = 0
        for a in items:
            v = a["variant"]
            if (v["target_param"], v["payload"]) in existing_keys:
                continue
            existing_keys.add((v["target_param"], v["payload"]))
            user = (f"Endpoint: {v['endpoint']}\n"
                    f"Target parameter(s): {v['target_param']}\n"
                    f"Recon evidence: {v['recon_evidence']}\n"
                    f"Planner's rationale: {v['planner_rationale']}")
            assistant_obj = {
                "vuln_class": v["vuln_class"], "target_param": v["target_param"],
                "payload": v["payload"], "injection_point": v["injection_point"],
                "expected_success_signal": v["expected_success_signal"],
                "confidence": v["confidence"], "reasoning": v["reasoning"],
            }
            kept.append({"messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
                {"role": "assistant", "content": json.dumps(assistant_obj, ensure_ascii=False)},
            ]})
            added += 1
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for row in kept:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        summary.append((cls, len(rows), added, removed_seeds, len(kept)))
        print(f"{cls:<14} before={len(rows):>3} +{added:>2} -{removed_seeds} bad-seeds -> {len(kept)}")

    print(f"\nreview-rejected candidates: {n_rej}")
    print("per-class (before, added, bad-seeds removed, after):")
    for s in summary:
        print("  ", s)

if __name__ == "__main__":
    main()
