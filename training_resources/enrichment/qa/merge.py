#!/usr/bin/env python3
"""Final gate: apply model-review verdicts + my manual overrides, append survivors to
the merged per-class datasets, and write a manifest.

Inputs:
  filtered/<cls>_candidates.jsonl   (from qa/validate.py — line numbers 1-based)
  reviews/<cls>_review.json         (from the cross-model review run)
  manual_review.json                (optional, mine: {"<cls>": {"<line>": "reason"}} )

Behavior:
  - A line is appended only if the model review accepts it AND it is not in manual_review.
  - The merged file is rewritten as: original records first (unchanged), then appended
    records in line order. A backup of the original is kept in backups/.
  - manifest.json records per-class existing/appended/final counts, provenance of every
    appended line, and every rejection with its reason.

Run:  python training_resources/enrichment/qa/merge.py [--dry-run]
"""

import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENRICH = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
MERGED = os.path.join(REPO, "training_resources", "Merged_training_data")
CLASSES = ["sqli", "ssrf", "idor", "open_redirect", "xss_reflected"]


def load_review(path: str) -> dict:
    """Return {line:int -> verdict dict}; tolerates bare arrays or wrapped shapes."""
    data = json.load(open(path, encoding="utf-8"))
    entries = None
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        for k in ("verdicts", "entries", "reviews", "results", "lines"):
            if isinstance(data.get(k), list):
                entries = data[k]
                break
    if entries is None:
        raise ValueError(f"unrecognized review shape in {path}: top-level keys "
                         f"{list(data)[:5] if isinstance(data, dict) else type(data)}")
    out = {}
    for e in entries:
        try:
            out[int(e["line"])] = e
        except (KeyError, TypeError, ValueError):
            continue
    return out


def main() -> int:
    dry = "--dry-run" in sys.argv
    manual_path = os.path.join(ENRICH, "manual_review.json")
    manual = json.load(open(manual_path, encoding="utf-8")) if os.path.exists(manual_path) else {}
    prov = json.load(open(os.path.join(ENRICH, "provenance.json"), encoding="utf-8"))
    manifest = {"dry_run": dry, "classes": {}}
    total_appended = 0

    for cls in CLASSES:
        cand_path = os.path.join(ENRICH, "filtered", f"{cls}_candidates.jsonl")
        review_path = os.path.join(ENRICH, "reviews", f"{cls}_review.json")
        merged_path = os.path.join(MERGED, f"{cls}_merged_training_data.jsonl")
        if not os.path.exists(cand_path):
            manifest["classes"][cls] = {"skipped": "no candidates"}
            continue
        lines = [l for l in open(cand_path, encoding="utf-8").read().splitlines() if l.strip()]
        review = load_review(review_path) if os.path.exists(review_path) else {}
        my_rej = manual.get(cls, {})

        accepted, rejected = [], []
        for i, line in enumerate(lines, 1):
            v = review.get(i)
            if my_rej and str(i) in my_rej:
                rejected.append({"line": i, "by": "me", "reason": my_rej[str(i)]})
            elif v is None:
                rejected.append({"line": i, "by": "no-verdict", "reason": "review missing a verdict"})
            elif v.get("verdict") == "reject":
                rejected.append({"line": i, "by": "model-review",
                                 "reason": v.get("reason", "unspecified")})
            else:
                accepted.append((i, line))
        existing = open(merged_path, encoding="utf-8").read()
        existing_lines = [l for l in existing.splitlines() if l.strip()]
        if not dry:
            bdir = os.path.join(ENRICH, "backups")
            os.makedirs(bdir, exist_ok=True)
            shutil.copy2(merged_path, os.path.join(bdir, f"{cls}_merged_training_data.jsonl.bak"))
            with open(merged_path, "w", encoding="utf-8") as fh:
                fh.write(existing.rstrip("\n") + "\n")
                for _, line in accepted:
                    fh.write(line + "\n")
        appended_prov = {str(i): prov.get(f"{cls}:{i}") for i, _ in accepted}
        manifest["classes"][cls] = {
            "existing": len(existing_lines),
            "appended": len(accepted),
            "final": len(existing_lines) + len(accepted),
            "rejected": rejected,
            "appended_provenance": appended_prov,
        }
        total_appended += len(accepted)
        print(f"{cls:<14} existing={len(existing_lines):>3}  +{len(accepted):>2}  "
              f"final={len(existing_lines)+len(accepted):>3}  model-rejects="
              f"{sum(1 for r in rejected if r['by']=='model-review')}, mine={len(my_rej)}")

    manifest["total_appended"] = total_appended
    out = os.path.join(ENRICH, "manifest.json")
    if not dry:
        json.dump(manifest, open(out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"manifest -> {out}")
    print(f"TOTAL appended {'(dry-run) ' if dry else ''}= {total_appended}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
