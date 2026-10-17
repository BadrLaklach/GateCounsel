#!/usr/bin/env python3
"""Round 2 pipeline step 1: fetch reports ranked 13-30 per class, cross-check IDs,
prefilter obviously thin files (program-summary-only disclosures)."""
import csv, json, os, re, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
IDX = {
    "idor": "h1/insecure-direct-object-reference-idor.md",
    "ssrf": "h1/server-side-request-forgery-ssrf.md",
    "sqli": "h1/sql-injection.md",
    "open_redirect": "h1/open-redirect.md",
}

def index_ids(path, lo, hi):
    ids = []
    for line in open(os.path.join(HERE, path), encoding="utf-8"):
        m = re.search(r"\[(\d+)\]\(\.\./reports/\1\.md\)", line)
        if m:
            ids.append(m.group(1))
    return ids[lo:hi]  # ranks are 1-based; rows 13..30 => slice(12,30)

# independent confirmation set
confirmed = set()
with open(os.path.join(HERE, "reddelexc.csv"), encoding="utf-8", errors="replace") as fh:
    for row in csv.DictReader(fh):
        try:
            confirmed.add(int(row["link"].rsplit("/", 1)[1]))
        except (ValueError, IndexError, KeyError):
            pass

plan = {}
for cls, path in IDX.items():
    ids = index_ids(path, 12, 30)
    plan[cls] = ids
    print(cls, "ranks 13-30:", ids)

manifest = {}
os.makedirs(os.path.join(HERE, "h1", "round2"), exist_ok=True)
for cls, ids in plan.items():
    for rid in ids:
        out = os.path.join(HERE, "h1", "round2", f"{cls}_{rid}.md")
        url = f"https://raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/reports/{rid}.md"
        subprocess.run(["curl", "-s", "--max-time", "30", "-o", out, url], check=False)
        ok_id = int(rid) in confirmed
        size = os.path.getsize(out) if os.path.exists(out) else 0
        thin = False
        if size > 0:
            try:
                body = open(out, encoding="utf-8", errors="replace").read()
            except OSError:
                body = ""
            thin = ("No vulnerability information available" in body) or (len(body) < 1200)
        manifest[f"{cls}_{rid}"] = {
            "id": rid, "class": cls, "size": size,
            "confirmed_independent": ok_id, "thin_prefilter": thin,
        }

json.dump(manifest, open(os.path.join(HERE, "round2_manifest.json"), "w"), indent=1)
good = [k for k, v in manifest.items() if v["confirmed_independent"] and not v["thin_prefilter"] and v["size"] > 0]
print("\ndownloaded:", len(manifest),
      "| independently confirmed:", sum(1 for v in manifest.values() if v["confirmed_independent"]),
      "| thin-prefiltered out:", sum(1 for v in manifest.values() if v["thin_prefilter"]),
      "| candidates for extraction:", len(good))
print("candidates:", good)
