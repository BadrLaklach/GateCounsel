#!/usr/bin/env python3
"""Round 3 pipeline step 1: fetch reports ranked 31-55 per class, cross-check IDs,
prefilter thin files."""
import csv, json, os, re, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROUND = "round3"
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
    return ids[lo:hi]

confirmed = set()
with open(os.path.join(HERE, "reddelexc.csv"), encoding="utf-8", errors="replace") as fh:
    for row in csv.DictReader(fh):
        try:
            confirmed.add(int(row["link"].rsplit("/", 1)[1]))
        except (ValueError, IndexError, KeyError):
            pass

os.makedirs(os.path.join(HERE, "h1", ROUND), exist_ok=True)
manifest = {}
for cls, path in IDX.items():
    ids = index_ids(path, 30, 55)
    print(cls, "ranks 31-55:", len(ids), "ids")
    for rid in ids:
        out = os.path.join(HERE, "h1", ROUND, f"{cls}_{rid}.md")
        url = f"https://raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/reports/{rid}.md"
        subprocess.run(["curl", "-s", "--max-time", "30", "-o", out, url], check=False)
        ok_id = int(rid) in confirmed
        size = os.path.getsize(out) if os.path.exists(out) else 0
        thin = False
        if size > 0:
            body = open(out, encoding="utf-8", errors="replace").read()
            thin = ("No vulnerability information available" in body) or (len(body) < 1200)
        manifest[f"{cls}_{rid}"] = {
            "id": rid, "class": cls, "size": size,
            "confirmed_independent": ok_id, "thin_prefilter": thin,
        }

json.dump(manifest, open(os.path.join(HERE, f"{ROUND}_manifest.json"), "w"), indent=1)
good = [k for k, v in manifest.items() if v["confirmed_independent"] and not v["thin_prefilter"] and v["size"] > 0]
print(f"\ndownloaded: {len(manifest)} | confirmed: {sum(1 for v in manifest.values() if v['confirmed_independent'])} "
      f"| thin: {sum(1 for v in manifest.values() if v['thin_prefilter'])} | candidates: {len(good)}")
json.dump(good, open(os.path.join(HERE, f"{ROUND}_candidates.json"), "w"))
print("candidates:", good)
