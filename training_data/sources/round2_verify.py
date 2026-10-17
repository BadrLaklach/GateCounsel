#!/usr/bin/env python3
"""Round 2 pipeline step 3: verify agent extractions against ground-truth files.

For every non-null field the agent claimed to quote verbatim, confirm the
whitespace-normalized string actually appears in the source report file.
A report is USABLE only if: quality=='good' AND payload verifies AND endpoint verifies.
"""
import glob
import json
import os
import re
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))

def norm(s):
    if not isinstance(s, str):
        return None
    s = unicodedata.normalize("NFC", s)
    s = s.replace("`", "").replace("*", "")
    s = re.sub(r"\s+", " ", s).strip()
    return s

def field_in_file(field, body):
    f = norm(field)
    if not f:
        return False
    b = norm(body)
    return f in b

results = {}
for path in sorted(glob.glob(os.path.join(HERE, "round2_extractions", "*.json"))):
    key = os.path.basename(path)[:-5]
    rec = json.load(open(path, encoding="utf-8"))
    src = os.path.join(HERE, "h1", "round2", f"{key}.md")
    body = open(src, encoding="utf-8", errors="replace").read() if os.path.exists(src) else ""

    field_verdicts = {}
    for f in ("title", "endpoint", "param", "payload", "evidence", "signal"):
        v = rec.get(f)
        if v is None or (isinstance(v, str) and not v.strip()):
            field_verdicts[f] = "absent"
        else:
            field_verdicts[f] = "PASS" if field_in_file(v, body) else "FAIL"

    usable = (
        rec.get("quality") == "good"
        and field_verdicts.get("payload") == "PASS"
        and field_verdicts.get("endpoint") == "PASS"
    )
    results[key] = {
        "model": rec.get("model"),
        "quality": rec.get("quality"),
        "fields": field_verdicts,
        "usable": usable,
    }
    mark = "USABLE" if usable else "reject"
    fails = ",".join(f for f, v in field_verdicts.items() if v == "FAIL")
    print(f"{key:<22} {str(rec.get('quality')):<5} {mark:<7} "
          f"{'quote-fails: ' + fails if fails else 'all quotes verified'}")

n = len(results)
usable = [k for k, v in results.items() if v["usable"]]
qfail = [k for k, v in results.items() if any(x == "FAIL" for x in v["fields"].values())]
print(f"\ntotal: {n} | usable: {len(usable)} | with >=1 failed quote: {len(qfail)}")
print("usable keys:", usable)
json.dump(results, open(os.path.join(HERE, "round2_verify.json"), "w"), indent=1)
