#!/usr/bin/env python3
"""Diff cujanovic Open-Redirect payload list against the PATT Intruder list (ground truth),
categorize what is new, and print technically-reviewable samples."""
import collections, os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

patt = set()
p = os.path.join(REPO, "Open Redirect", "Intruder", "Open-Redirect-payloads.txt")
for line in open(p, encoding="utf-8", errors="replace"):
    if line.strip():
        patt.add(line.strip())

cuj = []
p = os.path.join(HERE, "Open-Redirect-Payloads", "Open-Redirect-payloads.txt")
for line in open(p, encoding="utf-8", errors="replace"):
    s = line.strip()
    if s and not s.startswith("#"):
        cuj.append(s)

new = [x for x in dict.fromkeys(cuj) if x not in patt]
print(f"PATT: {len(patt)} | cujanovic uniq: {len(set(cuj))} | new: {len(new)}")

BSLASH = chr(92)

def cat(s):
    lo = s.lower()
    if lo.count("%") >= 4 or "%25" in lo:
        return "heavy-encoding"
    if BSLASH + "x" in lo or BSLASH + "u" in lo or BSLASH + "1" in lo:
        return "escape-seq"
    if "javascript" in lo:
        return "js-scheme"
    if "whitelisteddomain" in lo or "@" in s:
        return "at-userinfo"
    if s.startswith("//") or s.startswith("/") or s.startswith("http") or s.startswith(BSLASH):
        return "structural"
    return "other"

c = collections.Counter(cat(x) for x in new)
print(c)

print("--- structural/other samples (up to 40):")
n = 0
for x in new:
    if cat(x) in ("structural", "other") and n < 40:
        print("  ", x)
        n += 1
