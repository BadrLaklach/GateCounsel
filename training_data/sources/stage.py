#!/usr/bin/env python3
"""Materialize a stage snapshot of the training_data data modules.

stage base   : files without any round blocks (PATT-grounded 176 examples)
stage round1 : base + '# --- verified from disclosed HackerOne reports' blocks
stage round2 : + '# --- round 2:' blocks
stage round3 : final files as-is (copy from backup)
"""
import os
import re
import shutil
import sys

BACKUP = os.path.join(os.environ["LOCALAPPDATA"], "Temp", "td_final")
TD = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FILES = ["data_sqli.py", "data_ssrf.py", "data_idor.py", "data_open_redirect.py"]

MARKER_ANY = re.compile(r"^    # --- .*(disclosed HackerOne reports|round [23]:)")

def is_round_marker(line):
    return bool(MARKER_ANY.match(line))
MARKER_R2 = "    # --- round 2:"
MARKER_R3 = "    # --- round 3:"

def cut_at_first(content, pred):
    lines = content.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if pred(line):
            return "".join(lines[:i]).rstrip("\n") + "\n]\n"
    raise SystemExit("marker not found")

def main():
    stage = sys.argv[1]
    for name in FILES:
        final = open(os.path.join(BACKUP, name), encoding="utf-8").read()
        if stage == "round3":
            out = final
        elif stage == "round2":
            out = cut_at_first(final, lambda l: l.startswith(MARKER_R3))
        elif stage == "round1":
            out = cut_at_first(final, lambda l: l.startswith(MARKER_R2))
        elif stage == "base":
            out = cut_at_first(final, is_round_marker)
        else:
            raise SystemExit(f"unknown stage {stage}")
        open(os.path.join(TD, name), "w", encoding="utf-8", newline="\n").write(out)
        print(f"{stage}: {name} -> {len(out.splitlines())} lines")

if __name__ == "__main__":
    main()
