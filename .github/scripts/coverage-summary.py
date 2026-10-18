#!/usr/bin/env python3
"""Print a Markdown table of JaCoCo line and branch coverage for every module that produced a report."""
import csv
import glob
import os

rows = []
totals = [0, 0, 0, 0]
for path in sorted(glob.glob("*/target/site/jacoco/jacoco.csv")):
    module = path.split(os.sep)[0]
    with open(path, newline="") as f:
        records = list(csv.DictReader(f))
    lm = sum(int(r["LINE_MISSED"]) for r in records)
    lc = sum(int(r["LINE_COVERED"]) for r in records)
    bm = sum(int(r["BRANCH_MISSED"]) for r in records)
    bc = sum(int(r["BRANCH_COVERED"]) for r in records)
    if not module.startswith("sample-"):
        totals = [t + v for t, v in zip(totals, (lm, lc, bm, bc))]
    rows.append((module, lc, lc + lm, bc, bc + bm))


def pct(covered, total):
    return f"{100 * covered / total:.1f}%" if total else "n/a"


print("### Coverage")
print()
print("| Module | Lines | Branches |")
print("| --- | ---: | ---: |")
for module, lc, lt, bc, bt in rows:
    print(f"| {module} | {pct(lc, lt)} ({lc}/{lt}) | {pct(bc, bt)} ({bc}/{bt}) |")
lm, lc, bm, bc = totals
print(f"| **Libraries** | **{pct(lc, lc + lm)}** | **{pct(bc, bc + bm)}** |")
