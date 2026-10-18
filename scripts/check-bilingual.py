#!/usr/bin/env python3
"""C-1: the English and Chinese reference documents stay in step.

Checks, for docs/reference/*.md and docs/reference/zh/*.md:
  - the file sets are equal;
  - each pair has the same number of markdown headings.

Exit 0 when in step, 1 otherwise.  Run from the repository root:
    python3 scripts/check-bilingual.py
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
EN = ROOT / "docs" / "reference"
ZH = EN / "zh"


def headings(p: pathlib.Path) -> int:
    return sum(1 for line in p.read_text(encoding="utf-8").splitlines() if line.startswith("#"))


def main() -> int:
    en = {p.name for p in EN.glob("*.md")}
    zh = {p.name for p in ZH.glob("*.md")}
    problems: list[str] = []

    for name in sorted(en - zh):
        problems.append(f"missing zh/{name}")
    for name in sorted(zh - en):
        problems.append(f"extra zh/{name}")
    for name in sorted(en & zh):
        a, b = headings(EN / name), headings(ZH / name)
        if a != b:
            problems.append(f"heading count differs for {name}: en={a} zh={b}")

    if problems:
        print("bilingual check FAILED")
        for p in problems:
            print("  " + p)
        return 1
    print(f"bilingual check OK: {len(en)} pairs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
