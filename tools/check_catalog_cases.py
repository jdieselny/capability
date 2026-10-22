#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
"""Check the catalog corpus and its cross-language evidence.

This is the §10 acceptance entry point.  It runs the two checks that make the
catalog corpus meaningful:

1. the checked-in corpus is exactly what scripts/gen-catalog-vectors.py emits
   (digests are content addresses, so a hand edit must not be silently stale);
2. Go, Python and TypeScript reach the same verdict and reason for every vector,
   and the checked-in evidence files match (contrib/catalog/run.py --check).

Usage: python3 tools/check_catalog_cases.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> int:
    print("$ " + " ".join(command))
    result = subprocess.run(command, cwd=ROOT, check=False)
    return result.returncode


def main() -> int:
    steps = [
        [sys.executable, "scripts/gen-catalog-vectors.py", "--check"],
        [sys.executable, "contrib/catalog/run.py", "--check"],
    ]
    for step in steps:
        code = run(step)
        if code != 0:
            return code
    print("catalog cases OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
