#!/usr/bin/env python3
"""Language-neutral NativeCheckExpectation/NativeCheckAssessment probe (Python).

Only the inventory comparison is implemented: no CLC requirement evaluation and
no carrier-specific logic. The corpus is shared with the Go and TypeScript
runners.

Corpus path: CLC_NATIVE_CHECK_CASES, else the first argument.
"""

from __future__ import annotations

import json
import os
import sys


def key(entry):
    return (
        entry.get("checkId", ""),
        entry.get("componentType", ""),
        entry.get("evidenceDigest", ""),
    )


def assess(expected, results):
    """Mirror projection.AssessNativeChecks.

    An empty inventory is never complete. A duplicate expectation is reported
    as missing rather than silently deduplicated. Unexpected results are only
    counted when an inventory was declared.
    """
    outcomes = {}
    for result in results:
        outcomes.setdefault(key(result), set()).add(result.get("outcome", ""))

    expected_keys = set()
    missing = 0
    for want in expected:
        k = key(want)
        if k in expected_keys:
            missing += 1
            continue
        expected_keys.add(k)
        if not outcomes.get(k):
            missing += 1

    unexpected = 0
    if expected_keys:
        for result in results:
            if key(result) not in expected_keys:
                unexpected += 1

    conflicting = sum(1 for seen in outcomes.values() if len(seen) > 1)
    complete = bool(expected) and missing == 0 and unexpected == 0 and conflicting == 0
    return complete, missing, unexpected, conflicting


def main():
    path = os.environ.get("CLC_NATIVE_CHECK_CASES")
    if not path and len(sys.argv) > 1:
        path = sys.argv[1]
    if not path:
        print(
            "usage: probe.py <cases.json> (or CLC_NATIVE_CHECK_CASES)",
            file=sys.stderr,
        )
        return 2
    corpus = json.loads(open(path, encoding="utf-8").read())

    failures = 0
    for case in corpus["cases"]:
        complete, missing, unexpected, conflicting = assess(
            case.get("expected", []), case.get("results", [])
        )
        got = (
            f"complete={str(complete).lower()},missing={missing},"
            f"unexpected={unexpected},conflicting={conflicting}"
        )
        status = "PASS" if got == case["want"] else "FAIL"
        if status == "FAIL":
            failures += 1
        print(f"{status} {case['id']} {case['name']:<52} want={case['want']} got={got}")

    if failures:
        print(f"{failures} case(s) failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
