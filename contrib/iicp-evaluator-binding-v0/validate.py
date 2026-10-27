#!/usr/bin/env python3
"""Validate the v0 external-evaluator binding draft.

Checks every result against management-evaluator-result-v0.schema.json, then
applies the composition rules from issue #168 and compares the computed
outcome with each case's normative expectation.

No network, no dependencies beyond jsonschema.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "management-evaluator-result-v0.schema.json"
CASES = HERE / "management-evaluator-binding-cases-v0.json"

BINDING_FIELDS = (
    "request_digest",
    "action",
    "target",
    "audience",
    "administrative_domain",
    "policy_generation",
)


def evaluate(case: dict) -> tuple[str, list[str], list[str]]:
    """Return (outcome, reason_codes, evidence_digests)."""
    result = case["result"]
    expected_binding = case["request"]

    if result["evaluator"]["profile_version"] not in case["accepted_profile_versions"]:
        return "reject", ["IICP-EVAL-PROFILE-UNSUPPORTED"], []

    if case["now"] >= result["freshness"]["expires_at"]:
        return "reject", ["IICP-EVAL-STALE"], []
    if result["freshness"]["issued_at"] > case["now"]:
        return "reject", ["IICP-EVAL-NOT-YET-VALID"], []

    for field in BINDING_FIELDS:
        if result["binding"][field] != expected_binding[field]:
            return "reject", ["IICP-EVAL-BINDING-MISMATCH"], []

    if case["local_decision"] == "deny":
        return "deny", ["IICP-LOCAL-DENY"], []

    if result["decision"] == "deny":
        return "deny", ["IICP-EVAL-DENY"], []

    if case["local_decision"] == "allow_unresolved":
        return "allow_unresolved", ["IICP-LOCAL-UNRESOLVED"], []

    if result["decision"] == "allow_unresolved":
        resolver = case.get("downstream", {}).get("resolved_by")
        bound = [item for item in result["unresolved"] if item.get("responsible_component")]
        if not resolver or len(bound) != len(result["unresolved"]):
            return "reject", ["IICP-EVAL-UNRESOLVED-UNBOUND"], []
        return "allow_unresolved", ["IICP-EVAL-UNRESOLVED"], []

    understood = set(case.get("understood_extensions", []))
    codes = ["IICP-EVAL-ALLOW"]
    for ext in result["extensions"]:
        if ext["id"] in understood:
            continue
        if ext["class"].startswith("REQUIRED_"):
            return "reject", ["IICP-EVAL-EXTENSION-REQUIRED-UNKNOWN"], []
        codes.append("IICP-EVAL-EXTENSION-IGNORED")

    evidence = [item["digest"] for item in result["evidence"]]
    return "allow", codes, evidence


def main() -> int:
    schema = json.loads(SCHEMA.read_text())
    document = json.loads(CASES.read_text())
    validator = Draft202012Validator(schema)

    failures = 0
    cases = document["cases"]
    ids = [case["id"] for case in cases]
    if len(ids) != len(set(ids)):
        print("duplicate case ids")
        return 1

    for case in cases:
        errors = sorted(validator.iter_errors(case["result"]), key=lambda e: list(e.path))
        if errors:
            failures += 1
            print(f"FAIL {case['id']}: schema")
            for error in errors[:3]:
                print(f"  {list(error.path)}: {error.message}")
            continue

        outcome, codes, evidence = evaluate(case)
        expected = case["expected"]
        problems = []
        if outcome != expected["outcome"]:
            problems.append(f"outcome {outcome!r} != {expected['outcome']!r}")
        if set(codes) != set(expected["reason_codes"]):
            problems.append(f"codes {codes} != {expected['reason_codes']}")
        if "evidence_digests" in expected and evidence != expected["evidence_digests"]:
            problems.append(f"evidence {evidence} != {expected['evidence_digests']}")

        if problems:
            failures += 1
            print(f"FAIL {case['id']}: " + "; ".join(problems))
        else:
            print(f"PASS {case['id']}: {outcome} {' '.join(codes)}")

    print(f"\n{len(cases) - failures}/{len(cases)} cases pass")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
