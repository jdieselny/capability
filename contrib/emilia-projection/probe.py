#!/usr/bin/env python3
"""Cross-language EMILIA binding projection probe (Python)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import sys
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURE = pathlib.Path(
    os.environ.get(
        "CLC_EMILIA_BINDING_FIXTURE",
        str(ROOT.parent / "register" / "cmd" / "emilia-projection-probe" /
            "testdata" / "emilia-binding-fixture-v1.json"),
    )
)
PY_DIR = pathlib.Path(
    os.environ.get(
        "CLC_PY_DIR",
        str(ROOT.parent / "aic-capability-demo"),
    )
)
sys.path.insert(0, str(PY_DIR))

import clc_semantics as clc  # noqa: E402
import evidence_semantics as evidence  # noqa: E402


def digest_object(value):
    canonical = clc.canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def relation_tuple(binding):
    subjects = sorted(target["subject"] for target in binding["targets"])
    issued_at = sorted(
        [binding["source"]["issued_at"]]
        + [target["issued_at"] for target in binding["targets"]]
    )
    return {
        "requirement_id": "treasury-wire-evidence@7",
        "policy_generation": binding["source"]["policy_generation"],
        "from": {
            "type": "policy-permit",
            "artifact_digest": digest_object(binding["source"]),
        },
        "relation": "permits",
        "to": {
            "type": "ep-quorum",
            "artifact_set_digest": digest_object(binding["targets"]),
        },
        "action_digest": digest_object(binding["action"]),
        "subjects": subjects,
        "trust": binding["trust"],
        "status_digest": digest_object(binding["status"]),
        "status_snapshot": binding["status"],
        "evidence_issued_at": issued_at,
    }


def binding_subject(binding):
    canonical = clc.canonical_json(relation_tuple(binding)).encode("utf-8")
    return base64.urlsafe_b64encode(
        hashlib.sha256(canonical).digest()
    ).rstrip(b"=").decode("ascii")


def mutate(binding, mutation):
    value = json.loads(json.dumps(binding))
    path = mutation["path"]
    current = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = mutation["value"]
    return value


def parse_instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def evidence_facts(case, now, subject):
    facts = []
    for role, entries in case["facts"].items():
        for entry in entries:
            facts.append({
                "type": role,
                "subject": subject if entry["subject"] == "$binding" else entry["subject"],
                "verified": entry["verified"],
                "issued_at": (
                    now - timedelta(seconds=entry["age_sec"])
                ).isoformat().replace("+00:00", "Z"),
            })
    return facts


def verdict_string(verdict, reason):
    return verdict + (("/" + reason) if reason else "")


def print_case(case_id, name, want, got, expected_got=None):
    status = "PASS" if got == (expected_got or want) else "FAIL"
    print(f"{status} {case_id} {name:<55} want={want} got={got}")


def main():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    now = parse_instant(fixture["now"])
    subject = binding_subject(fixture["binding"])
    binding_role = fixture["binding_role"]

    print("EMILIA → CLC evidence projection probe (Python)")
    print("fixture: register/cmd/emilia-projection-probe/testdata/"
          "emilia-binding-fixture-v1.json")
    print()

    print_case(
        "EMI-BIND-001",
        "base relation tuple has the pinned subject",
        fixture["expected_subject"],
        subject,
    )

    requirement = fixture["mapped_requirement"]
    for case in fixture["evidence_cases"]:
        verdict, reason = evidence.evaluate_requirement(
            requirement,
            evidence_facts(case, now, subject),
            {"now": fixture["now"]},
        )
        print_case(
            case["id"], case["name"], case["want"],
            verdict_string(verdict, reason), case["expected_got"],
        )

    caid = fixture["caid"]
    definition = caid["type"]
    operation_id = clc.compute_action_id(
        definition["name"], definition["material"], caid["suite"],
        caid["operation"],
    )
    for case in caid["cases"]:
        observed_id = clc.compute_action_id(
            definition["name"], definition["material"], caid["suite"],
            case["observed"],
        )
        got = "MATCH" if operation_id == observed_id else "NOT_EQUIVALENT"
        print_case(case["id"], case["name"], case["want"], got)

    for kind in ("source", "target", "action", "status"):
        changed = binding_subject(
            mutate(fixture["binding"], fixture["mutations"][kind])
        )
        print_case(
            {
                "source": "EMI-BIND-002",
                "target": "EMI-BIND-003",
                "action": "EMI-BIND-004",
                "status": "EMI-BIND-005",
            }[kind],
            kind + " mutation changes the relation subject",
            "different",
            "different" if changed != subject else "unchanged",
        )

    opaque_case = {
        "facts": {
            "ep-quorum": [
                {"subject": "alice", "verified": True, "age_sec": 30},
                {"subject": "bob", "verified": True, "age_sec": 20},
            ],
            "policy-permit": [
                {"subject": "policy", "verified": True, "age_sec": 60},
            ],
            binding_role: [
                {"subject": "arbitrary-unbound-subject",
                 "verified": True, "age_sec": 60},
            ],
        },
    }
    verdict, reason = evidence.evaluate_requirement(
        requirement, evidence_facts(opaque_case, now, subject),
        {"now": fixture["now"]},
    )
    got = (
        "opaque-subject-accepted"
        if verdict_string(verdict, reason) == "SATISFIED"
        else "unexpectedly-rejected"
    )
    print_case(
        "EMI-BIND-006",
        "CLC treats the binding subject as opaque",
        "opaque-subject-accepted",
        got,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
