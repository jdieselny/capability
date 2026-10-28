#!/usr/bin/env python3
"""Cross-language EMILIA binding projection probe (Python)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
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
    return "sha-256:" + hashlib.sha256(canonical).hexdigest()


def utf8_sorted(values):
    return sorted(values, key=lambda value: value.encode("utf-8"))


def relation_tuple(binding):
    subjects = utf8_sorted(target["subject"] for target in binding["targets"])
    issued_at = utf8_sorted(
        [binding["source"]["issued_at"]]
        + [target["issued_at"] for target in binding["targets"]]
    )
    return {
        "requirement_digest": binding["requirement_digest"],
        "policy_generation": binding["source"]["policy_generation"],
        "from": {
            "type": binding["source"]["type"],
            "artifact_digest": digest_object(binding["source"]),
        },
        "relation": binding["relation"],
        "to": {
            "type": binding["targets"][0]["type"],
            "artifact_set_digest": digest_object(binding["targets"]),
        },
        "action_digest": digest_object(binding["action"]),
        "subjects": subjects,
        "trust": binding["trust"],
        "trust_snapshot_digest": binding["trust_snapshot_digest"],
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
    for role in sorted(case["facts"], key=lambda value: value.encode("utf-8")):
        for entry in case["facts"][role]:
            facts.append({
                "type": role,
                "subject": subject if entry["subject"] == "$binding" else entry["subject"],
                "verified": entry["verified"],
                "issued_at": (
                    now - timedelta(seconds=entry["age_sec"])
                ).isoformat().replace("+00:00", "Z"),
            })
    return facts


ROLE_MAP = {
    "ep-human-authorization": "ep-quorum",
    "ep-quorum": "ep-quorum",
    "policy-permit": "policy-permit",
}

AEC_VERSION = "EP-AEC-REQUIREMENT-v1"
AEC_TOP = {
    "@version", "requirement_id", "purpose", "expression", "freshness_sec",
    "status_required", "role_constraints", "required_bindings",
}
AEC_ROLE_CONSTRAINT = {"type", "component_type", "threshold", "subject_id_source"}
AEC_BINDING = {"from_type", "relation", "to_type"}
AEC_IDENT = re.compile(r"^[A-Za-z0-9._:-]+$")


def check_aec_members(source):
    unknown = sorted(set(source) - AEC_TOP)
    if unknown:
        raise ValueError(f"unknown AEC member(s): {', '.join(unknown)}")
    for index, rc in enumerate(source.get("role_constraints", [])):
        extra = sorted(set(rc) - AEC_ROLE_CONSTRAINT)
        if extra:
            raise ValueError(f"role_constraints[{index}] unknown member {extra[0]}")
    for index, binding in enumerate(source.get("required_bindings", [])):
        extra = sorted(set(binding) - AEC_BINDING)
        if extra:
            raise ValueError(f"required_bindings[{index}] unknown member {extra[0]}")


def check_aec_identifier(field, value):
    if not value or not AEC_IDENT.match(value):
        raise ValueError(f"AEC {field} {value!r} is outside the identifier set")


def binding_role_name(from_type, relation, to_type):
    """The §5 bounded injective role encoding (uint32be length-prefixed parts)."""
    payload = b""
    for part in (from_type, relation, to_type):
        encoded = part.encode("utf-8")
        if len(encoded) > 256:
            raise ValueError("AEC required_bindings part is too long")
        payload += len(encoded).to_bytes(4, "big") + encoded
    role = "clc:evidence-binding:" + base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    if len(role) > 256:
        raise ValueError("encoded binding role exceeds 256 bytes")
    return role


def project_aec(source):
    """Project an EP-AEC-REQUIREMENT-v1 object into CLC-REQUIREMENT-v1."""
    if source.get("@version") != AEC_VERSION:
        raise ValueError(f"unsupported AEC version {source.get('@version')!r}")
    check_aec_members(source)
    if not source.get("requirement_id"):
        raise ValueError("AEC requirement_id is required")
    constraints = []
    freshness = source.get("freshness_sec", {})
    for role in sorted(freshness, key=lambda value: value.encode("utf-8")):
        if role not in ROLE_MAP:
            raise ValueError(f"AEC role {role!r} has no pinned CLC mapping")
        constraints.append({
            "role": ROLE_MAP[role],
            "constraint": f"varwof/evidence-v1:freshness:sec:{freshness[role]}",
        })
    for rc in source.get("role_constraints", []):
        if rc["type"] != "distinct-subject-quorum":
            raise ValueError(f"unsupported role constraint {rc['type']}")
        if rc["subject_id_source"] != "native-verifier":
            raise ValueError("subject_id_source must be native-verifier")
        if rc["component_type"] not in ROLE_MAP:
            raise ValueError(
                f"AEC role {rc['component_type']!r} has no pinned CLC mapping")
        constraints.append({
            "role": ROLE_MAP[rc["component_type"]],
            "constraint": f"varwof/evidence-v1:quorum:distinct:{rc['threshold']}",
        })

    for role in source.get("status_required", []):
        if not role or role not in ROLE_MAP:
            raise ValueError(f"AEC status_required role {role!r} has no pinned mapping")

    parts = ["(" + source["expression"] + ")"]
    seen = set()
    for binding in source.get("required_bindings", []):
        for field in ("from_type", "relation", "to_type"):
            check_aec_identifier(field, binding[field])
        role = binding_role_name(
            binding["from_type"], binding["relation"], binding["to_type"])
        if role not in seen:
            parts.append(role)
            seen.add(role)

    out = {
        "@version": "CLC-REQUIREMENT-v1",
        "requirement_id": source["requirement_id"],
    }
    if source.get("purpose"):
        out["purpose"] = source["purpose"]
    out["expression"] = " AND ".join(parts)
    if len(out["expression"].encode("utf-8")) > 512:
        raise ValueError("projected expression exceeds the CLC 512-byte limit")
    if constraints:
        out["constraints"] = constraints
    return out


def requirement_digest(value):
    canonical = clc.canonical_json(value).encode("utf-8")
    return "sha-256:" + hashlib.sha256(canonical).hexdigest()



def verdict_string(verdict, reason):
    return verdict + (("/" + reason) if reason else "")


def print_case(case_id, name, want, got, expected_got=None):
    status = "PASS" if got == (expected_got or want) else "FAIL"
    print(f"{status} {case_id} {name:<55} want={want} got={got}")


def main():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    binding = fixture["binding"]
    if digest_object(binding["trust_inputs"]) != binding["trust_snapshot_digest"]:
        raise SystemExit("trust_snapshot_digest does not match trust_inputs")
    now = parse_instant(fixture["now"])
    subject = binding_subject(fixture["binding"])
    binding_role = fixture["binding_role"]
    required = fixture["source_requirement"]["required_bindings"][0]
    assert binding_role_name(
        required["from_type"], required["relation"], required["to_type"]
    ) == binding_role
    endpoints = fixture["binding"]
    assert binding_role_name(
        endpoints["source"]["type"],
        endpoints["relation"],
        endpoints["targets"][0]["type"],
    ) == binding_role

    print("EMILIA → CLC evidence projection probe (Python)")
    print("fixture: register/cmd/emilia-projection-probe/testdata/"
          "emilia-binding-fixture-v1.json")
    print()

    source = fixture["source_requirement"]
    projected = project_aec(source)
    expected = fixture["mapped_requirement"]
    print_case(
        "EMI-PROJ-001",
        "AEC projects to the pinned CLC requirement",
        "match",
        "match" if clc.canonical_json(projected) == clc.canonical_json(expected) else "different",
    )
    print_case(
        "EMI-PROJ-002",
        "source requirement digest",
        fixture["requirement_digests"]["source"],
        requirement_digest(source),
    )
    print_case(
        "EMI-PROJ-003",
        "projected requirement digest",
        fixture["requirement_digests"]["projected"],
        requirement_digest(projected),
    )

    negative = [
        ("EMI-PROJ-004", "unknown AEC member rejected",
         lambda doc: doc.update({"authorized": True})),
        ("EMI-PROJ-005", "unpinned role rejected",
         lambda doc: doc.update({"freshness_sec": {"unpinned": 30}})),
        ("EMI-PROJ-006", "over-long projected expression rejected",
         lambda doc: doc.update({"expression": "a" * 520})),
        ("EMI-PROJ-007", "unknown role constraint rejected",
         lambda doc: doc["role_constraints"][0].update({"type": "new-constraint"})),
        ("EMI-PROJ-008", "presenter-supplied subject rejected",
         lambda doc: doc["role_constraints"][0].update({"subject_id_source": "presenter"})),
        ("EMI-PROJ-009", "empty binding part rejected",
         lambda doc: doc["required_bindings"][0].update({"from_type": ""})),
        ("EMI-PROJ-010", "quorum below two rejected",
         lambda doc: doc["role_constraints"][0].update({"threshold": 1})),
        ("EMI-PROJ-011", "invalid expression grammar rejected",
         lambda doc: doc.update({"expression": "ep-quorum AND"})),
        ("EMI-PROJ-012", "unknown nested role-constraint member rejected",
         lambda doc: doc["role_constraints"][0].update({"note": "x"})),
        ("EMI-PROJ-013", "negative freshness rejected",
         lambda doc: doc["freshness_sec"].update({"ep-quorum": -1})),
        ("EMI-PROJ-014", "unknown AEC version rejected",
         lambda doc: doc.update({"@version": "EP-AEC-REQUIREMENT-v2"})),
        ("EMI-PROJ-015", "missing requirement id rejected",
         lambda doc: doc.pop("requirement_id", None)),
        ("EMI-PROJ-016", "invalid binding identifier rejected",
         lambda doc: doc["required_bindings"][0].update({"from_type": "policy permit"})),
        ("EMI-PROJ-017", "over-long binding role rejected",
         lambda doc: doc["required_bindings"][0].update({"from_type": "a" * 200})),
        ("EMI-PROJ-018", "unknown nested binding member rejected",
         lambda doc: doc["required_bindings"][0].update({"note": "x"})),
        ("EMI-PROJ-019", "unpinned status_required role rejected",
         lambda doc: doc.update({"status_required": ["unpinned"]})),
    ]
    for case_id, name, apply_mutation in negative:
        candidate = json.loads(json.dumps(source))
        apply_mutation(candidate)
        try:
            projected = project_aec(candidate)
            evidence.evaluate_requirement(projected, [], {"now": fixture["now"]})
            got = "accepted"
        except Exception:  # noqa: BLE001 - the probe only records rejection
            got = "rejected"
        print_case(case_id, name, "rejected", got)

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
            case["id"], case["name"], case["expected_got"],
            verdict_string(verdict, reason),
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
