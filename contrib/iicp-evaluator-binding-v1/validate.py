#!/usr/bin/env python3
"""Validate the v1 external-evaluator binding draft.

Checks every result against external-evaluator-result-v1.schema.json, verifies
the versioned request projection (derived from the controller's own request),
the optional integrity envelope, then composes the evaluator verdict with the
local decision.  No network; only jsonschema is required.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "external-evaluator-result-v1.schema.json"
CASES = HERE / "external-evaluator-binding-cases-v1.json"

BINDING_FIELDS = ("action", "target", "audience", "administrative_domain")
LOCAL_DECISIONS = {"allow", "deny", "allow_unresolved"}
INTEGRITY_FORMATS = {"ed25519"}


class DuplicateMember(ValueError):
    pass


def no_duplicates(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise DuplicateMember(key)
        seen.add(key)
    return dict(pairs)


def load_json(path: Path):
    return json.loads(path.read_text(), object_pairs_hook=no_duplicates)


def canonical(value) -> bytes:
    """RFC 8785 canonical form for the value domain this profile uses:
    null, booleans, integers, strings, arrays and objects.  Keys are ordered by
    UTF-16 code units; non-integer numbers are refused rather than guessed."""
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise ValueError("non-integer number is outside this profile's domain")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(canonical(item) for item in value) + b"]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return b"{" + b",".join(
            canonical(key) + b":" + canonical(value[key]) for key in keys) + b"}"
    raise ValueError(f"unsupported canonical value {type(value)!r}")


def digest(value) -> str:
    return "sha-256:" + hashlib.sha256(canonical(value)).hexdigest()


def intent_digest(case: dict) -> str:
    """SHA-256 over the exact request-body bytes, never a re-encoding."""
    return "sha-256:" + hashlib.sha256(
        case["request"]["intent"].encode("utf-8")).hexdigest()


def expected_projection(case: dict, projection: dict) -> dict:
    """The controller derives the projection from its own request.  Only the
    id/version it accepted come from the result."""
    expected = {
        "projection_id": projection["projection_id"],
        "projection_version": projection["projection_version"],
        "request_id": case["request"]["request_id"],
        "intent_digest": intent_digest(case),
    }
    expected["policy_generation"] = case["request"]["policy_generation"]
    expected["parameter_ids"] = case["request"]["parameter_ids"]
    for field in BINDING_FIELDS:
        expected[field] = case["request"][field]
    if "authority_context" in case["request"]:
        expected["authority_context"] = case["request"]["authority_context"]
    return expected


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def integrity_error(result: dict, required: bool, trusted_keys: dict[str, str]) -> str:
    envelope = result.get("integrity")
    if envelope is None:
        return "IICP-EVAL-INTEGRITY-MISSING" if required else ""
    body = {key: value for key, value in result.items() if key != "integrity"}
    raw = canonical(body)
    want = "sha-256:" + hashlib.sha256(raw).hexdigest()
    for signature in envelope["signatures"]:
        if signature["format"] not in INTEGRITY_FORMATS:
            return "IICP-EVAL-INTEGRITY-UNSUPPORTED"
        if signature["signed_digest"] != want:
            return "IICP-EVAL-INTEGRITY-MISMATCH"
        key = trusted_keys.get(signature.get("key_id", ""))
        if not key:
            return "IICP-EVAL-INTEGRITY-KEY-UNKNOWN"
        try:
            public = Ed25519PublicKey.from_public_bytes(b64url_decode(key))
            public.verify(b64url_decode(signature["value"]), raw)
        except (InvalidSignature, ValueError):
            return "IICP-EVAL-INTEGRITY-SIGNATURE-INVALID"
    return ""


def check_extensions(result: dict, understood: set[str],
                     ignorable: set[str]) -> tuple[list[str], bool]:
    """Return (codes, ok).  An optional extension may be ignored only when the
    controller profile declares it non-security-critical by id."""
    codes: list[str] = []
    seen: set[str] = set()
    for extension in result["extensions"]:
        if extension["id"] in seen:
            return ["IICP-EVAL-EXTENSION-DUPLICATE"], False
        seen.add(extension["id"])
    for extension in result["extensions"]:
        if extension["id"] in understood:
            continue
        if extension["class"].startswith("REQUIRED_"):
            return ["IICP-EVAL-EXTENSION-REQUIRED-UNKNOWN"], False
        if extension["class"] == "OPTIONAL_NEGOTIABLE":
            return ["IICP-EVAL-EXTENSION-NEGOTIATION-REQUIRED"], False
        if extension["id"] not in ignorable:
            return ["IICP-EVAL-EXTENSION-NOT-DECLARED"], False
        codes.append("IICP-EVAL-EXTENSION-IGNORED")
    return codes, True


def evaluator_verdict(case: dict) -> tuple[str, list[str], list[str]]:
    """Evaluate the evaluator result on its own terms (no local decision)."""
    result = case["result"]
    request = case["request"]

    problem = integrity_error(result, case.get("require_integrity", False),
                              case.get("trusted_keys", {}))
    if problem:
        return "reject", [problem], []

    projection = result["binding"]["request_projection"]
    projection_id = f"{projection['projection_id']}.v{projection['projection_version']}"
    if projection_id not in case["accepted_request_projections"]:
        return "reject", ["IICP-EVAL-PROJECTION-UNSUPPORTED"], []

    want_projection = expected_projection(case, projection)
    if result["binding"]["request_digest"] != digest(want_projection):
        return "reject", ["IICP-EVAL-REQUEST-DIGEST"], []
    if projection != want_projection:
        return "reject", ["IICP-EVAL-BINDING-MISMATCH"], []
    context = result["management_context"]
    requirement = case["management_requirement"]
    if context["requirement_digest"] not in case["accepted_requirement_digests"]:
        return "reject", ["IICP-EVAL-REQUIREMENT-UNTRUSTED"], []
    for field in ("controller_id", "administrative_domain", "api_version",
                  "policy_evaluator", "canonicalization"):
        if context[field] != requirement[field]:
            return "reject", ["IICP-EVAL-NEGOTIATION-MISMATCH"], []

    known_parameters = set(case.get("known_parameter_ids", []))
    for parameter in projection["parameter_ids"]:
        if parameter not in known_parameters:
            return "reject", ["IICP-EVAL-PARAMETER-UNKNOWN"], []

    evaluator = result["evaluator"]
    if evaluator["profile_id"] not in case["accepted_profile_ids"]:
        return "reject", ["IICP-EVAL-PROFILE-ID-UNTRUSTED"], []
    if evaluator["profile_version"] not in case["accepted_profile_versions"]:
        return "reject", ["IICP-EVAL-PROFILE-UNSUPPORTED"], []
    if evaluator.get("evaluator_id") not in case["accepted_evaluator_ids"]:
        return "reject", ["IICP-EVAL-EVALUATOR-UNTRUSTED"], []

    if "accepted_policy_digests" not in case:
        return "reject", ["IICP-EVAL-POLICY-PIN-MISSING"], []
    if result["policy"]["digest"] not in case["accepted_policy_digests"]:
        return "reject", ["IICP-EVAL-POLICY-UNTRUSTED"], []

    issued = result["freshness"]["issued_at"]
    expires = result["freshness"]["expires_at"]
    if expires <= issued:
        return "reject", ["IICP-EVAL-STALE"], []
    if case["now"] >= expires:
        return "reject", ["IICP-EVAL-STALE"], []
    if issued > case["now"]:
        return "reject", ["IICP-EVAL-NOT-YET-VALID"], []
    if expires - issued > case["max_validity"]:
        return "reject", ["IICP-EVAL-VALIDITY-TOO-LONG"], []

    extension_codes, ok = check_extensions(
        result, set(case.get("understood_extensions", [])),
        set(case.get("ignorable_extensions", [])))
    if not ok:
        return "reject", extension_codes, []

    if result["decision"] not in {"allow", "deny", "allow_unresolved"}:
        return "reject", ["IICP-EVAL-DECISION-UNKNOWN"], []
    if result["decision"] == "deny":
        return "deny", ["IICP-EVAL-DENY"], []
    if result["decision"] == "allow_unresolved":
        downstream = case.get("downstream", {})
        if not downstream.get("outcome"):
            return "reject", ["IICP-EVAL-UNRESOLVED-UNBOUND"], []
        if downstream["outcome"] == "unsupported":
            return "reject", ["IICP-EVAL-UNRESOLVED-UNSUPPORTED"], []
        if downstream["outcome"] != "pending":
            return "reject", ["IICP-EVAL-UNRESOLVED-TIMEOUT"], []
        known = case.get("known_obligations", {})
        seen: set[str] = set()
        for item in result["unresolved"]:
            if not item.get("responsible_component"):
                return "reject", ["IICP-EVAL-UNRESOLVED-UNBOUND"], []
            if item["obligation_id"] in seen:
                return "reject", ["IICP-EVAL-UNRESOLVED-DUPLICATE"], []
            seen.add(item["obligation_id"])
            if item["obligation_id"] not in known:
                return "reject", ["IICP-EVAL-OBLIGATION-UNKNOWN"], []
            if known[item["obligation_id"]] != item["responsible_component"]:
                return "reject", ["IICP-EVAL-RESOLVER-MISMATCH"], []
            if item["status"] == "unknown":
                return "reject", ["IICP-EVAL-UNRESOLVED-UNKNOWN"], []
            if item["status"] == "unsupported":
                return "reject", ["IICP-EVAL-UNRESOLVED-UNSUPPORTED"], []
            if item["status"] == "violated":
                return "deny", ["IICP-EVAL-UNRESOLVED-VIOLATED"], []
            if item["status"] == "satisfied":
                return "reject", ["IICP-EVAL-UNRESOLVED-SATISFIED"], []
        return "allow_unresolved", ["IICP-EVAL-UNRESOLVED"] + extension_codes, []

    if result["decision"] == "allow" and not result["evidence"]:
        return "reject", ["IICP-EVAL-EVIDENCE-MISSING"], []
    for item in result["evidence"]:
        uri = item.get("uri")
        if uri is not None and not uri.startswith("https://"):
            return "reject", ["IICP-EVAL-EVIDENCE-URI-UNSUPPORTED"], []
    evidence = [item["digest"] for item in result["evidence"]]
    return "allow", ["IICP-EVAL-ALLOW"] + extension_codes, evidence


def evaluate(case: dict) -> tuple[str, list[str], list[str]]:
    local = case["local_decision"]
    if local not in LOCAL_DECISIONS:
        return "reject", ["IICP-EVAL-LOCAL-DECISION-UNKNOWN"], []

    verdict, codes, evidence = evaluator_verdict(case)
    if verdict == "reject":
        return "reject", codes, []
    if verdict == "deny":
        return "deny", codes, []
    if local == "deny":
        return "deny", ["IICP-LOCAL-DENY"], []
    if verdict == "allow_unresolved":
        return "allow_unresolved", codes, []
    if local == "allow_unresolved":
        return "allow_unresolved", ["IICP-LOCAL-UNRESOLVED"], []
    return "allow", codes, evidence


def main() -> int:
    try:
        schema = load_json(SCHEMA)
        document = load_json(CASES)
    except DuplicateMember as error:
        print(f"duplicate JSON member: {error}")
        return 1
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
