# External authorization evaluator binding — v1 draft

Status: **experimental, non-activating** draft prepared for
[`RobLe3/iicp-management#168`](https://github.com/RobLe3/iicp-management/issues/168).
Not an adopted contract and not part of the frozen IICP qualification baseline.

v1 addresses the four points in Roble's 2026-10-29 review: the explicit
`external-` designation, a versioned canonical request projection, the
unresolved-result rules at the local-apply gate, and an infrastructure-neutral
integrity envelope. It remains additive: `management-profile-v1` and the
local-apply gate are unchanged.

## What it does not do

- It does not move CLC, a runtime sentinel, or another evaluator into
  Management.
- It does not make the evaluator the owner of Management policy, or Management
  the interpreter of the evaluator's capability language.
- It does not treat a successful evaluator call, compatibility, or discovery as
  execution authority. `authorizes_mutation` is `false` in every valid result.

## Explicit external designation

The artifact names itself external at three points: the schema identifier ends
in `external-evaluator-result-v1`, `schema_version` is
`iicp.external-management-evaluator-result.v1`, and the title says "External
Authorization Evaluator Result". A Management policy decision never carries
these names; an external evaluator result always does.

## Versioned request projection

`binding.request_projection` is the complete, versioned, canonical input to the
request digest:

| Member | Meaning |
|---|---|
| `projection_id` | `iicp-request-projection` |
| `projection_version` | `1` in this draft; the controller accepts a pinned set |
| `request_id` | controller-issued identifier; the gate accepts it once per validity window |
| `intent_digest` | `sha-256:` over the **exact request-body bytes**, never a re-encoding |
| `policy_generation` | management-side policy generation the result was evaluated against |
| `parameter_ids` | identities of the required parameters; an unknown identity is refused |
| `action`, `target`, `audience`, `administrative_domain` | security-relevant request identity |
| `authority_context` | optional `authority_id`, `delegation_digest`, `request_id` |

`binding.request_digest` is `sha-256:<64 lowercase hex>` over the JCS
serialization of `request_projection`. The projection is closed: a member not
listed above is rejected, not ignored. A controller that does not accept the
projection version refuses the result
(`IICP-EVAL-PROJECTION-UNSUPPORTED`); it does not guess a newer layout.

The controller MUST derive the expected projection from its own request and
compare both the projection and the digest against it. Checking a digest that
the evaluator computed over its own copy is circular and does not bind the
request the controller actually received.

## Unresolved results

`allow_unresolved` is an explicit intermediate result, never execution
permission:

1. every `unresolved[]` entry names an `obligation_id` and a
   `responsible_component` (the resolver);
2. the local-apply gate refuses or defers application until the named resolver
   produces a valid decision;
3. a missing, unsupported, stale or timed-out resolution fails closed;
4. an obligation identity the controller does not recognise is an **unknown
   parameter identity** and fails validation, not a delegated obligation
   (`IICP-EVAL-OBLIGATION-UNKNOWN`);
5. a recognised obligation whose resolver reports `unknown` fails closed
   (`IICP-EVAL-UNRESOLVED-UNKNOWN`); a resolver that reports `violated` denies
   (`IICP-EVAL-UNRESOLVED-VIOLATED`).

The distinction in (4) is deliberate: unknown parameters are a validation
failure, while a recognised obligation with a named resolver is a legitimate
deferral.

## Integrity envelope

`integrity` is optional and infrastructure-neutral:

```json
{
  "integrity": {
    "signatures": [
      {
        "format": "ed25519",
        "key_id": "evaluator-key-1",
        "signed_digest": "sha-256:...",
        "value": "base64url-ed25519-signature"
      }
    ]
  }
}
```

`signed_digest` is SHA-256 over the canonical serialization of the result with
the `integrity` member removed; `value` is the Ed25519 signature over the same
bytes. The validator verifies the signature against `key_id` in the controller's
trusted key set and refuses an unknown key, an invalid signature or a digest
mismatch. Other signature formats may be registered later; an unregistered
format is refused.

Removing the whole `integrity` member is undetectable unless the deployment sets
`require_integrity`; a deployment that needs durable evidence MUST require it.
Transport authentication is additional protection, not a substitute.

## Composition rules

The evaluator result is evaluated first, including extensions and obligations;
only then is it composed with the local decision.

1. The local decision MUST be one of `allow`, `deny` or `allow_unresolved`; any
   other value is refused (`IICP-EVAL-LOCAL-DECISION-UNKNOWN`), never treated
   as allow.
2. Local policy and the evaluator result compose by **intersection**.
3. **Deny takes precedence**, from either side; a violated obligation denies
   even when the local state is unresolved.
4. **Unknown required semantics fail profile validation** (reject).
5. Unknown **optional** extensions may be ignored only when declared
   `OPTIONAL_IGNORABLE`; an unknown `OPTIONAL_NEGOTIABLE` is refused, not
   ignored.
6. A result whose projection, binding, policy generation or freshness does not
   match the request is **rejected**.
7. An unrecognised integrity format or a mismatched integrity digest is
   **rejected**.
8. An `allow` result must carry at least one evidence reference, and an evidence
   URI must be `https:`; otherwise the result is refused.
9. Management does not infer containment or intersection from an
   evaluator-specific language; rejection is fail-closed and maps to deny at the
   local gate, never to allow.

## Required pins and bounds

A controller accepts a result only when its own configuration pins:

- `profile_id` and `profile_version` (`IICP-EVAL-PROFILE-ID-UNTRUSTED` /
  `IICP-EVAL-PROFILE-UNSUPPORTED`);
- `evaluator_id` (`IICP-EVAL-EVALUATOR-UNTRUSTED`);
- the evaluator policy digest (`IICP-EVAL-POLICY-PIN-MISSING` when no set is
  configured, `IICP-EVAL-POLICY-UNTRUSTED` when the digest is absent from it);
- the negotiated management requirement: its digest must be pinned, and the
  controller, domain, API version, policy evaluator and canonicalization must
  match the requirement the controller holds;
- the parameter identities the controller knows (an unknown id is refused);
- the optional extension ids the controller declares ignorable; an optional
  extension not declared by id is refused even if the result labels it
  `OPTIONAL_IGNORABLE`;
- the request projection version (`IICP-EVAL-PROJECTION-UNSUPPORTED`);
- a maximum validity window in seconds; a longer `expires_at - issued_at` is
  refused (`IICP-EVAL-VALIDITY-TOO-LONG`).

A missing pin set is a refusal, not "pinning disabled".

## Files

| File | Purpose |
|---|---|
| `external-evaluator-result-v1.schema.json` | Result artifact schema (JSON Schema 2020-12) |
| `external-evaluator-binding-cases-v1.json` | 43 cases |
| `validate.py` | Schema, projection digest, integrity, composition, expectations |

## Cases

| Case | Group | Expected |
|---|---|---|
| `eval-001-both-allow` | both permit | allow |
| `eval-002-evaluator-deny-wins` | evaluator denies | deny |
| `eval-003-local-deny-wins` | local denies | deny |
| `eval-004-unsupported-profile-version` | unknown required profile version | reject |
| `eval-005-allow-unresolved-bound` | unresolved with resolver | allow_unresolved |
| `eval-006-allow-unresolved-unbound` | unresolved without resolver | reject |
| `eval-007-stale-result` | stale or expired | reject |
| `eval-008-binding-mismatch` | different target | reject |
| `eval-009-optional-extension-ignored` | ignorable optional extension | allow |
| `eval-010-evidence-preserved` | evidence preservation | allow |
| `eval-011-local-unresolved` | local decision unresolved | allow_unresolved |
| `eval-012-signed-result` | recognised integrity envelope | allow |
| `eval-013-integrity-mismatch` | integrity digest mismatch | reject |
| `eval-014-unresolved-unknown-status` | resolver status unknown | reject |
| `eval-015-projection-unsupported` | unknown projection version | reject |
| `eval-016-unresolved-violated` | resolver reports violated | deny |
| `eval-017-obligation-unknown` | unrecognised obligation identity | reject |
| `eval-018-integrity-required-missing` | integrity required but absent | reject |
| `eval-019-unrequested-authority-context` | projection carries context the controller did not request | reject |
| `eval-020-optional-negotiable-unknown` | unnegotiated OPTIONAL_NEGOTIABLE extension | reject |
| `eval-021-unresolved-duplicate` | duplicated obligation identity | reject |
| `eval-022-resolver-mismatch` | resolver differs from the responsible component | reject |
| `eval-023-policy-untrusted` | evaluator policy digest not in the controller set | reject |
| `eval-024-local-decision-unknown` | local decision not one of the three states | reject |
| `eval-025-unresolved-timeout` | resolver timed out | reject |
| `eval-026-validity-too-long` | validity window exceeds the controller maximum | reject |
| `eval-027-request-digest-mismatch` | digest does not match the derived projection | reject |
| `eval-028-local-unresolved-violated` | local unresolved cannot mask a violation | deny |
| `eval-029-local-unresolved-required-extension` | local unresolved cannot skip required semantics | reject |
| `eval-030-not-yet-valid` | result issued after the controller clock | reject |
| `eval-031-extension-duplicate` | duplicate extension identity | reject |
| `eval-032-evaluator-untrusted` | evaluator identity not pinned | reject |
| `eval-033-policy-pin-missing` | no accepted policy set configured | reject |
| `eval-034-profile-id-untrusted` | evaluator profile id not pinned | reject |
| `eval-035-integrity-key-unknown` | signature key not in the trust store | reject |
| `eval-036-integrity-signature-invalid` | canonical bytes changed after signing | reject |
| `eval-037-intent-mismatch` | intent digest does not match the request body | reject |
| `eval-038-extension-not-declared` | optional extension not declared ignorable by the controller | reject |
| `eval-039-evidence-missing` | allow without any evidence reference | reject |
| `eval-040-unresolved-unsupported` | resolver reports unsupported | reject |
| `eval-041-parameter-unknown` | unknown required parameter identity | reject |
| `eval-042-negotiation-mismatch` | management context differs from the requirement | reject |
| `eval-043-requirement-untrusted` | requirement digest not pinned | reject |

## Running

```sh
cd iicp-evaluator-binding-v1
python3 validate.py
```

Expected:

```text
43/43 cases pass
```

`jsonschema` and `cryptography` are required (Ed25519 verification). Each case
carries its own `derivation`. The case document is parsed strictly: duplicate
JSON members are rejected, not last-one-wins.

## Mapping to Roble's review

| Point | Where it lands |
|---|---|
| `external-` designation | schema id, `schema_version`, title |
| Versioned canonical request projection | `binding.request_projection` + `request_digest` rule |
| Unresolved is not permission | “Unresolved results” section, and cases 005/006/014/016/017/021/022 |
| Integrity and provenance | optional `integrity` envelope + cases 012/013/018/032; validator checks digest only, controller verifies the signature |

## Known limitations of v1

- **Replay requires gate state.** `request_id` is now in the projection and the
  contract requires single use, but enforcing it needs a replay cache at the
  local gate; the document cannot provide that state.
- **Canonicalization domain.** The reference `canonical()` orders keys by
  UTF-16 code units and renders integers exactly; it refuses non-integer
  numbers. That is RFC 8785 for this profile's value domain, not a general JCS
  implementation.
- **One signature format.** Ed25519 is the only format the reference validator
  verifies; other infrastructures are refused until registered.

## Open questions

1. Reason-code namespace: keep `IICP-EVAL-*` for controller outcomes; evaluator
   codes stay opaque.
2. Whether a valid signature is required or optional. The validator checks
   that `signed_digest` covers the canonical result; cryptographic
   verification of `value` against `key_id` under pinned trust is the
   controller's job and is not implemented in this draft.
3. Whether `authority_context` needs additional members for the first deployed
   profile.
