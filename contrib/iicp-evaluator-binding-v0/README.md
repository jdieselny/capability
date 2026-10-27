# External authorization evaluator binding — v0 draft

Status: **architecture input** for
[`RobLe3/iicp-management#168`](https://github.com/RobLe3/iicp-management/issues/168).
Not a pull request, not an adopted contract, and not part of the frozen IICP
qualification baseline.

This draft defines an **optional, non-activating** binding by which an
independently governed external authorization evaluator returns a bounded
result to an IICP management controller. It uses
`management-profile-v1` / `management-profile-requirement-v1` for compatibility
negotiation and adds one separately versioned result artifact.

## What it does not do

- It does not move CLC, a runtime sentinel, or another evaluator into
  Management.
- It does not change `management-profile-v1`, the local-apply gate, or the
  qualification baseline.
- It does not make the evaluator the owner of Management policy, or Management
  the interpreter of the evaluator's capability language.
- It does not treat a successful evaluator call, compatibility, or discovery as
  execution authority.

`authorizes_mutation` is `false` in every valid result. The controller's
existing local policy and local-apply gate still decide execution.

## Files

| File | Purpose |
|---|---|
| `management-evaluator-result-v0.schema.json` | Result artifact schema (JSON Schema 2020-12) |
| `management-evaluator-binding-cases-v0.json` | 11 cases covering the 9 groups in the issue |
| `validate.py` | Checks each result against the schema, applies the composition rules, compares with the normative expectation |

## Result fields

| Field | Content |
|---|---|
| `evaluator.profile_id` / `profile_version` | Evaluator profile and version, negotiated through the management profile pair |
| `decision` | `allow`, `deny`, or `allow_unresolved` |
| `reason_codes` | Stable evaluator reason codes; Management does not reinterpret them |
| `binding` | `request_digest`, `action`, `target`, `audience`, `administrative_domain`, `policy_generation` |
| `policy` | Digest of the evaluator policy or delegation context used; the management-side generation stays in `binding.policy_generation` |
| `freshness` | `issued_at`, `expires_at` |
| `unresolved` | Bounded list of `obligation_id`, `responsible_component`, `status` |
| `evidence` | Digest references only; no raw credentials or unrestricted policy content |
| `extensions` | Same classes as the management profile: `OPTIONAL_IGNORABLE`, `OPTIONAL_NEGOTIABLE`, `REQUIRED_UNDERSTOOD`, `REQUIRED_SECURITY_CRITICAL` |
| `authorizes_mutation` | Always `false` |

## Composition rules

The draft applies the rules already proposed in the issue:

1. Local policy and the evaluator result compose by **intersection**.
2. **Deny takes precedence.**
3. **Unknown required semantics fail profile validation** (reject).
4. Unknown **optional** extensions may be ignored only when declared
   `OPTIONAL_IGNORABLE`.
5. `allow_unresolved` is **never execution permission**; it requires a named
   resolver and an explicit downstream outcome.
6. A result whose action, target, audience, domain, policy generation or
   freshness does not match the request is **rejected**.
7. Management does not infer containment or intersection from an
   evaluator-specific language.

Rejection is fail-closed: it maps to deny at the local gate, never to allow.

## Cases

Eleven cases cover the nine groups in the issue; the `allow_unresolved` group
is split into bound and unbound, and one case exercises a local unresolved
decision.

| Case | Group | Expected |
|---|---|---|
| `eval-001-both-allow` | both permit | allow |
| `eval-002-evaluator-deny-wins` | local permits, evaluator denies | deny |
| `eval-003-local-deny-wins` | local denies, evaluator permits | deny |
| `eval-004-unsupported-profile-version` | unknown required profile version | reject |
| `eval-005-allow-unresolved-bound` | unresolved with resolver and downstream outcome | allow_unresolved |
| `eval-006-allow-unresolved-unbound` | unresolved without resolver | reject |
| `eval-007-stale-result` | stale or expired | reject |
| `eval-008-binding-mismatch` | different target | reject |
| `eval-009-optional-extension-ignored` | safely ignored optional extension | allow |
| `eval-010-evidence-preserved` | evidence preservation | allow |
| `eval-011-local-unresolved` | local decision unresolved, evaluator permits | allow_unresolved |

## Running

```sh
cd iicp-evaluator-binding-v0
python3 validate.py
```

Expected:

```text
11/11 cases pass
```

The validator needs `jsonschema` and nothing else. Each case carries its own
`derivation`, so the expectation can be reviewed without running the
implementation that produced the result.

## Open questions for the management maintainers

Each question carries a proposed answer, so the first review can accept or
change a default instead of starting from a blank page.

| # | Question | Proposed answer |
|---|---|---|
| 1 | Artifact name and namespace | `iicp.management-evaluator-result.v0`; no `external-` prefix, because the binding is already optional |
| 2 | Reason-code namespace | Keep `IICP-EVAL-*` for the composition outcomes the controller emits; evaluator-internal codes stay opaque and are not reinterpreted |
| 3 | What `request_digest` covers | SHA-256 over the JCS-canonicalized signed request envelope, including action, target, audience and administrative domain |
| 4 | Generation semantics | One field only: `binding.policy_generation` is the management-side generation. Evaluator policy identity is `policy.digest`; no second generation |
| 5 | `allow_unresolved` at the local gate | Explicit sentinel state, never allow. The named resolver must complete before execution, and the gate records the pending obligation |
| 6 | Evidence shape | Digest plus optional `uri`; evidence `kind` values are profile-defined, not enumerated in v0 |
| 7 | Extension classes | Reuse the management profile's four classes unchanged |
| 8 | Integrity and transport | v0 has no signature field. The result must travel over an authenticated channel, or a later version adds a signature envelope; the maintainers should pick one before this leaves draft |

## Provenance

Drafted from the issue text and the existing management contracts
(`management-profile-v1`, `management-profile-requirement-v1`,
`management-profile-intersection-v1`, `local-apply-gate-v1`). The result schema
does not modify those contracts.

Drafted with AI assistance; reviewed before any proposal is opened.
