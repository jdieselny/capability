# Scheme administration (varwof/scheme-admin-v1)

Status: **provisional, project-local**. `varwof/scheme-admin-v1` is a reference
name used by this repository. It is not a registered IETF or CLC namespace, and
nothing here changes the CLC language.

This note describes the first implementation slice of
`analysis/2026-10-22-authority-bounded-capability-publication-architecture.md`
§4.9: two immutable artifacts, a deployer confirmation path, and the corpus that
pins them. A Chinese translation is not provided yet.

## 1. What it adds, and what it does not

It adds **management artifacts** and a **local decision procedure**:

- `CLC-SCHEME-PACKAGE-v1` — one immutable, content-addressed scheme package;
- `CLC-SCHEME-TRANSITION-v1` — one proposed change to a package lineage;
- a deployer algorithm that reconstructs a CLC operation and recomputes
  authority from the publisher's AIC grant plus its own trust policy.

It adds **no CLC grammar and no CLC verdict**. The managed parameters get their
CLC-1.19 domains from an ordinary `CLC-SCHEME-v1` declaration
(`clc-declaration.json`), and containment/authorization run through
`semantics.ContainsWithDomains` and `semantics.AuthorizeSetWithDomains`.

Three consequences are deliberate:

- **No trusted result member.** Both artifacts are closed objects. An
  `authorized`, `verified` or `approved` member is an undeclared member and is
  refused as a shape error; the deployer never reads it.
- **No `scheme:verify` capability.** Any party may verify schemas, digests and
  compatibility. A signed verification result is governance evidence only when
  an explicit approval profile says so.
- **No deletion.** `scheme:revoke` produces a signed tombstone. A revoked digest
  stays revoked for every later generation.

## 2. Capabilities

| Capability | Purpose |
|---|---|
| `scheme:create` | create the first package in an authorized namespace |
| `scheme:update` | move from one package digest/generation to another |
| `scheme:revoke` | revoke a package digest and create a tombstone |
| `scheme:delegate` | delegate a never-wider subset of namespace/actions/versions |
| `scheme:root-rotate` | replace the bootstrap root by current-root authorization |
| `scheme:approve` | optional exact multi-party approval |

A full capability id is `varwof/scheme-admin-v1:<capability>`, e.g.
`varwof/scheme-admin-v1:scheme:update`.

## 3. Parameter domains

`clc-declaration.json` states the domains the deployer relies on:

| Parameter | Domain | Effect |
|---|---|---|
| `namespace` | `path-prefix` | a grant at `/std` covers `/std/payments-v1`; `/std/a` does not cover `/std/ab` |
| `change_class` | `enum` | membership in `patch`, `minor`, `major` |
| `major` | `bound` | numeric upper bound |
| `clc_revision` | `enum` | accepted language revisions |
| `package_digest`, `transition_digest` | `exact` | equality, used by `scheme:approve` |

`namespace` is the absolute clean path form of the scheme namespace. For a
package transition it must equal `/` + `scheme`.

## 4. Package

```json
{
  "@version": "CLC-SCHEME-PACKAGE-v1",
  "scheme": "std/payments-v1",
  "revision": "1.2",
  "definition_digest": "sha256:...",
  "declaration_digest": "sha256:...",
  "clc_revision": "CLC-1.19",
  "change_class": "minor",
  "previous_package_digest": "sha256:...",
  "publisher": "principal:payments-scheme-admin",
  "generation": 7
}
```

Schema: `data/_vectors/scheme-admin-v1/package.schema.json`.

- `definition_digest` and `declaration_digest` are digests of the exact payload
  bytes pinned by the deployment fixture. The declaration additionally
  self-checks its own `digest` and must name the same `scheme` and
  `clc_revision`.
- `revision` is `major.minor`. `patch` keeps it, `minor` advances the minor
  component, `major` advances the major component and resets minor to 0.
- `previous_package_digest` is absent exactly when `generation` is 1.
- `issued_at` and `valid_until` are optional; the deployer applies its own
  staleness and expiry windows.
- `publisher` is a **binding to be checked** against the signing certificate's
  AIC, never an assertion of authority.

## 5. Transition

```json
{
  "@version": "CLC-SCHEME-TRANSITION-v1",
  "action": "update",
  "scheme": "std/payments-v1",
  "namespace": "/std/payments-v1",
  "from_generation": 6,
  "to_generation": 7,
  "from_digest": "sha256:...",
  "to_digest": "sha256:...",
  "change_class": "minor",
  "target_clc_revision": "CLC-1.19"
}
```

Schema: `data/_vectors/scheme-admin-v1/transition.schema.json`.

`create` carries no `from_*` and targets generation 1. `update` and `revoke`
require `from_generation` and `from_digest`. `revoke` additionally requires
`revocation_reason`, `revocation_effective_time` and `tombstone_generation`.
`root-rotate` additionally requires `next_root_package_digest`,
`next_root_keys` and `next_root_threshold`.

## 6. Lifecycle

```text
proposed -> verified -> approved -> active -> superseded
                                    \-> revoked
```

Hard deletion is not a lifecycle operation. The tombstone records the revoked
digest, replacement digest when known, revocation generation, effective time,
stable reason code and publisher evidence.

## 7. Bootstrap and root rotation

The scheme-administration scheme cannot authorize its own first version, so a
deployer ships a `bootstrap.json`-shaped configuration:

- root administration package digest;
- root public keys (`sha256:` ids over SubjectPublicKeyInfo) and threshold;
- supported CLC revisions;
- local namespace policy.

The checked-in `bootstrap.json` uses concrete deterministic fixture key ids and
a real next-root package digest. They are test identities: replace them with
`scheme-admin keyid --cert` output for a real bootstrap ceremony.

Changing that root requires `scheme:root-rotate` plus **authorization from the
current root**, and it must satisfy the separately configured next-root
threshold. A key that appears only in the proposed next root cannot authorize its
own installation: that is `root_rotate_self_authorized`, and it is checked before
CLC authorization so no grant can override it.

## 8. Deployer confirmation

`register/schemeadmin.ConfirmSigned` (and the fail-closed compatibility stub
`Confirm`) implements §4.9's eleven steps:

1. policy, package, transition and payload-digest validation;
2. target definition and `CLC-SCHEME-v1` declaration validation;
3. publisher certificate chain, AIC presence, principal and key binding;
4. grant extraction for the concrete capability;
5. management operation construction;
6. CLC containment against the configured root authority, then CLC decision;
7. namespace ownership, major limit, change-class continuity;
8. `from_digest`/generation comparison with local registry state;
9. revocation, freshness and approval checks;
10. (the caller persists only after all checks pass);
11. a replayable `ConfirmationResult` binding every input digest.

The result never contains a bare trust boolean: `verdict` is this deployer's own
recomputation.

### Failure codes

| Code | Meaning |
|---|---|
| `package_shape` | closed package schema violation (includes embedded result members) |
| `package_digest_mismatch` | definition/declaration bytes do not match the pinned digests |
| `declaration_invalid` | the target declaration is malformed or self-inconsistent |
| `transition_shape` | closed transition schema violation |
| `package_transition_mismatch` | package and transition disagree |
| `signature_missing` / `signature_chain` / `signature_no_aic` | publisher proof absent, untrusted, or unbounded |
| `publisher_mismatch` / `publisher_key_binding` | AIC principal/key does not bind the package publisher |
| `authority_no_grant` | the AIC declares no capability for the operation |
| `authority_not_contained` | the grant is outside the configured root authority |
| `authority_not_authorized` | CLC decision denies the operation |
| `namespace_outside_policy` | the namespace is outside the deployer's prefixes |
| `namespace_mismatch` | transition namespace is not `/` + scheme |
| `clc_revision_unsupported` | the package requires a revision the deployer does not support |
| `major_exceeds_limit` | the revision major exceeds `max_major` |
| `change_class_invalid` | the revision does not follow from the previous one |
| `create_shape` | create is not generation 1 / not `major` / carries `from_*` |
| `state_not_empty` | create over a namespace that already has state |
| `state_generation_mismatch` / `state_digest_mismatch` | local head disagrees with `from_*` |
| `generation_rollback` / `generation_fork` | replay of an accepted generation, or a same-generation fork |
| `package_revoked` | the source or target digest is tombstoned |
| `package_expired` / `package_stale` | `valid_until` or staleness window violated |
| `approval_insufficient` | fewer exact approvals than the policy threshold |
| `root_rotate_no_current_root` | the signer is not a current root key |
| `root_rotate_self_authorized` | the signer is only in the proposed next root, or the next root is the current root |
| `root_rotate_policy_mismatch` | the transition does not match the configured next root |
| `root_rotate_threshold` | the next root has fewer keys than its threshold |
| `delegation_not_contained` | the child grant is not CLC-contained by the delegator's grant |

### Note on digests and the management operation

The operation carries the bounded dimensions only: `namespace`, `change_class`,
`major`, `clc_revision` (and `package_digest` for revoke / root-rotate). CLC-1.19
requires every operation parameter to be declared by the granting capability, and
a long-lived namespace grant cannot enumerate future package digests. Package and
transition digests are therefore integrity bindings: they are covered by the
detached PKCS#7 signature over the exact package bytes and emitted in the
confirmation record. `scheme:approve` is the one operation that pins them
exactly.

## 9. Conformance corpus

`data/_vectors/scheme-admin-v1/scheme-admin-vectors.json` contains 26 vectors:
the 22 required cases plus an expired package, a stale package, and an embedded
`authorized`/`verified` member.

The corpus is generated by `scripts/gen-scheme-admin-vectors.py` because every
digest is a content address. Package and transition digests are materialized by
the generator; `*_key_seeds` are materialized by the Go runner
(`register/schemeadmin/vectors_test.go`), which exercises the same path as the
deployer CLI: closed parse, detached PKCS#7 verification, then `Confirm`.

## 10. Command line

```sh
scheme-admin check \
  --package pkg.json --transition tr.json \
  --definition v1.json --declaration clc-declaration.json \
  --signature pkg.json.p7s --trust roots.pem \
  --policy policy.json --state state.json

scheme-admin root-rotate ...      # same inputs; action must be root-rotate
scheme-admin delegation --delegation d.json --policy policy.json
scheme-admin operation --package pkg.json --transition tr.json
scheme-admin keyid --cert CERT.pem
```

Exit status is 0 for accept, 2 for reject, 1 for usage or I/O failure.

## 11. Cross-language evidence

`contrib/scheme-admin/` holds a Python and a TypeScript reading of the same 26
vectors. The Go test `TestCrossLanguageVectors` materializes the corpus bundle
(inputs only: payload bytes, canonical artifacts, materialized trust policy,
registry state, detached PKCS#7 signature), runs both probes, and requires all
three to print the same evidence line per vector:

```text
sa-001 confirm accept - pkg=sha256:… tr=sha256:… op=sha256:… key=sha256:…
sa-002 confirm reject authority_not_authorized pkg=… tr=… op=… key=…
```

The probes verify the CMS signature, extract and check the AIC binding, redo the
JCS digests, and run the CLC containment/authorization relations with the
CLC-1.19 `path-prefix` domain layer. They do not receive an expected verdict.

```sh
python3 contrib/scheme-admin/run.py          # refresh out-python.txt / out-typescript.txt
python3 contrib/scheme-admin/run.py --check  # verify checked-in evidence
```

`publisher_certificate_digest` is deliberately absent from the evidence line:
the fixture certificate carries a fresh ECDSA signature on every run, so its DER
digest is a deployment-time value, not a reproducible corpus value. The
deterministic `publisher_key_id` (the `sha256:` id of the SPKI) is pinned
instead.

This is the same stewardship's cross-language validation, not an independent
implementation claim.
