# Capability catalog plane (Milestones A–C)

Status: implemented 2026-10-22.  This note covers the catalog artifacts, the
deployer admission path and the three-language evidence.  It is the companion to
`analysis/2026-10-22-authority-bounded-capability-publication-architecture.md`
§4.5–§4.7 and §5; the scheme-administration plane it builds on is documented in
`docs/scheme-admin-v1.md`.

The plane answers one question: *may this deployer execute these capabilities
because this producer published them, right now, at this generation?*  It does
so without a directory service, without a network fetch at decision time and
without trusting any member of an artifact that asserts its own result.

## 1. Artifacts

| Artifact | Identifier | Mutability |
|---|---|---|
| Catalog snapshot | `CLC-CAPABILITY-CATALOG-v1` | immutable; addressed by generation + digest |
| Catalog delta | `CLC-CAPABILITY-CATALOG-DELTA-v1` | immutable; applies to exactly one base |
| Discovery record | `CLC-CATALOG-DISCOVERY-v1` | immutable; a pointer, never a verdict |

Schemas live next to the corpus:

- `data/_vectors/catalog-v1/catalog.schema.json`
- `data/_vectors/catalog-v1/delta.schema.json`
- `data/_vectors/catalog-v1/discovery.schema.json`

All three objects are **closed**.  Go decodes with
`json.Decoder.DisallowUnknownFields`; the Python and TypeScript readers reject the
first unknown member.  A discovery record carrying `verified`, `authorized`,
`approved`, `verdict`, `allowed`, `trusted` or `accepted` is refused with
`discovery_verdict_member` rather than ignored.

There is no `signature` member in any artifact.  The signature is detached
PKCS#7 over the exact file bytes; the signer is recovered from the CMS blob and
then re-checked by the validator.  This is the same split as scheme
administration: signing and verifying bytes is a CLI concern, recomputing
authority is the library's.

### 1.1 Snapshot

```json
{
  "@version": "CLC-CAPABILITY-CATALOG-v1",
  "domain": "example.org/payments",
  "catalog_id": "example.org/payments/catalog",
  "generation": 1,
  "issued_at": "2026-10-22T00:59:55Z",
  "valid_until": "2026-10-22T01:10:00Z",
  "producer": "principal:payments-ops",
  "entries": [
    {
      "capability": "std/payments-v1:transfer",
      "provider": "spiffe://example.org/provider/payments",
      "scheme": "std/payments-v1",
      "scheme_declaration_digest": "sha256:...",
      "operations": [
        {
          "operation": "payments.transfer",
          "params": {"amount": 5000, "counterparty": "vendor.example", "currency": "USD"}
        }
      ],
      "status": {"reference": "status:provider-payments", "checked_at": "2026-10-22T00:59:50Z"}
    }
  ]
}
```

Rules enforced by `catalog.Validate`:

- `@version` is exact; `domain` and `catalog_id` are catalog names; `generation >= 1`.
- `previous_digest` is forbidden at generation 1 and required for generation > 1.
- `valid_until > issued_at`.
- `entries` is non-empty and capabilities are unique across the whole catalog.
- `capability` is `<scheme>:<name>` and `scheme` is a scheme id.
- every entry has at least one operation; operation names are unique inside the entry.
- `status`, when present, carries a reference and a parseable `checked_at`;
  absence is never "healthy".

### 1.2 Delta

```json
{
  "@version": "CLC-CAPABILITY-CATALOG-DELTA-v1",
  "domain": "example.org/payments",
  "catalog_id": "example.org/payments/catalog",
  "base_generation": 1,
  "target_generation": 2,
  "base_digest": "sha256:...",
  "target_digest": "sha256:...",
  "issued_at": "2026-10-22T00:59:55Z",
  "valid_until": "2026-10-22T01:10:00Z",
  "producer": "principal:payments-ops",
  "replace": [{"capability": "std/payments-v1:transfer", "...": "..."}],
  "remove": ["std/payments-v1:refund"]
}
```

- `target_generation == base_generation + 1`; a multi-generation jump is a shape error.
- the delta must have an effect.
- a capability may appear on exactly one side (`add`, `replace`, `remove`); overlap
  is `delta_operation_invalid`.
- applying requires the base *generation and digest* to match exactly; otherwise
  `delta_base_mismatch`.
- `remove` and `replace` must name existing capabilities; `add` must not.
- the applied catalog is ordered by capability, so the result does not depend on
  the order the producer wrote the arrays in.
- the recomputed digest must equal `target_digest`; otherwise `delta_digest_mismatch`.

### 1.3 Discovery

```json
{
  "@version": "CLC-CATALOG-DISCOVERY-v1",
  "provider": "spiffe://example.org/provider/payments",
  "catalog_id": "example.org/payments/catalog",
  "catalog_digest": "sha256:...",
  "generation": 1,
  "issued_at": "2026-10-22T00:59:55Z",
  "valid_until": "2026-10-22T01:10:00Z",
  "status_reference": "status:provider-payments",
  "scheme_declaration_digests": ["sha256:..."]
}
```

`catalog.Match` only proves that the record names this exact object.  It returns
no execution decision; a consumer still verifies the catalog.

## 2. Digests and canonical form

```
digest(x) = "sha256:" + base64url(SHA-256(JCS(x)))      (unpadded)
```

JCS is the same canonicalization the rest of the repository uses.  A catalog
digest covers the object exactly as the Go struct marshals it, so omitted
optional members and `omitempty` are part of the definition; the Python and
TypeScript readers rebuild the same member set before hashing.

A declaration's digest is over its JCS form **without** the `digest` member,
matching `internal/schemedecl`.  `catalog.DigestOfDeclaration` and the policy
pinning both use that single rule.

`gen-catalog` writes the JCS form plus one newline.  That file is the exact byte
string that gets signed, so two producers that agree on the object produce
identical files.

## 3. Deployer policy and state

Policy (an input, never an artifact):

```json
{
  "domain": "example.org/payments",
  "catalog_id": "example.org/payments/catalog",
  "schemes": {
    "std/payments-v1": {"declaration": {"@version": "CLC-SCHEME-v1", "...": "..."}}
  },
  "max_staleness_seconds": 600,
  "max_status_staleness_seconds": 120,
  "require_status": true,
  "observed_at": "2026-10-22T01:00:00Z"
}
```

- The policy pins the **declaration object itself**, not only a digest.  The
  validator parses it, computes its digest and compares that against every
  entry's `scheme_declaration_digest`, and uses its `DomainMap` for the CLC-1.19
  containment check.  There is no second source of truth to drift.
- `observed_at` is an explicit policy clock.  Freshness and status staleness are
  evaluated against it, never against an implicit `time.Now()` inside the
  validator, so a decision is replayable.
- `max_staleness_seconds` / `max_status_staleness_seconds` of `0` disable the
  age check; `valid_until` still applies unconditionally.
- `require_status` refuses an entry without a status reference.

State (the deployer's accepted-generation view):

```json
{
  "domain": "example.org/payments",
  "catalog_id": "example.org/payments/catalog",
  "generation": 2,
  "digest": "sha256:...",
  "history": [{"generation": 1, "digest": "sha256:..."}, {"generation": 2, "digest": "sha256:..."}]
}
```

`RegistryState.Accept` appends the new generation once and keeps the ordered
history.  There is no rollback flag, no "recovery" mode and no downgrade path:
a lower generation is always refused.

## 4. Verification algorithm

`catalog.VerifySigned` first verifies the detached PKCS#7 signature over the
exact catalog bytes and records the catalog digest and signer key.  It then runs
the following semantic steps in this order and returns at most one stable code.
The order is part of the corpus, so all three implementations report the same
reason and the same already-established evidence fields for a multi-fault
artifact.  The legacy `catalog.Verify` is a fail-closed compatibility stub.

1. `ValidatePolicy` — domain, catalog id, at least one scheme, every declaration
   well-formed, non-negative windows, parseable `observed_at`.
2. `Catalog.Validate` — shape rules from §1.1.
3. identity — `catalog.domain` and `catalog_id` equal the policy's
   (`catalog_identity_mismatch`).
4. signer — certificate present (`signature_missing`), chains to a configured
   root (`signature_chain`), carries an AIC (`signature_no_aic`), the AIC
   principal names the producer (`publisher_mismatch`), and the AIC key hash
   binds the signing key (`publisher_key_binding`).
5. scheme support — the entry's scheme is in the policy
   (`catalog_scheme_unsupported`) and its declaration digest is the pinned one
   (`catalog_declaration_mismatch`).
6. generation — see §4.1.
7. freshness — `valid_until` (`catalog_expired`), then `issued_at` age
   (`catalog_stale`).
8. status — missing when required (`catalog_status_unavailable`), checked in the
   future or older than the window (`catalog_status_stale`).
9. publication boundary — every operation of every entry is inside a grant the
   signer holds for that exact capability, using CLC-1.19 declared-domain
   containment (`catalog_entry_outside_authority`).

The producer and provider are deliberately distinct. `catalog.producer` is the
AIC-bound publisher/administrator that signs the catalog. `entry.provider`
names the provider for which the capability is published. A publication gate
binds the peer to `entry.provider` (through one SPIFFE URI SAN or an explicit
route pin); the peer principal need not equal the catalog producer. A local
`provider_bindings` policy map may additionally bind provider names to the
producer. Without that map, `entry.provider` is attribution, not a delegation
from the peer principal.

### 4.1 Generation rules

With `state.generation == 0` the first accepted catalog must be generation 1
(`catalog_bootstrap_required`).  Otherwise:

| Situation | Result |
|---|---|
| same generation, same digest | accept (idempotent re-verification) |
| same generation, different digest | `catalog_generation_fork` |
| lower generation | `catalog_generation_rollback` |
| higher by more than one | `catalog_generation_rollback` (gap) |
| exactly +1 with `previous_digest` ≠ accepted digest | `catalog_previous_digest_mismatch` |

A digest recorded in history for the incoming generation that differs from the
incoming digest is a fork even when the generation is older than the head.

### 4.2 Failure codes

```text
catalog_shape                    catalog_digest_mismatch
catalog_duplicate_entry          catalog_scheme_unsupported
catalog_declaration_mismatch     catalog_identity_mismatch
catalog_bootstrap_required       catalog_generation_rollback
catalog_generation_fork          catalog_previous_digest_mismatch
catalog_expired                  catalog_stale
catalog_status_unavailable       catalog_status_stale
catalog_entry_outside_authority
signature_missing                signature_invalid
signature_chain
signature_no_aic                 publisher_mismatch
publisher_key_binding
delta_shape                      delta_base_mismatch
delta_operation_invalid          delta_digest_mismatch
discovery_shape                  discovery_verdict_member
```

## 5. Commands

All four commands exit `0` on success, `2` on a refused artifact and `1` on
usage or I/O failure.

```sh
# validate + canonicalize (the bytes to sign)
go run ./cmd/gen-catalog -in catalog.json -out catalog.canonical.json

# detached PKCS#7 over the exact bytes
go run ./cmd/sign-catalog -catalog catalog.canonical.json \
    -cert producer.pem -key producer.key -out catalog.p7s

# deployer admission; optionally persist the advanced state
go run ./cmd/verify-catalog -catalog catalog.canonical.json -signature catalog.p7s \
    -trust roots.pem -policy policy.json -state state.json -state-out state.next.json

# apply a delta to an exact base and emit the next snapshot
go run ./cmd/apply-catalog-delta -catalog base.json -delta delta.json -out next.json
```

`verify-catalog` prints the replayable `catalog.Result`
(`verdict`, `reason`, `detail`, `catalog_digest`, `signer_key_id`,
`policy_digest`, `state_digest`, `inputs_digest`).  It writes the new state only
on accept.

Deltas are not separately signed in this milestone.  The authority check happens
on the resulting catalog, and `target_digest` binds the delta to exactly that
catalog; signing deltas is deferred (see §8).

## 6. Corpus

`data/_vectors/catalog-v1/catalog-vectors.json`, generated by
`scripts/gen-catalog-vectors.py`:

| Kind | Vectors | Covers |
|---|---:|---|
| snapshot | 23 | accept, malformed digest, duplicate entry, unknown member, unsupported scheme, declaration mismatch, rollback, fork, stale predecessor, generation gap, bootstrap, stale, expired, missing status, stale status, two authority failures, untrusted chain, no AIC, producer mismatch, missing signature, idempotent replay |
| delta | 8 | apply, wrong base digest, add-existing, remove-unknown, wrong target digest, wrong target generation, cross-side duplicate, add-back |
| discovery | 3 | valid pointer, verdict member, wrong digest |

The fixture declaration `std/payments-v1` is **vector-local**: it exists only to
give the corpus a declared-domain layer.  It is not a registered scheme.

Regenerate and check:

```sh
python3 scripts/gen-catalog-vectors.py           # rewrite
python3 scripts/gen-catalog-vectors.py --check   # stale check
```

## 7. Cross-language evidence

`contrib/catalog/probe.py` and `probe.ts` read the same inputs as the Go runner
(exact artifact bytes, policy, state, root, detached signature) and print one
positional line per vector:

```text
<id> <kind> <verdict> <reason|-> [cat=<digest>] [key=<keyid>] [gen=<n>]
```

`register/catalog/TestCrossLanguageVectors` builds the bundle, renders the Go
line, runs both probes and requires byte equality.  The bundle contains no
expected verdict and no Go result.  The DER/CMS/AIC reader and the CLC-1.19
declared-domain relation are shared verbatim with the scheme-administration
probes; the catalog algorithm is a second reading under the same stewardship,
not an independent implementation.

```sh
python3 tools/check_catalog_cases.py        # corpus freshness + 34/34 agreement + evidence pins
node --experimental-strip-types contrib/catalog/probe.ts BUNDLE.json
```

Checked-in evidence: `contrib/catalog/out-python.txt`,
`contrib/catalog/out-typescript.txt` (34 vectors, corpus
`sha256:ki4pOy15N4LF0brT0wJ0mZHHmSKSXxgsd2gszPK2ifs`).

## 8. Deliberate limits

- **No directory plane.**  There is no global catalog service, no fetch, no
  caching layer and no gossip.  Discovery is a provider-supplied pointer.
- **Deltas require separate signed transport.**  `VerifySignedDelta` verifies
  detached PKCS#7 over exact delta bytes, binds the accepted base generation
  and revalidates the complete resulting catalog. The bounded profile does not
  provide a directory service that fetches or distributes deltas.
- **One producer per catalog.**  Multi-producer aggregation, threshold
  signatures and per-entry signer delegation are not modelled.
- **Status references are opaque strings.**  The plane checks freshness and
  presence, not the semantics of the referenced status source.
- **Bootstrap starts at generation 1.**  A deployer joining an existing catalog
  series has no "trust on first use" path; it must be given the current
  generation and digest out of band.
- **No rollback recovery.**  A refused or lost generation cannot be re-admitted.
- **`catalog_id` is local.**  Uniqueness is enforced per deployer policy, not by
  any registration authority.

None of these gaps changes CLC core authorization: the plugin only narrows what
the AIC grant already allows.
