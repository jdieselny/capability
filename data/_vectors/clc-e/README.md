# CLC-E report vectors

`report-vectors.json` holds report-layer regression vectors for the CLC
Evidence Projection (M1–M4): shape validation, inventory/lineage consistency,
completeness, snapshot lifecycle and replay comparison.

Scope and limits:

- **Data only.** No private keys and no signatures are stored here; signed
  report behaviour is covered by `register/projection` unit tests, which
  generate a certificate at run time.
- **Not a conformance suite.** This file is regression evidence. It does not
  claim CLC-E conformance and does not freeze a conformance revision.
- The assessment parity corpus lives separately in
  `contrib/native-check-assessment/cases-v1.json`.

## Vector shape

| field | meaning |
|---|---|
| `id` | stable case id (`cle-001` …) |
| `name` | one-line description |
| `kind` | `validate`, `verify` or `lifecycle` |
| `report` | the report object under test (must carry `@version` and `assurance`) |
| `policy` | optional `requireProfile`, `requireComplete`, `requireSnapshotBinding`, `requireReplay`, `minAssurance`, `requiredCheckIds`, `snapshots`, `replayArtifacts` |
| `want` | `verdict` (`accept`/`reject`) and, for rejections, the stable `code` |

`kind` maps to:

- `validate` → `projection.ValidateEvidenceReport`;
- `verify` → `projection.VerifyEvidenceReport`;
- `lifecycle` → `projection.CheckReportLifecycle`.

## Run

```sh
CLC_E_VECTORS=/path/to/capability/data/_vectors/clc-e/report-vectors.json \
  go run ./cmd/clc-e-vectors-run
```

Every runner exits non-zero on any mismatch. A vector whose report cannot be
decoded is reported as `reject/report_shape`.

## Coverage

35 cases: report version/assurance (both the accepted value and refusals),
shape, digest syntax, closed outcomes, freshness, profile shape and
content-derived digest, inventory mismatch, fact-index binding (including two
records claiming one fact), unbound facts, artifact/check binding, observation
binding, `not_applicable` authority (both the unauthorized refusal and the
authorized acceptance), incompleteness, completeness-flag recomputation,
assurance enforcement (`E2` needs derivations, `E3` needs a verified
attestation, a deployer minimum is honoured and an unknown minimum is refused), derivation fact binding,
verifier attribution, a deployer-pinned required check, snapshot
rollback/fork/advance/idempotence, snapshot-coordinate requirement,
snapshot-source allowlist, replay missing/mismatch/reproduction and a complete
required-profile acceptance.

Not covered here (deliberately):

- signature, trust root, verifier allowlist and verdict recomputation — these
  need keys and live in unit tests;
- timestamp assertion and report age (`MaxAge`) — these run on the signed path;
- attestation verification itself — the vectors only prove that `E3` is
  refused when no attestation was verified;
- cross-language outcome semantics — only the assessment corpus is
  cross-language today;
- Security, Privacy and IANA considerations text.
