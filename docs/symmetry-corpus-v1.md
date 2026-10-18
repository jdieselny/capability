# Symmetry corpus v1 (authorization ⇄ evidence)
[中文](zh/symmetry-corpus-v1.md)

`data/_vectors/clc-v1/symmetry-vectors.json` — 50 vectors plus two property tests.
Runner: `register/internal/symmetryvectors` (`TestSymmetryVectors`,
`TestSymmetryIdempotent`, `TestMultiGrantOrderIndependent`).

Run it fresh — the corpus is read at run time, so the Go test cache does not
invalidate on a corpus edit:

```
cd register && go test -count=1 ./internal/symmetryvectors/
```

Each vector carries **both sides of one action**: the grant/operation the
authorization relation decides, and the action observed after execution
(plus, where relevant, the evidence constraint or requirement, and facts).
The runner asserts the pair, not two unrelated outcomes.

## What the corpus pins

- **Authority is set-bounded, evidence identity is exact.** An operation inside a
  grant bound is authorized; the same operation executed with a different value is
  a different action (`sym-010`, `sym-034`).
- **An extra key behaves differently on the two sides.** An undeclared operation
  parameter denies (`undeclared_param: <key>`, `sym-009`); an undeclared observed
  field carries no identity (`sym-002`).
- **Multi-grant aggregation is any-one-covers** (`sym-033`), and a covering grant’s
  constraint is still kept when another grant also covers (`sym-035`).
- **Chain containment is per hop, then the intersection bounds the operation**
  (`sym-037`, `sym-039`). Widening a bound is `params_not_narrower`, not
  `child_exceeds_parent` (`sym-038`).
- **Constraint union is a real union**: chain hops (`sym-041`), a root-only residual
  (`sym-042`), multi-grant (`sym-043`) and cross-type (`sym-044`) all keep every
  residual obligation.
- **Evaluated vs residual is a closed split**: `max_rows` is evaluated
  (`sym-045`/`sym-046`); `time:window` and `network:cidr` are carried as residuals.
  `consumption:once` is `unknown` in the core (`sym-023`) — the enforcement point
  decides it.
- **No automatic conversion between §8.1 and §8.2**: an authorization-side
  `time:window` offered as an evidence constraint is refused
  (`invalid_evidence_constraint`, `sym-027`).
- **Relations are not expressible.** Endpoints present is not the relation
  (`sym-047`); once a carrier normalizes the relation to a fact, the role evaluates
  normally (`sym-048`). See `docs/evidence-relation-normalization.md`. The derived
  relation fact then obeys the ordinary evidence rules: fresh it satisfies
  (`sym-049`), stale it does not (`sym-050`).
- **A refused action produces no evidence** (`sym-012`, `sym-013`, `sym-036`,
  `sym-038`, `sym-039`, `sym-046`).

## Vectors

### Identity and material projection (§4.2, §4.3, §6.2, §6.4)

| id | clause | authorization | match | evidence |
|---|---|---|---|---|
| sym-001 | §4.2/§6.4 + §9 | allow | MATCH |  |
| sym-002 | §4.2 undeclared fields carry no identity | allow | MATCH |  |
| sym-003 | §4.2 material content | allow | NOT_EQUIVALENT |  |
| sym-004 | §4.2 missing material field | allow | action_not_matchable |  |
| sym-005 | §6.2 number identity | allow | MATCH |  |
| sym-006 | §4.2 + RFC 8785 §3.2.2.2 (no HTML escaping) | allow | MATCH |  |
| sym-007 | §4.2 material content | allow | NOT_EQUIVALENT |  |
| sym-008 | §6.4 step 1 different action types | allow | INDETERMINATE |  |
| sym-014 | §6.4 step 1 cross-type | allow | INDETERMINATE |  |
| sym-015 | §6.4 cross-suite | allow | INDETERMINATE |  |

### Where the two sides differ (§9 key closure vs §4.2, set-bounded authority vs exact identity)

| id | clause | authorization | match | evidence |
|---|---|---|---|---|
| sym-009 | §9.1 layer 7 vs §4.2 | deny/undeclared_param: note | MATCH |  |
| sym-010 | §4.2 set-bounded authority vs exact identity | allow | NOT_EQUIVALENT |  |

### Evidence obligations carried by the same action (§8.2, §10, AEB §5.6, AEC §4)

| id | clause | authorization | match | evidence |
|---|---|---|---|---|
| sym-013 | §9 over-bound deny; no evidence | deny/params_exceed_grant | NO_EVIDENCE |  |
| sym-016 | §8.4 residual + §4.2 identity | allow_unresolved | MATCH |  |
| sym-017 | §8.4 residual vs §8.2 explicit freshness | allow_unresolved | MATCH | varwof/evidence-v1:freshness:sec:60 -> satisfied |
| sym-018 | §10 step 4 freshness bound | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated |
| sym-019 | AEC §4 role_constraints → §8.2 quorum | allow | MATCH | varwof/evidence-v1:quorum:distinct:2 -> satisfied |
| sym-020 | §8.2 quorum counts distinct subjects | allow | MATCH | varwof/evidence-v1:quorum:distinct:2 -> violated |
| sym-021 | AEB §5.6 exclusion:initiator | allow | MATCH | varwof/evidence-v1:exclusion:initiator -> violated (exclusion:initiator_is_approver) |
| sym-022 | AEB §5.6 exclusion:initiator | allow | MATCH | varwof/evidence-v1:exclusion:initiator -> satisfied |
| sym-023 | §10 boundary: consumption is not core-evaluated | allow | MATCH | varwof/evidence-v1:consumption:once -> unknown (evidence_not_core_evaluated) |
| sym-024 | §10 eligibility: only verified facts count | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated |
| sym-025 | §10 step 4: absent issued_at fails freshness | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated |
| sym-026 | AEB §5.6: exclusion needs boundary identities | allow | MATCH | varwof/evidence-v1:exclusion:initiator -> unknown (exclusion:identity_not_supplied) |
| sym-027 | §8.2: no automatic conversion from §8.1 constraints | allow_unresolved | MATCH | varwof/constraint-v1:time:window:[{"start":"09:00","end":"17:00"}] |
| sym-028 | §10 step 4: no eligible fact fails the bound | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated (freshness:no_eligible_fact) |
| sym-029 | AEC §4 role_constraints: only verified subjects count | allow | MATCH | varwof/evidence-v1:quorum:distinct:2 -> violated |
| sym-030 | §10 step 4: a future issuance instant is not fresh | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated (freshness:future_issued) |
| sym-031 | §8.4 residual vs §10 evidence failure | allow_unresolved | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated (freshness:stale) |
| sym-032 | AEB §5.6 exclusion:executor | allow | MATCH | varwof/evidence-v1:exclusion:executor -> violated (exclusion:executor_is_approver) |

### Multi-grant aggregation (§9, §7 rule 3)

| id | clause | authorization | match | evidence |
|---|---|---|---|---|
| sym-011 | §7 intersection then §4.2 | allow | MATCH |  |
| sym-033 | §9 any-one-covers over three grants | allow | MATCH |  |
| sym-034 | §9 any-one-covers + §4.2 exact identity | allow | NOT_EQUIVALENT |  |
| sym-035 | §9 residual union: a covering grant's constraint is kept even when another grant covers | allow_unresolved | MATCH |  |
| sym-036 | §9 no covering grant; no evidence | deny/params_exceed_grant | NO_EVIDENCE |  |
| sym-043 | §7 rule 3: multi-grant constraint union keeps both | allow_unresolved | MATCH |  |

### Delegation chains (§13.11, §13.4.3, §7 rule 3)

| id | clause | authorization | match | evidence |
|---|---|---|---|---|
| sym-012 | §13.11 chain intersection bounds; no evidence after deny | deny/params_exceed_grant | NO_EVIDENCE |  |
| sym-037 | §13.11 three-hop chain: per-hop Contains then intersection | allow | MATCH |  |
| sym-038 | §13.4.3 a hop that widens a bound is refused; no evidence | deny/params_not_narrower | NO_EVIDENCE |  |
| sym-039 | §13.11 operation above the chain intersection | deny/params_exceed_grant | NO_EVIDENCE |  |
| sym-040 | §13.11 chain with a residual constraint | allow_unresolved | MATCH |  |
| sym-041 | §7 rule 3 / §13.11: chain constraint union keeps both hops | allow_unresolved | MATCH |  |
| sym-042 | §8.4 residual carried from the root of a two-hop chain | allow_unresolved | MATCH |  |
| sym-044 | §7 rule 3 / §8.4: cross-type residual union | allow_unresolved | MATCH |  |
| sym-045 | §8.1: max_rows is core-evaluated, not residual | allow | MATCH |  |
| sym-046 | §8.1: over the evaluated max_rows bound | deny/max_rows:violated | NO_EVIDENCE |  |

### Relations between artifacts (§11)

| id | clause | authorization | match | evidence |
|---|---|---|---|---|
| sym-047 | §11: a relation between artifacts is not expressible | allow | MATCH | requirement -> UNSATISFIED (requirement:expression_false) |
| sym-048 | §11: a normalized relation is a fact, and then it evaluates | allow | MATCH | requirement -> SATISFIED |
| sym-049 | §11 + §8.2: a derived relation fact carries a freshness bound | allow | MATCH | requirement -> SATISFIED |
| sym-050 | §10 step 4: a stale derived relation fact is not satisfied | allow | MATCH | requirement -> UNSATISFIED |

## Properties

- `TestSymmetryIdempotent` — the same inputs evaluated twice give the same verdict
  and note (P3, P5).
- `TestMultiGrantOrderIndependent` — for non-chain vectors with two or more
  grants, reversing the grant order does not change the outcome (P11). It
  currently covers six vectors.
