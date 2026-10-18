# Symmetry corpus in Python and TypeScript (2026-10-18)

`data/_vectors/clc-v1/symmetry-vectors.json` has 50 vectors.  Until now only the
Go runner (`register/internal/symmetryvectors`) executed them; this directory
records the Python and TypeScript runs.

## Scope

| Port | Ran | Skipped (evidence side) | Fail |
|---|---|---|---|
| Python | **50** | 0 | 0 |
| TypeScript | **50** | 0 | 0 |

Python now has `evidence_semantics.py` (freshness / quorum / exclusion /
consumption, plus the AND/OR requirement grammar), so the whole symmetry corpus
runs there.  TypeScript still lacks the evidence evaluator and skips the 20
evidence-block vectors.

there the vectors that carry an `evidence` block are **counted and skipped**,
not passed:
there the vectors that carry an `evidence` block are **counted and skipped**,
not passed:

```
Ran: 30 | Skipped (evidence side): 20 | Fail: 0
```

The 30 that run cover:

- authorization verdict (`authorizeSet` / `authorizeWithChain`, including the
  `chain: true` vectors);
- action identity (`computeActionId` over the declared material fields) and the
  `MATCH` / `NOT_EQUIVALENT` / `INDETERMINATE` / `action_not_matchable`
  outcomes;
- `no_evidence` vectors, where a refused action must produce no evidence.

The 18 evidence-block vectors (freshness, quorum, exclusion, consumption,
requirement expressions) remain Go-only until the evidence evaluator is ported.

## Outputs

`out-python.txt` and `out-typescript.txt` are the same run and are
byte-identical.

Run:

```sh
cd aic-capability-demo
CLC_CAPABILITY_DIR=../capability python3 symmetry-vectors-run.py
CLC_CAPABILITY_DIR=../capability node --experimental-strip-types ts/symmetry-vectors-run.ts
```
