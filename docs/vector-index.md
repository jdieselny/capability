# Vector index (2026-10-20)

Every corpus under `data/_vectors/`, grouped by what it decides.  Counts are
the file lengths, checked against the files on 2026-10-20.

## At a glance

| Group | Corpora | Vectors |
|---|---|---|
| CLC-A authorization core | 7 | 281 |
| CLC-D containment | 4 | 87 |
| Carrier cross-walks | 3 | 58 (+11 profile declarations) |
| Evidence side | 2 | 44 |
| Symmetry and declared domains (CLC-1.18/1.19) | 4 | 91 |
| Property corpora (generate inputs, assert invariants) | 3 | — |

## CLC-A authorization core (`data/_vectors/clc-v1/`)

| File | Vectors | Kinds | What it pins |
|---|---|---|---|
| `vectors.json` | 154 | syntax 9, entail 65, intersect 17, decide 63 | the core grammar, entailment, intersection and decision function |
| `param-bounds-vectors.json` | 49 | param-bounds 45, param-defaults 4 | §6.5 bounds, defaults, number corners |
| `param-bounds-equality-vectors.json` | 11 | param-bounds 11 | JSON type-sensitive equality |
| `param-bounds-meet-vectors.json` | 27 | param-bounds-meet 27 | §6.6 meet, cross-family refusal |
| `constraint-union-vectors.json` | 12 | constraint-union 12 | §7.1 union |
| `constraint-union-collation-vectors.json` | 2 | constraint-union 2 | UTF-8 byte ordering |
| `resolve-vectors.json` | 26 | resolve 26 | §8.5 residual-obligation loop |

## CLC-D containment (`data/_vectors/clc-d/`)

| File | Vectors | Kinds | What it pins |
|---|---|---|---|
| `containment-vectors.json` | 64 | contain 64 | §13.4 `Contains` layers |
| `authorize-chain-vectors.json` | 15 | authorize-chain 15 | §13.11 fused chain check |
| `reason-collapse-vectors.json` | 3 | reason-collapse 3 | first-failing-hop reason |
| `profile-owned/aic-jwt-da-mode-lattice-vectors.json` | 5 | mode-lattice 5 | profile-owned delegation-mode pre-check |

## Carrier cross-walks

| File | Vectors | Kinds | What it pins |
|---|---|---|---|
| `clc-v1/crosswalk-vectors.json` | 13 | crosswalk 8, crossing 5 | native → CLC and back |
| `clc-d/containment-crosswalk-vectors.json` | 45 | contain-crosswalk 45 | per-carrier containment |
| `clc-v1/profile-declarations.json` | 11 declarations | — | §13.8.1 obligations 6/7, one per carrier profile |

## Evidence side (`data/_vectors/clc-v1/`)

| File | Vectors | Kinds | What it pins |
|---|---|---|---|
| `evidence-vectors.json` | 32 | constraint 16, requirement 6, requirement_raw 1, action_id 6, match 3 | §8.2 value grammar, §10 satisfaction, ActionId/Match |
| `offline-vectors.json` | 12 | object (`_meta`, `vectors`) | OCMP offline cases |

## Symmetry and declared domains (CLC-1.18/1.19)

| File | Vectors | Kinds | What it pins |
|---|---|---|---|
| `symmetry-vectors.json` | 50 | symmetry 50 | authorization ⇄ evidence pairs, chain/multi-grant unions, §11 relations and their derived facts |
| `scheme-declaration-vectors.json` | 9 | (no kind field) | §6.7 `CLC-SCHEME-v1` declaration validation: digest match, member closure, `unsupported_domain`, `invalid_params_binding` |
| `quantity-vectors.json` | 8 | authorize 5, contains 3 | `quantity` domain pilot |
| `string-domain-vectors.json` | 24 | (no kind field) | `decimal-string`, `subdomain`, `path-prefix`, including the lexical refusals |

## Cross-language canonical parity

| File | Count | Outputs | What it pins |
|---|---:|---:|---|
| `clc-v1/extension-parity-vectors.json` | 1 fixture | 10 + 8 errors | one shared input, fixed positive outputs and stable negative error codes for Decision Context, Record, Challenge, DSSE Envelope, ActionId, SourceChain and Requirement |

## Property corpora

| File | Shape | Invariant |
|---|---|---|
| `clc-v1/property-cases.json` | `_meta` + cases | P11 intersection properties |
| `clc-v1/param-bounds-meet-property-cases.json` | `_meta` + ops + cases | a successful meet authorizes only what every source authorizes |
| `clc-d/containment-property-cases.json` | `_meta` + ops + cases | containment forward-closure properties |

## Which runner covers what

| Corpus | Register (Go) | Demo (Python / TypeScript) |
|---|---|---|
| `vectors.json`, bounds, meet, union, resolve | `semantics` tests | the matching `*-vectors-run.py` / `ts/*-run.ts` |
| containment, chain, reason-collapse, mode-lattice | `semantics` + CLC-D runners | `contains-*`, `authorize-chain-*` |
| cross-walks | `internal/crosswalkvectors` (+ profile declarations) | crosswalk runners / Java test-local copy |
| evidence | `internal/evidencevectors` | — (Go only) |
| symmetry | `internal/symmetryvectors` | `symmetry-vectors-run.py` / `ts/symmetry-vectors-run.ts` |
| scheme declarations, quantity, declared domains | `internal/schemedecl` + `semantics` | `quantity-vectors-run.py` / `ts/quantity-vectors-run.ts` |
| extension canonical parity | `cmd/extension-parity-run` | `extension-parity-run.py` / `ts/extension-parity-run.ts` |

## Notes

- `string-domain-vectors.json` entries carry `domain`, `param`, `grant`, `op`
  and `expect` but no `kind`; the runner treats every entry as an authorization
  case.  A `kind` field would make it uniform with the other corpora.
- The three property corpora are not counted as vectors: they generate inputs
  and assert an invariant.
- The extension parity fixture is one input object with ten fixed outputs, not
  a decision corpus, plus eight stable negative error codes for the same object
  graph. Go, Python and TypeScript each validate the expected values and emit
  canonical JSON; CI compares all three byte-for-byte.
- **OCMP (2026-10-18, structured, three ports):** every vector carries a
  **structured `inputs` object** (the original prose is kept under
  `description`).  Go (`register/ocmp`), Python (`aic-capability-demo/ocmp.py`)
  and TypeScript (`aic-capability-demo/ts/ocmp.ts`) all read the corpus
  directly and pass 12/12; the Python/TypeScript outputs are byte-identical
  (`contrib/ocmp-parity/`).  The three ports share an author, so the profile
  claim is still short of P12's independent-implementation bar.
