# Boundary coverage map (audit V-3 / V-4 / V-6)
[中文](zh/boundary-coverage-map.md)

Status: informative.  The audit asked for more cross-family, I-JSON and JCS
boundary coverage.  This map shows where each class is already pinned, so new
work does not duplicate existing vectors.

## V-3 cross-family

| Case | Pinned by |
|---|---|
| numeric × enum, both orders | `param-bounds-meet-vectors.json` `bm-012`/`bm-013`; `bm-026`/`bm-027` |
| scalar × nested (numeric/enum vs object) | `param-bounds-meet-vectors.json` (`bm-019`), design-notes D12 |
| string × number in `Intersect` | `vectors.json` `intersect-011`…`intersect-013` |
| cross-family at authorization | `decide` vectors for the `invalid_params_binding` path |
| declared domain × different declared domain | §6.7 rule + `string-domain-vectors.json` s-022…s-024 |

## V-4 I-JSON / integer boundary

| Case | Pinned by |
|---|---|
| integer > 2^53−1 refused on the raw path | `vectors.json` `params-053`…`params-062` |
| exponent / trailing `.0` cannot launder an over-bound integer | same range |
| number identity `-0`≡`0`, `1e3`≡`1000`, `1.5e-3`≡`0.0015` | `params-063`…`params-070` |
| decoded-path int64/uint64 carriers | `semantics/rawparams_sanity_test.go` `TestIJSONIntegerBoundDecoded` |
| `param_bounds` number corners | `param-bounds-vectors.json` `pb-044`…`pb-049` |

## V-6 JCS / canonicalization

| Case | Pinned by |
|---|---|
| `&`, `<`, `>` not HTML-escaped | `semantics/canonical_test.go` ampersand tests; `evidence-vectors.json` `eva-006` |
| key order is UTF-16 code-unit order | `TestCanonicalJSONUTF16KeyOrder` |
| number canonical form | `TestCanonicalJSONNumbers` |
| key-insertion order does not change bytes; idempotence | `TestCanonicalJSONOrderAndIdempotence` |
| equivalent text → same signing input | `TestSigningInputStableAcrossRepresentation` |

## Gaps found while mapping

1. **Depth boundary** was untested and the implementation was one level
   stricter than §6.2; fixed 2026-10-18 (`paramsDepth` counts containers only;
   `TestParamsNestingBoundary` pins 32 accepted / 33 refused).
2. No vector pins **canonical form of a `decimal-string` value** beyond the
   lexical rule — `string-domain-vectors.json` s-012…s-018 cover rejection and
   `007`≡`7`, which is the comparison rule; canonical bytes are not separately
   pinned because the value is a string and JCS leaves strings unchanged.
3. ~~No rule for a declared domain inside `param_bounds`.~~  **Closed
   2026-10-18**: §6.7 now says a declared-domain parameter MUST live in
   `params`; a `param_bounds` family on the same key is
   `invalid_params_binding`.  Implemented in Go/Python/TypeScript and pinned by
   `p-001` (authorization) and the matching containment rule
   (`params_not_narrower`).

Item 2 is recorded rather than invented: a `decimal-string` value is a string,
so JCS leaves it unchanged; the comparison rule is pinned by s-012…s-018.
