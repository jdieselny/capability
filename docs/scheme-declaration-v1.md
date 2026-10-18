# Scheme Declaration (CLC-SCHEME-v1) — draft text for review
[中文](zh/scheme-declaration-v1.md)

Status: **integrated as §6.7 of the specification at CLC-1.19** (2026-10-17).
This note is the design rationale and the four decisions that were taken; the
normative text is in `capability-language-core-v1.md` §6.7.

## 1. What it adds, and what it does not

A **scheme declaration** is a content-addressed artifact that states, for one
capability scheme, **which domain each parameter has**.  It is an *input* to
evaluation, pinned by the carrier or the relying party, exactly as a grant or a
fact is pinned.  CLC never fetches it (P9).

It adds **no grammar**: a grant's `params` and `param_bounds` are unchanged.
Today the domain is inferred from the value's shape (number → bound, array →
enum, scalar → exact); with a declaration the domain is stated, and the
declared domain governs.  Where a parameter has no declaration, the current
shape inference applies unchanged, so every existing grant keeps its meaning.

It does not let a scheme define **how** a constraint value is evaluated — that
remains the declaring scheme's business (§8.1), and a constraint type the core
does not know is still `unknown_constraint`.

## 2. The artifact

```json
{
  "@version": "CLC-SCHEME-v1",
  "scheme": "std/payments-v1",
  "declaration_id": "std/payments-v1@2026-10-17",
  "clc_revision": "CLC-1.19",
  "digest": "sha256:<base64url of JCS(this object without the digest member)>",
  "capabilities": {
    "transfer": {
      "params": {
        "amount":      { "domain": "quantity", "unit": "CNY" },
        "currency":    { "domain": "enum" },
        "counterparty":{ "domain": "enum" },
        "path":        { "domain": "path-prefix", "optional": true }
      }
    }
  },
  "constraint_types": ["payments:quota:daily"]
}
```

Rules:

- `@version` MUST be `CLC-SCHEME-v1`.
- `scheme` MUST equal the scheme segment of the capability ids it governs.
- `digest` is computed over the JCS (RFC 8785) form of the object **with the
  `digest` member absent**, then base64url-encoded without padding.  A carrier
  that pins the declaration pins this digest, not a revision number.
- `clc_revision` is the language revision the declaration requires.  An input
  evaluated under it MUST declare at least that revision; an implementation
  that does not implement it refuses through the §12.1 minor gate.
- Every member is closed: an undeclared member makes the declaration malformed.
- A capability's `params` names parameters; a parameter not listed keeps the
  shape-inferred domain.  A declaration MUST NOT list a parameter the scheme's
  capability does not define.

## 3. Domains

The core currently dispatches on three domains (P4):

| domain | value shape | authorization comparison | containment (§13.4.3) |
|---|---|---|---|
| `bound` | number | operation value ≤ grant value | child value ≤ parent value |
| `enum` | array of scalars | operation value ∈ grant set | child set ⊆ parent set |
| `exact` | scalar | equal | equal |

CLC-1.19 adds four, all **types rather than syntax** (§6 extension rule):

| domain | value shape | comparison | containment |
|---|---|---|---|
| `quantity` | `{ "value": number, "unit": string, "scale"?: integer }` | unit MUST equal the declared `unit` (no conversion); normalized `value × 10^-scale` ≤ grant's | same unit; child ≤ parent |
| `decimal-string` | string, canonical decimal | value-space comparison (`"500"` ≡ `"500.00"`, `"1e3"` ≡ `"1000"`) | child ≤ parent |
| `subdomain` | DNS name | whole-label suffix, case-insensitive | child domain is the parent domain or below it |
| `path-prefix` | path | segment-boundary prefix (`/a/b` does not cover `/a/bc`) | child path is the parent path or below it |

Each domain must state, in its normative definition: determinism (P5),
termination and linear cost (P10), local decidability (P9), its reason code,
and its behaviour in `Intersect` (`BoundMeet`, §6.6).

## 4. Evaluation

1. Resolve the declaration for the grant's scheme (input, pinned by digest).
2. For each parameter present in the grant, use the declared domain if there is
   one; otherwise infer the domain from the value shape as today.
3. Authorization (`Entails`, §6): compare the operation value against the grant
   value under the domain's comparison.
4. Containment (`Contains`, §13.4.3): compare child against parent under the
   **parent's** declared domain.  If the two sides declare different domains
   for the same key, the pair is not comparable → `params_not_narrower`.
5. Intersection (`BoundMeet`, §6.6): same domain meets per that domain's rule;
   different domains refuse `invalid_params_binding` (the CLC-1.15 rule for
   cross-family meets applies unchanged).

## 5. Fail-closed rules

- A declaration with an unknown `domain` → the input is refused
  (`unsupported_domain`, see the open decision below).
- An implementation that does not implement `CLC-SCHEME-v1` and is handed an
  input declaring `CLC-1.19` → `unsupported_language_revision` (§12.1).
- A parameter declared with a domain whose value does not match the domain's
  shape → `invalid_params_binding`.
- A declaration whose `digest` does not match its content → the declaration is
  invalid; an input relying on it is refused.

## 6. Conformance

- `scheme-declaration.schema.json` validates the artifact.
- A domain's rule needs at least: a positive case, a boundary case, a negative
  case, a containment case, and a cross-domain refusal case.
- As with every rule (P12), the claim is withheld until two independent
  implementations agree.

## 7. Decisions (settled 2026-10-17)

1. **Unknown or unsupported domain → `unsupported_domain`.**  A new §9.2 code,
   produced by declaration validation and resolved before §9.1 layer 1, not
   `unknown_constraint` (the declaration is not a constraint).
2. **Unit mismatch → `unit_mismatch`.**  A new §9.2 code in §9.1 layer 9.
   "50 CNY does not cover 7 USD" is neither an exceedance nor an enumeration
   failure.
3. **The declaration lives on the scheme registry entry.**  The standalone
   artifact (`CLC-SCHEME-v1`) is normative; a carrier's registry entry (the
   existing `data/std/<scheme>/v1.json` shape) carries it as a
   `clc_declaration` member pinned by its digest.
4. **`quantity` fixes the unit at declaration time** (`"unit": "CNY"`).  Units
   are never converted, and the comparison reduces to a single numeric bound;
   a value with another unit is `unit_mismatch`.

## 8. Pilot implementation (2026-10-17)

The `quantity` domain has a working reference pilot, deliberately outside the
core comparison code:

- `register/internal/schemedecl` loads a `CLC-SCHEME-v1` declaration, validates
  the closed shape, the known domains, the quantity unit rule and the digest,
  and applies the domain through the semantics-level API
  (`semantics.AuthorizeSetWithDomains`, `semantics.ContainsWithDomains`,
  `semantics.EntailsWithDomains`): each declared quantity value becomes its
  normalized number before the ordinary relations run;
- the corpus is `data/_vectors/clc-v1/quantity-vectors.json` (8 vectors:
  inside bound, above bound, unit mismatch, scale normalization, missing scale,
  non-object value, containment accepted, containment refused);
- two tests: `TestQuantityVectors` and `TestDeclarationValidation` (unknown
  domain, digest mismatch, quantity without unit).
- **Python and TypeScript mirrors**: `aic-capability-demo/scheme_decl.py` and
  `ts/scheme_decl.ts`, each with its own runner over the same corpus.  All
  three implementations pass 8/8, and the Python and TypeScript runner outputs
  are byte-identical (`contrib/quantity-domain/`).

The three string-shaped domains are implemented in the same layer (2026-10-17):
`stringDomainCovers` in Go (`semantics/domains.go`, exact `big.Rat` for
`decimal-string`), the Python mirror (`decimal.Decimal`) and the TypeScript
mirror (`BigInt`).  The `*WithDomains` functions pre-check the string domains,
neutralize the value, then run the ordinary relations; Go has ten string-domain
cases (`TestStringDomains`).  Python and TypeScript cover the same cases in
their semantics modules.
