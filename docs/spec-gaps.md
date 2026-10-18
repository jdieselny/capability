# Specification boundary notes for CLC-v1

This file records, for a set of parameter- and containment-boundary questions
raised while cross-checking the CLC-v1 decision core across the Go, Java, .NET,
Python and TypeScript ports, **what the current normative text says** and **what
the corpus does and does not reach**. It is a current-state record — not a plan,
not a changelog, and not a conformance statement about any implementation.

Normative text: [`capability-language-core-v1.md`](capability-language-core-v1.md).
Parameter rules discussed below are in
[`reference/07-parameters.md`](reference/07-parameters.md).
Conformance corpus: [`../data/_vectors/clc-v1/`](../data/_vectors/clc-v1/).

Each entry states the current rule (with its clause), then the evidence that the
rule is observable — the vector ids resolve in the corpus files named, and the
probe behaviour is what the reference engine returns today.

---

## A. Parameter and containment boundaries in the current text

### A1. Host-language numeric types normalize to one comparison

**Current text.** §6.2 step 9 requires every numeric carrier — integer,
`float64`, arbitrary-precision integer or decimal — to normalize to the JSON
number *semantics* before comparison, and forbids falling into a string-shaped
fallback; §6.5 layer 8 applies the same rule inside the params algebra. A
numeric value therefore compares numerically whichever host type carries it, and
a host-language `true == 1` comparison is a conformance bug.

**What the corpus does not reach.** Every JSON number decodes to a single
numeric type per implementation, so the decision vectors pass under both the
narrower and the normalized behaviour. Representation invariance across a host's
own numeric types is the property that separates them, and no corpus vector
expresses it — it is pinned by §6.2 step 9 rather than by a shared vector. The
reference engine once had the string-shaped shape (a grant carried as `int`
compared as text while the same grant as `float64` compared numerically); §6.2
step 9 closes it as a normative obligation.

### A2. The precision and range boundary for `number`

**Current text.** §6.2 step 3 fixes the boundary. A numeric param is refused
`invalid_params_number` when it is non-finite or out of IEEE-754 range (e.g.
`1e400`) or over-precision (more than 17 significant decimal digits). An
**integer-valued** number whose mathematical magnitude exceeds 2^53 − 1 is
refused with the same code — judged on the value, not on digit count and not on
whether binary64 represents it exactly, so `1e100` and `9007199254740992` are
refused although binary64 holds them exactly, and `9007199254740993` is refused
although it carries only 16 digits. A non-integer-valued token of at most 17
significant digits is carried as its IEEE-754 binary64 value (round-to-nearest,
ties to even). §6.2 step 3 also fixes **number identity**: two tokens that
denote the same JSON number are one value (`-0` ≡ `0`, `1e3` ≡ `1000`,
`1.5e-3` ≡ `0.0015`). The corpus pins the boundary with `params-053`–`params-070`
and `pb-044`–`pb-049`.

**Why it matters for a port.** A JSON number is arbitrary-precision text, and a
host type may hold more or less than binary64. On the .NET port, `BigInteger`
does not implement `IConvertible`, so "convert to double and compare" is not
merely lossy but does not compile; the Java port needs the same decision for
`BigInteger` and `BigDecimal`. §6.2 step 3 (with step 9) decides it once for
every port: integer-valued magnitudes are bounded at 2^53 − 1 on the raw token,
and non-integer tokens are pinned to their binary64 value.

### A3. Key closure and the `max_rows` constraint

**Current text.** §8.1 reconciles the two rules. The `max_rows` operand is the
operation's `max_rows` parameter, read from the same params object layer-7 key
closure governs, and it is **not** exempt: an operation carrying `max_rows`
against a grant that declares other params without declaring `max_rows` fails
`undeclared_param: max_rows` before the constraint is consulted, and an
operation omitting the parameter under a `max_rows` constraint fails closed
`max_rows:violated`. A grant that declares any params *and* carries a `max_rows`
constraint MUST declare `max_rows` among its `params`/`param_bounds` keys —
written into both places at once — and only an unconstrained grant (`params`
absent, or `params:{}`) carries the constraint alone.

**What the corpus does not reach.** The `max_rows` vectors
(`decide-006`, `decide-023`, `decide-027`, `decide-031`–`decide-034`,
`combined-009`) each carry a grant with `constraints` and no `params`, so they
exercise the constraint alone, not the two-places-at-once case.

### A4. `Contains` does not treat `:`-separated action names as a hierarchy

**Current text.** §13.4.2 (`Segments are not a hierarchy`) states that the
`:`-separated segments of a capability identifier are compared by segment
equality or a trailing wildcard only; a shared *prefix* confers nothing.
`Contains(std/database-v1:query, std/database-v1:query:SELECT)` fails at that
layer with `child_exceeds_parent`, and so does the reverse. Coverage comes only
from an explicit parent trailing wildcard (`std/database-v1:query:*` covers
`std/database-v1:query:SELECT`), and the relation between an action class and an
action inside it is declared by an action type definition, never inferred from
the identifier text.

### A5. The parameter containment condition as a decision procedure

**Current text.** §13.4.3 reduces parameter narrowing to a normative table; the
operative condition is:

| parent params | child params | `Contains(parent, child)` |
|---|---|---|
| absent | absent | governed by the identifier alone |
| absent | present | contains |
| present | absent | `params_not_narrower` |
| present | present, child keys ⊇ parent keys | contains, per key |
| present | present, key sets differ | `params_not_narrower` |

The key sets are each the union of `params` and `param_bounds` keys (§6.5), and
the two readings a caller might guess — "fewer keys is narrower", "more keys is
narrower" — are each refused.

### A6. The decoded entry point and the received text

**Current text.** §6.2 step 7 pins the input boundary. The entry point that
takes the raw text is the **sole conformance entry point**: steps 1–5 run on the
received text, not on a re-serialization of a decoded value, and a decoded-value
entry point inherits the obligation that its decoding was **lossless** — a
decoder that repairs malformed input (replacing an invalid octet or an unpaired
surrogate escape with U+FFFD, as Go's `encoding/json` does) MUST NOT feed an
entry point used for a conformance claim. An implementation whose decoded entry
cannot establish losslessness MUST NOT be described as refusing malformed
Unicode: its verdict is defined over the value it was handed.

**Observed today.** The same bytes `{"s":"\ud800"}` are refused
`invalid_params_number` by the Python and TypeScript decoded entry points, while
the Go decoded entry (repairing the surrogate to U+FFFD) accepts them; across a
5 990-case differential run this produced 126 decoded-path disagreements, of
which 72 are unpaired surrogates. On the raw-text path the ports agreed on 120
of those 126 cases, all refusing `invalid_params_number`. A decoded entry point
is therefore free to disagree with another port on the same repaired input while
neither is out of conformance; §6.2 step 7 states this rather than leaving it
unstated.


## B. Corpus coverage and what it does not reach

### B1. The corpus is a set of files, and the decision vectors are one of them

[`../data/_vectors/clc-v1/`](../data/_vectors/clc-v1/) holds 14 vector corpora,
the 11 profile declarations of `profile-declarations.json`, and 2 property-case
files:

| file | cases | declared revision |
|---|---|---|
| `vectors.json` | 154 | CLC-1.0 … CLC-2.0 |
| `resolve-vectors.json` | 26 | CLC-1.11 |
| `param-bounds-vectors.json` | 49 | CLC-1.10, CLC-1.17 |
| `param-bounds-meet-vectors.json` | 27 | CLC-1.14, CLC-1.15 |
| `param-bounds-equality-vectors.json` | 11 | CLC-1.15 |
| `constraint-union-vectors.json` | 12 | CLC-1.12 |
| `constraint-union-collation-vectors.json` | 2 | CLC-1.15 |
| `crosswalk-vectors.json` | 13 | — |
| `evidence-vectors.json` | 32 | — |
| `offline-vectors.json` | 12 | — |
| `symmetry-vectors.json` | 50 | CLC-1.18, CLC-1.19 |
| `scheme-declaration-vectors.json` | 9 | CLC-1.19 |
| `quantity-vectors.json` | 8 | CLC-1.19 |
| `string-domain-vectors.json` | 24 | CLC-1.19 |
| `profile-declarations.json` | 11 declarations | CLC-1.18 |
| `property-cases.json`, `param-bounds-meet-property-cases.json` | property corpora | — |

`vectors.json` is the corpus every test entry point loads: the Go
`TestRecordVectorsRecompute`, and the Java and .NET `ClcVectorsTest`. The two
CLC-1.15 supplementary files, `constraint-union-collation-vectors` (2) and
`param-bounds-equality-vectors` (11), are not in any port's default corpus path,
so each port also carries a dedicated test that names them; all three ports run
them under `go test` / `mvn test` / `dotnet test`.

The remaining corpora — `resolve-vectors` (26), `param-bounds-vectors` (49),
`param-bounds-meet-vectors` (27), `constraint-union-vectors` (12), and the two
CLC-D sets `containment-vectors` (64) and `authorize-chain-vectors` (15) — ran
only through standalone `cmd/*-vectors-run` programs. Each now also runs from the
ordinary test entry point: Go in `semantics/corpus_runners_test.go`, Java in
`ClcCorpusRunnersTest` over the per-kind `run()` methods, .NET through
`Program.Main("all")` in `ClcCorpusRunnersTest`. The standalone runners stay as
the manual path and load the same files.

`crosswalk-vectors` (13) and `containment-crosswalk-vectors` (44) are different:
their `crosswalk`/`crossing`/`contain-crosswalk` kinds apply a **carrier binding
profile** (§13.12) that maps another ecosystem's native structure into CLC grants
— eleven profiles, one per carrier (OAuth-RAR RFC 9396, AIC-JWT, UCAN, ATN
manifests, AAE, AoA scope, AEGIS delegation, …). The pinned adapter lives in
`register/internal/crosswalkvectors`. Java carries a test-local copy of the same
eleven mappings (`CrosswalkProfiles`) and runs both corpora against the Java
engine, all 13 and 44 green; .NET has no counterpart. The CLC-side operations the
profiles drive (`Contains`, `Authorize`, `Intersect`) are ported on both SDKs and
green. `evidence-vectors` (32) likewise has no Java or .NET implementation, and
`offline-vectors` (12) is a Python check.

**§7.1 pins the union order, and every port now enforces it.** §7.1 (rev
CLC-1.15) orders normalized strings by UTF-8 byte sequence, and the same
collation governs the §8.4 `unresolved` list and the §8.5 `Resolve` output. The
reference engine's `sort.Strings` compares bytes, and the Java and .NET ports
compare UTF-8 octets as well (`Clc.UTF8_ORDER`, `Clc.Utf8Order`). The
distinguishing input is a private-use code point against an astral one: U+E000
is `EE 80 80` in UTF-8 but `E000` in UTF-16, ahead of the surrogate `D83D`.

| port | comparator | order |
|---|---|---|
| reference engine | byte order (`sort.Strings`) | `ascii`, U+E000, U+1F600 |
| Java port | UTF-8 octets | `ascii`, U+E000, U+1F600 |
| .NET port | UTF-8 octets | `ascii`, U+E000, U+1F600 |

A UTF-16 comparator reverses the last two; with `String.compareTo` or
`StringComparer.Ordinal` the .NET `ConstraintUnionRun` fails `cuc-001` and
`cuc-002`. Two things let that stand silently: the engine also has a UTF-16 site
that is correctly UTF-16 — canonical-JSON key order (§3.2.3, RFC 8785) — so the
ordinal comparator looked right next to it; and the port runners pre-sorted both
sides of `result_constraints` and `unresolved` before comparing, which made
those assertions order-insensitive. The runners now compare strictly, as the Go
runners always did, and every corpus still passes.

**A .NET test host resolves the corpus by walking up from the assembly.** Its
working directory is the test output directory, so `Helper.CorpusPath`
supplements its working-directory default with a search upward from
`AppContext.BaseDirectory`; a corpus test otherwise finds nothing and reports a
skip that passes without asserting.


### B2. The fused chain check is covered by its own corpus on all five ports

The CLC-A decision set, `vectors.json`, carries the `syntax`, `entail`,
`intersect` and `decide` kinds. The §13.11 fused chain check is specified
against its own corpus,
[`../data/_vectors/clc-d/authorize-chain-vectors.json`](../data/_vectors/clc-d/authorize-chain-vectors.json)
(15 cases, kind `authorize-chain`). All five ports implement the check —
`AuthorizeWithChain` (Go, .NET), `authorizeWithChain` (Java, TypeScript),
`authorize_with_chain` (Python) — and each runs the corpus green at 15/15.

**The fused check equals its own decomposition.** §13.11 says the fused check is
the chain gate (`Contains` per adjacent pair) followed by `Intersect(chain...)`
then `Authorize`. The Go, Java and .NET ports now prove that: each has a
decomposition test (`semantics/authorizechain_equiv_test.go`,
`ClcChainDecompositionTest` in both SDKs) that recomputes the expected decision
from those public functions alone and requires `AuthorizeWithChain` to agree,
including the ordering rule that the gate runs before operation validation. The
corpus alone does not pin this — a fused path that skipped the gate still passes
the vectors whose chain happens to be valid — so the decomposition test is what
makes "verdict-preserving" an assertion rather than a statement.

The rest of `../data/_vectors/clc-d/` is unevenly covered:
`containment-vectors.json` (64) runs on Go, Java and .NET, and
`containment-crosswalk-vectors.json` (44) runs on Go and, through the Java
test-local profile copy, on Java.

---

## C. Open ends in the evidence itself

These are not specification gaps; they bound what the observations above can
claim, and record what the differential run did and did not settle.

Reproduced with the shipped harness at seed `20260915`: 3990 regular + 2000
boundary cases (5990 total), the boundary set re-identified with a `b` prefix
to avoid the generator collision below. The three ports agree on the raw path in
all but 10 cases and on the decoded path in all but 140; no case was unstable.

- **Every decoded-path disagreement is malformed Unicode in the input.** The 140
  cases split into 96 whose text carries a lone surrogate escape (`\ud800`,
  `\udfff`, or a high surrogate not followed by a low one) and 44 whose bytes
  are literal invalid UTF-8 (`raw_b64`). The cause is one: Go's `encoding/json`
  decoder replaces the malformed sequence with U+FFFD and evaluates → `allow`,
  while the Python and TypeScript decoders reject at the decoded entry point with
  `invalid_params_number`. This is the A6 boundary; §6.2 step 7 (rev CLC-1.16)
  now pins it — the raw-text entry is the sole conformance entry point and a
  decoder that repairs malformed input MUST NOT feed one, so these 140 cases are
  outside the conformance claim rather than an unpinned behaviour. An earlier
  reading of this document left 54 of these unattributed; they are the `raw_b64`
  shares of the same set.
- **A leading UTF-8 BOM exposes a Unicode-whitespace divergence on the raw
  path.** The 10 raw-path disagreements are all `EF BB BF` before the params
  object. TypeScript's `validateRawParams` does `raw.trim()` first, and
  ECMAScript classifies U+FEFF (the BOM code point) as `WhiteSpace`, so `.trim()`
  removes it and the object validates → `allow`. Python's `str.strip` and Go's
  `strings.TrimSpace` do not treat U+FEFF as whitespace, so the BOM survives and
  both reject with `invalid_params_number`. RFC 8259 §8.1 permits a parser to
  ignore a leading BOM, so neither side was unilaterally wrong under RFC 8259;
  §6.2 step 8 (rev CLC-1.16) now removes the choice by refusing a leading BOM on
  the raw path, so the `.trim()` behaviour is out of conformance (**allow →
  deny**, recorded in §12.1).
- **The differential case generator can emit duplicate identifiers.**
  Concatenating the regular and boundary corpora without a distinct id prefix
  collides their numbering (5990 lines, 3990 unique ids); the first comparison
  run reported 85 disagreements that were entirely an artifact of the collision.
  The generator still numbers both sets from one counter.

