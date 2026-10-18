# Projection probes: five carriers, both sides of CLC

A **projection probe** maps one carrier's native structure into CLC, runs the
CLC decision, and lists what the mapping could not carry.  It is not a
conformance suite: it shows that the mapping is *possible and honest* for a
carrier, case by case, rather than asserting that CLC "can express" it.

All probes are small Go programs under `register/cmd/`, with their raw output
checked in beside a README under `contrib/`.  Checked 2026-10-17.

## Evidence side

| Probe | Carrier (revision) | What is projected | Cases | Main residuals |
|---|---|---|---|---|
| [`emilia-projection`](emilia-projection/) | `draft-schrock-ep-authorization-evidence-chain-08` §4; AEB-07 §5.2; CAID-05 §4.7 | `EP-AEC-REQUIREMENT-v1` → `CLC-REQUIREMENT-v1`; AEB facts; CAID action identity → §4.2 | 6/6 PASS | quorum role naming (`ep-quorum` vs `ep-human-authorization`), `status_required`, `subject_id_source`, `purpose`; **`required_bindings` is a relation** |
| [`gilda-projection`](gilda-projection/) | checked against `draft-gilda-wimse-agent-audit-record-02` §5.3/§6.5 (now renamed `draft-gilda-audit-agent-audit-record-00`) | `decision.reported` × `evaluation.status` → CLC verdict; `unavailableInput` → residual | 6/6 PASS | conditions; `unavailableInput`; **`agreement` is a relation** between decision and effect |
| [`oasnt-projection`](oasnt-projection/) | `draft-thallapelly-oasnt-02` §5.3, §6.2 | approval token → one Fact + an action binding (`adg`) | 6/6 PASS | `dsp`, `rqf`, `asl`, `int` (only via eligibility), `jti`, `exp`, nested parameters |

Evidence-side pattern: the projection target is
**Observation / Fact / Requirement / Result**, and the residuals are mostly
**relations between artifacts** or carriers' own metadata.

## Authorization side

| Probe | Carrier (revision) | What is projected | Cases | Main residuals |
|---|---|---|---|---|
| [`asor-authorization-projection`](asor-authorization-projection/) | `draft-asor-wimse-agent-delegation-chain-02` §3, §4.1, §4.2 | each `scope` → one Grant; `constraints[{key,max}]` → params; chain → `AuthorizeWithChain` | 7/7 PASS | `par_hash`, `del_depth`/`del_max_depth`, `delegation_mode`, principal standing, status/revocation; one token maps to **several** grants |
| [`rar-authorization-projection`](rar-authorization-projection/) | RFC 9396 §2/§3 (`authorization_details`) | `type`+`actions` → Grants; type-specific fields → params | 4/4 PASS | `locations` (no slot), `datatypes`; actions multiply into grants |

Authorization-side pattern: the target is **Grant + Operation**, and the
residuals are mostly **identity dimensions and carrier metadata**, not
relations.

## What the five probes pin together

1. **Both sides project.** The evidence side has four target objects; the
   authorization side has two.  Neither needs carriage, trust or lifecycle to
   be part of CLC.
2. **The residual class differs by side.** Evidence carriers lose *relations*
   (AEC `required_bindings`, Gilda `agreement`); authorization carriers lose
   *identity dimensions and metadata* (`par_hash`, depth, mode, `locations`).
3. **Relations become identities.** A carrier that wants a relation to count
   normalizes it into a fact whose subject is a digest over the relation tuple
   (see [`docs/evidence-relation-normalization.md`](../docs/evidence-relation-normalization.md)).
   Endpoints present is not the relation (`sym-047`); the normalized fact
   evaluates normally (`sym-048`).
4. **One carrier object may become many grants.** ASOR scopes and RAR actions
   both multiply; a "chain" or a "detail" is not a grant.

## Run them

```sh
cd register
go run ./cmd/emilia-projection-probe
go run ./cmd/gilda-projection-probe
go run ./cmd/oasnt-projection-probe
go run ./cmd/asor-projection-probe
go run ./cmd/rar-projection-probe
```

Each program prints its mapping, its cases, and its residuals; the checked-in
`out-probe.txt` beside each README is the output of the same run.

## What these probes do not claim

- They are **not conformance tests** and do not replace the corpora
  (`vectors.json`, `evidence-vectors.json`, `symmetry-vectors.json`).
- They use the drafts' published examples and shapes; a carrier's own
  implementation may differ in details the probe does not exercise.
- They are written by the same author as CLC, so they are regression evidence
  for the mapping, not independent interpretation.

## Related probes

- [`iicp-touchpoint`](iicp-touchpoint/) — the fixed CLC grant/operation pair and
  twelve adverse cases answering IICP's comparison touchpoint (not a carrier
  projection).
- [`clc-unit-encoding`](clc-unit-encoding/) — quantity as `{value, unit}`
  objects across two implementations.
