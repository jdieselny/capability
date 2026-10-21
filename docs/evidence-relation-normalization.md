# Evidence relations: normalize to identity (draft section for the projection)
[中文](zh/evidence-relation-normalization.md)

Status: design note, 2026-10-17.  Intended as a section of the generic
**Evidence Projection** document (not of the core).  It implements §11 of the
specification ("a relation between two artifacts is not expressible") with a
concrete mechanism, so a carrier is never forced to either invent language or
silently drop the relation.

## 1. The rule

A relation between two artifacts is **not** a CLC object.  A carrier that has
one MUST do exactly one of:

1. **Normalize it to identity** — evaluate the relation in its own verifier and
   emit a *derived fact* whose subject is a digest over the relation's inputs
   (§2).  CLC then evaluates that fact as an ordinary role; or
2. **Enforce it outside the projection** and report it as a residual
   obligation.  CLC MUST NOT report an unchecked relation as satisfied.

The first option is preferred: it turns "is A related to B?" into "does an
artifact exist that attests to it?", which is the shape CLC already evaluates.
It is the same move OASNT makes for actions (`adg`, `draft-thallapelly-oasnt-02`
§6.2): bind by identity, not by relation.

## 2. The derived fact

```
type      = <carrier>:binding:<relation>         e.g. ep:binding:permits
subject   = base64url(SHA-256(JCS(relation tuple)))
verified  = true      (the carrier's verifier decided the relation)
issued_at = the conservative freshness instant of the bound evidence
            (never the time the relation was recomputed)
```

The type is also the **role identifier** a requirement names, and the
requirement grammar's identifier alphabet does not include `/` (AEC §8.1:
letters, digits, `.`, `:`, `-`, `_`), so the separator is `:`.  Colons are
already the scheme separator elsewhere in CLC, so the shape reads as
`<carrier>:binding:<relation>`.

The **relation tuple** is a fixed, carrier-declared object:

```json
{"requirement_id":"treasury-wire-evidence@7",
 "policy_generation":"policy-7",
 "from":{"type":"policy-permit","artifact_digest":"sha256:..."},
 "relation":"permits",
 "to":{"type":"ep-quorum","artifact_set_digest":"sha256:..."},
 "action_digest":"sha256:...",
 "subjects":["alice","bob"],
 "trust":{"verifier":"native-verifier","result":"verified"},
 "status_digest":"sha256:...",
 "evidence_issued_at":["2026-09-13T11:59:00Z", "..."],
 "status_snapshot":{"outcome":"valid","source":"aeb-status",
                    "checked_at":"2026-09-13T12:00:00Z",
                    "valid_until":"2026-09-13T12:01:00Z",
                    "revocation_generation":"rev-42"}}
```

Rules for the tuple, all of which keep the mechanism bounded and local:

- the object is closed (no undeclared members) and canonicalized with JCS
  (RFC 8785), the same canonicalization §4.2/§6.2 already require;
- `subjects` is ordered deterministically (the carrier states the order, e.g.
  UTF-8 byte order) before hashing, or the tuple carries a set digest instead;
- the tuple binds the actual source and target artifacts, the exact action, the
  native verifier and trust result, the distinct subjects, the original
  evidence times, the requirement/policy generation, and the status/revocation
  snapshot used by that verifier;
- the carrier MUST state the relation's semantics, the tuple's members, and who
  verifies it — a binding profile's four obligations, applied to one relation;
- the fact is **not** self-authenticating: it is eligible only when the carrier's
  native verification produced it (the same `verified` rule as any fact).

Recomputing a relation cannot refresh the evidence it relates. The derived
fact's freshness and validity bound come from the original source and target
evidence and status snapshot. A verifier that recomputes a true relation today
over an expired approval still has expired evidence.

The probe uses concrete synthetic artifact fixtures to exercise this shape; it
does not claim that those fixtures are bytes from EMILIA's production system.
The verifier that emits the fact is authoritative for the relation and the
artifact digests. CLC treats the fact subject as opaque.

## 3. Worked example 1 — AEC `required_bindings`

`draft-schrock-ep-authorization-evidence-chain-08` §4 carries
`required_bindings: [{from_type: policy-permit, relation: permits,
to_type: ep-quorum}]`.  Normalized:

```
type    = ep:binding:permits
subject = b64url(SHA-256(JCS(relation tuple)))
```

The relying party keeps the original terms and adds the derived role:

```json
{"@version":"CLC-REQUIREMENT-v1","requirement_id":"treasury-wire-evidence@7",
 "expression":"ep-quorum AND policy-permit AND ep:binding:permits",
 "constraints":[
   {"role":"ep-quorum","constraint":"varwof/evidence-v1:freshness:sec:300"},
   {"role":"policy-permit","constraint":"varwof/evidence-v1:freshness:sec:600"},
   {"role":"ep-quorum","constraint":"varwof/evidence-v1:quorum:distinct:2"}
 ]}
```

The binding fact supplements, rather than replaces, the original quorum and
permit terms. If the chain verifier does not emit the fact, the expression is
false. Endpoints being present is not the relation (sym-047). If the source
approval is stale, a freshly recomputed binding fact does not make it fresh.

## 4. Worked example 2 — Gilda `agreement`

`draft-gilda-wimse-agent-audit-record-02` §5.3 derives `agreement` from
`decision.reported` and `effect.observed` (its Table 2).  The record already
carries the derivation; the projection makes it a fact instead of a comparison
CLC would have to perform:

```
type    = gilda/agreement-v1:<value>          e.g. gilda/agreement-v1:disagree
subject = b64url(SHA-256(JCS({"request": "<decision.requestDigest>",
                              "effect_root": "<effect.interval.afterRoot>"})))
```

A requirement that cares about disagreement names the role
`gilda/agreement-v1:disagree`; a requirement that does not care simply omits it.
The audit record keeps its own member; nothing is inferred by the projection.

## 5. What this does not do

- It does not let CLC compare two facts directly; the comparison happens in the
  carrier, once, and becomes an identity.
- It does not let a carrier omit the relation: if it has one and does not
  normalize it, the projection must carry a residual (§1 option 2), and a
  consumer that cannot discharge the residual must refuse.
- It does not define the relation vocabulary.  `permits` means what AEC says it
  means; the projection only fixes the *shape* of the normalized artifact.

## 6. If a language-level operator is ever added

Only if at least two independent carriers need the same relation, the vocabulary
closes to a small set (e.g. `subject-in:<role>`), and two independent
implementations can run it (P12).  Until then the derived-fact route costs
nothing and keeps the core minimal.
