#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
"""Generate data/_vectors/catalog-v1/catalog-vectors.json.

The corpus is generated rather than hand-maintained because catalog, delta and
declaration digests are content addresses: a hand edit would silently break the
binding the vector is meant to test.

Digest convention (shared with register/internal/schemedecl and
register/schemeadmin):

  digest(x) = "sha256:" + base64url(SHA-256(JCS(x)))     (unpadded)

A scheme declaration's digest is taken over its JCS form without the `digest`
member, exactly as schemedecl computes it.

Signing keys are not reproducible in this script, so a vector names a
*publisher fixture* instead: the Go runner derives the key from the seed, issues
the certificate with the listed AIC capabilities and compares the recomputed
decision with `expect`.

Usage:
  scripts/gen-catalog-vectors.py            # rewrite the corpus
  scripts/gen-catalog-vectors.py --check    # fail if the file is stale
"""

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VECTOR_DIR = os.path.join(ROOT, "data", "_vectors", "catalog-v1")
DECL_PATH = os.path.join(VECTOR_DIR, "declaration.json")
OUT_PATH = os.path.join(VECTOR_DIR, "catalog-vectors.json")

OBSERVED = "2026-10-22T01:00:00Z"
ISSUED = "2026-10-22T00:59:55Z"
UNTIL = "2026-10-22T01:10:00Z"

DOMAIN = "example.org/payments"
CATALOG_ID = "example.org/payments/catalog"
SCHEME = "std/payments-v1"
PRODUCER = "principal:payments-ops"


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(obj_or_bytes):
    raw = obj_or_bytes if isinstance(obj_or_bytes, bytes) else canon(obj_or_bytes).encode()
    return "sha256:" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def d(n):
    """A syntactically valid placeholder digest."""
    return "sha256:" + base64.urlsafe_b64encode(bytes([n]) * 32).decode().rstrip("=")


WRONG = d(0x66)
OTHER = d(0x77)


def write_json(path, obj):
    text = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


# --------------------------------------------------------------- declaration

with open(DECL_PATH, encoding="utf-8") as f:
    declaration = json.load(f)
DECL_DIGEST = digest({k: v for k, v in declaration.items() if k != "digest"})
declaration["digest"] = DECL_DIGEST


# ------------------------------------------------------------------- entries

def status(reference="status:provider-payments", checked_at="2026-10-22T00:59:50Z"):
    return {"reference": reference, "checked_at": checked_at}


def transfer(amount=5000, decl_digest=DECL_DIGEST, entry_status=None, **over):
    e = {
        "capability": SCHEME + ":transfer",
        "provider": "spiffe://example.org/provider/payments",
        "scheme": SCHEME,
        "scheme_declaration_digest": decl_digest,
        "operations": [
            {
                "operation": "payments.transfer",
                "params": {
                    "amount": amount,
                    "counterparty": "vendor.example",
                    "currency": "USD",
                },
            }
        ],
    }
    if entry_status is None:
        entry_status = status()
    if entry_status is not False:
        e["status"] = entry_status
    e.update(over)
    return e


def refund(amount=5000, entry_status=None, **over):
    e = {
        "capability": SCHEME + ":refund",
        "provider": "spiffe://example.org/provider/payments",
        "scheme": SCHEME,
        "scheme_declaration_digest": DECL_DIGEST,
        "operations": [
            {"operation": "payments.refund", "params": {"amount": amount}}
        ],
    }
    if entry_status is None:
        entry_status = status()
    if entry_status is not False:
        e["status"] = entry_status
    e.update(over)
    return e


def orders(entry_status=None):
    e = {
        "capability": "std/orders-v1:submit",
        "provider": "spiffe://example.org/provider/orders",
        "scheme": "std/orders-v1",
        "scheme_declaration_digest": OTHER,
        "operations": [{"operation": "orders.submit", "params": {}}],
    }
    if entry_status is None:
        entry_status = status()
    if entry_status is not False:
        e["status"] = entry_status
    return e


def catalog(entries, generation=1, previous=None, issued=ISSUED, until=UNTIL, producer=PRODUCER):
    c = {
        "@version": "CLC-CAPABILITY-CATALOG-v1",
        "domain": DOMAIN,
        "catalog_id": CATALOG_ID,
        "generation": generation,
        "issued_at": issued,
        "valid_until": until,
        "producer": producer,
        "entries": entries,
    }
    if previous is not None:
        c["previous_digest"] = previous
    return c


gen1 = catalog([transfer(), refund()])
GEN1 = digest(gen1)

gen2 = catalog([transfer(7000)], generation=2, previous=GEN1)
GEN2 = digest(gen2)

gen3 = catalog([refund(2500), transfer(7000)], generation=3, previous=GEN2)
GEN3 = digest(gen3)

catalogs = {
    "gen1": gen1,
    "gen2": gen2,
    "gen3": gen3,
    # Same generation and predecessor as gen2 but different content.
    "gen2-fork": catalog([refund(), transfer(8000)], generation=2, previous=GEN1),
    # Generation 2 whose predecessor is not the accepted generation 1.
    "gen2-badprev": catalog([refund(), transfer(7000)], generation=2, previous=WRONG),
    # Generation 3 while the deployer only accepted generation 1.
    "gen3-gap": catalog([refund(2500), transfer(7000)], generation=3, previous=GEN2),
    # Signer outside the published capability.
    "gen1-narrow": catalog([transfer(), refund()], producer="principal:narrow-ops"),
    # Signer holds transfer only up to amount 5000.
    "gen1-high": catalog([transfer(6000), refund()], producer="principal:capped-ops"),
    "gen1-noaic": catalog([transfer(), refund()], producer="principal:noaic-ops"),
    "gen1-foreign": catalog([transfer(), refund()], producer="principal:foreign-ops"),
    # Freshness variants.
    "gen1-stale": catalog(
        [transfer(), refund()],
        issued="2026-10-21T00:00:00Z",
        until="2026-10-23T00:00:00Z",
    ),
    "gen1-expired": catalog(
        [transfer(), refund()],
        issued="2026-10-21T23:00:00Z",
        until="2026-10-22T00:30:00Z",
    ),
    # Status variants.
    "gen1-nostatus": catalog([transfer(entry_status=False), refund(entry_status=False)]),
    "gen1-stalestatus": catalog(
        [
            transfer(entry_status=status(checked_at="2026-10-21T00:00:00Z")),
            refund(entry_status=status(checked_at="2026-10-21T00:00:00Z")),
        ]
    ),
    # Shape variants.
    "gen1-baddigest": catalog([transfer(decl_digest="sha256:short"), refund()]),
    "gen1-duplicate": catalog([transfer(), transfer()]),
    "gen1-orders": catalog([transfer(), orders()]),
    "gen1-declmismatch": catalog([transfer(decl_digest=WRONG), refund()]),
}
catalogs["gen1-unknown"] = dict(gen1)
catalogs["gen1-unknown"]["signature"] = {"profile": "none", "signer_hint": PRODUCER}


# ------------------------------------------------------------------- deltas

def delta(base, target_generation, base_digest=None, target_digest=None, **over):
    d_ = {
        "@version": "CLC-CAPABILITY-CATALOG-DELTA-v1",
        "domain": DOMAIN,
        "catalog_id": CATALOG_ID,
        "base_generation": base,
        "target_generation": target_generation,
        "base_digest": base_digest if base_digest is not None else GEN1,
        "target_digest": target_digest if target_digest is not None else GEN2,
        "issued_at": ISSUED,
        "valid_until": UNTIL,
        "producer": PRODUCER,
    }
    d_.update(over)
    return d_


# Mirror of catalog.Apply: remove, replace, add, then order by capability.
def apply(base_catalog, d_):
    entries = {e["capability"]: e for e in base_catalog["entries"]}
    for capability in d_.get("remove", []):
        del entries[capability]
    for e in d_.get("replace", []):
        entries[e["capability"]] = e
    for e in d_.get("add", []):
        entries[e["capability"]] = e
    result = dict(base_catalog)
    result["generation"] = d_["target_generation"]
    result["issued_at"] = d_["issued_at"]
    result["valid_until"] = d_["valid_until"]
    result["previous_digest"] = d_["base_digest"]
    result["producer"] = d_["producer"]
    result["entries"] = [entries[k] for k in sorted(entries)]
    return result


d_apply = delta(1, 2, replace=[transfer(7000)], remove=[SCHEME + ":refund"])
d_addback = delta(2, 3, base_digest=GEN2, target_digest=GEN3, add=[refund(2500)])
applied = apply(gen1, d_apply)
assert applied == gen2, "delta d-apply does not reproduce gen2"
assert digest(applied) == GEN2

deltas = {
    "d-apply": d_apply,
    "d-addback": d_addback,
    "d-wrongbase": delta(1, 2, base_digest=WRONG, replace=[transfer(7000)]),
    "d-add-existing": delta(1, 2, add=[transfer(9000)]),
    "d-remove-unknown": delta(1, 2, remove=[SCHEME + ":unknown"]),
    "d-wrongtarget": delta(1, 2, target_digest=WRONG, replace=[transfer(7000)], remove=[SCHEME + ":refund"]),
    "d-badtargetgen": delta(1, 3, replace=[transfer(7000)]),
    "d-double": delta(1, 2, replace=[transfer(7000)], remove=[SCHEME + ":refund", SCHEME + ":transfer"]),
}


# ---------------------------------------------------------------- discovery

discovery = {
    "@version": "CLC-CATALOG-DISCOVERY-v1",
    "provider": "spiffe://example.org/provider/payments",
    "catalog_id": CATALOG_ID,
    "catalog_digest": GEN1,
    "generation": 1,
    "issued_at": ISSUED,
    "valid_until": UNTIL,
    "status_reference": "status:provider-payments",
    "scheme_declaration_digests": [DECL_DIGEST],
}
discoveries = {
    "disc-1": discovery,
    "disc-verdict": dict(discovery, verified=True),
    "disc-wrongdigest": dict(discovery, catalog_digest=WRONG),
}


# ---------------------------------------------------------------- publishers

publishers = {
    "payments-ops": {
        "seed": "catalog-payments-ops",
        "principal": PRODUCER,
        "trust_root": "ca",
        "capabilities": [
            {"scheme_id": SCHEME, "capability_id": "transfer"},
            {"scheme_id": SCHEME, "capability_id": "refund"},
        ],
    },
    "narrow-ops": {
        "seed": "catalog-narrow-ops",
        "principal": "principal:narrow-ops",
        "trust_root": "ca",
        "capabilities": [
            {"scheme_id": SCHEME, "capability_id": "refund"},
        ],
    },
    "capped-ops": {
        "seed": "catalog-capped-ops",
        "principal": "principal:capped-ops",
        "trust_root": "ca",
        "capabilities": [
            {"scheme_id": SCHEME, "capability_id": "transfer", "parameters": {"amount": 5000}},
            {"scheme_id": SCHEME, "capability_id": "refund"},
        ],
    },
    "noaic-ops": {
        "seed": "catalog-noaic-ops",
        "principal": "principal:noaic-ops",
        "trust_root": "ca",
        "has_aic": False,
        "capabilities": [],
    },
    "foreign-ops": {
        "seed": "catalog-foreign-ops",
        "principal": "principal:foreign-ops",
        "trust_root": "foreign",
        "capabilities": [
            {"scheme_id": SCHEME, "capability_id": "transfer"},
            {"scheme_id": SCHEME, "capability_id": "refund"},
        ],
    },
    "other-ops": {
        "seed": "catalog-other-ops",
        "principal": "principal:other-ops",
        "trust_root": "ca",
        "capabilities": [
            {"scheme_id": SCHEME, "capability_id": "transfer"},
            {"scheme_id": SCHEME, "capability_id": "refund"},
        ],
    },
}

roots = {
    "ca": "catalog-root-ca",
    "foreign": "catalog-foreign-ca",
}


# ----------------------------------------------------------------- policies

policy_standard = {
    "domain": DOMAIN,
    "catalog_id": CATALOG_ID,
    "schemes": {SCHEME: {"declaration": declaration}},
    "max_staleness_seconds": 600,
    "max_status_staleness_seconds": 120,
    "observed_at": OBSERVED,
}
policies = {
    "standard": policy_standard,
    "strict-status": dict(
        policy_standard,
        require_status=True,
        status_values={"status:provider-payments": "healthy"},
    ),
}


# ------------------------------------------------------------------- states

states = {
    "empty": {"generation": 0},
    "gen1": {
        "domain": DOMAIN,
        "catalog_id": CATALOG_ID,
        "generation": 1,
        "digest": GEN1,
        "history": [{"generation": 1, "digest": GEN1}],
    },
    "gen2": {
        "domain": DOMAIN,
        "catalog_id": CATALOG_ID,
        "generation": 2,
        "digest": GEN2,
        "history": [
            {"generation": 1, "digest": GEN1},
            {"generation": 2, "digest": GEN2},
        ],
    },
}


# ------------------------------------------------------------------ vectors

vectors = [
    # Accepted snapshots.
    {"id": "cat-001", "kind": "snapshot", "catalog": "gen1", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": True}},
    {"id": "cat-002", "kind": "snapshot", "catalog": "gen2", "publisher": "payments-ops",
     "policy": "standard", "state": "gen1", "roots": "ca", "expect": {"ok": True}},
    {"id": "cat-003", "kind": "snapshot", "catalog": "gen1", "publisher": "payments-ops",
     "policy": "standard", "state": "gen1", "roots": "ca",
     "expect": {"ok": True, "note": "re-verifying an accepted generation is idempotent"}},
    # Shape.
    {"id": "cat-004", "kind": "snapshot", "catalog": "gen1-baddigest", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_shape"}},
    {"id": "cat-005", "kind": "snapshot", "catalog": "gen1-duplicate", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_duplicate_entry"}},
    {"id": "cat-006", "kind": "snapshot", "catalog": "gen1-unknown", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_shape"}},
    # Scheme and declaration pinning.
    {"id": "cat-007", "kind": "snapshot", "catalog": "gen1-orders", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_scheme_unsupported"}},
    {"id": "cat-008", "kind": "snapshot", "catalog": "gen1-declmismatch", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_declaration_mismatch"}},
    # Generation state.
    {"id": "cat-009", "kind": "snapshot", "catalog": "gen1", "publisher": "payments-ops",
     "policy": "standard", "state": "gen2", "roots": "ca", "expect": {"ok": False, "reason": "catalog_generation_rollback"}},
    {"id": "cat-010", "kind": "snapshot", "catalog": "gen2-fork", "publisher": "payments-ops",
     "policy": "standard", "state": "gen2", "roots": "ca", "expect": {"ok": False, "reason": "catalog_generation_fork"}},
    {"id": "cat-011", "kind": "snapshot", "catalog": "gen2-badprev", "publisher": "payments-ops",
     "policy": "standard", "state": "gen1", "roots": "ca", "expect": {"ok": False, "reason": "catalog_previous_digest_mismatch"}},
    {"id": "cat-012", "kind": "snapshot", "catalog": "gen3-gap", "publisher": "payments-ops",
     "policy": "standard", "state": "gen1", "roots": "ca", "expect": {"ok": False, "reason": "catalog_generation_rollback"}},
    {"id": "cat-013", "kind": "snapshot", "catalog": "gen2", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_bootstrap_required"}},
    # Freshness.
    {"id": "cat-014", "kind": "snapshot", "catalog": "gen1-stale", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_stale"}},
    {"id": "cat-015", "kind": "snapshot", "catalog": "gen1-expired", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_expired"}},
    # Status.
    {"id": "cat-016", "kind": "snapshot", "catalog": "gen1-nostatus", "publisher": "payments-ops",
     "policy": "strict-status", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_status_unavailable"}},
    {"id": "cat-017", "kind": "snapshot", "catalog": "gen1-stalestatus", "publisher": "payments-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_status_stale"}},
    # Publication boundary.
    {"id": "cat-018", "kind": "snapshot", "catalog": "gen1-narrow", "publisher": "narrow-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_entry_outside_authority"}},
    {"id": "cat-019", "kind": "snapshot", "catalog": "gen1-high", "publisher": "capped-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "catalog_entry_outside_authority"}},
    # Signer.
    {"id": "cat-020", "kind": "snapshot", "catalog": "gen1-foreign", "publisher": "foreign-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "signature_chain"}},
    {"id": "cat-021", "kind": "snapshot", "catalog": "gen1-noaic", "publisher": "noaic-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "signature_no_aic"}},
    {"id": "cat-022", "kind": "snapshot", "catalog": "gen1", "publisher": "other-ops",
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "publisher_mismatch"}},
    {"id": "cat-023", "kind": "snapshot", "catalog": "gen1", "publisher": None,
     "policy": "standard", "state": "empty", "roots": "ca", "expect": {"ok": False, "reason": "signature_missing"}},
    # Deltas.
    {"id": "cat-024", "kind": "delta", "delta": "d-apply", "catalog": "gen1",
     "expect": {"ok": True, "generation": 2, "digest": GEN2}},
    {"id": "cat-034", "kind": "delta", "delta": "d-addback", "catalog": "gen2",
     "expect": {"ok": True, "generation": 3, "digest": GEN3}},
    {"id": "cat-025", "kind": "delta", "delta": "d-wrongbase", "catalog": "gen1",
     "expect": {"ok": False, "reason": "delta_base_mismatch"}},
    {"id": "cat-026", "kind": "delta", "delta": "d-add-existing", "catalog": "gen1",
     "expect": {"ok": False, "reason": "delta_operation_invalid"}},
    {"id": "cat-027", "kind": "delta", "delta": "d-remove-unknown", "catalog": "gen1",
     "expect": {"ok": False, "reason": "delta_operation_invalid"}},
    {"id": "cat-028", "kind": "delta", "delta": "d-wrongtarget", "catalog": "gen1",
     "expect": {"ok": False, "reason": "delta_digest_mismatch"}},
    {"id": "cat-029", "kind": "delta", "delta": "d-badtargetgen", "catalog": "gen1",
     "expect": {"ok": False, "reason": "delta_shape"}},
    {"id": "cat-030", "kind": "delta", "delta": "d-double", "catalog": "gen1",
     "expect": {"ok": False, "reason": "delta_operation_invalid"}},
    # Discovery: a pointer, never a verdict.
    {"id": "cat-031", "kind": "discovery", "discovery": "disc-1", "catalog": "gen1",
     "expect": {"ok": True}},
    {"id": "cat-032", "kind": "discovery", "discovery": "disc-verdict", "catalog": "gen1",
     "expect": {"ok": False, "reason": "discovery_verdict_member"}},
    {"id": "cat-033", "kind": "discovery", "discovery": "disc-wrongdigest", "catalog": "gen1",
     "expect": {"ok": False, "reason": "catalog_digest_mismatch"}},
]

corpus = {
    "@version": "CLC-CATALOG-VECTORS-v1",
    "generated_by": "scripts/gen-catalog-vectors.py",
    "observed_at": OBSERVED,
    "declaration": "declaration.json",
    "declaration_digest": DECL_DIGEST,
    "roots": roots,
    "publishers": publishers,
    "policies": policies,
    "states": states,
    "catalogs": catalogs,
    "deltas": deltas,
    "discoveries": discoveries,
    "vectors": vectors,
}


def main(argv):
    check = "--check" in argv[1:]
    decl_text = json.dumps(declaration, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    corpus_text = json.dumps(corpus, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    if check:
        stale = []
        for path, text in ((DECL_PATH, decl_text), (OUT_PATH, corpus_text)):
            with open(path, encoding="utf-8") as f:
                if f.read() != text:
                    stale.append(os.path.relpath(path, ROOT))
        if stale:
            print("catalog vectors are stale: " + ", ".join(stale), file=sys.stderr)
            print("run scripts/gen-catalog-vectors.py", file=sys.stderr)
            return 1
        print("catalog vectors are current (%d vectors)" % len(vectors))
        return 0

    with open(DECL_PATH, "w", encoding="utf-8") as f:
        f.write(decl_text)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write(corpus_text)
    print("wrote %s (%d vectors)" % (os.path.relpath(OUT_PATH, ROOT), len(vectors)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
