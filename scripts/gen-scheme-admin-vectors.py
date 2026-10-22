#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
"""Generate data/_vectors/scheme-admin-v1/scheme-admin-vectors.json.

The corpus is generated rather than hand-maintained because every package and
transition digest is a content address: editing one member by hand would
silently invalidate the binding the vector is supposed to test.

Digest convention (shared with register/internal/schemedecl):

  digest(x) = "sha256:" + base64url(SHA-256(JCS(x)))     (unpadded)

Payload bytes are pinned as the JCS encoding, so a deployer that receives a
differently formatted file canonicalizes before hashing.  Key ids are
`digest(SubjectPublicKeyInfo)` and are materialized by the Go runner from the
`*_key_seeds` fixture names; ECDSA key generation is not reproducible in this
script, so seeds are the only runtime-filled members.

Usage:
  scripts/gen-scheme-admin-vectors.py            # rewrite corpus + bootstrap
  scripts/gen-scheme-admin-vectors.py --check    # fail if either file is stale
"""

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "data", "_vectors", "scheme-admin-v1", "scheme-admin-vectors.json")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(obj_or_bytes):
    raw = obj_or_bytes if isinstance(obj_or_bytes, bytes) else canon(obj_or_bytes).encode()
    return "sha256:" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def d(n):
    """A syntactically valid placeholder digest."""
    return "sha256:" + base64.urlsafe_b64encode(bytes([n]) * 32).decode().rstrip("=")


PREV5 = d(0x11)
PREV6 = d(0x22)
PREV7 = d(0x33)
PREV8 = d(0x44)
ROOTPKG = d(0x55)
WRONG = d(0x66)

ADMIN = "varwof/scheme-admin-v1"


def load(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return json.load(f)


# ---------------------------------------------------------------- definitions

definitions = {
    "payments-v1": {
        "scheme_id": "std/payments-v1",
        "name": "Standard Payments Capabilities (v1)",
        "version": "1.0.0",
        "description": "Minimal payments scheme used by the scheme-admin conformance corpus.",
        "vendor": "std",
        "product": "payments-v1",
        "author": "varwof",
        "license": "Apache-2.0",
        "capabilities": [
            {"id": "transfer", "description": "Transfer funds"},
            {"id": "refund", "description": "Refund a transfer"},
        ],
    },
    "scheme-admin-v1": load("data/varwof/scheme-admin-v1/v1.json"),
}

declarations = {
    "payments-v1": {
        "@version": "CLC-SCHEME-v1",
        "scheme": "std/payments-v1",
        "declaration_id": "std/payments-v1@2026-10-22",
        "clc_revision": "CLC-1.19",
        "capabilities": {
            "transfer": {
                "params": {
                    "amount": {"domain": "quantity", "unit": "CNY"},
                    "currency": {"domain": "enum"},
                }
            },
            "refund": {"params": {"amount": {"domain": "quantity", "unit": "CNY"}}},
        },
    },
    "payments-v1-clc120": {
        "@version": "CLC-SCHEME-v1",
        "scheme": "std/payments-v1",
        "declaration_id": "std/payments-v1@2026-10-22-clc120",
        "clc_revision": "CLC-1.20",
        "capabilities": {
            "transfer": {
                "params": {
                    "amount": {"domain": "quantity", "unit": "CNY"},
                    "currency": {"domain": "enum"},
                }
            }
        },
    },
    "scheme-admin-v1": load("data/varwof/scheme-admin-v1/clc-declaration.json"),
}

for _name, _decl in declarations.items():
    if "digest" not in _decl:
        _decl["digest"] = digest(_decl)

definition_digests = {k: digest(v) for k, v in definitions.items()}
declaration_digests = {k: digest(v) for k, v in declarations.items()}


# ------------------------------------------------------------------ publishers

def cap(capability, **params):
    return {"scheme_id": ADMIN, "capability_id": capability, "parameters": params}


PUBLISHERS = {
    "payments-admin": {
        "seed": "payments-admin",
        "principal": "principal:payments-scheme-admin",
        "capabilities": [
            cap("scheme:create", namespace="/std/payments-v1",
                change_class=["major"], major=3, clc_revision=["CLC-1.19"]),
            cap("scheme:update", namespace="/std/payments-v1",
                change_class=["patch", "minor"], major=3, clc_revision=["CLC-1.19"]),
            cap("scheme:revoke", namespace="/std/payments-v1",
                package_digest=PREV6, clc_revision=["CLC-1.19"]),
        ],
    },
    "payments-admin-major": {
        "seed": "payments-admin-major",
        "principal": "principal:payments-scheme-admin",
        "capabilities": [
            cap("scheme:update", namespace="/std/payments-v1",
                change_class=["patch", "minor", "major"], major=3, clc_revision=["CLC-1.19"]),
        ],
    },
    "payments-admin-patchonly": {
        "seed": "payments-admin-patchonly",
        "principal": "principal:payments-scheme-admin",
        "capabilities": [
            cap("scheme:update", namespace="/std/payments-v1",
                change_class=["patch"], major=3, clc_revision=["CLC-1.19"]),
        ],
    },
    "wrong-namespace": {
        "seed": "wrong-namespace",
        "principal": "principal:acme-scheme-admin",
        "capabilities": [
            cap("scheme:create", namespace="/x-vendor/acme-v1",
                change_class=["major"], major=3, clc_revision=["CLC-1.19"]),
        ],
    },
    "unbounded-major": {
        "seed": "unbounded-major",
        "principal": "principal:payments-scheme-admin",
        "capabilities": [
            cap("scheme:create", namespace="/std/payments-v1",
                change_class=["major"], major=10, clc_revision=["CLC-1.19"]),
            cap("scheme:update", namespace="/std/payments-v1",
                change_class=["major"], major=10, clc_revision=["CLC-1.19"]),
        ],
    },
    "no-grant": {
        "seed": "no-grant",
        "principal": "principal:payments-scheme-admin",
        "capabilities": [],
    },
    "no-aic": {
        "seed": "payments-admin",
        "principal": "principal:payments-scheme-admin",
        "has_aic": False,
        "capabilities": [
            cap("scheme:update", namespace="/std/payments-v1",
                change_class=["patch", "minor"], major=3, clc_revision=["CLC-1.19"]),
        ],
    },
    "root-a": {
        "seed": "root-a",
        "principal": "principal:root-admin",
        "capabilities": [
            cap("scheme:root-rotate", package_digest=ROOTPKG, clc_revision=["CLC-1.19"]),
        ],
    },
    "root-outsider": {
        "seed": "root-outsider",
        "principal": "principal:root-admin",
        "capabilities": [
            cap("scheme:root-rotate", package_digest=ROOTPKG, clc_revision=["CLC-1.19"]),
        ],
    },
    "root-next-a": {
        "seed": "next-a",
        "principal": "principal:root-admin",
        "capabilities": [
            cap("scheme:root-rotate", package_digest=ROOTPKG, clc_revision=["CLC-1.19"]),
        ],
    },
    "delegator": {
        "seed": "delegator",
        "principal": "principal:payments-delegator",
        "capabilities": [
            cap("scheme:delegate", namespace="/std/payments-v1",
                change_class=["patch", "minor"], major=2, clc_revision=["CLC-1.19"]),
        ],
    },
}

# -------------------------------------------------------------------- policies

ROOT_GRANTS = [
    {"id": f"{ADMIN}:scheme:create",
     "params": {"namespace": "/std", "change_class": ["patch", "minor", "major"],
                "major": 10, "clc_revision": ["CLC-1.19"]}},
    {"id": f"{ADMIN}:scheme:update",
     "params": {"namespace": "/std", "change_class": ["patch", "minor", "major"],
                "major": 10, "clc_revision": ["CLC-1.19"]}},
    {"id": f"{ADMIN}:scheme:revoke",
     "params": {"namespace": "/std", "package_digest": PREV6,
                "clc_revision": ["CLC-1.19"]}},
    {"id": f"{ADMIN}:scheme:delegate",
     "params": {"namespace": "/std", "change_class": ["patch", "minor", "major"],
                "major": 10, "clc_revision": ["CLC-1.19"]}},
    {"id": f"{ADMIN}:scheme:create",
     "params": {"namespace": "/x-vendor", "change_class": ["patch", "minor", "major"],
                "major": 10, "clc_revision": ["CLC-1.19"]}},
]

BASE_POLICY = {
    "administration_declaration": declarations["scheme-admin-v1"],
    "root_package_digest": ROOTPKG,
    "root_key_seeds": ["payments-admin"],
    "root_threshold": 1,
    "root_grants": ROOT_GRANTS,
    "supported_clc_revisions": ["CLC-1.19"],
    "namespace_prefixes": ["/std"],
    "max_major": 3,
    "observed_at": "2026-10-22T00:00:00Z",
    "max_staleness_seconds": 86400,
}


def policy(**over):
    p = json.loads(json.dumps(BASE_POLICY))
    p.update(over)
    return p


POLICIES = {"std": policy()}

# ---------------------------------------------------------------------- states

def state(gen, pkg_digest, revision, history=None, **extra):
    s = {"scheme": "std/payments-v1", "revision": revision,
         "generation": gen, "package_digest": pkg_digest}
    if history is not None:
        s["history"] = [{"generation": g, "package_digest": dg} for g, dg in history]
    s.update(extra)
    return s


STATES = {
    "empty": {"scheme": "std/payments-v1", "generation": 0, "package_digest": ""},
    "gen6": state(6, PREV6, "1.2", [(6, PREV6)]),
    "gen5": state(5, PREV5, "1.1", [(5, PREV5)]),
    "gen7": state(7, PREV7, "1.3", [(7, PREV7)]),
}

# --------------------------------------------------------------------- builders

VECTORS = []


def pkg(scheme, revision, decl_name, change, gen, prev=None, publisher="principal:payments-scheme-admin",
        definition="payments-v1", decl_digest=None, clc="CLC-1.19", issued=None, valid=None):
    p = {
        "@version": "CLC-SCHEME-PACKAGE-v1",
        "scheme": scheme,
        "revision": revision,
        "definition_digest": definition_digests[definition],
        "declaration_digest": decl_digest or declaration_digests[decl_name],
        "clc_revision": clc,
        "change_class": change,
        "publisher": publisher,
        "generation": gen,
    }
    if prev is not None:
        p["previous_package_digest"] = prev
    if issued is not None:
        p["issued_at"] = issued
    elif valid is None:
        # Every accepted fixture is recent relative to observed_at.  Packages
        # that intentionally omit issued_at are expiry/shape vectors.
        p["issued_at"] = "2026-10-21T12:00:00Z"
    if valid is not None:
        p["valid_until"] = valid
    return p


def tr(action, scheme, namespace, to_gen, pkgobj, change, from_gen=None, from_digest=None,
       clc="CLC-1.19", **extra):
    t = {
        "@version": "CLC-SCHEME-TRANSITION-v1",
        "action": action,
        "scheme": scheme,
        "namespace": namespace,
        "to_generation": to_gen,
        "to_digest": digest(pkgobj),
        "change_class": change,
        "target_clc_revision": clc,
    }
    if from_gen is not None:
        t["from_generation"] = from_gen
    if from_digest is not None:
        t["from_digest"] = from_digest
    t.update(extra)
    return t


FAILURE_CLASS = {
    "authority_not_authorized": "authority",
    "major_exceeds_limit": "authority",
    "authority_no_grant": "authority",
    "delegation_not_contained": "authority",
    "root_rotate_no_current_root": "authority",
    "root_rotate_self_authorized": "authority",
    "state_digest_mismatch": "state",
    "state_generation_mismatch": "state",
    "generation_fork": "state",
    "generation_rollback": "state",
    "package_revoked": "state",
    "signature_no_aic": "signature",
    "clc_revision_unsupported": "schema",
    "transition_shape": "schema",
    "package_shape": "schema",
    "package_digest_mismatch": "schema",
    "package_expired": "freshness",
    "package_stale": "freshness",
}


def vec(vid, clause, derivation, package, transition, expect, publisher="payments-admin",
        policy_ref="std", state_ref=None, kind="confirm", definition="payments-v1",
        declaration="payments-v1", delegation=None, extra=None):
    v = {
        "id": vid,
        "kind": kind,
        "spec_clause": clause,
        "derivation": derivation,
        "publisher": publisher,
        "policy": policy_ref,
        "expect": expect,
    }
    if not expect.get("ok"):
        reason = expect.get("reason")
        if reason not in FAILURE_CLASS:
            raise ValueError(f"vector {vid}: no failure class for {reason!r}")
        v["failure_class"] = FAILURE_CLASS[reason]
    if definition is not None:
        v["definition"] = definition
    if declaration is not None:
        v["declaration"] = declaration
    if package is not None:
        v["package"] = package
    if transition is not None:
        v["transition"] = transition
    if state_ref is not None:
        v["state"] = state_ref
    if delegation is not None:
        v["delegation"] = delegation
    if extra:
        v.update(extra)
    VECTORS.append(v)


ACCEPT = {"ok": True}


def reject(reason):
    return {"ok": False, "reason": reason}


# 1. valid create
p = pkg("std/payments-v1", "1.0", "payments-v1", "major", 1)
vec("sa-001", "Architecture §4.9 lifecycle (create)",
    "generation 1, no previous package, publisher grant covers /std/payments-v1 create major",
    p, tr("create", "std/payments-v1", "/std/payments-v1", 1, p, "major"),
    ACCEPT, state_ref="empty")

# 2. create outside namespace (grant is for another namespace; CLC refuses the op)
p = pkg("std/payments-v1", "1.0", "payments-v1", "major", 1,
        publisher="principal:acme-scheme-admin")
vec("sa-002", "Architecture §4.9 step 7 (namespace ownership)",
    "root authority contains the /x-vendor grant, but the operation targets /std/payments-v1",
    p, tr("create", "std/payments-v1", "/std/payments-v1", 1, p, "major"),
    reject("authority_not_authorized"), publisher="wrong-namespace", state_ref="empty")

# 3. create over the policy maximum major
p = pkg("std/payments-v1", "9.0", "payments-v1", "major", 1)
vec("sa-003", "Architecture §4.9 step 7 (major limit)",
    "the grant allows major 10, so CLC admits the operation; local max_major 3 refuses it",
    p, tr("create", "std/payments-v1", "/std/payments-v1", 1, p, "major"),
    reject("major_exceeds_limit"), publisher="unbounded-major", state_ref="empty")

# 4. valid patch
p = pkg("std/payments-v1", "1.2", "payments-v1", "patch", 7, prev=PREV6)
vec("sa-004", "Architecture §4.9 lifecycle (update/patch)",
    "patch keeps major.minor 1.2 and advances generation 6 -> 7",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "patch",
          from_gen=6, from_digest=PREV6),
    ACCEPT, state_ref="gen6")

# 5. valid minor
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
vec("sa-005", "Architecture §4.9 lifecycle (update/minor)",
    "minor advances 1.2 -> 1.3 and generation 6 -> 7",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    ACCEPT, state_ref="gen6")

# 6. major update without major permission
p = pkg("std/payments-v1", "2.0", "payments-v1", "major", 7, prev=PREV6)
vec("sa-006", "Architecture §5.1 (publication boundary)",
    "publisher grant permits patch/minor only; change_class major is outside the grant set",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "major",
          from_gen=6, from_digest=PREV6),
    reject("authority_not_authorized"), state_ref="gen6")

# 7. update from the wrong digest
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV7)
vec("sa-007", "Architecture §4.9 step 8 / §9.3",
    "local head is PREV6 but the transition starts from PREV7",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV7),
    reject("state_digest_mismatch"), state_ref="gen6")

# 8. update from the wrong generation
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
vec("sa-008", "Architecture §9.3 (generation)",
    "local head is generation 5 but the transition starts from generation 6",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("state_generation_mismatch"), state_ref="gen5")

# 9. same-target-generation fork with a different digest
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
fork_state = state(6, PREV6, "1.2", [(6, PREV6), (7, PREV7)])
vec("sa-009", "Architecture §9.3 (fork)",
    "generation 7 is already recorded with PREV7; this transition proposes a different content address",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("generation_fork"), state_ref=fork_state)

# 10. replay of an already accepted generation
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
replay_state = state(6, PREV6, "1.2", [(6, PREV6), (7, digest(p))])
vec("sa-010", "Architecture §9.3 (replay)",
    "generation 7 already holds this exact digest, so the transition is a replay",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("generation_rollback"), state_ref=replay_state)

# 11. valid revoke / tombstone
p = pkg("std/payments-v1", "1.2", "payments-v1", "patch", 7, prev=PREV6)
vec("sa-011", "Architecture §4.9 lifecycle (revoke/tombstone)",
    "signed tombstone for PREV6 at generation 7 with a stable reason code",
    p, tr("revoke", "std/payments-v1", "/std/payments-v1", 7, p, "patch",
          from_gen=6, from_digest=PREV6,
          revocation_reason="security-defect",
          revocation_effective_time="2026-10-22T00:00:00Z",
          tombstone_generation=7,
          replacement_digest=PREV7),
    ACCEPT, state_ref="gen6")

# 12. reuse of a revoked package for a new deployment
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
revoked_state = state(6, PREV6, "1.2", [(6, PREV6)],
                      revoked=[{"package_digest": digest(p), "generation": 7,
                                "effective_time": "2026-10-20T00:00:00Z",
                                "reason": "security-defect"}])
vec("sa-012", "Architecture §4.9 lifecycle (revocation is permanent)",
    "the proposed package digest is in the tombstone set, so it cannot be adopted",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("package_revoked"), state_ref=revoked_state)

# 13. valid namespace delegation
delegation = {
    "grantee": "principal:payments-team",
    "parent": {"id": f"{ADMIN}:scheme:update",
               "params": {"namespace": "/std/payments-v1",
                          "change_class": ["patch", "minor"],
                          "major": 2, "clc_revision": ["CLC-1.19"]}},
    "child": {"id": f"{ADMIN}:scheme:update",
              "params": {"namespace": "/std/payments-v1/refund",
                         "change_class": ["patch"],
                         "major": 2, "clc_revision": ["CLC-1.19"]}},
}
vec("sa-013", "Architecture §4.9 (scheme:delegate)",
    "child narrows namespace (path-prefix), change class and capability; CLC containment accepts",
    None, None, ACCEPT, publisher="delegator", kind="delegation",
    delegation=delegation)

# 14. delegation outside the delegator namespace
delegation = {
    "grantee": "principal:payments-team",
    "parent": {"id": f"{ADMIN}:scheme:update",
               "params": {"namespace": "/std/payments-v1",
                          "change_class": ["patch", "minor"],
                          "major": 2, "clc_revision": ["CLC-1.19"]}},
    "child": {"id": f"{ADMIN}:scheme:update",
              "params": {"namespace": "/std/billing-v1",
                         "change_class": ["patch"],
                         "major": 2, "clc_revision": ["CLC-1.19"]}},
}
vec("sa-014", "Architecture §4.9 (scheme:delegate)",
    "child namespace /std/billing-v1 is not below the parent /std/payments-v1",
    None, None, reject("delegation_not_contained"), publisher="delegator",
    kind="delegation", delegation=delegation)

# 15. valid root rotation, current root + next-root threshold
root_pkg = pkg(ADMIN, "1.1", "scheme-admin-v1", "minor", 2, prev=ROOTPKG,
               publisher="principal:root-admin", definition="scheme-admin-v1")
root_policy = policy(
    root_package_digest=ROOTPKG,
    root_key_seeds=["root-a"],
    next_root_package_digest=digest(root_pkg),
    next_root_key_seeds=["next-a", "next-b"],
    next_root_threshold=2,
    namespace_prefixes=["/varwof", "/std"],
    max_major=3,
    root_grants=[
        {"id": f"{ADMIN}:scheme:root-rotate",
         "params": {"package_digest": ROOTPKG, "clc_revision": ["CLC-1.19"]}},
    ],
    administration_declaration=declarations["scheme-admin-v1"],
)
POLICIES["root"] = root_policy
root_state = {"scheme": ADMIN, "revision": "1.0", "generation": 1,
              "package_digest": ROOTPKG,
              "history": [{"generation": 1, "package_digest": ROOTPKG}]}
vec("sa-015", "Architecture §4.9 bootstrap (scheme:root-rotate)",
    "current root key authorizes, transition matches the configured next root and its threshold is met",
    root_pkg,
    tr("root-rotate", ADMIN, "/varwof/scheme-admin-v1", 2, root_pkg, "minor",
       from_gen=1, from_digest=ROOTPKG,
       next_root_package_digest=digest(root_pkg),
       next_root_key_seeds=["next-a", "next-b"],
       next_root_threshold=2),
    ACCEPT, publisher="root-a", policy_ref="root", state_ref=root_state,
    declaration="scheme-admin-v1", definition="scheme-admin-v1")

# 16. root rotation without the current root
vec("sa-016", "Architecture §4.9 bootstrap",
    "the signer is not a configured current root key",
    root_pkg,
    tr("root-rotate", ADMIN, "/varwof/scheme-admin-v1", 2, root_pkg, "minor",
       from_gen=1, from_digest=ROOTPKG,
       next_root_package_digest=digest(root_pkg),
       next_root_key_seeds=["next-a", "next-b"],
       next_root_threshold=2),
    reject("root_rotate_no_current_root"), publisher="root-outsider",
    policy_ref="root", state_ref=root_state,
    declaration="scheme-admin-v1", definition="scheme-admin-v1")

# 17. root rotation authorized only by the proposed next root
vec("sa-017", "Architecture §4.9 bootstrap (a new key cannot self-assert root)",
    "the signer key is only in the proposed next root, never in the current root",
    root_pkg,
    tr("root-rotate", ADMIN, "/varwof/scheme-admin-v1", 2, root_pkg, "minor",
       from_gen=1, from_digest=ROOTPKG,
       next_root_package_digest=digest(root_pkg),
       next_root_key_seeds=["next-a", "next-b"],
       next_root_threshold=2),
    reject("root_rotate_self_authorized"), publisher="root-next-a",
    policy_ref="root", state_ref=root_state,
    declaration="scheme-admin-v1", definition="scheme-admin-v1")

# 18. signature valid, no AIC
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
vec("sa-018", "Architecture §5.1 (two distinct checks)",
    "the PKCS#7 signature verifies but the certificate carries no AIC extension",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("signature_no_aic"), publisher="no-aic", state_ref="gen6")

# 19. AIC valid, no scheme-admin-v1 grant
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
vec("sa-019", "Architecture §4.9 step 4",
    "the AIC is well formed but declares no scheme:update capability",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("authority_no_grant"), publisher="no-grant", state_ref="gen6")

# 20. unsupported CLC revision
p = pkg("std/payments-v1", "1.3", "payments-v1-clc120", "minor", 7, prev=PREV6,
        clc="CLC-1.20")
vec("sa-020", "Architecture §4.9 step 1 / CLC §12.1",
    "package and declaration require CLC-1.20; the deployer supports CLC-1.19 only",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6, clc="CLC-1.20"),
    reject("clc_revision_unsupported"), declaration="payments-v1-clc120",
    state_ref="gen6")

# 21. unknown required transition field
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
t = tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
       from_gen=6, from_digest=PREV6)
t["authorization"] = {"approved": True}
vec("sa-021", "Architecture §4.9 (transition MUST NOT carry a trusted result)",
    "an unrecognized `authorization` member is refused by the closed transition schema",
    p, t, reject("transition_shape"), state_ref="gen6")

# 22. content digest mismatch
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6,
        decl_digest=WRONG)
vec("sa-022", "Architecture §4.9 step 1",
    "declaration_digest does not equal the digest of the exact declaration bytes",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("package_digest_mismatch"), state_ref="gen6")

# 23. expired package
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6,
        valid="2026-10-21T00:00:00Z")
vec("sa-023", "Architecture §4.9 step 9 / §9.3",
    "valid_until precedes the deployer's observed_at",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("package_expired"), state_ref="gen6")

# 24. stale package
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6,
        issued="2026-10-01T00:00:00Z")
vec("sa-024", "Architecture §4.9 step 9 / §9.3",
    "issued_at is older than the local maximum staleness of 86400 seconds",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("package_stale"), state_ref="gen6")

# 25. package embeds a trusted result boolean
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
p["authorized"] = True
vec("sa-025", "Architecture §4.9 (no trusted authorized member)",
    "an embedded `authorized: true` is an undeclared package member and is refused",
    p, tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
          from_gen=6, from_digest=PREV6),
    reject("package_shape"), state_ref="gen6")

# 26. transition embeds a trusted result boolean
p = pkg("std/payments-v1", "1.3", "payments-v1", "minor", 7, prev=PREV6)
t = tr("update", "std/payments-v1", "/std/payments-v1", 7, p, "minor",
       from_gen=6, from_digest=PREV6)
t["verified"] = True
vec("sa-026", "Architecture §4.9 (no trusted verified member)",
    "an embedded `verified: true` is an undeclared transition member and is refused",
    p, t, reject("transition_shape"), state_ref="gen6")


# ----------------------------------------------------------------------- emit

corpus = {
    "_meta": {
        "@version": "varwof/scheme-admin-vectors-v1",
        "generated_by": "scripts/gen-scheme-admin-vectors.py",
        "spec": "analysis/2026-10-22-authority-bounded-capability-publication-architecture.md §4.9, §9",
        "digest_rule": "sha256:<base64url-unpadded> over the JCS encoding; package and transition digest members are content addresses of their own object.",
        "key_rule": "publisher.seed, policy.root_key_seeds and *_next_root_key_seeds name deterministic fixture keys. The Go runner materialises them into certificates and fills root_keys/next_root_keys/next_root_keys, because ECDSA key generation is not reproducible in this generator.",
        "payload_rule": "Definitions and declarations are pinned as their JCS encoding. A deployer that receives a differently formatted file canonicalises before hashing.",
    },
    "definitions": definitions,
    "declarations": declarations,
    "publishers": PUBLISHERS,
    "policies": POLICIES,
    "states": STATES,
    "vectors": VECTORS,
}

# ----------------------------------------------------------------- bootstrap

# Key ids for the deterministic fixture keys used by the Go runner:
#   payments-admin       -> root_keys[0]
#   payments-admin-next  -> next_root_keys[0]
# They are test identities, not a production key-management scheme.  Keeping
# them concrete makes bootstrap.json a real pinned fixture instead of a
# fail-closed placeholder.
PAYMENTS_ADMIN_KEY_ID = "sha256:0_slIaCK6vLwO6K6vEP-wwgUbZqt_Ems0cPH1CARkuc"
PAYMENTS_ADMIN_NEXT_KEY_ID = "sha256:pSTSB8cZsDlxerMV42bQ18XWbwdepfc0PCjFPMSIjiY"

root_admin_pkg = pkg(ADMIN, "1.0", "scheme-admin-v1", "major", 1,
                     publisher="principal:root-admin", definition="scheme-admin-v1")
bootstrap_next_pkg = pkg(ADMIN, "1.1", "scheme-admin-v1", "minor", 2,
                         prev=digest(root_admin_pkg),
                         publisher="principal:root-admin-next",
                         definition="scheme-admin-v1")
bootstrap = {
    "_note": (
        "Deployment fixture for varwof/scheme-admin-v1. root_package and "
        "root_keys are real deterministic test values; root_package_digest, "
        "root_keys and next_root_* are pinned. Replace the deterministic test "
        "keys with your bootstrap ceremony's keys before deployment."
    ),
    "@version": "varwof/scheme-admin-bootstrap-v1",
    "root_package": root_admin_pkg,
    "policy": policy(
        root_package_digest=digest(root_admin_pkg),
        root_keys=[PAYMENTS_ADMIN_KEY_ID],
        root_key_seeds=["payments-admin"],
        next_root_key_seeds=["payments-admin-next"],
        root_threshold=1,
        root_grants=[
            {"id": f"{ADMIN}:scheme:create",
             "params": {"namespace": "/", "change_class": ["patch", "minor", "major"],
                        "major": 10, "clc_revision": ["CLC-1.19"]}},
            {"id": f"{ADMIN}:scheme:update",
             "params": {"namespace": "/", "change_class": ["patch", "minor", "major"],
                        "major": 10, "clc_revision": ["CLC-1.19"]}},
            {"id": f"{ADMIN}:scheme:revoke",
             "params": {"namespace": "/", "package_digest": digest(root_admin_pkg),
                        "clc_revision": ["CLC-1.19"]}},
            {"id": f"{ADMIN}:scheme:delegate",
             "params": {"namespace": "/", "change_class": ["patch", "minor", "major"],
                        "major": 10, "clc_revision": ["CLC-1.19"]}},
            {"id": f"{ADMIN}:scheme:root-rotate",
             "params": {"package_digest": digest(root_admin_pkg),
                        "clc_revision": ["CLC-1.19"]}},
        ],
        namespace_prefixes=["/"],
        max_major=10,
        next_root_package_digest=digest(bootstrap_next_pkg),
        next_root_keys=[PAYMENTS_ADMIN_NEXT_KEY_ID],
        next_root_threshold=1,
    ),
}
BOOTSTRAP = os.path.join(os.path.dirname(OUT), "bootstrap.json")
bootstrap_text = json.dumps(bootstrap, indent=2, ensure_ascii=False) + "\n"
corpus_text = json.dumps(corpus, indent=2, ensure_ascii=False) + "\n"

if "--check" in sys.argv[1:]:
    stale = []
    for path, text in ((BOOTSTRAP, bootstrap_text), (OUT, corpus_text)):
        try:
            with open(path, encoding="utf-8") as f:
                if f.read() != text:
                    stale.append(os.path.relpath(path, ROOT))
        except FileNotFoundError:
            stale.append(os.path.relpath(path, ROOT))
    if stale:
        print("scheme-admin vectors are stale: " + ", ".join(stale), file=sys.stderr)
        print("run scripts/gen-scheme-admin-vectors.py", file=sys.stderr)
        sys.exit(1)
    print(f"scheme-admin vectors are current ({len(VECTORS)} vectors)")
    sys.exit(0)

with open(BOOTSTRAP, "w", encoding="utf-8") as f:
    f.write(bootstrap_text)
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write(corpus_text)

print(f"wrote {OUT}: {len(VECTORS)} vectors")
