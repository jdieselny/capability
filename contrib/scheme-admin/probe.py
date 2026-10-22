#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
"""Cross-language evidence probe for varwof/scheme-admin-v1.

Reads a bundle produced by the Go confirmation test (only inputs: payload
bytes, canonical artifacts, the materialised trust policy, registry state and
the detached PKCS#7 signature) and prints one evidence line per corpus vector.

This is the same stewardship's second reading of the same artifacts, not an
independent implementation.  It is written against the CLC-1.15 language
package plus the CLC-1.19 declared-domain layer (path-prefix), exactly as the
Go side calls ContainsWithDomains/AuthorizeSetWithDomains.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# --------------------------------------------------------------------- CLC

_HERE = Path(__file__).resolve()
CLC_DIR = os.environ.get("CLC_PY_DIR") or str(_HERE.parents[3] / "clc-python")
sys.path.insert(0, CLC_DIR)
try:
    from clc.clc_semantics import authorize_set, canonical_json, contains
except ImportError:
    try:
        # aic-capability-demo exports the same CLC-1.19 module at its root.
        from clc_semantics import authorize_set, canonical_json, contains
    except Exception as exc:  # pragma: no cover - environment guard
        sys.stderr.write(f"probe.py: cannot import a CLC implementation from {CLC_DIR}: {exc}\n")
        raise SystemExit(2)

SCHEME_ID = "varwof/scheme-admin-v1"
PACKAGE_VERSION = "CLC-SCHEME-PACKAGE-v1"
TRANSITION_VERSION = "CLC-SCHEME-TRANSITION-v1"
AIC_OID = "1.3.6.1.4.1.66257.1.1"

CAP_CREATE = "scheme:create"
CAP_UPDATE = "scheme:update"
CAP_REVOKE = "scheme:revoke"
CAP_DELEGATE = "scheme:delegate"
CAP_ROOT_ROTATE = "scheme:root-rotate"
CAP_APPROVE = "scheme:approve"

ADMIN_CAPABILITIES = {
    CAP_CREATE,
    CAP_UPDATE,
    CAP_REVOKE,
    CAP_DELEGATE,
    CAP_ROOT_ROTATE,
    CAP_APPROVE,
}

DIGEST_RE = re.compile(r"^sha256:[A-Za-z0-9_-]{43}$")
SCHEME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_.-]*-v[0-9]+$")
REVISION_RE = re.compile(r"^[0-9]+\.[0-9]+$")
CLC_RE = re.compile(r"^CLC-[0-9]+\.[0-9]+$")
PRINCIPAL_RE = re.compile(r"^principal:[A-Za-z0-9_.:-]+$")
NAMESPACE_RE = re.compile(r"^/[A-Za-z0-9_.:/-]+$")

STRING_DOMAINS = {"decimal-string", "subdomain", "path-prefix"}
KNOWN_DOMAINS = {
    "bound",
    "enum",
    "exact",
    "quantity",
    "decimal-string",
    "subdomain",
    "path-prefix",
}


class Reject(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code + (": " + detail if detail else ""))
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------ encoding

def digest(raw: bytes) -> str:
    return "sha256:" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def canonical_digest(value) -> str:
    return digest(canonical_json(value).encode("utf-8"))


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


# ----------------------------------------------------------------------- DER

def der(buf: bytes, off: int = 0):
    if off + 2 > len(buf):
        raise ValueError("truncated DER")
    tag = buf[off]
    off += 1
    length = buf[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or off + n > len(buf):
            raise ValueError("bad DER length")
        length = int.from_bytes(buf[off : off + n], "big")
        off += n
    end = off + length
    if end > len(buf):
        raise ValueError("truncated DER value")
    return tag, buf[off:end], end


def der_children(value: bytes):
    out = []
    off = 0
    while off < len(value):
        tag, body, off = der(value, off)
        out.append((tag, body))
    return out


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_set(value: bytes) -> bytes:
    return b"\x31" + der_len(len(value)) + value


def oid_string(value: bytes) -> str:
    if not value:
        return ""
    parts = [value[0] // 40, value[0] % 40]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(p) for p in parts)


def utf8(value: bytes) -> str:
    return value.decode("utf-8")


def integer(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True)


# ----------------------------------------------------------------------- CMS

def verify_detached(p7s: bytes, payload: bytes) -> x509.Certificate:
    """Verify a detached PKCS#7 SignedData and return the signer certificate."""
    tag, body, _ = der(p7s)
    if tag != 0x30:
        raise ValueError("PKCS#7: not a SEQUENCE")
    content_info = der_children(body)
    if len(content_info) < 2 or content_info[0][0] != 0x06:
        raise ValueError("PKCS#7: missing content type")
    if oid_string(content_info[0][1]) != "1.2.840.113549.1.7.2":
        raise ValueError("PKCS#7: not signedData")
    _, explicit = content_info[1]
    _, signed_data, _ = der(explicit)
    fields = der_children(signed_data)

    certs = []
    signer_infos = []
    for f_tag, f_body in fields:
        if f_tag == 0xA0:  # certificates [0] IMPLICIT
            for c_tag, c_body in der_children(f_body):
                if c_tag == 0x30:
                    # re-encode to hand a full certificate to the X.509 parser
                    certs.append(x509.load_der_x509_certificate(
                        b"\x30" + der_len(len(c_body)) + c_body
                    ))
        elif f_tag == 0x31:  # signerInfos SET
            signer_infos = der_children(f_body)

    if not signer_infos:
        raise ValueError("PKCS#7: no SignerInfo")
    _, signer_body = signer_infos[0]
    si = der_children(signer_body)
    # version, issuerAndSerialNumber, digestAlgorithm, [0] signedAttrs,
    # signatureAlgorithm, signature
    idx = 2
    if idx < len(si) and si[idx][0] == 0x30:
        idx += 1  # digestAlgorithm
    signed_attrs_raw = None
    if idx < len(si) and si[idx][0] == 0xA0:
        signed_attrs_raw = der_set(si[idx][1])
        idx += 1
    if idx + 1 >= len(si):
        raise ValueError("PKCS#7: truncated SignerInfo")
    signature = si[idx + 1][1]
    if signed_attrs_raw is None:
        raise ValueError("PKCS#7: signed attributes are required by this profile")

    # messageDigest binding
    found = False
    attrs = der_children(_der_set_content(signed_attrs_raw))
    for a_tag, a_body in attrs:
        akids = der_children(a_body)
        if not akids or akids[0][0] != 0x06:
            continue
        if oid_string(akids[0][1]) == "1.2.840.113549.1.9.4" and len(akids) > 1:
            values = der_children(akids[1][1])
            if values and values[0][0] == 0x04:
                if values[0][1] != hashlib.sha256(payload).digest():
                    raise ValueError("PKCS#7: message digest mismatch")
                found = True
    if not found:
        raise ValueError("PKCS#7: no messageDigest attribute")

    for cert in certs:
        try:
            cert.public_key().verify(
                signature,
                signed_attrs_raw,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError):
            continue
        return cert
    raise ValueError("PKCS#7: no certificate verifies the signature")


def _der_set_content(encoded: bytes) -> bytes:
    tag, body, _ = der(encoded)
    if tag != 0x31:
        raise ValueError("signed attributes are not a SET")
    return body


# ----------------------------------------------------------------------- AIC

def aic_of(cert: x509.Certificate):
    for ext in cert.extensions:
        if ext.oid.dotted_string == AIC_OID:
            tag, body, _ = der(ext.value.value)
            if tag != 0x30:
                raise ValueError("AIC: not a SEQUENCE")
            return parse_aic(body)
    return None


def parse_aic(body: bytes):
    kids = der_children(body)
    idx = 0
    if kids and kids[0][0] == 0x02:
        idx = 1  # version, default 1
    if idx + 2 >= len(kids):
        raise ValueError("AIC: truncated")
    principal = der_children(kids[idx + 1][1])
    pidx = 1 if principal and principal[0][0] == 0x02 else 0
    realm = utf8(principal[pidx][1])
    identifier = utf8(principal[pidx + 1][1])
    key_hash = principal[pidx + 2][1]
    capabilities = []
    for c_tag, c_body in der_children(kids[idx + 2][1]):
        ck = der_children(c_body)
        scheme_id = utf8(ck[0][1])
        capability_id = utf8(ck[1][1])
        params = None
        if len(ck) > 2 and ck[2][0] == 0xA0:
            inner = der_children(ck[2][1])
            if inner and inner[0][0] == 0x04:
                params = json.loads(inner[0][1])
        capabilities.append({
            "full_id": scheme_id + ":" + capability_id,
            "params": params,
        })
    return {"realm": realm, "identifier": identifier, "key_hash": key_hash,
            "capabilities": capabilities}


# ---------------------------------------------------------- declared domains

def domain_map(declaration, capability: str):
    caps = declaration.get("capabilities") or {}
    entry = caps.get(capability)
    if entry is None:
        return None
    return {name: (spec.get("domain"), spec.get("unit") or "")
            for name, spec in (entry.get("params") or {}).items()}


def declared_bound_conflict(grant, dm) -> bool:
    for name in (grant.get("param_bounds") or {}):
        if name in dm:
            return True
    return False


def normalize(params, dm):
    if not dm or not params:
        return params, ""
    out = dict(params)
    for k, v in params.items():
        spec = dm.get(k)
        if spec is None:
            out[k] = v
            continue
        name = spec[0]
        if name in ("bound", "enum", "exact", "decimal-string", "subdomain", "path-prefix"):
            out[k] = v
        elif name == "quantity":
            number, reason = quantity_number(v, spec[1])
            if reason:
                return None, reason
            out[k] = number
        else:
            return None, "unsupported_domain"
    return out, ""


def quantity_number(value, unit):
    if not isinstance(value, dict):
        return 0, "invalid_params_binding"
    val = value.get("value")
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        return 0, "invalid_params_binding"
    u = value.get("unit")
    if not isinstance(u, str) or u == "":
        return 0, "invalid_params_binding"
    if u != unit:
        return 0, "unit_mismatch"
    scale = value.get("scale", 0)
    if not isinstance(scale, int) or isinstance(scale, bool):
        return 0, "invalid_params_binding"
    return float(val) * (10.0 ** -scale), ""


def string_domain_covers(domain, parent, child):
    if not isinstance(parent, str):
        return False, "invalid_params_binding"
    if not isinstance(child, str):
        return False, "invalid_params_binding"
    if domain == "decimal-string":
        return _decimal_covers(parent, child)
    if domain == "subdomain":
        return _subdomain_covers(parent, child)
    if domain == "path-prefix":
        return _path_covers(parent, child)
    return False, "unsupported_domain"


def _path_covers(parent, child):
    if not parent.startswith("/") or not child.startswith("/"):
        return False, "invalid_params_binding"
    if path_clean(parent) != parent or path_clean(child) != child:
        return False, "invalid_params_binding"
    if child == parent or child.startswith(parent.rstrip("/") + "/"):
        return True, ""
    return False, "params_exceed_grant"


def _subdomain_covers(parent, child):
    p = _domain_name(parent)
    c = _domain_name(child)
    if not p or not c:
        return False, "invalid_params_binding"
    if c == p or c.endswith("." + p):
        return True, ""
    return False, "params_exceed_grant"


def _domain_name(s: str) -> str:
    s = s.lower()
    if s.endswith("."):
        s = s[:-1]
    if any(ch.isspace() for ch in s):
        return ""
    if any(label == "" for label in s.split(".")):
        return ""
    return s


def _decimal_covers(parent, child):
    p = _parse_decimal(parent)
    c = _parse_decimal(child)
    if p is None or c is None:
        return False, "invalid_params_binding"
    if c > p:
        return False, "params_exceed_grant"
    return True, ""


_DECIMAL_RE = re.compile(r"^[+-]?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$")


def _parse_decimal(s: str):
    if not _DECIMAL_RE.match(s):
        return None
    mantissa, exp = s, 0
    for marker in ("e", "E"):
        if marker in s:
            mantissa, raw_exp = s.split(marker, 1)
            try:
                exp = int(raw_exp)
            except ValueError:
                return None
            break
    try:
        if "." in mantissa:
            whole, frac = mantissa.split(".", 1)
            sign = -1 if whole.startswith("-") else 1
            whole = whole.lstrip("+-")
            digits = int((whole or "0") + frac)
            return sign * digits * (10 ** (exp - len(frac)))
        return int(mantissa) * (10 ** exp)
    except ValueError:
        return None


def neutralize(params, name):
    out = dict(params or {})
    out[name] = "domain-covered"
    return out


def contains_with_domains(parent, child, parent_dom, child_dom):
    if declared_bound_conflict(parent, parent_dom) or declared_bound_conflict(child, child_dom):
        return False, "params_not_narrower"
    parent = dict(parent)
    child = dict(child)
    for name, pspec in (parent_dom or {}).items():
        cspec = (child_dom or {}).get(name)
        if cspec is None:
            continue
        if pspec[0] != cspec[0]:
            return False, "params_not_narrower"
        if pspec[0] in STRING_DOMAINS:
            pp = parent.get("params") or {}
            cc = child.get("params") or {}
            if name not in pp or name not in cc:
                continue
            ok, _ = string_domain_covers(pspec[0], pp[name], cc[name])
            if not ok:
                return False, "params_not_narrower"
            parent["params"] = neutralize(pp, name)
            child["params"] = neutralize(cc, name)
    pp, reason = normalize(parent.get("params") or {}, parent_dom)
    if reason:
        return False, "params_not_narrower"
    cp, reason = normalize(child.get("params") or {}, child_dom)
    if reason:
        return False, "params_not_narrower"
    parent["params"] = pp
    child["params"] = cp
    result = contains(parent, child)
    return bool(result.get("contains")), result.get("reason") or ""


def authorize_set_with_domains(grants, op, dm):
    op = dict(op)
    op_params = dict(op.get("params") or {})
    normalized = []
    for grant in grants:
        if declared_bound_conflict(grant, dm):
            return {"verdict": "deny", "reason": "invalid_params_binding"}
        usable = True
        grant = dict(grant)
        gp = dict(grant.get("params") or {})
        for name, spec in (dm or {}).items():
            if spec[0] not in STRING_DOMAINS:
                continue
            if name not in gp or name not in op_params:
                continue
            ok, reason = string_domain_covers(spec[0], gp[name], op_params[name])
            if not ok:
                if reason == "invalid_params_binding":
                    return {"verdict": "deny", "reason": reason}
                usable = False
                break
            gp = neutralize(gp, name)
            op_params = neutralize(op_params, name)
        if not usable:
            continue
        gp, reason = normalize(gp, dm)
        if reason:
            return {"verdict": "deny", "reason": reason}
        grant["params"] = gp
        normalized.append(grant)
    if not normalized and grants:
        return {"verdict": "deny", "reason": "params_exceed_grant"}
    op_params, reason = normalize(op_params, dm)
    if reason:
        return {"verdict": "deny", "reason": reason}
    op["params"] = op_params
    return authorize_set(normalized, op)


# ------------------------------------------------------------------- objects

PACKAGE_FIELDS = {
    "@version", "scheme", "revision", "definition_digest", "declaration_digest",
    "clc_revision", "change_class", "previous_package_digest", "publisher",
    "generation", "issued_at", "valid_until",
}
TRANSITION_FIELDS = {
    "@version", "action", "scheme", "namespace", "from_generation",
    "to_generation", "from_digest", "to_digest", "change_class",
    "target_clc_revision", "revocation_reason", "revocation_effective_time",
    "replacement_digest", "tombstone_generation", "next_root_package_digest",
    "next_root_keys", "next_root_threshold",
}
DECLARATION_FIELDS = {
    "@version", "scheme", "declaration_id", "clc_revision", "digest",
    "capabilities", "constraint_types",
}
GRANT_FIELDS = {"id", "params", "param_bounds", "constraints"}
DELEGATION_FIELDS = {"grantee", "parent", "child"}


def parse_closed(raw: bytes, allowed, code: str):
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise Reject(code, str(exc))
    if not isinstance(value, dict):
        raise Reject(code, "not an object")
    for key in value:
        if key not in allowed:
            raise Reject(code, f"unknown member {key!r}")
    return value


def _str(value, code, name):
    if not isinstance(value, str):
        raise Reject(code, f"{name} is not a string")
    return value


def _int(value, code, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise Reject(code, f"{name} is not an integer")
    return value


def package_digest_object(pkg):
    obj = {
        "@version": pkg["@version"],
        "scheme": pkg["scheme"],
        "revision": pkg["revision"],
        "definition_digest": pkg["definition_digest"],
        "declaration_digest": pkg["declaration_digest"],
        "clc_revision": pkg["clc_revision"],
        "change_class": pkg["change_class"],
        "publisher": pkg["publisher"],
        "generation": pkg["generation"],
    }
    for key in ("previous_package_digest", "issued_at", "valid_until"):
        if pkg.get(key):
            obj[key] = pkg[key]
    return obj


def transition_digest_object(tr):
    obj = {
        "@version": tr["@version"],
        "action": tr["action"],
        "scheme": tr["scheme"],
        "namespace": tr["namespace"],
        "to_generation": tr["to_generation"],
        "to_digest": tr["to_digest"],
        "change_class": tr["change_class"],
        "target_clc_revision": tr["target_clc_revision"],
    }
    if tr.get("from_generation") is not None:
        obj["from_generation"] = tr["from_generation"]
    for key in ("from_digest", "revocation_reason", "revocation_effective_time",
                "replacement_digest", "next_root_package_digest"):
        if tr.get(key):
            obj[key] = tr[key]
    if tr.get("next_root_keys"):
        obj["next_root_keys"] = tr["next_root_keys"]
    if tr.get("next_root_threshold"):
        obj["next_root_threshold"] = tr["next_root_threshold"]
    if tr.get("tombstone_generation") is not None:
        obj["tombstone_generation"] = tr["tombstone_generation"]
    return obj


# ------------------------------------------------------------------ validity

def validate_package(pkg):
    code = "package_shape"
    if pkg["@version"] != PACKAGE_VERSION:
        raise Reject(code, "wrong @version")
    if not SCHEME_RE.match(pkg["scheme"]):
        raise Reject(code, "bad scheme")
    if not REVISION_RE.match(pkg["revision"]):
        raise Reject(code, "bad revision")
    for name in ("definition_digest", "declaration_digest"):
        if not DIGEST_RE.match(pkg[name]):
            raise Reject(code, f"bad {name}")
    if not CLC_RE.match(pkg["clc_revision"]):
        raise Reject(code, "bad clc_revision")
    if pkg["change_class"] not in ("patch", "minor", "major"):
        raise Reject(code, "bad change_class")
    if not PRINCIPAL_RE.match(pkg["publisher"]):
        raise Reject(code, "bad publisher")
    if pkg["generation"] < 1:
        raise Reject(code, "bad generation")
    previous = pkg.get("previous_package_digest", "")
    if previous and not DIGEST_RE.match(previous):
        raise Reject(code, "bad previous_package_digest")
    if pkg["generation"] == 1 and previous:
        raise Reject(code, "generation 1 with previous digest")
    if pkg["generation"] > 1 and not previous:
        raise Reject(code, "generation > 1 without previous digest")
    for name in ("issued_at", "valid_until"):
        if pkg.get(name) and parse_time(pkg[name]) is None:
            raise Reject(code, f"bad {name}")


def validate_transition(tr):
    code = "transition_shape"
    if tr["@version"] != TRANSITION_VERSION:
        raise Reject(code, "wrong @version")
    if tr["action"] not in ("create", "update", "revoke", "root-rotate"):
        raise Reject(code, "bad action")
    if not SCHEME_RE.match(tr["scheme"]):
        raise Reject(code, "bad scheme")
    if not NAMESPACE_RE.match(tr["namespace"]) or path_clean(tr["namespace"]) != tr["namespace"]:
        raise Reject(code, "namespace is not an absolute clean path")
    if tr["namespace"] != "/" + tr["scheme"]:
        raise Reject("namespace_mismatch", "namespace does not match scheme")
    if tr["to_generation"] < 1:
        raise Reject(code, "bad to_generation")
    if not DIGEST_RE.match(tr["to_digest"]):
        raise Reject(code, "bad to_digest")
    if tr["change_class"] not in ("patch", "minor", "major"):
        raise Reject("change_class_invalid", "bad change_class")
    if not CLC_RE.match(tr["target_clc_revision"]):
        raise Reject(code, "bad target_clc_revision")

    if tr["action"] == "create":
        if tr.get("from_generation") is not None or tr.get("from_digest"):
            raise Reject("create_shape", "create declares from_*")
        if tr["to_generation"] != 1:
            raise Reject("create_shape", "create must target generation 1")
        if tr["change_class"] != "major":
            raise Reject("create_shape", "create must be a major change")
    elif tr["action"] == "update":
        require_from(tr)
    elif tr["action"] == "revoke":
        require_from(tr)
        reason = tr.get("revocation_reason", "")
        if not reason:
            raise Reject(code, "revoke requires revocation_reason")
        if reason not in ("superseded", "security-defect", "publisher-withdrawal",
                          "policy-violation", "compromised"):
            raise Reject(code, "unknown revocation_reason")
        if not tr.get("revocation_effective_time"):
            raise Reject(code, "revoke requires revocation_effective_time")
        if parse_time(tr["revocation_effective_time"]) is None:
            raise Reject(code, "bad revocation_effective_time")
        if tr.get("tombstone_generation") is None:
            raise Reject(code, "revoke requires tombstone_generation")
        if tr["tombstone_generation"] < tr["to_generation"]:
            raise Reject(code, "bad tombstone_generation")
        replacement = tr.get("replacement_digest", "")
        if replacement and not DIGEST_RE.match(replacement):
            raise Reject(code, "bad replacement_digest")
    elif tr["action"] == "root-rotate":
        require_from(tr)
        if not DIGEST_RE.match(tr.get("next_root_package_digest", "")):
            raise Reject(code, "root-rotate requires next_root_package_digest")
        if not tr.get("next_root_keys"):
            raise Reject(code, "root-rotate requires next_root_keys")
        for key in tr["next_root_keys"]:
            if not isinstance(key, str) or not DIGEST_RE.match(key):
                raise Reject(code, "bad next_root_keys entry")
        if tr.get("next_root_threshold", 0) < 1:
            raise Reject(code, "root-rotate requires next_root_threshold >= 1")


def require_from(tr):
    if tr.get("from_generation") is None:
        raise Reject("transition_shape", f"{tr['action']} requires from_generation")
    if tr["from_generation"] < 1:
        raise Reject("transition_shape", "from_generation must be >= 1")
    if not DIGEST_RE.match(tr.get("from_digest", "")):
        raise Reject("transition_shape", f"{tr['action']} requires from_digest")


def parse_declaration(raw: bytes):
    decl = parse_closed(raw, DECLARATION_FIELDS, "declaration_invalid")
    try:
        validate_declaration(decl)
    except Reject as exc:
        raise Reject("declaration_invalid", exc.detail or exc.code)
    return decl


def validate_declaration(decl):
    if decl.get("@version") != "CLC-SCHEME-v1":
        raise Reject("declaration_invalid", "wrong @version")
    if not decl.get("scheme") or not decl.get("declaration_id") or not decl.get("clc_revision"):
        raise Reject("declaration_invalid", "missing member")
    capabilities = decl.get("capabilities") or {}
    if not capabilities:
        raise Reject("declaration_invalid", "no capabilities")
    for cap_name, cap in capabilities.items():
        for param_name, param in (cap.get("params") or {}).items():
            domain = param.get("domain")
            if domain not in KNOWN_DOMAINS:
                raise Reject("declaration_invalid", "unsupported_domain")
            unit = param.get("unit", "")
            if domain == "quantity" and not unit:
                raise Reject("declaration_invalid", "quantity without unit")
            if domain != "quantity" and unit:
                raise Reject("declaration_invalid", "unit outside quantity")
    if decl.get("digest"):
        want = declaration_digest(decl)
        if want != decl["digest"]:
            raise Reject("declaration_invalid", "declaration_digest_mismatch")


def declaration_digest(decl):
    obj = {k: v for k, v in decl.items() if k != "digest"}
    return canonical_digest(obj)


def validate_policy(policy):
    root_digest = policy.get("root_package_digest", "")
    if root_digest and not DIGEST_RE.match(root_digest):
        raise Reject("package_shape", "bad root_package_digest")
    if policy.get("root_keys") and policy.get("root_threshold", 0) < 1:
        raise Reject("package_shape", "root_threshold must be >= 1")
    if policy.get("max_major", 0) < 1:
        raise Reject("package_shape", "max_major must be >= 1")
    raw = policy.get("administration_declaration")
    if raw is None:
        raise Reject("declaration_invalid", "administration_declaration is required")
    parse_declaration(json.dumps(raw).encode())
    for key in policy.get("next_root_keys") or []:
        if not DIGEST_RE.match(key):
            raise Reject("package_shape", "bad next_root_keys entry")


# ------------------------------------------------------------------ time

_TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$"
)


def parse_time(raw: str):
    match = _TIME_RE.match(raw)
    if not match:
        return None
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    micro = int((match.group(7) or "0")[:6].ljust(6, "0"))
    zone = match.group(8)
    if zone == "Z":
        offset = timedelta(0)
    else:
        sign = 1 if zone[0] == "+" else -1
        offset = sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
    return datetime(year, month, day, hour, minute, second, micro,
                    tzinfo=timezone(offset))


def path_clean(value: str) -> str:
    """Go path.Clean for absolute slash paths."""
    if value == "":
        return "."
    rooted = value.startswith("/")
    parts = []
    for element in value.split("/"):
        if element in ("", "."):
            continue
        if element == "..":
            if parts:
                parts.pop()
            elif not rooted:
                parts.append("..")
            continue
        parts.append(element)
    joined = "/".join(parts)
    if rooted:
        return "/" + joined
    return joined or "."


# -------------------------------------------------------------- confirmation

def verify_publisher(pkg, cert, roots):
    if cert is None:
        raise Reject("signature_missing")
    if not roots:
        raise Reject("signature_chain", "no trust roots")
    chained = False
    for root in roots:
        try:
            cert.verify_directly_issued_by(root)
            chained = True
            break
        except Exception:
            continue
    if not chained:
        raise Reject("signature_chain", "certificate does not chain to a trust root")

    aic = aic_of(cert)
    if aic is None:
        raise Reject("signature_no_aic", "no AIC extension")

    want = pkg["publisher"][len("principal:"):] if pkg["publisher"].startswith("principal:") else pkg["publisher"]
    identifier = aic["identifier"]
    realm = aic["realm"]
    if want != identifier and want != realm + ":" + identifier:
        raise Reject("publisher_mismatch", "principal does not match")

    key_hash = aic["key_hash"]
    if not key_hash or all(b == 0 for b in key_hash):
        raise Reject("publisher_key_binding", "no principal key hash")
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if key_hash != hashlib.sha256(spki).digest():
        raise Reject("publisher_key_binding", "key hash does not match")
    return aic


def major_of(revision: str) -> int:
    return int(revision.split(".", 1)[0])


def minor_of(revision: str) -> int:
    return int(revision.split(".", 1)[1])


def capability_of(full_id: str):
    prefix = SCHEME_ID + ":"
    if not full_id.startswith(prefix):
        return None
    return full_id[len(prefix):]


def build_management_operation(pkg, tr):
    action = tr["action"]
    table = {
        "create": CAP_CREATE,
        "update": CAP_UPDATE,
        "revoke": CAP_REVOKE,
        "root-rotate": CAP_ROOT_ROTATE,
    }
    capability = table.get(action)
    if capability is None:
        raise Reject("transition_shape", "unknown action")
    op = {"id": SCHEME_ID + ":" + capability, "params": {}}
    if action in ("create", "update"):
        op["params"] = {
            "namespace": tr["namespace"],
            "change_class": tr["change_class"],
            "major": major_of(pkg["revision"]),
            "clc_revision": tr["target_clc_revision"],
        }
    elif action == "revoke":
        op["params"] = {
            "namespace": tr["namespace"],
            "package_digest": tr["from_digest"],
            "clc_revision": tr["target_clc_revision"],
        }
    elif action == "root-rotate":
        if not tr.get("from_digest"):
            raise Reject("transition_shape", "root-rotate requires from_digest")
        op["params"] = {
            "package_digest": tr["from_digest"],
            "clc_revision": tr["target_clc_revision"],
        }
    return op


def operation_digest(op):
    if op.get("params") == {}:
        obj = {"id": op["id"]}
    else:
        obj = {"id": op["id"], "params": op["params"]}
    return canonical_digest(obj)


def grants_for(aic, full_id):
    out = []
    for cap in aic["capabilities"]:
        if cap["full_id"] != full_id:
            continue
        grant = {"id": full_id}
        if cap["params"] is not None:
            if not isinstance(cap["params"], dict):
                continue
            grant["params"] = cap["params"]
        out.append(grant)
    return out


def contain_grants(grants, roots, dm):
    kept = []
    for grant in grants:
        for root in roots:
            ok, _ = contains_with_domains(root, grant, dm, dm)
            if ok:
                kept.append(grant)
                break
    return kept


def revision_follows(prev, nxt, change_class):
    pmaj, pmin = major_of(prev), minor_of(prev)
    nmaj, nmin = major_of(nxt), minor_of(nxt)
    if change_class == "patch":
        return nmaj == pmaj and nmin == pmin
    if change_class == "minor":
        return nmaj == pmaj and nmin == pmin + 1
    if change_class == "major":
        return nmaj == pmaj + 1 and nmin == 0
    return False


def namespace_under(namespace, prefixes):
    for prefix in prefixes or []:
        if namespace == prefix:
            return True
        if namespace.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def check_state(tr, state, package_rev, package_change):
    if tr["action"] == "create":
        if state.get("history") or state.get("generation", 0) != 0 or state.get("package_digest"):
            raise Reject("state_not_empty", "create requires an empty namespace")
        return

    recorded = digest_at(state, tr["to_generation"])
    if recorded is not None and recorded != tr["to_digest"]:
        raise Reject("generation_fork", "generation already holds another digest")

    if tr.get("from_generation") is None:
        raise Reject("transition_shape", f"{tr['action']} requires from_generation")
    if state.get("generation", 0) != tr["from_generation"]:
        raise Reject("state_generation_mismatch", "local head generation differs")
    if state.get("package_digest", "") != tr.get("from_digest", ""):
        raise Reject("state_digest_mismatch", "local head digest differs")
    if tr["to_generation"] != tr["from_generation"] + 1:
        raise Reject("state_generation_mismatch", "transition must advance one generation")
    if tr["to_generation"] <= head_of(state):
        raise Reject("generation_rollback", "generation is not newer than the head")
    if tr["action"] == "update" and state.get("revision"):
        if not revision_follows(state["revision"], package_rev, package_change):
            raise Reject("change_class_invalid", "revision does not follow the change class")


def head_of(state):
    head = state.get("generation", 0)
    for entry in state.get("history") or []:
        head = max(head, entry.get("generation", 0))
    return head


def digest_at(state, generation):
    if state.get("generation", 0) == generation and state.get("package_digest"):
        return state["package_digest"]
    for entry in state.get("history") or []:
        if entry.get("generation", 0) == generation:
            return entry.get("package_digest")
    return None


def is_revoked(state, digest_value):
    if not digest_value:
        return False
    return any(r.get("package_digest") == digest_value for r in state.get("revoked") or [])


def count_approvals(state, package_digest_value, transition_digest_value):
    return sum(
        1 for a in state.get("approvals") or []
        if a.get("package_digest") == package_digest_value
        and a.get("transition_digest") == transition_digest_value
    )


def check_root_rotation(pkg, tr, cert, policy):
    signer = digest(spki_of(cert))
    in_current = signer in (policy.get("root_keys") or [])
    in_next = signer in (policy.get("next_root_keys") or [])
    if in_next and not in_current:
        raise Reject("root_rotate_self_authorized", "signer is only in the next root")
    if not in_current:
        raise Reject("root_rotate_no_current_root", "signer is not a current root")
    if not policy.get("root_package_digest") or tr.get("from_digest") != policy["root_package_digest"]:
        raise Reject("root_rotate_policy_mismatch", "from_digest is not the root package")
    if (not policy.get("next_root_package_digest") or not policy.get("next_root_keys")
            or policy.get("next_root_threshold", 0) < 1):
        raise Reject("root_rotate_policy_mismatch", "policy configures no next root")
    if tr.get("next_root_package_digest") != policy["next_root_package_digest"]:
        raise Reject("root_rotate_policy_mismatch", "next root package differs")
    if tr.get("next_root_threshold") != policy["next_root_threshold"]:
        raise Reject("root_rotate_policy_mismatch", "threshold differs")
    if not same_set(tr.get("next_root_keys") or [], policy["next_root_keys"]):
        raise Reject("root_rotate_policy_mismatch", "next root keys differ")
    if len(tr.get("next_root_keys") or []) < tr["next_root_threshold"]:
        raise Reject("root_rotate_threshold", "next root threshold not met")
    if policy["next_root_package_digest"] == policy["root_package_digest"]:
        raise Reject("root_rotate_self_authorized", "next root package is the current root package")
    if tr["to_digest"] != policy["next_root_package_digest"]:
        raise Reject("root_rotate_policy_mismatch", "to_digest is not the next root package")


def same_set(a, b):
    return sorted(a) == sorted(b)


def spki_of(cert):
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def confirm(bundle_vector):
    definition = b64d(bundle_vector["definition_b64"])
    declaration = b64d(bundle_vector["declaration_b64"])
    package_raw = b64d(bundle_vector["package_b64"])
    transition_raw = b64d(bundle_vector["transition_b64"])
    policy = json.loads(b64d(bundle_vector["policy_b64"]).decode("utf-8"))
    state = json.loads(b64d(bundle_vector["state_b64"]).decode("utf-8"))
    roots = [x509.load_der_x509_certificate(b64d(r)) for r in bundle_vector.get("roots_b64") or []]

    cert = None
    p7s = bundle_vector.get("p7s_b64")
    if p7s:
        cert = verify_detached(b64d(p7s), package_raw)

    result = {}
    pkg = parse_closed(package_raw, PACKAGE_FIELDS, "package_shape")
    validate_package(pkg)
    tr = parse_closed(transition_raw, TRANSITION_FIELDS, "transition_shape")
    validate_transition(tr)

    result["package_digest"] = canonical_digest(package_digest_object(pkg))
    result["transition_digest"] = canonical_digest(transition_digest_object(tr))
    if cert is not None:
        result["publisher_key_id"] = digest(spki_of(cert))
    try:
        op = build_management_operation(pkg, tr)
    except Reject:
        op = None
    if op is not None:
        result["management_operation_digest"] = operation_digest(op)

    try:
        decide(pkg, tr, definition, declaration, cert, roots, state, policy, result, op)
    except Reject as exc:
        exc.result = result
        raise
    return result


def decide(pkg, tr, definition, declaration, cert, roots, state, policy, result, op):
    validate_policy(policy)
    validate_package(pkg)
    validate_transition(tr)

    if digest(definition) != pkg["definition_digest"]:
        raise Reject("package_digest_mismatch", "definition digest differs")
    if digest(declaration) != pkg["declaration_digest"]:
        raise Reject("package_digest_mismatch", "declaration digest differs")
    decl = parse_declaration(declaration)
    if decl.get("scheme") != pkg["scheme"]:
        raise Reject("declaration_invalid", "declaration names another scheme")
    if decl.get("clc_revision") != pkg["clc_revision"]:
        raise Reject("declaration_invalid", "declaration requires another revision")

    if pkg["scheme"] != tr["scheme"]:
        raise Reject("package_transition_mismatch", "package scheme differs")
    if pkg["generation"] != tr["to_generation"]:
        raise Reject("package_transition_mismatch", "package generation differs")
    if pkg["change_class"] != tr["change_class"]:
        raise Reject("package_transition_mismatch", "package change_class differs")
    if pkg["clc_revision"] != tr["target_clc_revision"]:
        raise Reject("package_transition_mismatch", "package clc_revision differs")
    if result["package_digest"] != tr["to_digest"]:
        raise Reject("package_transition_mismatch", "to_digest differs")
    if tr.get("from_digest") and pkg.get("previous_package_digest") != tr["from_digest"]:
        raise Reject("package_transition_mismatch", "previous_package_digest differs")

    aic = verify_publisher(pkg, cert, roots)

    if pkg["clc_revision"] not in (policy.get("supported_clc_revisions") or []):
        raise Reject("clc_revision_unsupported", "package revision unsupported")
    if tr["target_clc_revision"] not in (policy.get("supported_clc_revisions") or []):
        raise Reject("clc_revision_unsupported", "transition revision unsupported")

    if tr["action"] == "root-rotate":
        check_root_rotation(pkg, tr, cert, policy)

    if op is None:
        op = build_management_operation(pkg, tr)
    capability = capability_of(op["id"])
    dm = domain_map(declaration_of(policy), capability)
    grants = grants_for(aic, op["id"])
    if not grants:
        raise Reject("authority_no_grant", "AIC declares no matching capability")
    contained = contain_grants(grants, policy.get("root_grants") or [], dm)
    if not contained:
        raise Reject("authority_not_contained", "no grant is inside the root authority")
    decision = authorize_set_with_domains(contained, op, dm)
    if decision.get("verdict") != "allow":
        raise Reject("authority_not_authorized", "CLC " + str(decision.get("reason") or decision.get("verdict")))

    if not namespace_under(tr["namespace"], policy.get("namespace_prefixes")):
        raise Reject("namespace_outside_policy", "namespace outside policy")
    if major_of(pkg["revision"]) > policy.get("max_major", 0):
        raise Reject("major_exceeds_limit", "major exceeds policy")

    check_state(tr, state, pkg["revision"], pkg["change_class"])

    if is_revoked(state, tr.get("from_digest")):
        raise Reject("package_revoked", "from_digest is revoked")
    if is_revoked(state, result["package_digest"]):
        raise Reject("package_revoked", "package digest is revoked")

    check_freshness(pkg, policy)

    if policy.get("approval_threshold", 0) > 0:
        have = count_approvals(state, result["package_digest"], result["transition_digest"])
        if have < policy["approval_threshold"]:
            raise Reject("approval_insufficient", "not enough approvals")


def declaration_of(policy):
    raw = policy.get("administration_declaration")
    if raw is None:
        raise Reject("declaration_invalid", "administration_declaration is required")
    return parse_declaration(json.dumps(raw).encode())


def check_freshness(pkg, policy):
    now = parse_time(policy.get("observed_at", ""))
    if now is None:
        raise Reject("package_stale", "policy.observed_at is required")
    issued = None
    if pkg.get("issued_at"):
        issued = parse_time(pkg["issued_at"])
        if issued is None:
            raise Reject("package_shape", "bad issued_at")
        if issued > now + timedelta(minutes=5):
            raise Reject("package_stale", "issued_at is in the future")
    if pkg.get("valid_until"):
        until = parse_time(pkg["valid_until"])
        if until is None:
            raise Reject("package_shape", "bad valid_until")
        if issued is not None and until <= issued:
            raise Reject("package_shape", "valid_until is not after issued_at")
        if now > until:
            raise Reject("package_expired", "valid_until precedes observed_at")
    if policy.get("max_staleness_seconds", 0) > 0:
        if issued is None:
            raise Reject("package_stale", "issued_at is required")
        if now - issued > timedelta(seconds=policy["max_staleness_seconds"]):
            raise Reject("package_stale", "package is older than the staleness window")


# ---------------------------------------------------------------- delegation

def validate_delegation(bundle_vector):
    policy = json.loads(b64d(bundle_vector["policy_b64"]).decode("utf-8"))
    delegation = json.loads(b64d(bundle_vector["delegation_b64"]).decode("utf-8"))
    for key in delegation:
        if key not in DELEGATION_FIELDS:
            raise Reject("delegation_not_contained", f"unknown member {key!r}")
    if not PRINCIPAL_RE.match(delegation.get("grantee", "")):
        raise Reject("delegation_not_contained", "bad grantee")
    parent = delegation.get("parent") or {}
    child = delegation.get("child") or {}
    for grant in (parent, child):
        check_administration_grant(grant)
    capability = capability_of(child.get("id", ""))
    if capability is None:
        raise Reject("delegation_not_contained", "child is not an administration capability")
    if capability.endswith("*"):
        raise Reject("delegation_not_contained", "child must not be a wildcard")
    dm = domain_map(declaration_of(policy), capability)
    if not policy.get("root_grants"):
        raise Reject("authority_not_contained", "policy configures no root authority")
    if not any(contains_with_domains(root, parent, dm, dm)[0] for root in policy["root_grants"]):
        raise Reject("authority_not_contained", "delegator is outside the root authority")
    if not contains_with_domains(parent, child, dm, dm)[0]:
        raise Reject("delegation_not_contained", "child is wider than the parent")


def check_administration_grant(grant):
    if not isinstance(grant, dict):
        raise Reject("delegation_not_contained", "grant is not an object")
    for key in grant:
        if key not in GRANT_FIELDS:
            raise Reject("delegation_not_contained", f"unknown grant member {key!r}")
    capability = capability_of(grant.get("id", ""))
    if capability is None:
        raise Reject("delegation_not_contained", "grant is not an administration capability")
    if capability not in ADMIN_CAPABILITIES:
        raise Reject("delegation_not_contained", "grant is not an administration capability")


# --------------------------------------------------------------------- main

def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: probe.py BUNDLE.json\n")
        return 2
    bundle = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    if bundle.get("@version") != "varwof/scheme-admin-crosslang-bundle-v1":
        sys.stderr.write("probe.py: wrong bundle version\n")
        return 2
    lines = []
    for vector in bundle["vectors"]:
        try:
            if vector["kind"] == "delegation":
                validate_delegation(vector)
                result = {}
                verdict, reason = "accept", ""
            else:
                result = confirm(vector)
                verdict, reason = "accept", ""
        except Reject as exc:
            verdict, reason = "reject", exc.code
            result = getattr(exc, "result", {})
        lines.append(render(vector["id"], vector["kind"], verdict, reason, result))
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def render(vector_id, kind, verdict, reason, result):
    parts = [vector_id, kind, verdict, reason or "-"]
    for label, key in (
        ("pkg", "package_digest"),
        ("tr", "transition_digest"),
        ("op", "management_operation_digest"),
        ("key", "publisher_key_id"),
    ):
        value = result.get(key)
        if value:
            parts.append(label + "=" + value)
    return " ".join(parts)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
