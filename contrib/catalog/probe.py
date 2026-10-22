#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
"""Cross-language evidence probe for the capability catalog plane.

Reads a bundle produced by register/catalog TestCrossLanguageVectors.  The
bundle carries inputs only -- exact artifact bytes, the deployer policy, the
accepted-generation state, the trusted root, the detached PKCS#7 signature --
and this probe prints one positional evidence line per corpus vector.

This is the same stewardship's second reading of the same artifacts, not an
independent implementation.  The DER/CMS/AIC reader and the CLC-1.19
declared-domain relation are shared verbatim with contrib/scheme-admin/probe.py;
the catalog algorithm below is written from register/catalog.

Usage: probe.py BUNDLE.json
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

AIC_OID = "1.3.6.1.4.1.66257.1.1"
DIGEST_RE = re.compile(r"^sha256:[A-Za-z0-9_-]{43}$")
SCHEME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_.-]*-v[0-9]+$")
PRINCIPAL_RE = re.compile(r"^principal:[A-Za-z0-9_.:-]+$")
STRING_DOMAINS = {"decimal-string", "subdomain", "path-prefix"}
KNOWN_DOMAINS = {
    "bound", "enum", "exact", "quantity", "decimal-string", "subdomain", "path-prefix",
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

# ===================================================================== catalog

CATALOG_VERSION = "CLC-CAPABILITY-CATALOG-v1"
DELTA_VERSION = "CLC-CAPABILITY-CATALOG-DELTA-v1"
DISCOVERY_VERSION = "CLC-CATALOG-DISCOVERY-v1"

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*(/[a-z0-9][a-z0-9._-]*)*$")
REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

CATALOG_FIELDS = {
    "@version", "domain", "catalog_id", "generation", "issued_at",
    "valid_until", "previous_digest", "producer", "entries",
}
ENTRY_FIELDS = {
    "capability", "provider", "scheme", "scheme_declaration_digest",
    "operations", "status",
}
OPERATION_FIELDS = {"operation", "params"}
STATUS_FIELDS = {"reference", "checked_at"}
DELTA_FIELDS = {
    "@version", "domain", "catalog_id", "base_generation", "target_generation",
    "base_digest", "target_digest", "issued_at", "valid_until", "producer",
    "add", "replace", "remove",
}
DISCOVERY_FIELDS = {
    "@version", "provider", "catalog_id", "catalog_digest", "generation",
    "issued_at", "valid_until", "status_reference", "scheme_declaration_digests",
}
POLICY_FIELDS = {
    "domain", "catalog_id", "schemes", "max_staleness_seconds",
    "max_status_staleness_seconds", "require_status", "status_values",
    "provider_bindings", "observed_at",
}
SCHEME_POLICY_FIELDS = {"declaration"}
STATE_FIELDS = {"domain", "catalog_id", "generation", "digest", "history"}
HISTORY_FIELDS = {"generation", "digest"}
DECLARATION_FIELDS = {
    "@version", "scheme", "declaration_id", "clc_revision", "digest",
    "capabilities", "constraint_types",
}
DECLARATION_CAPABILITY_FIELDS = {"params"}
DECLARATION_PARAM_FIELDS = {"domain", "unit", "optional"}

VERDICT_MEMBERS = (
    "verdict", "authorized", "authorised", "verified", "approved", "allowed",
    "trusted", "accepted",
)


def required(obj, keys, code):
    for key in keys:
        if key not in obj:
            raise Reject(code, f"missing member {key!r}")


def is_name(value) -> bool:
    return isinstance(value, str) and NAME_RE.fullmatch(value) is not None


def is_digest(value) -> bool:
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


# --------------------------------------------------------------- object shapes

def parse_catalog(raw: bytes):
    cat = parse_closed(raw, CATALOG_FIELDS, "catalog_shape")
    validate_catalog(cat)
    return cat


def validate_catalog(cat):
    required(cat, ("@version", "domain", "catalog_id", "generation", "issued_at",
                   "valid_until", "producer", "entries"), "catalog_shape")
    if cat["@version"] != CATALOG_VERSION:
        raise Reject("catalog_shape", "@version")
    if not is_name(cat["domain"]):
        raise Reject("catalog_shape", "domain")
    if not is_name(cat["catalog_id"]):
        raise Reject("catalog_shape", "catalog_id")
    generation = _int(cat["generation"], "catalog_shape", "generation")
    if generation < 1:
        raise Reject("catalog_shape", "generation")
    if not isinstance(cat["producer"], str) or not PRINCIPAL_RE.fullmatch(cat["producer"]):
        raise Reject("catalog_shape", "producer")
    issued = parse_time(_str(cat["issued_at"], "catalog_shape", "issued_at"))
    until = parse_time(_str(cat["valid_until"], "catalog_shape", "valid_until"))
    if issued is None or until is None:
        raise Reject("catalog_shape", "issued_at/valid_until")
    if not until > issued:
        raise Reject("catalog_shape", "valid_until must be after issued_at")
    previous = cat.get("previous_digest") or None
    if generation == 1:
        if previous is not None:
            raise Reject("catalog_shape", "generation 1 must not carry previous_digest")
    elif not is_digest(previous):
        raise Reject("catalog_shape", "previous_digest")
    entries = cat["entries"]
    if not isinstance(entries, list) or not entries:
        raise Reject("catalog_shape", "entries")
    seen = set()
    for entry in entries:
        validate_entry(entry)
        capability = entry["capability"]
        if capability in seen:
            raise Reject("catalog_duplicate_entry", capability)
        seen.add(capability)


def validate_entry(entry):
    if not isinstance(entry, dict):
        raise Reject("catalog_shape", "entry is not an object")
    unknown = set(entry) - ENTRY_FIELDS
    if unknown:
        raise Reject("catalog_shape", f"unknown member {sorted(unknown)[0]!r}")
    required(entry, ("capability", "provider", "scheme", "scheme_declaration_digest",
                     "operations"), "catalog_shape")
    scheme = entry["scheme"]
    if not isinstance(scheme, str) or not SCHEME_RE.fullmatch(scheme):
        raise Reject("catalog_shape", "scheme")
    capability = entry["capability"]
    if not isinstance(capability, str) or not capability.startswith(scheme + ":") or len(capability) == len(scheme) + 1:
        raise Reject("catalog_shape", "capability is not inside scheme")
    provider = entry["provider"]
    if not isinstance(provider, str) or not provider or any(c.isspace() for c in provider):
        raise Reject("catalog_shape", "provider")
    if not is_digest(entry["scheme_declaration_digest"]):
        raise Reject("catalog_shape", "scheme_declaration_digest")
    operations = entry["operations"]
    if not isinstance(operations, list) or not operations:
        raise Reject("catalog_shape", "operations")
    names = set()
    for operation in operations:
        if not isinstance(operation, dict):
            raise Reject("catalog_shape", "operation is not an object")
        unknown = set(operation) - OPERATION_FIELDS
        if unknown:
            raise Reject("catalog_shape", f"unknown member {sorted(unknown)[0]!r}")
        name = operation["operation"]
        if not isinstance(name, str) or not name.strip():
            raise Reject("catalog_shape", "operation name")
        if name in names:
            raise Reject("catalog_shape", "duplicate operation")
        names.add(name)
        params = operation.get("params")
        if params is not None and not isinstance(params, dict):
            raise Reject("catalog_shape", "params is not an object")
    status = entry.get("status")
    if status is not None:
        if not isinstance(status, dict):
            raise Reject("catalog_shape", "status is not an object")
        unknown = set(status) - STATUS_FIELDS
        if unknown:
            raise Reject("catalog_shape", f"unknown member {sorted(unknown)[0]!r}")
        required(status, ("reference", "checked_at"), "catalog_shape")
        if not isinstance(status["reference"], str) or not REFERENCE_RE.fullmatch(status["reference"]):
            raise Reject("catalog_shape", "status reference")
        if not isinstance(status["checked_at"], str) or parse_time(status["checked_at"]) is None:
            raise Reject("catalog_shape", "status checked_at")


def catalog_digest_object(cat):
    """The exact member set Go marshals for Catalog (omitempty applied)."""
    obj = {
        "@version": cat["@version"],
        "domain": cat["domain"],
        "catalog_id": cat["catalog_id"],
        "generation": cat["generation"],
        "issued_at": cat["issued_at"],
        "valid_until": cat["valid_until"],
        "producer": cat["producer"],
        "entries": [entry_digest_object(entry) for entry in cat["entries"]],
    }
    previous = cat.get("previous_digest")
    if previous:
        obj["previous_digest"] = previous
    return obj


def entry_digest_object(entry):
    operations = []
    for operation in entry["operations"]:
        op = {"operation": operation["operation"]}
        params = operation.get("params")
        if params:
            op["params"] = params
        operations.append(op)
    obj = {
        "capability": entry["capability"],
        "provider": entry["provider"],
        "scheme": entry["scheme"],
        "scheme_declaration_digest": entry["scheme_declaration_digest"],
        "operations": operations,
    }
    status = entry.get("status")
    if status is not None:
        obj["status"] = {"reference": status["reference"], "checked_at": status["checked_at"]}
    return obj


def catalog_digest(cat) -> str:
    return canonical_digest(catalog_digest_object(cat))


# ---------------------------------------------------------------- deltas

def parse_delta(raw: bytes):
    d = parse_closed(raw, DELTA_FIELDS, "delta_shape")
    validate_delta(d)
    return d


def delta_digest_object(d):
    obj = {
        "@version": d["@version"],
        "domain": d["domain"],
        "catalog_id": d["catalog_id"],
        "base_generation": d["base_generation"],
        "target_generation": d["target_generation"],
        "base_digest": d["base_digest"],
        "target_digest": d["target_digest"],
        "issued_at": d["issued_at"],
        "valid_until": d["valid_until"],
        "producer": d["producer"],
    }
    for side in ("add", "replace"):
        if d.get(side):
            obj[side] = [entry_digest_object(entry) for entry in d[side]]
    if d.get("remove"):
        obj["remove"] = d["remove"]
    return obj


def delta_digest(d) -> str:
    return canonical_digest(delta_digest_object(d))


def validate_delta(d):
    required(d, ("@version", "domain", "catalog_id", "base_generation", "target_generation",
                 "base_digest", "target_digest", "issued_at", "valid_until", "producer"),
             "delta_shape")
    if d["@version"] != DELTA_VERSION:
        raise Reject("delta_shape", "@version")
    if not is_name(d["domain"]) or not is_name(d["catalog_id"]):
        raise Reject("delta_shape", "domain/catalog_id")
    base = _int(d["base_generation"], "delta_shape", "base_generation")
    target = _int(d["target_generation"], "delta_shape", "target_generation")
    if base < 1:
        raise Reject("delta_shape", "base_generation")
    if target != base + 1:
        raise Reject("delta_shape", "target_generation must be base_generation + 1")
    if not is_digest(d["base_digest"]) or not is_digest(d["target_digest"]):
        raise Reject("delta_shape", "base_digest/target_digest")
    if not isinstance(d["producer"], str) or not PRINCIPAL_RE.fullmatch(d["producer"]):
        raise Reject("delta_shape", "producer")
    issued = parse_time(d["issued_at"])
    until = parse_time(d["valid_until"])
    if issued is None or until is None or not until > issued:
        raise Reject("delta_shape", "issued_at/valid_until")

    add = d.get("add") or []
    replace = d.get("replace") or []
    remove = d.get("remove") or []
    for side, value in (("add", add), ("replace", replace), ("remove", remove)):
        if not isinstance(value, list):
            raise Reject("delta_shape", f"{side} is not an array")
    if not add and not replace and not remove:
        raise Reject("delta_shape", "delta has no effect")

    touched = {}
    def note(capability, side):
        if not isinstance(capability, str) or not capability:
            raise Reject("delta_operation_invalid", f"{side} names an empty capability")
        if capability in touched:
            raise Reject("delta_operation_invalid",
                         f"{capability!r} appears in both {touched[capability]} and {side}")
        touched[capability] = side

    for entry in add:
        validate_entry(entry)
        note(entry["capability"], "add")
    for entry in replace:
        validate_entry(entry)
        note(entry["capability"], "replace")
    for capability in remove:
        note(capability, "remove")


def apply_delta(vector):
    result = {}
    base = parse_catalog(b64d(vector["catalog_b64"]))
    d = parse_delta(b64d(vector["delta_b64"]))

    base_digest = catalog_digest(base)
    if base["domain"] != d["domain"] or base["catalog_id"] != d["catalog_id"]:
        raise Reject("delta_base_mismatch", "delta identity")
    if base["generation"] != d["base_generation"]:
        raise Reject("delta_base_mismatch", "base generation")
    if base_digest != d["base_digest"]:
        raise Reject("delta_base_mismatch", "base digest")

    entries = {entry["capability"]: entry for entry in base["entries"]}
    for capability in d.get("remove") or []:
        if capability not in entries:
            raise Reject("delta_operation_invalid", f"remove names unknown capability {capability!r}")
        del entries[capability]
    for entry in d.get("replace") or []:
        if entry["capability"] not in entries:
            raise Reject("delta_operation_invalid", f"replace names unknown capability {entry['capability']!r}")
        entries[entry["capability"]] = entry
    for entry in d.get("add") or []:
        if entry["capability"] in entries:
            raise Reject("delta_operation_invalid", f"add names existing capability {entry['capability']!r}")
        entries[entry["capability"]] = entry

    next_catalog = {
        "@version": CATALOG_VERSION,
        "domain": base["domain"],
        "catalog_id": base["catalog_id"],
        "generation": d["target_generation"],
        "issued_at": d["issued_at"],
        "valid_until": d["valid_until"],
        "previous_digest": base_digest,
        "producer": d["producer"],
        "entries": [entries[name] for name in sorted(entries)],
    }
    validate_catalog(next_catalog)
    digest_value = catalog_digest(next_catalog)
    if digest_value != d["target_digest"]:
        raise Reject("delta_digest_mismatch", "target digest")
    result["catalog_digest"] = digest_value
    result["generation"] = next_catalog["generation"]
    return result


# -------------------------------------------------------------- discovery

def parse_discovery(raw: bytes):
    try:
        probe = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise Reject("discovery_shape", str(exc))
    if isinstance(probe, dict):
        for member in VERDICT_MEMBERS:
            if member in probe:
                raise Reject("discovery_verdict_member", f"discovery carries {member!r}")
    d = parse_closed(raw, DISCOVERY_FIELDS, "discovery_shape")
    validate_discovery(d)
    return d


def validate_discovery(d):
    required(d, ("@version", "provider", "catalog_id", "catalog_digest", "generation",
                 "issued_at", "valid_until"), "discovery_shape")
    if d["@version"] != DISCOVERY_VERSION:
        raise Reject("discovery_shape", "@version")
    if not is_name(d["catalog_id"]):
        raise Reject("discovery_shape", "catalog_id")
    if not isinstance(d["provider"], str) or not d["provider"]:
        raise Reject("discovery_shape", "provider")
    if not is_digest(d["catalog_digest"]):
        raise Reject("discovery_shape", "catalog_digest")
    if _int(d["generation"], "discovery_shape", "generation") < 1:
        raise Reject("discovery_shape", "generation")
    issued = parse_time(d["issued_at"])
    until = parse_time(d["valid_until"])
    if issued is None or until is None or not until > issued:
        raise Reject("discovery_shape", "issued_at/valid_until")
    for value in d.get("scheme_declaration_digests") or []:
        if not is_digest(value):
            raise Reject("discovery_shape", "scheme_declaration_digests")


def verify_discovery(vector):
    d = parse_discovery(b64d(vector["discovery_b64"]))
    cat = parse_catalog(b64d(vector["catalog_b64"]))
    if d["catalog_id"] != cat["catalog_id"]:
        raise Reject("discovery_shape", "catalog_id")
    if d["generation"] != cat["generation"]:
        raise Reject("discovery_shape", "generation")
    digest_value = catalog_digest(cat)
    if d["catalog_digest"] != digest_value:
        raise Reject("catalog_digest_mismatch", "discovery digest")
    return {"catalog_digest": digest_value, "generation": cat["generation"]}


# ---------------------------------------------------------------- policy

def parse_policy(raw: bytes):
    policy = parse_closed(raw, POLICY_FIELDS, "catalog_shape")
    validate_policy(policy)
    return policy


def validate_policy(policy):
    required(policy, ("domain", "catalog_id", "schemes", "observed_at"), "catalog_shape")
    if not is_name(policy["domain"]):
        raise Reject("catalog_shape", "policy.domain")
    if not is_name(policy["catalog_id"]):
        raise Reject("catalog_shape", "policy.catalog_id")
    schemes = policy["schemes"]
    if not isinstance(schemes, dict) or not schemes:
        raise Reject("catalog_scheme_unsupported", "policy supports no schemes")
    for name, scheme_policy in schemes.items():
        if not isinstance(name, str) or not SCHEME_RE.fullmatch(name):
            raise Reject("catalog_scheme_unsupported", name)
        if not isinstance(scheme_policy, dict) or set(scheme_policy) - SCHEME_POLICY_FIELDS:
            raise Reject("catalog_declaration_mismatch", "scheme policy shape")
        required(scheme_policy, ("declaration",), "catalog_declaration_mismatch")
        validate_declaration(scheme_policy["declaration"])
    for field in ("max_staleness_seconds", "max_status_staleness_seconds"):
        if _int(policy.get(field, 0), "catalog_shape", field) < 0:
            raise Reject("catalog_shape", f"{field} must be >= 0")
    status_values = policy.get("status_values") or {}
    if policy.get("require_status") and not status_values:
        raise Reject("catalog_status_unavailable", "policy.require_status requires explicit status_values")
    if not isinstance(status_values, dict):
        raise Reject("catalog_shape", "status_values must be an object")
    for reference, value in status_values.items():
        if not isinstance(reference, str) or not reference or any(c.isspace() for c in reference):
            raise Reject("catalog_shape", "status_values key is not a status reference")
        if value not in ("healthy", "unhealthy", "degraded", "unknown"):
            raise Reject("catalog_shape", "status_values contains an unknown health value")
    provider_bindings = policy.get("provider_bindings") or {}
    if not isinstance(provider_bindings, dict):
        raise Reject("catalog_shape", "provider_bindings must be an object")
    for provider, producer in provider_bindings.items():
        if not isinstance(provider, str) or not provider or any(c.isspace() for c in provider):
            raise Reject("catalog_shape", "provider_bindings key is not an identity reference")
        if not isinstance(producer, str) or not PRINCIPAL_RE.fullmatch(producer):
            raise Reject("catalog_shape", "provider_bindings value is not a producer principal")
    if parse_time(policy["observed_at"]) is None:
        raise Reject("catalog_stale", "policy.observed_at")


def validate_declaration(decl):
    if not isinstance(decl, dict):
        raise Reject("catalog_declaration_mismatch", "declaration is not an object")
    unknown = set(decl) - DECLARATION_FIELDS
    if unknown:
        raise Reject("catalog_declaration_mismatch", f"unknown member {sorted(unknown)[0]!r}")
    if decl["@version"] != "CLC-SCHEME-v1":
        raise Reject("catalog_declaration_mismatch", "@version")
    if not decl.get("scheme") or not decl.get("declaration_id") or not decl.get("clc_revision"):
        raise Reject("catalog_declaration_mismatch", "missing scheme/declaration_id/clc_revision")
    required(decl, ("@version", "scheme", "declaration_id", "clc_revision", "capabilities"),
             "catalog_declaration_mismatch")
    capabilities = decl["capabilities"]
    if not isinstance(capabilities, dict) or not capabilities:
        raise Reject("catalog_declaration_mismatch", "no capabilities")
    for cap_name, capability in capabilities.items():
        if not isinstance(capability, dict) or set(capability) - DECLARATION_CAPABILITY_FIELDS:
            raise Reject("catalog_declaration_mismatch", f"capability {cap_name!r}")
        params = capability.get("params")
        if not isinstance(params, dict):
            raise Reject("catalog_declaration_mismatch", f"capability {cap_name!r} params")
        for param_name, param in params.items():
            if not isinstance(param, dict) or set(param) - DECLARATION_PARAM_FIELDS:
                raise Reject("catalog_declaration_mismatch", f"{cap_name}.{param_name}")
            domain = param.get("domain")
            if domain not in KNOWN_DOMAINS:
                raise Reject("catalog_declaration_mismatch", f"unsupported domain {domain!r}")
            if domain == "quantity" and not param.get("unit"):
                raise Reject("catalog_declaration_mismatch", "quantity without unit")
            if domain != "quantity" and param.get("unit"):
                raise Reject("catalog_declaration_mismatch", "unit outside quantity")
    pinned = decl.get("digest")
    if pinned is not None and pinned != declaration_digest(decl):
        raise Reject("catalog_declaration_mismatch", "declaration digest")


def declaration_digest(decl) -> str:
    return canonical_digest({key: value for key, value in decl.items() if key != "digest"})


def policy_declaration(policy, scheme):
    scheme_policy = policy["schemes"].get(scheme)
    if scheme_policy is None:
        raise Reject("catalog_scheme_unsupported", f"scheme {scheme!r} is not supported")
    decl = scheme_policy["declaration"]
    return decl, declaration_digest(decl)


# ------------------------------------------------------------------ state

def parse_state(raw: bytes):
    state = parse_closed(raw, STATE_FIELDS, "catalog_shape")
    required(state, ("generation",), "catalog_shape")
    if _int(state["generation"], "catalog_shape", "generation") < 0:
        raise Reject("catalog_shape", "state generation")
    for record in state.get("history") or []:
        if not isinstance(record, dict) or set(record) - HISTORY_FIELDS:
            raise Reject("catalog_shape", "history record")
        required(record, ("generation", "digest"), "catalog_shape")
        _int(record["generation"], "catalog_shape", "history generation")
    return state


def digest_at(state, generation):
    if state["generation"] == generation:
        return state.get("digest")
    for record in state.get("history") or []:
        if record["generation"] == generation:
            return record.get("digest")
    return None


# ---------------------------------------------------------- verification

def roots_of(vector):
    return [x509.load_der_x509_certificate(b64d(value)) for value in vector.get("roots_b64") or []]


def signer_of(vector, payload: bytes):
    encoded = vector.get("signature_b64")
    if not encoded:
        raise Reject("signature_missing", "no detached signature")
    try:
        return verify_detached(b64d(encoded), payload)
    except Exception as exc:
        raise Reject("signature_invalid", str(exc))


def verify_signer(cat, cert, roots):
    if cert is None:
        raise Reject("signature_missing", "signer certificate is required")
    if not roots:
        raise Reject("signature_chain", "no trust roots configured")
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

    producer = cat["producer"]
    want = producer[len("principal:"):] if producer.startswith("principal:") else producer
    if want != aic["identifier"] and want != aic["realm"] + ":" + aic["identifier"]:
        raise Reject("publisher_mismatch", "producer does not match the AIC principal")

    key_hash = aic["key_hash"]
    if not key_hash or all(value == 0 for value in key_hash):
        raise Reject("publisher_key_binding", "no principal key hash")
    if key_hash != hashlib.sha256(spki_of(cert)).digest():
        raise Reject("publisher_key_binding", "key hash does not match")
    return aic


def spki_of(cert) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def verify_snapshot(vector, result):
    cat = parse_catalog(b64d(vector["catalog_b64"]))
    digest_value = catalog_digest(cat)
    result["catalog_digest"] = digest_value
    result["generation"] = cat["generation"]

    # Match catalog.VerifySigned's evidence order: the catalogue digest and
    # detached-signature signer are recorded before deployer policy validation.
    # A policy refusal must therefore not erase facts already established about
    # the signed artifact.
    cert = signer_of(vector, b64d(vector["catalog_b64"]))
    if cert is not None:
        result["key"] = digest(spki_of(cert))

    policy = parse_policy(b64d(vector["policy_b64"]))
    state = parse_state(b64d(vector["state_b64"]))

    if cat["domain"] != policy["domain"]:
        raise Reject("catalog_identity_mismatch", "catalog domain")
    if cat["catalog_id"] != policy["catalog_id"]:
        raise Reject("catalog_identity_mismatch", "catalog_id")

    aic = verify_signer(cat, cert, roots_of(vector))

    for entry in cat["entries"]:
        _, pinned = policy_declaration(policy, entry["scheme"])
        if entry["scheme_declaration_digest"] != pinned:
            raise Reject("catalog_declaration_mismatch", entry["capability"])

    check_generation(cat, state, digest_value)
    check_freshness(cat, policy)
    check_status(cat, policy)
    check_authority(cat, policy, aic)
    return result


def check_generation(cat, state, digest_value):
    if state.get("domain") and state["domain"] != cat["domain"]:
        raise Reject("catalog_identity_mismatch", "state domain")
    if state.get("catalog_id") and state["catalog_id"] != cat["catalog_id"]:
        raise Reject("catalog_identity_mismatch", "state catalog_id")

    accepted = state["generation"]
    if accepted == 0:
        if cat["generation"] != 1:
            raise Reject("catalog_bootstrap_required",
                         f"no accepted generation; catalog is generation {cat['generation']}")
        return

    recorded = digest_at(state, cat["generation"])
    if recorded and recorded != digest_value:
        raise Reject("catalog_generation_fork", "generation already holds another digest")
    if cat["generation"] < accepted:
        raise Reject("catalog_generation_rollback", "older than the accepted generation")
    if cat["generation"] == accepted:
        if digest_value != state.get("digest"):
            raise Reject("catalog_generation_fork", "same generation, different digest")
        return
    if cat["generation"] != accepted + 1:
        raise Reject("catalog_generation_rollback", "generation gap")
    if cat.get("previous_digest") != state.get("digest"):
        raise Reject("catalog_previous_digest_mismatch", "previous_digest")


def check_freshness(cat, policy):
    now = parse_time(policy["observed_at"])
    until = parse_time(cat["valid_until"])
    if now > until:
        raise Reject("catalog_expired", "valid_until precedes observed_at")
    window = policy.get("max_staleness_seconds") or 0
    if window > 0:
        issued = parse_time(cat["issued_at"])
        if (now - issued).total_seconds() > window:
            raise Reject("catalog_stale", "issued_at is older than the policy window")


def check_status(cat, policy):
    now = parse_time(policy["observed_at"])
    window = policy.get("max_status_staleness_seconds") or 0
    require = bool(policy.get("require_status"))
    for entry in cat["entries"]:
        status = entry.get("status")
        if status is None:
            if require:
                raise Reject("catalog_status_unavailable", entry["capability"])
            continue
        checked = parse_time(status["checked_at"])
        if checked > now:
            raise Reject("catalog_status_stale", entry["capability"])
        if window > 0 and (now - checked).total_seconds() > window:
            raise Reject("catalog_status_stale", entry["capability"])
        if require:
            value = (policy.get("status_values") or {}).get(status["reference"])
            if value is None:
                raise Reject("catalog_status_unavailable", entry["capability"])
            if value != "healthy":
                raise Reject("catalog_status_unavailable", entry["capability"])


def grants_for(aic, full_id):
    grants = []
    for capability in aic["capabilities"]:
        if capability["full_id"] != full_id:
            continue
        grant = {"id": full_id}
        if capability["params"]:
            grant["params"] = capability["params"]
        grants.append(grant)
    return grants


def capability_of(entry):
    return entry["capability"][len(entry["scheme"]) + 1:]


def check_authority(cat, policy, aic):
    bindings = policy.get("provider_bindings") or {}
    if bindings:
        for entry in cat["entries"]:
            producer = bindings.get(entry["provider"])
            if producer is None or producer != cat["producer"]:
                raise Reject("catalog_provider_mismatch", entry["capability"])
    for entry in cat["entries"]:
        grants = grants_for(aic, entry["capability"])
        if not grants:
            raise Reject("catalog_entry_outside_authority",
                         f"signer holds no grant for {entry['capability']!r}")
        declaration, _ = policy_declaration(policy, entry["scheme"])
        dm = domain_map(declaration, capability_of(entry))
        for operation in entry["operations"]:
            child = {"id": entry["capability"], "params": operation.get("params") or {}}
            covered = False
            for grant in grants:
                if contains_with_domains(grant, child, dm, dm)[0]:
                    covered = True
                    break
            if not covered:
                raise Reject("catalog_entry_outside_authority",
                             f"entry {entry['capability']!r} operation {operation['operation']!r}")


# --------------------------------------------------------------------- main

def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: probe.py BUNDLE.json\n")
        return 2
    bundle = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    if bundle.get("@version") != "varwof/catalog-crosslang-bundle-v1":
        sys.stderr.write("probe.py: wrong bundle version\n")
        return 2
    lines = []
    for vector in bundle["vectors"]:
        result = {}
        try:
            if vector["kind"] == "delta":
                result = apply_delta(vector)
            elif vector["kind"] == "discovery":
                result = verify_discovery(vector)
            else:
                result = verify_snapshot(vector, result)
            verdict, reason = "accept", ""
        except Reject as exc:
            verdict, reason = "reject", exc.code
        lines.append(render(vector["id"], vector["kind"], verdict, reason, result))
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def render(vector_id, kind, verdict, reason, result):
    parts = [vector_id, kind, verdict, reason or "-"]
    if result.get("catalog_digest"):
        parts.append("cat=" + result["catalog_digest"])
    if result.get("key"):
        parts.append("key=" + result["key"])
    if result.get("generation"):
        parts.append("gen=%d" % result["generation"])
    return " ".join(parts)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
