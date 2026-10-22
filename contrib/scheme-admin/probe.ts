#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// Cross-language evidence probe for varwof/scheme-admin-v1 (TypeScript).
//
// Reads a bundle produced by the Go confirmation test (inputs only) and prints
// one evidence line per corpus vector.  Same stewardship, second reading of the
// same artifacts; not an independent implementation.
//
// Run: node --experimental-strip-types probe.ts BUNDLE.json

import { createHash, verify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const clcDir = process.env.CLC_TS_DIR ?? new URL('../../../clc-ts/', import.meta.url).pathname;
const clc: any = await import(pathToFileURL(clcDir.endsWith('/') ? clcDir : clcDir + '/').href + 'clc_semantics.ts');
const { canonicalJSON, contains, authorizeSet } = clc;

const SCHEME_ID = 'varwof/scheme-admin-v1';
const PACKAGE_VERSION = 'CLC-SCHEME-PACKAGE-v1';
const TRANSITION_VERSION = 'CLC-SCHEME-TRANSITION-v1';
const AIC_OID = '1.3.6.1.4.1.66257.1.1';

const CAP_CREATE = 'scheme:create';
const CAP_UPDATE = 'scheme:update';
const CAP_REVOKE = 'scheme:revoke';
const CAP_DELEGATE = 'scheme:delegate';
const CAP_ROOT_ROTATE = 'scheme:root-rotate';
const CAP_APPROVE = 'scheme:approve';
const ADMIN_CAPABILITIES = new Set([CAP_CREATE, CAP_UPDATE, CAP_REVOKE, CAP_DELEGATE, CAP_ROOT_ROTATE, CAP_APPROVE]);

const DIGEST_RE = /^sha256:[A-Za-z0-9_-]{43}$/;
const SCHEME_RE = /^[a-z0-9][a-z0-9_-]*\/[a-z0-9][a-z0-9_.-]*-v[0-9]+$/;
const REVISION_RE = /^[0-9]+\.[0-9]+$/;
const CLC_RE = /^CLC-[0-9]+\.[0-9]+$/;
const PRINCIPAL_RE = /^principal:[A-Za-z0-9_.:-]+$/;
const NAMESPACE_RE = /^\/[A-Za-z0-9_.:/-]+$/;

const STRING_DOMAINS = new Set(['decimal-string', 'subdomain', 'path-prefix']);
const KNOWN_DOMAINS = new Set(['bound', 'enum', 'exact', 'quantity', 'decimal-string', 'subdomain', 'path-prefix']);

class Reject extends Error {
  code: string;
  result: Record<string, string> = {};

  constructor(code: string, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}

// ------------------------------------------------------------------ encoding

function digest(raw: Buffer): string {
  return 'sha256:' + createHash('sha256').update(raw).digest('base64url');
}

function canonicalDigest(value: any): string {
  return digest(Buffer.from(canonicalJSON(value), 'utf8'));
}

function b64d(text: string): Buffer {
  return Buffer.from(text, 'base64');
}

// ----------------------------------------------------------------------- DER

interface Tlv {
  tag: number;
  body: Buffer;
  next: number;
}

function der(buf: Buffer, off = 0): Tlv {
  if (off + 2 > buf.length) throw new Error('truncated DER');
  const tag = buf[off];
  let pos = off + 1;
  let length = buf[pos];
  pos += 1;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0 || pos + n > buf.length) throw new Error('bad DER length');
    length = 0;
    for (let i = 0; i < n; i += 1) length = length * 256 + buf[pos + i];
    pos += n;
  }
  const end = pos + length;
  if (end > buf.length) throw new Error('truncated DER value');
  return { tag, body: buf.subarray(pos, end), next: end };
}

function derChildren(value: Buffer): Tlv[] {
  const out: Tlv[] = [];
  let off = 0;
  while (off < value.length) {
    const item = der(value, off);
    out.push(item);
    off = item.next;
  }
  return out;
}

function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let rest = n;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return Buffer.concat([Buffer.from([0x80 | bytes.length]), Buffer.from(bytes)]);
}

function derSet(value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x31]), derLen(value.length), value]);
}

function oidString(value: Buffer): string {
  if (value.length === 0) return '';
  const parts = [Math.floor(value[0] / 40), value[0] % 40];
  let n = 0;
  for (let i = 1; i < value.length; i += 1) {
    n = (n << 7) | (value[i] & 0x7f);
    if ((value[i] & 0x80) === 0) {
      parts.push(n);
      n = 0;
    }
  }
  return parts.join('.');
}

function setContent(encoded: Buffer): Buffer {
  const item = der(encoded);
  if (item.tag !== 0x31) throw new Error('signed attributes are not a SET');
  return item.body;
}

// ----------------------------------------------------------------------- CMS

function verifyDetached(p7s: Buffer, payload: Buffer): X509Certificate {
  const outer = der(p7s);
  if (outer.tag !== 0x30) throw new Error('PKCS#7: not a SEQUENCE');
  const contentInfo = derChildren(outer.body);
  if (contentInfo.length < 2 || contentInfo[0].tag !== 0x06) throw new Error('PKCS#7: missing content type');
  if (oidString(contentInfo[0].body) !== '1.2.840.113549.1.7.2') throw new Error('PKCS#7: not signedData');
  const signedData = der(contentInfo[1].body);
  const fields = derChildren(signedData.body);

  const certs: X509Certificate[] = [];
  let signerInfos: Tlv[] = [];
  for (const field of fields) {
    if (field.tag === 0xa0) {
      for (const item of derChildren(field.body)) {
        if (item.tag === 0x30) {
          certs.push(new X509Certificate(Buffer.concat([Buffer.from([0x30]), derLen(item.body.length), item.body])));
        }
      }
    } else if (field.tag === 0x31) {
      signerInfos = derChildren(field.body);
    }
  }
  if (signerInfos.length === 0) throw new Error('PKCS#7: no SignerInfo');

  const si = derChildren(signerInfos[0].body);
  let idx = 2;
  if (idx < si.length && si[idx].tag === 0x30) idx += 1; // digestAlgorithm
  let signedAttrs: Buffer | null = null;
  if (idx < si.length && si[idx].tag === 0xa0) {
    signedAttrs = derSet(si[idx].body);
    idx += 1;
  }
  if (idx + 1 >= si.length) throw new Error('PKCS#7: truncated SignerInfo');
  const signature = si[idx + 1].body;
  if (signedAttrs === null) throw new Error('PKCS#7: signed attributes are required by this profile');

  let found = false;
  for (const attr of derChildren(setContent(signedAttrs))) {
    const kids = derChildren(attr.body);
    if (kids.length === 0 || kids[0].tag !== 0x06) continue;
    if (oidString(kids[0].body) === '1.2.840.113549.1.9.4' && kids.length > 1) {
      const values = derChildren(kids[1].body);
      if (values.length > 0 && values[0].tag === 0x04) {
        const want = createHash('sha256').update(payload).digest();
        if (!values[0].body.equals(want)) throw new Error('PKCS#7: message digest mismatch');
        found = true;
      }
    }
  }
  if (!found) throw new Error('PKCS#7: no messageDigest attribute');

  for (const cert of certs) {
    try {
      if (verify('sha256', signedAttrs, cert.publicKey, signature)) return cert;
    } catch {
      continue;
    }
  }
  throw new Error('PKCS#7: no certificate verifies the signature');
}

// ----------------------------------------------------------------------- AIC

function spkiOf(cert: X509Certificate): Buffer {
  return cert.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
}

function aicOf(cert: X509Certificate): any {
  const extensions = extensionsOf(cert.raw);
  const raw = extensions.get(AIC_OID);
  if (raw === undefined) return null;
  const item = der(raw);
  if (item.tag !== 0x30) throw new Error('AIC: not a SEQUENCE');
  return parseAic(item.body);
}

function extensionsOf(certDer: Buffer): Map<string, Buffer> {
  const outer = der(certDer);
  const tbs = derChildren(derChildren(outer.body)[0].body);
  const found = new Map<string, Buffer>();
  for (const field of tbs) {
    if (field.tag !== 0xa3) continue;
    const wrapper = der(field.body);
    for (const ext of derChildren(wrapper.body)) {
      const parts = derChildren(ext.body);
      const oid = oidString(parts[0].body);
      found.set(oid, parts[parts.length - 1].body);
    }
  }
  return found;
}

function parseAic(body: Buffer): any {
  const kids = derChildren(body);
  let idx = 0;
  if (kids.length > 0 && kids[0].tag === 0x02) idx = 1;
  if (idx + 2 >= kids.length) throw new Error('AIC: truncated');
  const principal = derChildren(kids[idx + 1].body);
  const pidx = principal.length > 0 && principal[0].tag === 0x02 ? 1 : 0;
  const realm = principal[pidx].body.toString('utf8');
  const identifier = principal[pidx + 1].body.toString('utf8');
  const keyHash = principal[pidx + 2].body;
  const capabilities: any[] = [];
  for (const cap of derChildren(kids[idx + 2].body)) {
    const ck = derChildren(cap.body);
    const schemeId = ck[0].body.toString('utf8');
    const capabilityId = ck[1].body.toString('utf8');
    let params: any = null;
    if (ck.length > 2 && ck[2].tag === 0xa0) {
      const inner = derChildren(ck[2].body);
      if (inner.length > 0 && inner[0].tag === 0x04) params = JSON.parse(inner[0].body.toString('utf8'));
    }
    capabilities.push({ fullId: `${schemeId}:${capabilityId}`, params });
  }
  return { realm, identifier, keyHash, capabilities };
}

// ---------------------------------------------------------- declared domains

function domainMap(declaration: any, capability: string): any {
  const caps = declaration?.capabilities ?? {};
  const entry = caps[capability];
  if (entry === undefined) return null;
  const out: any = {};
  for (const [name, spec] of Object.entries(entry.params ?? {})) {
    out[name] = [(spec as any).domain, (spec as any).unit ?? ''];
  }
  return out;
}

function declaredBoundConflict(grant: any, dm: any): boolean {
  for (const name of Object.keys(grant?.param_bounds ?? {})) {
    if (dm && Object.prototype.hasOwnProperty.call(dm, name)) return true;
  }
  return false;
}

function normalize(params: any, dm: any): [any, string] {
  if (!dm || !params) return [params, ''];
  const out = { ...params };
  for (const [k, v] of Object.entries(params)) {
    const spec = dm[k];
    if (spec === undefined) continue;
    const name = spec[0];
    if (name === 'bound' || name === 'enum' || name === 'exact' || STRING_DOMAINS.has(name)) {
      out[k] = v;
    } else if (name === 'quantity') {
      const [number, reason] = quantityNumber(v, spec[1]);
      if (reason) return [null, reason];
      out[k] = number;
    } else {
      return [null, 'unsupported_domain'];
    }
  }
  return [out, ''];
}

function quantityNumber(value: any, unit: string): [number, string] {
  if (typeof value !== 'object' || value === null) return [0, 'invalid_params_binding'];
  const val = value.value;
  if (typeof val !== 'number') return [0, 'invalid_params_binding'];
  const u = value.unit;
  if (typeof u !== 'string' || u === '') return [0, 'invalid_params_binding'];
  if (u !== unit) return [0, 'unit_mismatch'];
  const scale = value.scale ?? 0;
  if (typeof scale !== 'number' || !Number.isInteger(scale)) return [0, 'invalid_params_binding'];
  return [val * Math.pow(10, -scale), ''];
}

function stringDomainCovers(domain: string, parent: any, child: any): [boolean, string] {
  if (typeof parent !== 'string') return [false, 'invalid_params_binding'];
  if (typeof child !== 'string') return [false, 'invalid_params_binding'];
  if (domain === 'decimal-string') return decimalCovers(parent, child);
  if (domain === 'subdomain') return subdomainCovers(parent, child);
  if (domain === 'path-prefix') return pathCovers(parent, child);
  return [false, 'unsupported_domain'];
}

function pathCovers(parent: string, child: string): [boolean, string] {
  if (!parent.startsWith('/') || !child.startsWith('/')) return [false, 'invalid_params_binding'];
  if (pathClean(parent) !== parent || pathClean(child) !== child) return [false, 'invalid_params_binding'];
  if (child === parent || child.startsWith(parent.replace(/\/+$/, '') + '/')) return [true, ''];
  return [false, 'params_exceed_grant'];
}

function subdomainCovers(parent: string, child: string): [boolean, string] {
  const p = domainName(parent);
  const c = domainName(child);
  if (!p || !c) return [false, 'invalid_params_binding'];
  if (c === p || c.endsWith('.' + p)) return [true, ''];
  return [false, 'params_exceed_grant'];
}

function domainName(raw: string): string {
  let s = raw.toLowerCase();
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (/\s/.test(s)) return '';
  if (s.split('.').some((label) => label === '')) return '';
  return s;
}

const DECIMAL_RE = /^[+-]?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;

function decimalCovers(parent: string, child: string): [boolean, string] {
  const p = parseDecimal(parent);
  const c = parseDecimal(child);
  if (p === null || c === null) return [false, 'invalid_params_binding'];
  const cmp = compareDecimal(c, p);
  if (cmp > 0) return [false, 'params_exceed_grant'];
  return [true, ''];
}

// [sign, digits as BigInt, exponent]
function parseDecimal(s: string): [number, bigint, number] | null {
  if (!DECIMAL_RE.test(s)) return null;
  let mantissa = s;
  let exp = 0;
  const eIndex = s.search(/[eE]/);
  if (eIndex >= 0) {
    mantissa = s.slice(0, eIndex);
    exp = Number(s.slice(eIndex + 1));
    if (!Number.isInteger(exp)) return null;
  }
  let sign = 1;
  if (mantissa.startsWith('-')) {
    sign = -1;
    mantissa = mantissa.slice(1);
  } else if (mantissa.startsWith('+')) {
    mantissa = mantissa.slice(1);
  }
  const [whole, frac = ''] = mantissa.split('.');
  return [sign, BigInt((whole || '0') + frac), exp - frac.length];
}

function compareDecimal(a: [number, bigint, number], b: [number, bigint, number]): number {
  const ar = rational(a);
  const br = rational(b);
  if (ar[0] !== br[0]) return ar[0] < br[0] ? -1 : 1;
  const l = ar[1] * br[2];
  const r = br[1] * ar[2];
  return l === r ? 0 : l < r ? -1 : 1;
}

function rational(x: [number, bigint, number]): [number, bigint, bigint] {
  if (x[2] >= 0) return [x[0], x[1] * 10n ** BigInt(x[2]), 1n];
  return [x[0], x[1], 10n ** BigInt(-x[2])];
}

function neutralize(params: any, name: string): any {
  return { ...(params ?? {}), [name]: 'domain-covered' };
}

function containsWithDomains(parent: any, child: any, parentDom: any, childDom: any): [boolean, string] {
  if (declaredBoundConflict(parent, parentDom) || declaredBoundConflict(child, childDom)) {
    return [false, 'params_not_narrower'];
  }
  parent = { ...parent };
  child = { ...child };
  for (const [name, pspec] of Object.entries(parentDom ?? {})) {
    const cspec = (childDom ?? {})[name];
    if (cspec === undefined) continue;
    if ((pspec as any)[0] !== cspec[0]) return [false, 'params_not_narrower'];
    if (STRING_DOMAINS.has((pspec as any)[0])) {
      const pp = parent.params ?? {};
      const cc = child.params ?? {};
      if (!(name in pp) || !(name in cc)) continue;
      const [ok] = stringDomainCovers((pspec as any)[0], pp[name], cc[name]);
      if (!ok) return [false, 'params_not_narrower'];
      parent.params = neutralize(pp, name);
      child.params = neutralize(cc, name);
    }
  }
  const [pp, reason] = normalize(parent.params ?? {}, parentDom);
  if (reason) return [false, 'params_not_narrower'];
  const [cp, reason2] = normalize(child.params ?? {}, childDom);
  if (reason2) return [false, 'params_not_narrower'];
  parent.params = pp;
  child.params = cp;
  const result = contains(parent, child);
  return [Boolean(result.contains), result.reason ?? ''];
}

function authorizeSetWithDomains(grants: any[], op: any, dm: any): any {
  const opCopy = { ...op };
  let opParams = { ...(op.params ?? {}) };
  const normalized: any[] = [];
  for (let grant of grants) {
    if (declaredBoundConflict(grant, dm)) return { verdict: 'deny', reason: 'invalid_params_binding' };
    let usable = true;
    grant = { ...grant };
    let gp = { ...(grant.params ?? {}) };
    for (const [name, spec] of Object.entries(dm ?? {})) {
      if (!STRING_DOMAINS.has((spec as any)[0])) continue;
      if (!(name in gp) || !(name in opParams)) continue;
      const [ok, reason] = stringDomainCovers((spec as any)[0], gp[name], opParams[name]);
      if (!ok) {
        if (reason === 'invalid_params_binding') return { verdict: 'deny', reason };
        usable = false;
        break;
      }
      gp = neutralize(gp, name);
      opParams = neutralize(opParams, name);
    }
    if (!usable) continue;
    const [normalizedParams, reason] = normalize(gp, dm);
    if (reason) return { verdict: 'deny', reason };
    grant.params = normalizedParams;
    normalized.push(grant);
  }
  if (normalized.length === 0 && grants.length > 0) {
    return { verdict: 'deny', reason: 'params_exceed_grant' };
  }
  const [finalParams, reason] = normalize(opParams, dm);
  if (reason) return { verdict: 'deny', reason };
  opCopy.params = finalParams;
  return authorizeSet(normalized, opCopy);
}

// ------------------------------------------------------------------- objects

const PACKAGE_FIELDS = new Set([
  '@version', 'scheme', 'revision', 'definition_digest', 'declaration_digest',
  'clc_revision', 'change_class', 'previous_package_digest', 'publisher',
  'generation', 'issued_at', 'valid_until',
]);
const TRANSITION_FIELDS = new Set([
  '@version', 'action', 'scheme', 'namespace', 'from_generation', 'to_generation',
  'from_digest', 'to_digest', 'change_class', 'target_clc_revision',
  'revocation_reason', 'revocation_effective_time', 'replacement_digest',
  'tombstone_generation', 'next_root_package_digest', 'next_root_keys',
  'next_root_threshold',
]);
const DECLARATION_FIELDS = new Set([
  '@version', 'scheme', 'declaration_id', 'clc_revision', 'digest', 'capabilities', 'constraint_types',
]);
const GRANT_FIELDS = new Set(['id', 'params', 'param_bounds', 'constraints']);
const DELEGATION_FIELDS = new Set(['grantee', 'parent', 'child']);

function parseClosed(raw: Buffer, allowed: Set<string>, code: string): any {
  let value: any;
  try {
    value = JSON.parse(raw.toString('utf8'));
  } catch (exc) {
    throw new Reject(code, String(exc));
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Reject(code, 'not an object');
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Reject(code, `unknown member ${key}`);
  }
  return value;
}

function packageDigestObject(pkg: any): any {
  const obj: any = {
    '@version': pkg['@version'],
    scheme: pkg.scheme,
    revision: pkg.revision,
    definition_digest: pkg.definition_digest,
    declaration_digest: pkg.declaration_digest,
    clc_revision: pkg.clc_revision,
    change_class: pkg.change_class,
    publisher: pkg.publisher,
    generation: pkg.generation,
  };
  for (const key of ['previous_package_digest', 'issued_at', 'valid_until']) {
    if (pkg[key]) obj[key] = pkg[key];
  }
  return obj;
}

function transitionDigestObject(tr: any): any {
  const obj: any = {
    '@version': tr['@version'],
    action: tr.action,
    scheme: tr.scheme,
    namespace: tr.namespace,
    to_generation: tr.to_generation,
    to_digest: tr.to_digest,
    change_class: tr.change_class,
    target_clc_revision: tr.target_clc_revision,
  };
  if (tr.from_generation !== undefined && tr.from_generation !== null) obj.from_generation = tr.from_generation;
  for (const key of ['from_digest', 'revocation_reason', 'revocation_effective_time', 'replacement_digest', 'next_root_package_digest']) {
    if (tr[key]) obj[key] = tr[key];
  }
  if (tr.next_root_keys && tr.next_root_keys.length > 0) obj.next_root_keys = tr.next_root_keys;
  if (tr.next_root_threshold) obj.next_root_threshold = tr.next_root_threshold;
  if (tr.tombstone_generation !== undefined && tr.tombstone_generation !== null) {
    obj.tombstone_generation = tr.tombstone_generation;
  }
  return obj;
}

// ------------------------------------------------------------------ validity

function validatePackage(pkg: any): void {
  const code = 'package_shape';
  if (pkg['@version'] !== PACKAGE_VERSION) throw new Reject(code, 'wrong @version');
  if (!SCHEME_RE.test(pkg.scheme)) throw new Reject(code, 'bad scheme');
  if (!REVISION_RE.test(pkg.revision)) throw new Reject(code, 'bad revision');
  for (const name of ['definition_digest', 'declaration_digest']) {
    if (!DIGEST_RE.test(pkg[name])) throw new Reject(code, `bad ${name}`);
  }
  if (!CLC_RE.test(pkg.clc_revision)) throw new Reject(code, 'bad clc_revision');
  if (!['patch', 'minor', 'major'].includes(pkg.change_class)) throw new Reject(code, 'bad change_class');
  if (!PRINCIPAL_RE.test(pkg.publisher)) throw new Reject(code, 'bad publisher');
  if (!Number.isInteger(pkg.generation) || pkg.generation < 1) throw new Reject(code, 'bad generation');
  const previous = pkg.previous_package_digest ?? '';
  if (previous && !DIGEST_RE.test(previous)) throw new Reject(code, 'bad previous_package_digest');
  if (pkg.generation === 1 && previous) throw new Reject(code, 'generation 1 with previous digest');
  if (pkg.generation > 1 && !previous) throw new Reject(code, 'generation > 1 without previous digest');
  for (const name of ['issued_at', 'valid_until']) {
    if (pkg[name] && parseTime(pkg[name]) === null) throw new Reject(code, `bad ${name}`);
  }
}

function validateTransition(tr: any): void {
  const code = 'transition_shape';
  if (tr['@version'] !== TRANSITION_VERSION) throw new Reject(code, 'wrong @version');
  if (!['create', 'update', 'revoke', 'root-rotate'].includes(tr.action)) throw new Reject(code, 'bad action');
  if (!SCHEME_RE.test(tr.scheme)) throw new Reject(code, 'bad scheme');
  if (!NAMESPACE_RE.test(tr.namespace) || pathClean(tr.namespace) !== tr.namespace) {
    throw new Reject(code, 'namespace is not an absolute clean path');
  }
  if (tr.namespace !== '/' + tr.scheme) throw new Reject('namespace_mismatch', 'namespace does not match scheme');
  if (!Number.isInteger(tr.to_generation) || tr.to_generation < 1) throw new Reject(code, 'bad to_generation');
  if (!DIGEST_RE.test(tr.to_digest)) throw new Reject(code, 'bad to_digest');
  if (!['patch', 'minor', 'major'].includes(tr.change_class)) {
    throw new Reject('change_class_invalid', 'bad change_class');
  }
  if (!CLC_RE.test(tr.target_clc_revision)) throw new Reject(code, 'bad target_clc_revision');

  if (tr.action === 'create') {
    if (tr.from_generation !== undefined && tr.from_generation !== null) throw new Reject('create_shape', 'create declares from_*');
    if (tr.from_digest) throw new Reject('create_shape', 'create declares from_digest');
    if (tr.to_generation !== 1) throw new Reject('create_shape', 'create must target generation 1');
    if (tr.change_class !== 'major') throw new Reject('create_shape', 'create must be a major change');
  } else if (tr.action === 'update') {
    requireFrom(tr);
  } else if (tr.action === 'revoke') {
    requireFrom(tr);
    const reason = tr.revocation_reason ?? '';
    if (!reason) throw new Reject(code, 'revoke requires revocation_reason');
    if (!['superseded', 'security-defect', 'publisher-withdrawal', 'policy-violation', 'compromised'].includes(reason)) {
      throw new Reject(code, 'unknown revocation_reason');
    }
    if (!tr.revocation_effective_time) throw new Reject(code, 'revoke requires revocation_effective_time');
    if (parseTime(tr.revocation_effective_time) === null) throw new Reject(code, 'bad revocation_effective_time');
    if (tr.tombstone_generation === undefined || tr.tombstone_generation === null) {
      throw new Reject(code, 'revoke requires tombstone_generation');
    }
    if (tr.tombstone_generation < tr.to_generation) throw new Reject(code, 'bad tombstone_generation');
    if (tr.replacement_digest && !DIGEST_RE.test(tr.replacement_digest)) throw new Reject(code, 'bad replacement_digest');
  } else if (tr.action === 'root-rotate') {
    requireFrom(tr);
    if (!DIGEST_RE.test(tr.next_root_package_digest ?? '')) throw new Reject(code, 'root-rotate requires next_root_package_digest');
    if (!Array.isArray(tr.next_root_keys) || tr.next_root_keys.length === 0) {
      throw new Reject(code, 'root-rotate requires next_root_keys');
    }
    for (const key of tr.next_root_keys) {
      if (typeof key !== 'string' || !DIGEST_RE.test(key)) throw new Reject(code, 'bad next_root_keys entry');
    }
    if ((tr.next_root_threshold ?? 0) < 1) throw new Reject(code, 'root-rotate requires next_root_threshold >= 1');
  }
}

function requireFrom(tr: any): void {
  if (tr.from_generation === undefined || tr.from_generation === null) {
    throw new Reject('transition_shape', `${tr.action} requires from_generation`);
  }
  if (tr.from_generation < 1) throw new Reject('transition_shape', 'from_generation must be >= 1');
  if (!DIGEST_RE.test(tr.from_digest ?? '')) {
    throw new Reject('transition_shape', `${tr.action} requires from_digest`);
  }
}

function parseDeclaration(raw: Buffer): any {
  const decl = parseClosed(raw, DECLARATION_FIELDS, 'declaration_invalid');
  try {
    validateDeclaration(decl);
  } catch (exc) {
    if (exc instanceof Reject) throw new Reject('declaration_invalid', exc.message);
    throw exc;
  }
  return decl;
}

function validateDeclaration(decl: any): void {
  if (decl['@version'] !== 'CLC-SCHEME-v1') throw new Reject('declaration_invalid', 'wrong @version');
  if (!decl.scheme || !decl.declaration_id || !decl.clc_revision) throw new Reject('declaration_invalid', 'missing member');
  const capabilities = decl.capabilities ?? {};
  if (Object.keys(capabilities).length === 0) throw new Reject('declaration_invalid', 'no capabilities');
  for (const cap of Object.values<any>(capabilities)) {
    for (const param of Object.values<any>(cap.params ?? {})) {
      const domain = param.domain;
      if (!KNOWN_DOMAINS.has(domain)) throw new Reject('declaration_invalid', 'unsupported_domain');
      const unit = param.unit ?? '';
      if (domain === 'quantity' && !unit) throw new Reject('declaration_invalid', 'quantity without unit');
      if (domain !== 'quantity' && unit) throw new Reject('declaration_invalid', 'unit outside quantity');
    }
  }
  if (decl.digest) {
    const want = declarationDigest(decl);
    if (want !== decl.digest) throw new Reject('declaration_invalid', 'declaration_digest_mismatch');
  }
}

function declarationDigest(decl: any): string {
  const obj: any = {};
  for (const [key, value] of Object.entries(decl)) {
    if (key !== 'digest') obj[key] = value;
  }
  return canonicalDigest(obj);
}

function validatePolicy(policy: any): void {
  const rootDigest = policy.root_package_digest ?? '';
  if (rootDigest && !DIGEST_RE.test(rootDigest)) throw new Reject('package_shape', 'bad root_package_digest');
  if ((policy.root_keys ?? []).length > 0 && (policy.root_threshold ?? 0) < 1) {
    throw new Reject('package_shape', 'root_threshold must be >= 1');
  }
  if ((policy.max_major ?? 0) < 1) throw new Reject('package_shape', 'max_major must be >= 1');
  if (policy.administration_declaration === undefined || policy.administration_declaration === null) {
    throw new Reject('declaration_invalid', 'administration_declaration is required');
  }
  parseDeclaration(Buffer.from(JSON.stringify(policy.administration_declaration), 'utf8'));
  for (const key of policy.next_root_keys ?? []) {
    if (!DIGEST_RE.test(key)) throw new Reject('package_shape', 'bad next_root_keys entry');
  }
}

// ---------------------------------------------------------------------- time

const TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;

function parseTime(raw: string): number | null {
  const m = TIME_RE.exec(raw);
  if (!m) return null;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  const micro = Number(((m[7] ?? '0') + '000000').slice(0, 6));
  const zone = m[8];
  let offsetMinutes = 0;
  if (zone !== 'Z') {
    const sign = zone[0] === '+' ? 1 : -1;
    offsetMinutes = sign * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4, 6)));
  }
  return Date.UTC(year, month - 1, day, hour, minute, second, Math.floor(micro / 1000)) - offsetMinutes * 60000;
}

function pathClean(value: string): string {
  if (value === '') return '.';
  const rooted = value.startsWith('/');
  const parts: string[] = [];
  for (const element of value.split('/')) {
    if (element === '' || element === '.') continue;
    if (element === '..') {
      if (parts.length > 0) parts.pop();
      else if (!rooted) parts.push('..');
      continue;
    }
    parts.push(element);
  }
  const joined = parts.join('/');
  if (rooted) return '/' + joined;
  return joined || '.';
}

// -------------------------------------------------------------- confirmation

function verifyPublisher(pkg: any, cert: X509Certificate | null, roots: X509Certificate[]): any {
  if (cert === null) throw new Reject('signature_missing');
  if (roots.length === 0) throw new Reject('signature_chain', 'no trust roots');
  let chained = false;
  for (const root of roots) {
    try {
      if (cert.checkIssued(root) && cert.verify(root.publicKey)) {
        chained = true;
        break;
      }
    } catch {
      continue;
    }
  }
  if (!chained) throw new Reject('signature_chain', 'certificate does not chain to a trust root');

  const aic = aicOf(cert);
  if (aic === null) throw new Reject('signature_no_aic', 'no AIC extension');

  const want = pkg.publisher.startsWith('principal:') ? pkg.publisher.slice('principal:'.length) : pkg.publisher;
  const identifier = aic.identifier;
  const realm = aic.realm;
  if (want !== identifier && want !== `${realm}:${identifier}`) {
    throw new Reject('publisher_mismatch', 'principal does not match');
  }

  const keyHash: Buffer = aic.keyHash;
  if (keyHash.length === 0 || keyHash.every((b: number) => b === 0)) {
    throw new Reject('publisher_key_binding', 'no principal key hash');
  }
  const wantHash = createHash('sha256').update(spkiOf(cert)).digest();
  if (!keyHash.equals(wantHash)) throw new Reject('publisher_key_binding', 'key hash does not match');
  return aic;
}

function majorOf(revision: string): number {
  return Number(revision.split('.')[0]);
}

function minorOf(revision: string): number {
  return Number(revision.split('.')[1]);
}

function capabilityOf(fullId: string): string | null {
  const prefix = SCHEME_ID + ':';
  if (!fullId.startsWith(prefix)) return null;
  return fullId.slice(prefix.length);
}

function buildManagementOperation(pkg: any, tr: any): any {
  const table: Record<string, string> = {
    create: CAP_CREATE,
    update: CAP_UPDATE,
    revoke: CAP_REVOKE,
    'root-rotate': CAP_ROOT_ROTATE,
  };
  const capability = table[tr.action];
  if (capability === undefined) throw new Reject('transition_shape', 'unknown action');
  const op: any = { id: `${SCHEME_ID}:${capability}` };
  if (tr.action === 'create' || tr.action === 'update') {
    op.params = {
      namespace: tr.namespace,
      change_class: tr.change_class,
      major: majorOf(pkg.revision),
      clc_revision: tr.target_clc_revision,
    };
  } else if (tr.action === 'revoke') {
    op.params = {
      namespace: tr.namespace,
      package_digest: tr.from_digest,
      clc_revision: tr.target_clc_revision,
    };
  } else if (tr.action === 'root-rotate') {
    if (!tr.from_digest) throw new Reject('transition_shape', 'root-rotate requires from_digest');
    op.params = {
      package_digest: tr.from_digest,
      clc_revision: tr.target_clc_revision,
    };
  }
  return op;
}

function operationDigest(op: any): string {
  const obj: any = op.params && Object.keys(op.params).length === 0 ? { id: op.id } : { id: op.id, params: op.params };
  return canonicalDigest(obj);
}

function grantsFor(aic: any, fullId: string): any[] {
  const out: any[] = [];
  for (const cap of aic.capabilities) {
    if (cap.fullId !== fullId) continue;
    const grant: any = { id: fullId };
    if (cap.params !== null) {
      if (typeof cap.params !== 'object' || Array.isArray(cap.params)) continue;
      grant.params = cap.params;
    }
    out.push(grant);
  }
  return out;
}

function containGrants(grants: any[], roots: any[], dm: any): any[] {
  const kept: any[] = [];
  for (const grant of grants) {
    for (const root of roots) {
      const [ok] = containsWithDomains(root, grant, dm, dm);
      if (ok) {
        kept.push(grant);
        break;
      }
    }
  }
  return kept;
}

function revisionFollows(prev: string, next: string, changeClass: string): boolean {
  const pmaj = majorOf(prev);
  const pmin = minorOf(prev);
  const nmaj = majorOf(next);
  const nmin = minorOf(next);
  if (changeClass === 'patch') return nmaj === pmaj && nmin === pmin;
  if (changeClass === 'minor') return nmaj === pmaj && nmin === pmin + 1;
  if (changeClass === 'major') return nmaj === pmaj + 1 && nmin === 0;
  return false;
}

function namespaceUnder(namespace: string, prefixes: string[]): boolean {
  for (const prefix of prefixes ?? []) {
    if (namespace === prefix) return true;
    if (namespace.startsWith(prefix.replace(/\/+$/, '') + '/')) return true;
  }
  return false;
}

function checkState(tr: any, state: any, packageRevision: string, changeClass: string): void {
  if (tr.action === 'create') {
    if ((state.history ?? []).length > 0 || (state.generation ?? 0) !== 0 || state.package_digest) {
      throw new Reject('state_not_empty', 'create requires an empty namespace');
    }
    return;
  }

  const recorded = digestAt(state, tr.to_generation);
  if (recorded !== null && recorded !== tr.to_digest) {
    throw new Reject('generation_fork', 'generation already holds another digest');
  }

  if (tr.from_generation === undefined || tr.from_generation === null) {
    throw new Reject('transition_shape', `${tr.action} requires from_generation`);
  }
  if ((state.generation ?? 0) !== tr.from_generation) {
    throw new Reject('state_generation_mismatch', 'local head generation differs');
  }
  if ((state.package_digest ?? '') !== (tr.from_digest ?? '')) {
    throw new Reject('state_digest_mismatch', 'local head digest differs');
  }
  if (tr.to_generation !== tr.from_generation + 1) {
    throw new Reject('state_generation_mismatch', 'transition must advance one generation');
  }
  if (tr.to_generation <= headOf(state)) {
    throw new Reject('generation_rollback', 'generation is not newer than the head');
  }
  if (tr.action === 'update' && state.revision) {
    if (!revisionFollows(state.revision, packageRevision, changeClass)) {
      throw new Reject('change_class_invalid', 'revision does not follow the change class');
    }
  }
}

function headOf(state: any): number {
  let head = state.generation ?? 0;
  for (const entry of state.history ?? []) head = Math.max(head, entry.generation ?? 0);
  return head;
}

function digestAt(state: any, generation: number): string | null {
  if ((state.generation ?? 0) === generation && state.package_digest) return state.package_digest;
  for (const entry of state.history ?? []) {
    if ((entry.generation ?? 0) === generation) return entry.package_digest;
  }
  return null;
}

function isRevoked(state: any, value: string | undefined): boolean {
  if (!value) return false;
  return (state.revoked ?? []).some((r: any) => r.package_digest === value);
}

function countApprovals(state: any, packageDigest: string, transitionDigest: string): number {
  return (state.approvals ?? []).filter(
    (a: any) => a.package_digest === packageDigest && a.transition_digest === transitionDigest,
  ).length;
}

function checkRootRotation(tr: any, cert: X509Certificate, policy: any): void {
  const signer = digest(spkiOf(cert));
  const inCurrent = (policy.root_keys ?? []).includes(signer);
  const inNext = (policy.next_root_keys ?? []).includes(signer);
  if (inNext && !inCurrent) throw new Reject('root_rotate_self_authorized', 'signer is only in the next root');
  if (!inCurrent) throw new Reject('root_rotate_no_current_root', 'signer is not a current root');
  if (!policy.root_package_digest || tr.from_digest !== policy.root_package_digest) {
    throw new Reject('root_rotate_policy_mismatch', 'from_digest is not the root package');
  }
  if (!policy.next_root_package_digest || (policy.next_root_keys ?? []).length === 0 || (policy.next_root_threshold ?? 0) < 1) {
    throw new Reject('root_rotate_policy_mismatch', 'policy configures no next root');
  }
  if (tr.next_root_package_digest !== policy.next_root_package_digest) {
    throw new Reject('root_rotate_policy_mismatch', 'next root package differs');
  }
  if (tr.next_root_threshold !== policy.next_root_threshold) {
    throw new Reject('root_rotate_policy_mismatch', 'threshold differs');
  }
  if (!sameSet(tr.next_root_keys ?? [], policy.next_root_keys)) {
    throw new Reject('root_rotate_policy_mismatch', 'next root keys differ');
  }
  if ((tr.next_root_keys ?? []).length < tr.next_root_threshold) {
    throw new Reject('root_rotate_threshold', 'next root threshold not met');
  }
  if (policy.next_root_package_digest === policy.root_package_digest) {
    throw new Reject('root_rotate_self_authorized', 'next root package is the current root package');
  }
  if (tr.to_digest !== policy.next_root_package_digest) {
    throw new Reject('root_rotate_policy_mismatch', 'to_digest is not the next root package');
  }
}

function sameSet(a: string[], b: string[]): boolean {
  return [...a].sort().join('\u0000') === [...b].sort().join('\u0000');
}

function confirm(vector: any): Record<string, string> {
  const definition = b64d(vector.definition_b64);
  const declaration = b64d(vector.declaration_b64);
  const packageRaw = b64d(vector.package_b64);
  const transitionRaw = b64d(vector.transition_b64);
  const policy = JSON.parse(b64d(vector.policy_b64).toString('utf8'));
  const state = JSON.parse(b64d(vector.state_b64).toString('utf8'));
  const roots = (vector.roots_b64 ?? []).map((r: string) => new X509Certificate(b64d(r)));

  let cert: X509Certificate | null = null;
  if (vector.p7s_b64) cert = verifyDetached(b64d(vector.p7s_b64), packageRaw);

  const result: Record<string, string> = {};
  const pkg = parseClosed(packageRaw, PACKAGE_FIELDS, 'package_shape');
  validatePackage(pkg);
  const tr = parseClosed(transitionRaw, TRANSITION_FIELDS, 'transition_shape');
  validateTransition(tr);

  result.package_digest = canonicalDigest(packageDigestObject(pkg));
  result.transition_digest = canonicalDigest(transitionDigestObject(tr));
  if (cert !== null) result.publisher_key_id = digest(spkiOf(cert));
  let op: any = null;
  try {
    op = buildManagementOperation(pkg, tr);
  } catch (exc) {
    if (!(exc instanceof Reject)) throw exc;
    op = null;
  }
  if (op !== null) result.management_operation_digest = operationDigest(op);

  try {
    decide(pkg, tr, definition, declaration, cert, roots, state, policy, result, op);
  } catch (exc) {
    if (exc instanceof Reject) {
      exc.result = result;
      throw exc;
    }
    throw exc;
  }
  return result;
}

function decide(
  pkg: any,
  tr: any,
  definition: Buffer,
  declaration: Buffer,
  cert: X509Certificate | null,
  roots: X509Certificate[],
  state: any,
  policy: any,
  result: Record<string, string>,
  maybeOp: any,
): void {
  validatePolicy(policy);
  validatePackage(pkg);
  validateTransition(tr);

  if (digest(definition) !== pkg.definition_digest) throw new Reject('package_digest_mismatch', 'definition digest differs');
  if (digest(declaration) !== pkg.declaration_digest) throw new Reject('package_digest_mismatch', 'declaration digest differs');
  const decl = parseDeclaration(declaration);
  if (decl.scheme !== pkg.scheme) throw new Reject('declaration_invalid', 'declaration names another scheme');
  if (decl.clc_revision !== pkg.clc_revision) throw new Reject('declaration_invalid', 'declaration requires another revision');

  if (pkg.scheme !== tr.scheme) throw new Reject('package_transition_mismatch', 'package scheme differs');
  if (pkg.generation !== tr.to_generation) throw new Reject('package_transition_mismatch', 'package generation differs');
  if (pkg.change_class !== tr.change_class) throw new Reject('package_transition_mismatch', 'package change_class differs');
  if (pkg.clc_revision !== tr.target_clc_revision) throw new Reject('package_transition_mismatch', 'package clc_revision differs');
  if (result.package_digest !== tr.to_digest) throw new Reject('package_transition_mismatch', 'to_digest differs');
  if (tr.from_digest && pkg.previous_package_digest !== tr.from_digest) {
    throw new Reject('package_transition_mismatch', 'previous_package_digest differs');
  }

  const aic = verifyPublisher(pkg, cert, roots);

  if (!(policy.supported_clc_revisions ?? []).includes(pkg.clc_revision)) {
    throw new Reject('clc_revision_unsupported', 'package revision unsupported');
  }
  if (!(policy.supported_clc_revisions ?? []).includes(tr.target_clc_revision)) {
    throw new Reject('clc_revision_unsupported', 'transition revision unsupported');
  }

  if (tr.action === 'root-rotate') checkRootRotation(tr, cert as X509Certificate, policy);

  const op = maybeOp ?? buildManagementOperation(pkg, tr);
  const capability = capabilityOf(op.id);
  const dm = domainMap(declarationOf(policy), capability as string);
  const grants = grantsFor(aic, op.id);
  if (grants.length === 0) throw new Reject('authority_no_grant', 'AIC declares no matching capability');
  const contained = containGrants(grants, policy.root_grants ?? [], dm);
  if (contained.length === 0) throw new Reject('authority_not_contained', 'no grant is inside the root authority');
  const decision = authorizeSetWithDomains(contained, op, dm);
  if (decision.verdict !== 'allow') {
    throw new Reject('authority_not_authorized', 'CLC ' + (decision.reason ?? decision.verdict));
  }

  if (!namespaceUnder(tr.namespace, policy.namespace_prefixes)) {
    throw new Reject('namespace_outside_policy', 'namespace outside policy');
  }
  if (majorOf(pkg.revision) > (policy.max_major ?? 0)) throw new Reject('major_exceeds_limit', 'major exceeds policy');

  checkState(tr, state, pkg.revision, pkg.change_class);

  if (isRevoked(state, tr.from_digest)) throw new Reject('package_revoked', 'from_digest is revoked');
  if (isRevoked(state, result.package_digest)) throw new Reject('package_revoked', 'package digest is revoked');

  checkFreshness(pkg, policy);

  if ((policy.approval_threshold ?? 0) > 0) {
    const have = countApprovals(state, result.package_digest, result.transition_digest);
    if (have < policy.approval_threshold) throw new Reject('approval_insufficient', 'not enough approvals');
  }
}

function declarationOf(policy: any): any {
  if (policy.administration_declaration === undefined || policy.administration_declaration === null) {
    throw new Reject('declaration_invalid', 'administration_declaration is required');
  }
  return parseDeclaration(Buffer.from(JSON.stringify(policy.administration_declaration), 'utf8'));
}

function checkFreshness(pkg: any, policy: any): void {
  const now = parseTime(policy.observed_at ?? '');
  if (now === null) throw new Reject('package_stale', 'policy.observed_at is required');
  let issued: number | null = null;
  if (pkg.issued_at) {
    issued = parseTime(pkg.issued_at);
    if (issued === null) throw new Reject('package_shape', 'bad issued_at');
    if (issued > now + 5 * 60 * 1000) throw new Reject('package_stale', 'issued_at is in the future');
  }
  if (pkg.valid_until) {
    const until = parseTime(pkg.valid_until);
    if (until === null) throw new Reject('package_shape', 'bad valid_until');
    if (issued !== null && until <= issued) throw new Reject('package_shape', 'valid_until is not after issued_at');
    if (now > until) throw new Reject('package_expired', 'valid_until precedes observed_at');
  }
  if ((policy.max_staleness_seconds ?? 0) > 0) {
    if (issued === null) throw new Reject('package_stale', 'issued_at is required');
    if (now - issued > policy.max_staleness_seconds * 1000) {
      throw new Reject('package_stale', 'package is older than the staleness window');
    }
  }
}

// ---------------------------------------------------------------- delegation

function validateDelegation(vector: any): void {
  const policy = JSON.parse(b64d(vector.policy_b64).toString('utf8'));
  const delegation = JSON.parse(b64d(vector.delegation_b64).toString('utf8'));
  for (const key of Object.keys(delegation)) {
    if (!DELEGATION_FIELDS.has(key)) throw new Reject('delegation_not_contained', `unknown member ${key}`);
  }
  if (!PRINCIPAL_RE.test(delegation.grantee ?? '')) throw new Reject('delegation_not_contained', 'bad grantee');
  const parent = delegation.parent ?? {};
  const child = delegation.child ?? {};
  for (const grant of [parent, child]) checkAdministrationGrant(grant);
  const capability = capabilityOf(child.id ?? '');
  if (capability === null) throw new Reject('delegation_not_contained', 'child is not an administration capability');
  if (capability.endsWith('*')) throw new Reject('delegation_not_contained', 'child must not be a wildcard');
  const dm = domainMap(declarationOf(policy), capability);
  if ((policy.root_grants ?? []).length === 0) throw new Reject('authority_not_contained', 'policy configures no root authority');
  let parentOk = false;
  for (const root of policy.root_grants) {
    if (containsWithDomains(root, parent, dm, dm)[0]) {
      parentOk = true;
      break;
    }
  }
  if (!parentOk) throw new Reject('authority_not_contained', 'delegator is outside the root authority');
  if (!containsWithDomains(parent, child, dm, dm)[0]) {
    throw new Reject('delegation_not_contained', 'child is wider than the parent');
  }
}

function checkAdministrationGrant(grant: any): void {
  if (typeof grant !== 'object' || grant === null || Array.isArray(grant)) {
    throw new Reject('delegation_not_contained', 'grant is not an object');
  }
  for (const key of Object.keys(grant)) {
    if (!GRANT_FIELDS.has(key)) throw new Reject('delegation_not_contained', `unknown grant member ${key}`);
  }
  const capability = capabilityOf(grant.id ?? '');
  if (capability === null) throw new Reject('delegation_not_contained', 'grant is not an administration capability');
  if (!ADMIN_CAPABILITIES.has(capability)) {
    throw new Reject('delegation_not_contained', 'grant is not an administration capability');
  }
}

// --------------------------------------------------------------------- main

function render(id: string, kind: string, verdict: string, reason: string, result: Record<string, string>): string {
  const parts = [id, kind, verdict, reason || '-'];
  for (const [label, key] of [
    ['pkg', 'package_digest'],
    ['tr', 'transition_digest'],
    ['op', 'management_operation_digest'],
    ['key', 'publisher_key_id'],
  ] as Array<[string, string]>) {
    const value = result[key];
    if (value) parts.push(`${label}=${value}`);
  }
  return parts.join(' ');
}

function main(argv: string[]): number {
  if (argv.length !== 3) {
    process.stderr.write('usage: probe.ts BUNDLE.json\n');
    return 2;
  }
  const bundle = JSON.parse(readFileSync(argv[2], 'utf8'));
  if (bundle['@version'] !== 'varwof/scheme-admin-crosslang-bundle-v1') {
    process.stderr.write('probe.ts: wrong bundle version\n');
    return 2;
  }
  const lines: string[] = [];
  for (const vector of bundle.vectors) {
    let result: Record<string, string> = {};
    let verdict = 'accept';
    let reason = '';
    try {
      if (vector.kind === 'delegation') validateDelegation(vector);
      else result = confirm(vector);
    } catch (exc) {
      if (!(exc instanceof Reject)) throw exc;
      verdict = 'reject';
      reason = exc.code;
      result = exc.result;
    }
    lines.push(render(vector.id, vector.kind, verdict, reason, result));
  }
  process.stdout.write(lines.join('\n') + '\n');
  return 0;
}

process.exitCode = main(process.argv);
