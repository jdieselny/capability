#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// Cross-language evidence probe for the capability catalog plane (TypeScript).
//
// Reads a bundle produced by register/catalog TestCrossLanguageVectors (inputs
// only) and prints one evidence line per corpus vector.  Same stewardship,
// second reading of the same artifacts; not an independent implementation.
// The DER/CMS/AIC reader and the CLC-1.19 declared-domain relation are shared
// verbatim with contrib/scheme-admin/probe.ts.
//
// Run: node --experimental-strip-types probe.ts BUNDLE.json

import { createHash, verify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const clcDir = process.env.CLC_TS_DIR ?? new URL('../../../clc-ts/', import.meta.url).pathname;
const clc: any = await import(pathToFileURL(clcDir.endsWith('/') ? clcDir : clcDir + '/').href + 'clc_semantics.ts');
const { canonicalJSON, contains, authorizeSet } = clc;

const AIC_OID = '1.3.6.1.4.1.66257.1.1';
const DIGEST_RE = /^sha256:[A-Za-z0-9_-]{43}$/;
const SCHEME_RE = /^[a-z0-9][a-z0-9_-]*\/[a-z0-9][a-z0-9_.-]*-v[0-9]+$/;
const PRINCIPAL_RE = /^principal:[A-Za-z0-9_.:-]+$/;
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
// ==================================================================== catalog

const CATALOG_VERSION = 'CLC-CAPABILITY-CATALOG-v1';
const DELTA_VERSION = 'CLC-CAPABILITY-CATALOG-DELTA-v1';
const DISCOVERY_VERSION = 'CLC-CATALOG-DISCOVERY-v1';

const NAME_RE = /^[a-z0-9][a-z0-9.-]*(\/[a-z0-9][a-z0-9._-]*)*$/;
const REFERENCE_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;

const CATALOG_FIELDS = new Set([
  '@version', 'domain', 'catalog_id', 'generation', 'issued_at', 'valid_until',
  'previous_digest', 'producer', 'entries',
]);
const ENTRY_FIELDS = new Set([
  'capability', 'provider', 'scheme', 'scheme_declaration_digest', 'operations', 'status',
]);
const OPERATION_FIELDS = new Set(['operation', 'params']);
const STATUS_FIELDS = new Set(['reference', 'checked_at']);
const DELTA_FIELDS = new Set([
  '@version', 'domain', 'catalog_id', 'base_generation', 'target_generation',
  'base_digest', 'target_digest', 'issued_at', 'valid_until', 'producer',
  'add', 'replace', 'remove',
]);
const DISCOVERY_FIELDS = new Set([
  '@version', 'provider', 'catalog_id', 'catalog_digest', 'generation',
  'issued_at', 'valid_until', 'status_reference', 'scheme_declaration_digests',
]);
const POLICY_FIELDS = new Set([
  'domain', 'catalog_id', 'schemes', 'max_staleness_seconds',
  'max_status_staleness_seconds', 'require_status', 'status_values',
  'provider_bindings', 'observed_at',
]);
const SCHEME_POLICY_FIELDS = new Set(['declaration']);
const STATE_FIELDS = new Set(['domain', 'catalog_id', 'generation', 'digest', 'history']);
const HISTORY_FIELDS = new Set(['generation', 'digest']);
const DECLARATION_FIELDS = new Set([
  '@version', 'scheme', 'declaration_id', 'clc_revision', 'digest', 'capabilities', 'constraint_types',
]);
const DECLARATION_CAPABILITY_FIELDS = new Set(['params']);
const DECLARATION_PARAM_FIELDS = new Set(['domain', 'unit', 'optional']);

const VERDICT_MEMBERS = [
  'verdict', 'authorized', 'authorised', 'verified', 'approved', 'allowed', 'trusted', 'accepted',
];

function required(obj: any, keys: string[], code: string): void {
  for (const key of keys) {
    if (!(key in obj)) throw new Reject(code, `missing member ${key}`);
  }
}

function isName(value: any): boolean {
  return typeof value === 'string' && NAME_RE.test(value);
}

function isDigest(value: any): boolean {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function isInt(value: any): boolean {
  return typeof value === 'number' && Number.isInteger(value);
}

// --------------------------------------------------------------- object shapes

function parseCatalog(raw: Buffer): any {
  const cat = parseClosed(raw, CATALOG_FIELDS, 'catalog_shape');
  validateCatalog(cat);
  return cat;
}

function validateCatalog(cat: any): void {
  required(cat, ['@version', 'domain', 'catalog_id', 'generation', 'issued_at', 'valid_until', 'producer', 'entries'], 'catalog_shape');
  if (cat['@version'] !== CATALOG_VERSION) throw new Reject('catalog_shape', '@version');
  if (!isName(cat.domain)) throw new Reject('catalog_shape', 'domain');
  if (!isName(cat.catalog_id)) throw new Reject('catalog_shape', 'catalog_id');
  if (!isInt(cat.generation) || cat.generation < 1) throw new Reject('catalog_shape', 'generation');
  if (typeof cat.producer !== 'string' || !PRINCIPAL_RE.test(cat.producer)) {
    throw new Reject('catalog_shape', 'producer');
  }
  const issued = parseTime(cat.issued_at);
  const until = parseTime(cat.valid_until);
  if (issued === null || until === null) throw new Reject('catalog_shape', 'issued_at/valid_until');
  if (!(until > issued)) throw new Reject('catalog_shape', 'valid_until must be after issued_at');
  const previous = cat.previous_digest || null;
  if (cat.generation === 1) {
    if (previous !== null) throw new Reject('catalog_shape', 'generation 1 must not carry previous_digest');
  } else if (!isDigest(previous)) {
    throw new Reject('catalog_shape', 'previous_digest');
  }
  if (!Array.isArray(cat.entries) || cat.entries.length === 0) {
    throw new Reject('catalog_shape', 'entries');
  }
  const seen = new Set<string>();
  for (const entry of cat.entries) {
    validateEntry(entry);
    if (seen.has(entry.capability)) throw new Reject('catalog_duplicate_entry', entry.capability);
    seen.add(entry.capability);
  }
}

function validateEntry(entry: any): void {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    throw new Reject('catalog_shape', 'entry is not an object');
  }
  for (const key of Object.keys(entry)) {
    if (!ENTRY_FIELDS.has(key)) throw new Reject('catalog_shape', `unknown member ${key}`);
  }
  required(entry, ['capability', 'provider', 'scheme', 'scheme_declaration_digest', 'operations'], 'catalog_shape');
  const scheme = entry.scheme;
  if (typeof scheme !== 'string' || !SCHEME_RE.test(scheme)) throw new Reject('catalog_shape', 'scheme');
  if (typeof entry.capability !== 'string' || !entry.capability.startsWith(scheme + ':') ||
      entry.capability.length === scheme.length + 1) {
    throw new Reject('catalog_shape', 'capability is not inside scheme');
  }
  if (typeof entry.provider !== 'string' || entry.provider.length === 0 || /\s/.test(entry.provider)) {
    throw new Reject('catalog_shape', 'provider');
  }
  if (!isDigest(entry.scheme_declaration_digest)) {
    throw new Reject('catalog_shape', 'scheme_declaration_digest');
  }
  if (!Array.isArray(entry.operations) || entry.operations.length === 0) {
    throw new Reject('catalog_shape', 'operations');
  }
  const names = new Set<string>();
  for (const operation of entry.operations) {
    if (typeof operation !== 'object' || operation === null || Array.isArray(operation)) {
      throw new Reject('catalog_shape', 'operation is not an object');
    }
    for (const key of Object.keys(operation)) {
      if (!OPERATION_FIELDS.has(key)) throw new Reject('catalog_shape', `unknown member ${key}`);
    }
    if (typeof operation.operation !== 'string' || operation.operation.trim() === '') {
      throw new Reject('catalog_shape', 'operation name');
    }
    if (names.has(operation.operation)) throw new Reject('catalog_shape', 'duplicate operation');
    names.add(operation.operation);
    if (operation.params !== undefined && operation.params !== null &&
        (typeof operation.params !== 'object' || Array.isArray(operation.params))) {
      throw new Reject('catalog_shape', 'params is not an object');
    }
  }
  const status = entry.status;
  if (status !== undefined && status !== null) {
    if (typeof status !== 'object' || Array.isArray(status)) throw new Reject('catalog_shape', 'status is not an object');
    for (const key of Object.keys(status)) {
      if (!STATUS_FIELDS.has(key)) throw new Reject('catalog_shape', `unknown member ${key}`);
    }
    required(status, ['reference', 'checked_at'], 'catalog_shape');
    if (typeof status.reference !== 'string' || !REFERENCE_RE.test(status.reference)) {
      throw new Reject('catalog_shape', 'status reference');
    }
    if (parseTime(status.checked_at) === null) throw new Reject('catalog_shape', 'status checked_at');
  }
}

function catalogDigestObject(cat: any): any {
  const obj: any = {
    '@version': cat['@version'],
    domain: cat.domain,
    catalog_id: cat.catalog_id,
    generation: cat.generation,
    issued_at: cat.issued_at,
    valid_until: cat.valid_until,
    producer: cat.producer,
    entries: cat.entries.map((entry: any) => entryDigestObject(entry)),
  };
  if (cat.previous_digest) obj.previous_digest = cat.previous_digest;
  return obj;
}

function entryDigestObject(entry: any): any {
  const operations = entry.operations.map((operation: any) => {
    const op: any = { operation: operation.operation };
    if (operation.params && Object.keys(operation.params).length > 0) op.params = operation.params;
    return op;
  });
  const obj: any = {
    capability: entry.capability,
    provider: entry.provider,
    scheme: entry.scheme,
    scheme_declaration_digest: entry.scheme_declaration_digest,
    operations,
  };
  if (entry.status !== undefined && entry.status !== null) {
    obj.status = { reference: entry.status.reference, checked_at: entry.status.checked_at };
  }
  return obj;
}

function catalogDigest(cat: any): string {
  return canonicalDigest(catalogDigestObject(cat));
}

// ------------------------------------------------------------------- deltas

function parseDelta(raw: Buffer): any {
  const d = parseClosed(raw, DELTA_FIELDS, 'delta_shape');
  validateDelta(d);
  return d;
}

function deltaDigestObject(d: any): any {
  const obj: any = {
    '@version': d['@version'],
    domain: d.domain,
    catalog_id: d.catalog_id,
    base_generation: d.base_generation,
    target_generation: d.target_generation,
    base_digest: d.base_digest,
    target_digest: d.target_digest,
    issued_at: d.issued_at,
    valid_until: d.valid_until,
    producer: d.producer,
  };
  for (const side of ['add', 'replace']) {
    if (Array.isArray(d[side]) && d[side].length > 0) {
      obj[side] = d[side].map((entry: any) => entryDigestObject(entry));
    }
  }
  if (Array.isArray(d.remove) && d.remove.length > 0) obj.remove = d.remove;
  return obj;
}

function deltaDigest(d: any): string {
  return canonicalDigest(deltaDigestObject(d));
}

function validateDelta(d: any): void {
  required(d, ['@version', 'domain', 'catalog_id', 'base_generation', 'target_generation',
    'base_digest', 'target_digest', 'issued_at', 'valid_until', 'producer'], 'delta_shape');
  if (d['@version'] !== DELTA_VERSION) throw new Reject('delta_shape', '@version');
  if (!isName(d.domain) || !isName(d.catalog_id)) throw new Reject('delta_shape', 'domain/catalog_id');
  if (!isInt(d.base_generation) || d.base_generation < 1) throw new Reject('delta_shape', 'base_generation');
  if (!isInt(d.target_generation) || d.target_generation !== d.base_generation + 1) {
    throw new Reject('delta_shape', 'target_generation must be base_generation + 1');
  }
  if (!isDigest(d.base_digest) || !isDigest(d.target_digest)) {
    throw new Reject('delta_shape', 'base_digest/target_digest');
  }
  if (typeof d.producer !== 'string' || !PRINCIPAL_RE.test(d.producer)) throw new Reject('delta_shape', 'producer');
  const issued = parseTime(d.issued_at);
  const until = parseTime(d.valid_until);
  if (issued === null || until === null || !(until > issued)) throw new Reject('delta_shape', 'issued_at/valid_until');

  const add = d.add ?? [];
  const replace = d.replace ?? [];
  const remove = d.remove ?? [];
  for (const [side, value] of [['add', add], ['replace', replace], ['remove', remove]] as Array<[string, any]>) {
    if (!Array.isArray(value)) throw new Reject('delta_shape', `${side} is not an array`);
  }
  if (add.length === 0 && replace.length === 0 && remove.length === 0) {
    throw new Reject('delta_shape', 'delta has no effect');
  }

  const touched = new Map<string, string>();
  const note = (capability: any, side: string): void => {
    if (typeof capability !== 'string' || capability.length === 0) {
      throw new Reject('delta_operation_invalid', `${side} names an empty capability`);
    }
    if (touched.has(capability)) {
      throw new Reject('delta_operation_invalid', `${capability} appears in both ${touched.get(capability)} and ${side}`);
    }
    touched.set(capability, side);
  };
  for (const entry of add) {
    validateEntry(entry);
    note(entry.capability, 'add');
  }
  for (const entry of replace) {
    validateEntry(entry);
    note(entry.capability, 'replace');
  }
  for (const capability of remove) note(capability, 'remove');
}

function applyDelta(vector: any): Record<string, any> {
  const result: Record<string, any> = {};
  const base = parseCatalog(b64d(vector.catalog_b64));
  const d = parseDelta(b64d(vector.delta_b64));

  const baseDigest = catalogDigest(base);
  if (base.domain !== d.domain || base.catalog_id !== d.catalog_id) {
    throw new Reject('delta_base_mismatch', 'delta identity');
  }
  if (base.generation !== d.base_generation) throw new Reject('delta_base_mismatch', 'base generation');
  if (baseDigest !== d.base_digest) throw new Reject('delta_base_mismatch', 'base digest');

  const entries = new Map<string, any>();
  for (const entry of base.entries) entries.set(entry.capability, entry);
  for (const capability of d.remove ?? []) {
    if (!entries.has(capability)) {
      throw new Reject('delta_operation_invalid', `remove names unknown capability ${capability}`);
    }
    entries.delete(capability);
  }
  for (const entry of d.replace ?? []) {
    if (!entries.has(entry.capability)) {
      throw new Reject('delta_operation_invalid', `replace names unknown capability ${entry.capability}`);
    }
    entries.set(entry.capability, entry);
  }
  for (const entry of d.add ?? []) {
    if (entries.has(entry.capability)) {
      throw new Reject('delta_operation_invalid', `add names existing capability ${entry.capability}`);
    }
    entries.set(entry.capability, entry);
  }

  const nextCatalog = {
    '@version': CATALOG_VERSION,
    domain: base.domain,
    catalog_id: base.catalog_id,
    generation: d.target_generation,
    issued_at: d.issued_at,
    valid_until: d.valid_until,
    previous_digest: baseDigest,
    producer: d.producer,
    entries: [...entries.keys()].sort().map((name) => entries.get(name)),
  };
  validateCatalog(nextCatalog);
  const digestValue = catalogDigest(nextCatalog);
  if (digestValue !== d.target_digest) throw new Reject('delta_digest_mismatch', 'target digest');
  result.catalog_digest = digestValue;
  result.generation = nextCatalog.generation;
  return result;
}

// ---------------------------------------------------------------- discovery

function parseDiscovery(raw: Buffer): any {
  let probe: any;
  try {
    probe = JSON.parse(raw.toString('utf8'));
  } catch (exc) {
    throw new Reject('discovery_shape', String(exc));
  }
  if (typeof probe === 'object' && probe !== null && !Array.isArray(probe)) {
    for (const member of VERDICT_MEMBERS) {
      if (member in probe) throw new Reject('discovery_verdict_member', `discovery carries ${member}`);
    }
  }
  const d = parseClosed(raw, DISCOVERY_FIELDS, 'discovery_shape');
  validateDiscovery(d);
  return d;
}

function validateDiscovery(d: any): void {
  required(d, ['@version', 'provider', 'catalog_id', 'catalog_digest', 'generation', 'issued_at', 'valid_until'], 'discovery_shape');
  if (d['@version'] !== DISCOVERY_VERSION) throw new Reject('discovery_shape', '@version');
  if (!isName(d.catalog_id)) throw new Reject('discovery_shape', 'catalog_id');
  if (typeof d.provider !== 'string' || d.provider.length === 0) throw new Reject('discovery_shape', 'provider');
  if (!isDigest(d.catalog_digest)) throw new Reject('discovery_shape', 'catalog_digest');
  if (!isInt(d.generation) || d.generation < 1) throw new Reject('discovery_shape', 'generation');
  const issued = parseTime(d.issued_at);
  const until = parseTime(d.valid_until);
  if (issued === null || until === null || !(until > issued)) throw new Reject('discovery_shape', 'issued_at/valid_until');
  for (const value of d.scheme_declaration_digests ?? []) {
    if (!isDigest(value)) throw new Reject('discovery_shape', 'scheme_declaration_digests');
  }
}

function verifyDiscovery(vector: any): Record<string, any> {
  const d = parseDiscovery(b64d(vector.discovery_b64));
  const cat = parseCatalog(b64d(vector.catalog_b64));
  if (d.catalog_id !== cat.catalog_id) throw new Reject('discovery_shape', 'catalog_id');
  if (d.generation !== cat.generation) throw new Reject('discovery_shape', 'generation');
  const digestValue = catalogDigest(cat);
  if (d.catalog_digest !== digestValue) throw new Reject('catalog_digest_mismatch', 'discovery digest');
  return { catalog_digest: digestValue, generation: cat.generation };
}

// ------------------------------------------------------------------- policy

function parsePolicy(raw: Buffer): any {
  const policy = parseClosed(raw, POLICY_FIELDS, 'catalog_shape');
  validatePolicy(policy);
  return policy;
}

function validatePolicy(policy: any): void {
  required(policy, ['domain', 'catalog_id', 'schemes', 'observed_at'], 'catalog_shape');
  if (!isName(policy.domain)) throw new Reject('catalog_shape', 'policy.domain');
  if (!isName(policy.catalog_id)) throw new Reject('catalog_shape', 'policy.catalog_id');
  const schemes = policy.schemes;
  if (typeof schemes !== 'object' || schemes === null || Array.isArray(schemes) || Object.keys(schemes).length === 0) {
    throw new Reject('catalog_scheme_unsupported', 'policy supports no schemes');
  }
  for (const [name, schemePolicy] of Object.entries(schemes)) {
    if (!SCHEME_RE.test(name)) throw new Reject('catalog_scheme_unsupported', name);
    if (typeof schemePolicy !== 'object' || schemePolicy === null || Array.isArray(schemePolicy)) {
      throw new Reject('catalog_declaration_mismatch', 'scheme policy shape');
    }
    for (const key of Object.keys(schemePolicy)) {
      if (!SCHEME_POLICY_FIELDS.has(key)) throw new Reject('catalog_declaration_mismatch', 'scheme policy shape');
    }
    required(schemePolicy, ['declaration'], 'catalog_declaration_mismatch');
    validateDeclaration((schemePolicy as any).declaration);
  }
  for (const field of ['max_staleness_seconds', 'max_status_staleness_seconds']) {
    const value = policy[field] ?? 0;
    if (!isInt(value) || value < 0) throw new Reject('catalog_shape', `${field} must be >= 0`);
  }
  const statusValues = policy.status_values ?? {};
  if (policy.require_status && Object.keys(statusValues).length === 0) {
    throw new Reject('catalog_status_unavailable', 'policy.require_status requires explicit status_values');
  }
  if (typeof statusValues !== 'object' || statusValues === null || Array.isArray(statusValues)) {
    throw new Reject('catalog_shape', 'status_values must be an object');
  }
  for (const [reference, value] of Object.entries(statusValues)) {
    if (!reference || /\s/.test(reference)) throw new Reject('catalog_shape', 'status_values key');
    if (!['healthy', 'unhealthy', 'degraded', 'unknown'].includes(value as string)) {
      throw new Reject('catalog_shape', 'status_values value');
    }
  }
  const providerBindings = policy.provider_bindings ?? {};
  if (typeof providerBindings !== 'object' || providerBindings === null || Array.isArray(providerBindings)) {
    throw new Reject('catalog_shape', 'provider_bindings must be an object');
  }
  for (const [provider, producer] of Object.entries(providerBindings)) {
    if (!provider || /\s/.test(provider)) throw new Reject('catalog_shape', 'provider_bindings key');
    if (typeof producer !== 'string' || !PRINCIPAL_RE.test(producer)) {
      throw new Reject('catalog_shape', 'provider_bindings value');
    }
  }
  if (parseTime(policy.observed_at) === null) throw new Reject('catalog_stale', 'policy.observed_at');
}

function validateDeclaration(decl: any): void {
  if (typeof decl !== 'object' || decl === null || Array.isArray(decl)) {
    throw new Reject('catalog_declaration_mismatch', 'declaration is not an object');
  }
  for (const key of Object.keys(decl)) {
    if (!DECLARATION_FIELDS.has(key)) throw new Reject('catalog_declaration_mismatch', `unknown member ${key}`);
  }
  required(decl, ['@version', 'scheme', 'declaration_id', 'clc_revision', 'capabilities'], 'catalog_declaration_mismatch');
  if (decl['@version'] !== 'CLC-SCHEME-v1') throw new Reject('catalog_declaration_mismatch', '@version');
  if (!decl.scheme || !decl.declaration_id || !decl.clc_revision) {
    throw new Reject('catalog_declaration_mismatch', 'missing scheme/declaration_id/clc_revision');
  }
  const capabilities = decl.capabilities;
  if (typeof capabilities !== 'object' || capabilities === null || Object.keys(capabilities).length === 0) {
    throw new Reject('catalog_declaration_mismatch', 'no capabilities');
  }
  for (const [capName, capability] of Object.entries(capabilities)) {
    if (typeof capability !== 'object' || capability === null || Array.isArray(capability)) {
      throw new Reject('catalog_declaration_mismatch', `capability ${capName}`);
    }
    for (const key of Object.keys(capability)) {
      if (!DECLARATION_CAPABILITY_FIELDS.has(key)) throw new Reject('catalog_declaration_mismatch', `capability ${capName}`);
    }
    const params = (capability as any).params;
    if (typeof params !== 'object' || params === null || Array.isArray(params)) {
      throw new Reject('catalog_declaration_mismatch', `capability ${capName} params`);
    }
    for (const [paramName, param] of Object.entries(params)) {
      if (typeof param !== 'object' || param === null || Array.isArray(param)) {
        throw new Reject('catalog_declaration_mismatch', `${capName}.${paramName}`);
      }
      for (const key of Object.keys(param)) {
        if (!DECLARATION_PARAM_FIELDS.has(key)) throw new Reject('catalog_declaration_mismatch', `${capName}.${paramName}`);
      }
      const domain = (param as any).domain;
      if (!KNOWN_DOMAINS.has(domain)) throw new Reject('catalog_declaration_mismatch', `unsupported domain ${domain}`);
      if (domain === 'quantity' && !(param as any).unit) {
        throw new Reject('catalog_declaration_mismatch', 'quantity without unit');
      }
      if (domain !== 'quantity' && (param as any).unit) {
        throw new Reject('catalog_declaration_mismatch', 'unit outside quantity');
      }
    }
  }
  const pinned = decl.digest;
  if (pinned !== undefined && pinned !== declarationDigest(decl)) {
    throw new Reject('catalog_declaration_mismatch', 'declaration digest');
  }
}

function declarationDigest(decl: any): string {
  const obj: any = {};
  for (const [key, value] of Object.entries(decl)) {
    if (key !== 'digest') obj[key] = value;
  }
  return canonicalDigest(obj);
}

function policyDeclaration(policy: any, scheme: string): [any, string] {
  const schemePolicy = policy.schemes[scheme];
  if (schemePolicy === undefined) throw new Reject('catalog_scheme_unsupported', `scheme ${scheme} is not supported`);
  const decl = schemePolicy.declaration;
  return [decl, declarationDigest(decl)];
}

// -------------------------------------------------------------------- state

function parseState(raw: Buffer): any {
  const state = parseClosed(raw, STATE_FIELDS, 'catalog_shape');
  required(state, ['generation'], 'catalog_shape');
  if (!isInt(state.generation) || state.generation < 0) throw new Reject('catalog_shape', 'state generation');
  for (const record of state.history ?? []) {
    if (typeof record !== 'object' || record === null) throw new Reject('catalog_shape', 'history record');
    for (const key of Object.keys(record)) {
      if (!HISTORY_FIELDS.has(key)) throw new Reject('catalog_shape', 'history record');
    }
    required(record, ['generation', 'digest'], 'catalog_shape');
    if (!isInt(record.generation)) throw new Reject('catalog_shape', 'history generation');
  }
  return state;
}

function digestAt(state: any, generation: number): string | null {
  if (state.generation === generation) return state.digest ?? null;
  for (const record of state.history ?? []) {
    if (record.generation === generation) return record.digest ?? null;
  }
  return null;
}

// ------------------------------------------------------------- verification

function rootsOf(vector: any): X509Certificate[] {
  return (vector.roots_b64 ?? []).map((value: string) => new X509Certificate(b64d(value)));
}

function signerOf(vector: any, payload: Buffer): X509Certificate | null {
  if (!vector.signature_b64) throw new Reject('signature_missing', 'no detached signature');
  try {
    return verifyDetached(b64d(vector.signature_b64), payload);
  } catch (exc) {
    throw new Reject('signature_invalid', String(exc));
  }
}

function verifySigner(cat: any, cert: X509Certificate | null, roots: X509Certificate[]): any {
  if (cert === null) throw new Reject('signature_missing', 'signer certificate is required');
  if (roots.length === 0) throw new Reject('signature_chain', 'no trust roots configured');
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

  const producer = cat.producer;
  const want = producer.startsWith('principal:') ? producer.slice('principal:'.length) : producer;
  if (want !== aic.identifier && want !== `${aic.realm}:${aic.identifier}`) {
    throw new Reject('publisher_mismatch', 'producer does not match the AIC principal');
  }
  const keyHash: Buffer = aic.keyHash;
  if (keyHash.length === 0 || keyHash.every((value: number) => value === 0)) {
    throw new Reject('publisher_key_binding', 'no principal key hash');
  }
  const wantHash = createHash('sha256').update(spkiOf(cert)).digest();
  if (!keyHash.equals(wantHash)) throw new Reject('publisher_key_binding', 'key hash does not match');
  return aic;
}

function verifySnapshot(vector: any, result: Record<string, any>): Record<string, any> {
  const cat = parseCatalog(b64d(vector.catalog_b64));
  const digestValue = catalogDigest(cat);
  result.catalog_digest = digestValue;
  result.generation = cat.generation;

  // Match catalog.VerifySigned's evidence order: the catalogue digest and
  // detached-signature signer are recorded before deployer policy validation.
  // A policy refusal must therefore not erase facts already established about
  // the signed artifact.
  const cert = signerOf(vector, b64d(vector.catalog_b64));
  if (cert !== null) result.key = digest(spkiOf(cert));

  const policy = parsePolicy(b64d(vector.policy_b64));
  const state = parseState(b64d(vector.state_b64));

  if (cat.domain !== policy.domain) throw new Reject('catalog_identity_mismatch', 'catalog domain');
  if (cat.catalog_id !== policy.catalog_id) throw new Reject('catalog_identity_mismatch', 'catalog_id');

  const aic = verifySigner(cat, cert, rootsOf(vector));

  for (const entry of cat.entries) {
    const [, pinned] = policyDeclaration(policy, entry.scheme);
    if (entry.scheme_declaration_digest !== pinned) {
      throw new Reject('catalog_declaration_mismatch', entry.capability);
    }
  }

  checkGeneration(cat, state, digestValue);
  checkFreshness(cat, policy);
  checkStatus(cat, policy);
  checkAuthority(cat, policy, aic);
  return result;
}

function checkGeneration(cat: any, state: any, digestValue: string): void {
  if (state.domain && state.domain !== cat.domain) throw new Reject('catalog_identity_mismatch', 'state domain');
  if (state.catalog_id && state.catalog_id !== cat.catalog_id) {
    throw new Reject('catalog_identity_mismatch', 'state catalog_id');
  }
  const accepted = state.generation;
  if (accepted === 0) {
    if (cat.generation !== 1) {
      throw new Reject('catalog_bootstrap_required', `no accepted generation; catalog is generation ${cat.generation}`);
    }
    return;
  }
  const recorded = digestAt(state, cat.generation);
  if (recorded && recorded !== digestValue) {
    throw new Reject('catalog_generation_fork', 'generation already holds another digest');
  }
  if (cat.generation < accepted) throw new Reject('catalog_generation_rollback', 'older than the accepted generation');
  if (cat.generation === accepted) {
    if (digestValue !== (state.digest ?? '')) {
      throw new Reject('catalog_generation_fork', 'same generation, different digest');
    }
    return;
  }
  if (cat.generation !== accepted + 1) throw new Reject('catalog_generation_rollback', 'generation gap');
  if ((cat.previous_digest ?? '') !== (state.digest ?? '')) {
    throw new Reject('catalog_previous_digest_mismatch', 'previous_digest');
  }
}

function checkFreshness(cat: any, policy: any): void {
  const now = parseTime(policy.observed_at);
  const until = parseTime(cat.valid_until);
  if (now === null || until === null) throw new Reject('catalog_shape', 'freshness');
  if (now > until) throw new Reject('catalog_expired', 'valid_until precedes observed_at');
  const window = policy.max_staleness_seconds ?? 0;
  if (window > 0) {
    const issued = parseTime(cat.issued_at);
    if (issued === null) throw new Reject('catalog_shape', 'issued_at');
    if (now - issued > window * 1000) throw new Reject('catalog_stale', 'issued_at is older than the policy window');
  }
}

function checkStatus(cat: any, policy: any): void {
  const now = parseTime(policy.observed_at);
  if (now === null) throw new Reject('catalog_stale', 'policy.observed_at');
  const window = policy.max_status_staleness_seconds ?? 0;
  const require = Boolean(policy.require_status);
  for (const entry of cat.entries) {
    const status = entry.status;
    if (status === undefined || status === null) {
      if (require) throw new Reject('catalog_status_unavailable', entry.capability);
      continue;
    }
    const checked = parseTime(status.checked_at);
    if (checked === null) throw new Reject('catalog_shape', 'status checked_at');
    if (checked > now) throw new Reject('catalog_status_stale', entry.capability);
    if (window > 0 && now - checked > window * 1000) throw new Reject('catalog_status_stale', entry.capability);
    if (require) {
      const value = (policy.status_values ?? {})[status.reference];
      if (value === undefined) throw new Reject('catalog_status_unavailable', entry.capability);
      if (value !== 'healthy') throw new Reject('catalog_status_unavailable', entry.capability);
    }
  }
}

function grantsFor(aic: any, fullId: string): any[] {
  const grants: any[] = [];
  for (const capability of aic.capabilities) {
    if (capability.fullId !== fullId) continue;
    const grant: any = { id: fullId };
    if (capability.params) grant.params = capability.params;
    grants.push(grant);
  }
  return grants;
}

function capabilityOf(entry: any): string {
  return entry.capability.slice(entry.scheme.length + 1);
}

function checkAuthority(cat: any, policy: any, aic: any): void {
  const bindings = policy.provider_bindings ?? {};
  if (Object.keys(bindings).length > 0) {
    for (const entry of cat.entries) {
      const producer = bindings[entry.provider];
      if (producer === undefined || producer !== cat.producer) {
        throw new Reject('catalog_provider_mismatch', entry.capability);
      }
    }
  }
  for (const entry of cat.entries) {
    const grants = grantsFor(aic, entry.capability);
    if (grants.length === 0) {
      throw new Reject('catalog_entry_outside_authority', `signer holds no grant for ${entry.capability}`);
    }
    const [declaration] = policyDeclaration(policy, entry.scheme);
    const dm = domainMap(declaration, capabilityOf(entry));
    for (const operation of entry.operations) {
      const child = { id: entry.capability, params: operation.params ?? {} };
      let covered = false;
      for (const grant of grants) {
        if (containsWithDomains(grant, child, dm, dm)[0]) {
          covered = true;
          break;
        }
      }
      if (!covered) {
        throw new Reject('catalog_entry_outside_authority',
          `entry ${entry.capability} operation ${operation.operation}`);
      }
    }
  }
}

// ---------------------------------------------------------------------- main

function render(id: string, kind: string, verdict: string, reason: string, result: Record<string, any>): string {
  const parts = [id, kind, verdict, reason || '-'];
  if (result.catalog_digest) parts.push('cat=' + result.catalog_digest);
  if (result.key) parts.push('key=' + result.key);
  if (result.generation) parts.push(`gen=${result.generation}`);
  return parts.join(' ');
}

function main(argv: string[]): number {
  if (argv.length !== 3) {
    process.stderr.write('usage: probe.ts BUNDLE.json\n');
    return 2;
  }
  const bundle = JSON.parse(readFileSync(argv[2], 'utf8'));
  if (bundle['@version'] !== 'varwof/catalog-crosslang-bundle-v1') {
    process.stderr.write('probe.ts: wrong bundle version\n');
    return 2;
  }
  const lines: string[] = [];
  for (const vector of bundle.vectors) {
    const result: Record<string, any> = {};
    let verdict = 'accept';
    let reason = '';
    try {
      if (vector.kind === 'delta') Object.assign(result, applyDelta(vector));
      else if (vector.kind === 'discovery') Object.assign(result, verifyDiscovery(vector));
      else verifySnapshot(vector, result);
    } catch (exc) {
      if (!(exc instanceof Reject)) throw exc;
      verdict = 'reject';
      reason = exc.code;
    }
    lines.push(render(vector.id, vector.kind, verdict, reason, result));
  }
  process.stdout.write(lines.join('\n') + '\n');
  return 0;
}

process.exitCode = main(process.argv);
