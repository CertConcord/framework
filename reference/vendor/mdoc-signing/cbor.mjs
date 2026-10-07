import { createPublicKey } from 'node:crypto';
import { requireThat } from './errors.mjs';
const b64u = bytes => Buffer.from(bytes).toString('base64url');
const unb64u = value => {
  requireThat(typeof value === 'string' && /^[A-Za-z0-9_-]*$/.test(value), 'COSE_BASE64URL');
  const bytes = Buffer.from(value, 'base64url');
  requireThat(b64u(bytes) === value, 'COSE_BASE64URL');
  return bytes;
};

// Bounded reference codec for the selected mdoc CBOR profile.
// Extracted from CertConcord; see NOTICE. No application runtime dependencies.
export class Tag {
  constructor(tag, value) {
    this.tag = tag;
    this.value = value;
  }
}
export const embedded = (value) => new Tag(24, encode(value));
function head(m, v) {
  let n = BigInt(v);
  requireThat(n >= 0n && n <= 0xffffffffffffffffn, 'CBOR_RANGE');
  if (n < 24n) return Buffer.from([m * 32 + Number(n)]);
  const l = n <= 255n ? 1 : n <= 65535n ? 2 : n <= 0xffffffffn ? 4 : 8,
    b = Buffer.alloc(l + 1);
  b[0] = m * 32 + { 1: 24, 2: 25, 4: 26, 8: 27 }[l];
  for (let i = l; i; i--) {
    b[i] = Number(n & 255n);
    n >>= 8n;
  }
  return b;
}
export function encode(v, depth = 0) {
  requireThat(depth < 32, 'CBOR_DEPTH');
  const e = (x) => encode(x, depth + 1);
  if (v === null) return Buffer.from([246]);
  if (typeof v === 'boolean') return Buffer.from([v ? 245 : 244]);
  if (typeof v === 'number') requireThat(Number.isSafeInteger(v), 'CBOR_INTEGER');
  if (typeof v === 'number' || typeof v === 'bigint')
    return BigInt(v) >= 0n ? head(0, v) : head(1, -1n - BigInt(v));
  if (v instanceof Tag) return Buffer.concat([head(6, v.tag), e(v.value)]);
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === 'string') {
    const b = Buffer.from(v);
    requireThat(new TextDecoder('utf-8', { fatal: true }).decode(b) === v, 'CBOR_TEXT');
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(e)]);
  requireThat(
    v instanceof Map || (v && [Object.prototype, null].includes(Object.getPrototypeOf(v))),
    'CBOR_TYPE',
  );
  const entries = [...(v instanceof Map ? v.entries() : Object.entries(v))]
    .map(([k, x]) => [e(k), e(x)])
    .sort((a, b) => Buffer.compare(a[0], b[0]));
  return Buffer.concat([head(5, entries.length), ...entries.flat()]);
}
export function decode(
  input,
  { maxBytes = 8 * 1024 * 1024, maxItems = 100000, allowTrailing = false } = {},
) {
  const b = Buffer.from(input);
  requireThat(b.length <= maxBytes, 'CBOR_SIZE');
  let p = 0,
    items = 0;
  function read(depth) {
    requireThat(depth < 32 && ++items <= maxItems && p < b.length, 'CBOR_LIMIT');
    const h = b[p++],
      m = h >> 5,
      ai = h & 31;
    requireThat(ai < 28, 'CBOR_INDEFINITE');
    if (m === 7) {
      requireThat([20, 21, 22].includes(ai), 'CBOR_SIMPLE');
      return ai === 22 ? null : ai === 21;
    }
    let n = BigInt(ai);
    if (ai >= 24) {
      const l = [1, 2, 4, 8][ai - 24];
      requireThat(p + l <= b.length, 'CBOR_TRUNCATED');
      n = 0n;
      for (let i = 0; i < l; i++) n = n * 256n + BigInt(b[p++]);
      requireThat(n >= [24n, 256n, 65536n, 4294967296n][ai - 24], 'CBOR_NONMINIMAL');
    }
    if (m < 2) {
      const v = m === 0 ? n : -1n - n;
      return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(v)
        : v;
    }
    if (m === 6) {
      requireThat(n === 0n || n === 18n || n === 24n, 'CBOR_TAG');
      return new Tag(Number(n), read(depth + 1));
    }
    requireThat(n <= BigInt(maxBytes), 'CBOR_LENGTH');
    const l = Number(n);
    if (m === 2 || m === 3) {
      requireThat(p + l <= b.length, 'CBOR_TRUNCATED');
      const v = b.subarray(p, (p += l));
      return m === 2 ? Buffer.from(v) : new TextDecoder('utf-8', { fatal: true }).decode(v);
    }
    if (m === 4) {
      requireThat(l <= maxItems - items && l <= b.length - p, 'CBOR_ITEM_BUDGET');
      return Array.from({ length: l }, () => read(depth + 1));
    }
    requireThat(m === 5, 'CBOR_MAJOR');
    requireThat(
      l <= Math.floor((maxItems - items) / 2) && l <= Math.floor((b.length - p) / 2),
      'CBOR_ITEM_BUDGET',
    );
    const map = new Map(),
      seen = new Set();
    for (let i = 0; i < l; i++) {
      const k = read(depth + 1);
      requireThat(typeof k === 'string' || Number.isSafeInteger(k), 'CBOR_MAP_KEY');
      const id = typeof k + ':' + k;
      requireThat(!seen.has(id), 'CBOR_DUPLICATE');
      seen.add(id);
      map.set(k, read(depth + 1));
    }
    return map;
  }
  const result = read(0);
  requireThat(allowTrailing || p === b.length, 'CBOR_TRAILING');
  return allowTrailing ? { value: result, bytesRead: p } : result;
}
export function get(map, key) {
  requireThat(map instanceof Map && map.has(key), 'CBOR_FIELD_' + key);
  return map.get(key);
}
export function unembed(value) {
  requireThat(
    value instanceof Tag && value.tag === 24 && Buffer.isBuffer(value.value),
    'CBOR_EMBEDDED',
  );
  return decode(value.value);
}
export function coseKey(jwk) {
  requireThat(jwk.kty === 'EC' && jwk.crv === 'P-256' && !jwk.d, 'COSE_KEY');
  const x = unb64u(jwk.x),
    y = unb64u(jwk.y);
  requireThat(x.length === 32 && y.length === 32, 'COSE_POINT');
  return new Map([
    [1, 2],
    [-1, 1],
    [-2, x],
    [-3, y],
  ]);
}
export function coseJWK(key) {
  requireThat(get(key, 1) === 2 && get(key, -1) === 1 && !key.has(-4), 'COSE_KEY');
  const jwk = { kty: 'EC', crv: 'P-256', x: b64u(get(key, -2)), y: b64u(get(key, -3)) };
  coseKey(jwk);
  createPublicKey({ key: jwk, format: 'jwk' });
  return jwk;
}
