import { sign, verify, createPublicKey } from 'node:crypto';
import { requireThat, unb64u, b64u } from './core.mjs';

// ISO mdoc CBOR is a separate encoding domain from RRA deterministic CBOR.
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
export function prepareSign1(payload, { certificate, detached = false } = {}) {
  const protectedBytes = encode(new Map([[1, -7]])),
    unprotected = new Map(certificate ? [[33, certificate]] : []);
  return {
    tbs: encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]),
    finish: (signature) => [
      protectedBytes,
      unprotected,
      detached ? null : payload,
      Buffer.from(signature),
    ],
  };
}
export function sign1(payload, key, options) {
  const p = prepareSign1(payload, options);
  return p.finish(sign('sha256', p.tbs, { key, dsaEncoding: 'ieee-p1363' }));
}
export function verify1(value, key, { detached } = {}) {
  const c = value instanceof Tag && value.tag === 18 ? value.value : value;
  requireThat(
    Array.isArray(c) &&
      c.length === 4 &&
      Buffer.isBuffer(c[0]) &&
      c[1] instanceof Map &&
      Buffer.isBuffer(c[3]) &&
      c[3].length === 64,
    'COSE_SIGN1',
  );
  const headers = decode(c[0]);
  requireThat(
    headers instanceof Map &&
      headers.size === 1 &&
      headers.get(1) === -7 &&
      !c[1].has(1) &&
      !c[1].has(2),
    'COSE_ALGORITHM_OR_CRITICAL',
  );
  requireThat(
    (detached !== undefined && c[2] === null) || (detached === undefined && Buffer.isBuffer(c[2])),
    'COSE_PAYLOAD_MODE',
  );
  const payload = detached ?? c[2];
  requireThat(
    key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails.namedCurve === 'prime256v1',
    'COSE_KEY_ALGORITHM',
  );
  requireThat(
    verify(
      'sha256',
      encode(['Signature1', c[0], Buffer.alloc(0), payload]),
      { key, dsaEncoding: 'ieee-p1363' },
      c[3],
    ),
    'COSE_SIGNATURE',
  );
  return { payload, certificate: c[1].get(33) };
}
