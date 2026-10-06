import * as crypto from 'node:crypto';

export class ProtocolError extends Error {
  constructor(code, detail = code) {
    super(detail);
    this.name = 'ProtocolError';
    this.code = code;
  }
}
export function requireThat(condition, code) {
  if (!condition) throw new ProtocolError(code);
}
export const bytes = (value) => Buffer.from(value);
export const random = (size = 32) => crypto.randomBytes(size);
export const sha256 = (value) => crypto.createHash('sha256').update(value).digest();
export const sha512 = (value) => crypto.createHash('sha512').update(value).digest();
export const b64u = (value) => Buffer.from(value).toString('base64url');
export function unb64u(value) {
  requireThat(typeof value === 'string' && /^[A-Za-z0-9_-]*$/.test(value), 'BAD_BASE64URL');
  const result = Buffer.from(value, 'base64url');
  requireThat(b64u(result) === value, 'NONCANONICAL_BASE64URL');
  return result;
}
export const equal = (a, b) =>
  Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && crypto.timingSafeEqual(a, b);
export const now = () => Math.floor(Date.now() / 1000);
export function fields(value, required, optional = []) {
  requireThat(value !== null && typeof value === 'object' && !Array.isArray(value), 'EXPECTED_MAP');
  requireThat(
    required.every((k) => Object.hasOwn(value, k)),
    'MISSING_FIELD',
  );
  requireThat(
    Object.keys(value).every((k) => [...required, ...optional].includes(k)),
    'UNKNOWN_FIELD',
  );
  return value;
}

// RFC 8949 section 4.2.1: encoded-key bytewise order, NOT length-first order.
function head(major, n) {
  n = BigInt(n);
  requireThat(n >= 0n && n <= 0xffffffffffffffffn, 'INTEGER_RANGE');
  if (n < 24n) return Buffer.from([(major << 5) | Number(n)]);
  const len = n <= 255n ? 1 : n <= 65535n ? 2 : n <= 0xffffffffn ? 4 : 8;
  const out = Buffer.alloc(1 + len);
  out[0] = (major << 5) | { 1: 24, 2: 25, 4: 26, 8: 27 }[len];
  for (let i = len; i > 0; i--) {
    out[i] = Number(n & 255n);
    n >>= 8n;
  }
  return out;
}
export function dcbor(value, depth = 0) {
  requireThat(depth <= 32, 'DEPTH_LIMIT');
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === 'number') requireThat(Number.isSafeInteger(value), 'NONINTEGER');
  if (typeof value === 'number' || typeof value === 'bigint') {
    const n = BigInt(value);
    return n >= 0n ? head(0, n) : head(1, -1n - n);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array)
    return Buffer.concat([head(2, value.length), value]);
  if (typeof value === 'string') {
    requireThat(
      value === value.normalize('NFC') &&
        !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value),
      'NONCANONICAL_TEXT',
    );
    const b = Buffer.from(value);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Array.isArray(value))
    return Buffer.concat([head(4, value.length), ...value.map((v) => dcbor(v, depth + 1))]);
  requireThat(
    (value && Object.getPrototypeOf(value) === Object.prototype) ||
      (value && Object.getPrototypeOf(value) === null),
    'UNSUPPORTED_TYPE',
  );
  const entries = Object.entries(value)
    .map(([k, v]) => {
      requireThat(/^[\x20-\x7E]+$/.test(k), 'NONASCII_KEY');
      return [dcbor(k), dcbor(v, depth + 1)];
    })
    .sort((a, b) => Buffer.compare(a[0], b[0]));
  return Buffer.concat([head(5, entries.length), ...entries.flat()]);
}
export function decodeCBOR(input, { maxBytes = 16 * 1024 * 1024, maxItems = 100000 } = {}) {
  const b = bytes(input);
  requireThat(b.length <= maxBytes, 'SIZE_LIMIT');
  let p = 0,
    items = 0;
  function read(depth) {
    requireThat(depth <= 32 && ++items <= maxItems && p < b.length, 'CBOR_LIMIT_OR_TRUNCATION');
    const h = b[p++],
      major = h >> 5,
      ai = h & 31;
    if (major === 7) {
      requireThat([20, 21, 22].includes(ai), 'CBOR_SIMPLE');
      return ai === 22 ? null : ai === 21;
    }
    requireThat(major < 6 && ai < 28, 'CBOR_TAG_OR_INDEFINITE');
    let n = BigInt(ai);
    if (ai >= 24) {
      const width = [1, 2, 4, 8][ai - 24];
      requireThat(p + width <= b.length, 'CBOR_TRUNCATED');
      n = 0n;
      for (let i = 0; i < width; i++) n = (n << 8n) | BigInt(b[p++]);
      requireThat(n >= [24n, 256n, 65536n, 4294967296n][ai - 24], 'CBOR_NONMINIMAL');
    }
    if (major < 2) {
      const v = major === 0 ? n : -1n - n;
      return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(v)
        : v;
    }
    requireThat(n <= BigInt(maxBytes), 'CBOR_LENGTH_LIMIT');
    const size = Number(n);
    if (major === 2 || major === 3) {
      requireThat(p + size <= b.length, 'CBOR_TRUNCATED');
      const v = b.subarray(p, (p += size));
      return major === 2 ? Buffer.from(v) : new TextDecoder('utf-8', { fatal: true }).decode(v);
    }
    if (major === 4) {
      requireThat(size <= maxItems - items && size <= b.length - p, 'CBOR_ITEM_BUDGET');
      return Array.from({ length: size }, () => read(depth + 1));
    }
    requireThat(
      size <= Math.floor((maxItems - items) / 2) && size <= Math.floor((b.length - p) / 2),
      'CBOR_ITEM_BUDGET',
    );
    const out = Object.create(null);
    let previous;
    for (let i = 0; i < size; i++) {
      const start = p,
        key = read(depth + 1),
        encoded = b.subarray(start, p);
      requireThat(
        typeof key === 'string' &&
          !Object.hasOwn(out, key) &&
          (!previous || Buffer.compare(previous, encoded) < 0),
        'CBOR_MAP_ORDER_OR_DUPLICATE',
      );
      previous = encoded;
      out[key] = read(depth + 1);
    }
    return out;
  }
  const result = read(0);
  requireThat(p === b.length && equal(dcbor(result), b), 'NONCANONICAL_CBOR');
  return result;
}
export const D = (label, value) => dcbor(['CertConcord', 2, label, value]);
export const H = (label, value) => sha512(D(label, value));

export const der = (tag, value) => {
  value = bytes(value);
  let length;
  if (value.length < 128) length = Buffer.from([value.length]);
  else {
    let hex = value.length.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const l = Buffer.from(hex, 'hex');
    length = Buffer.concat([Buffer.from([128 | l.length]), l]);
  }
  return Buffer.concat([Buffer.from([tag]), length, value]);
};
export const seq = (...items) => der(0x30, Buffer.concat(items));
export const set = (...items) => der(0x31, Buffer.concat([...items].sort(Buffer.compare)));
export const octet = (value) => der(4, value);
export const bit = (value) => der(3, Buffer.concat([Buffer.from([0]), value]));
export function integer(value) {
  let n = BigInt(value);
  requireThat(n >= 0n, 'NEGATIVE_INTEGER');
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  let b = Buffer.from(h, 'hex');
  if (b[0] & 128) b = Buffer.concat([Buffer.from([0]), b]);
  return der(2, b);
}
export function base128(n) {
  n = BigInt(n);
  requireThat(n >= 0n, 'NEGATIVE_ARC');
  const a = [Number(n & 127n)];
  while ((n >>= 7n) > 0n) a.unshift(Number(n & 127n) | 128);
  return Buffer.from(a);
}
export function oid(value, relative = false) {
  const a = value.split('.').map(BigInt);
  requireThat(a.length >= (relative ? 1 : 2) && a.every((n) => n >= 0n), 'BAD_OID');
  if (!relative) {
    requireThat(a[0] <= 2n && (a[0] === 2n || a[1] < 40n), 'BAD_OID');
    a.splice(0, 2, a[0] * 40n + a[1]);
  }
  return der(relative ? 13 : 6, Buffer.concat(a.map(base128)));
}
export function parseDER(input) {
  const b = bytes(input);
  requireThat(b.length <= 16 * 1024 * 1024, 'SIZE_LIMIT');
  let p = 0,
    count = 0;
  function read(end, depth) {
    requireThat(depth <= 32 && ++count <= 100000 && p + 2 <= end, 'DER_LIMIT_OR_TRUNCATION');
    const start = p,
      tag = b[p++];
    requireThat((tag & 31) !== 31, 'DER_HIGH_TAG');
    let n = b[p++];
    if (n & 128) {
      const w = n & 127;
      requireThat(w > 0 && w <= 4 && p + w <= end && b[p] !== 0, 'DER_LENGTH');
      n = 0;
      for (let i = 0; i < w; i++) n = n * 256 + b[p++];
      requireThat(n >= 128, 'DER_NONMINIMAL');
    }
    const body = p,
      stop = p + n;
    requireThat(stop <= end, 'DER_TRUNCATED');
    let children;
    if (tag & 32) {
      children = [];
      while (p < stop) children.push(read(stop, depth + 1));
    } else p = stop;
    const value = b.subarray(body, stop);
    if (tag === 2) {
      requireThat(
        value.length > 0 &&
          !(
            value.length > 1 &&
            ((value[0] === 0 && !(value[1] & 128)) || (value[0] === 255 && value[1] & 128))
          ),
        'DER_INTEGER',
      );
    }
    if (tag === 0x31)
      for (let i = 1; i < children.length; i++)
        requireThat(Buffer.compare(children[i - 1].raw, children[i].raw) <= 0, 'DER_SET_ORDER');
    return { tag, value, children, raw: b.subarray(start, stop) };
  }
  const out = read(b.length, 0);
  requireThat(p === b.length, 'DER_TRAILING');
  return out;
}
export function oidText(node) {
  requireThat([6, 13].includes(node.tag), 'EXPECTED_OID');
  const a = [];
  let n = 0n,
    open = false;
  for (const v of node.value) {
    requireThat(!(n === 0n && v === 128 && !open), 'OID_NONMINIMAL');
    n = (n << 7n) | BigInt(v & 127);
    open = !!(v & 128);
    if (!open) {
      a.push(n);
      n = 0n;
    }
  }
  requireThat(!open && a.length > 0, 'BAD_OID');
  if (node.tag === 6) {
    const first = a.shift();
    a.unshift(
      first < 40n ? 0n : first < 80n ? 1n : 2n,
      first < 40n ? first : first < 80n ? first - 40n : first - 80n,
    );
  }
  return a.join('.');
}
export const intValue = (node) => {
  requireThat(node.tag === 2 && !(node.value[0] & 128), 'EXPECTED_UINT');
  let n = 0n;
  for (const v of node.value) n = (n << 8n) | BigInt(v);
  return n;
};
export const ALG = Object.freeze({
  'ml-dsa-65': { oid: '2.16.840.1.101.3.4.3.18', hash: null, signatureLength: 3309 },
  'ml-dsa-87': { oid: '2.16.840.1.101.3.4.3.19', hash: null, signatureLength: 4627 },
  ec: { oid: '1.2.840.10045.4.3.2', hash: 'sha256' },
  ed25519: { oid: '1.3.101.112', hash: null },
  'ml-kem-768': { oid: '2.16.840.1.101.3.4.4.2' },
  'ml-kem-1024': { oid: '2.16.840.1.101.3.4.4.3' },
});
export function generate(algorithm = 'ml-dsa-65') {
  requireThat(Object.hasOwn(ALG, algorithm), 'UNSUPPORTED_ALGORITHM');
  return crypto.generateKeyPairSync(algorithm, algorithm === 'ec' ? { namedCurve: 'P-256' } : {});
}
export const spki = (publicKey) => publicKey.export({ type: 'spki', format: 'der' });
export const keyID = (publicKey) => sha512(spki(publicKey));
export function sign(data, key) {
  const a = ALG[key.asymmetricKeyType];
  requireThat(a && Object.hasOwn(a, 'hash'), 'NOT_SIGNING_KEY');
  return crypto.sign(a.hash, data, key);
}
export function verify(data, signature, key) {
  const a = ALG[key.asymmetricKeyType];
  requireThat(a && Object.hasOwn(a, 'hash'), 'NOT_SIGNING_KEY');
  return crypto.verify(a.hash, data, key, signature);
}
export const hkdf = (secret, salt, info, len = 32) =>
  Buffer.from(crypto.hkdfSync('sha256', secret, salt, info, len));
export const mac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
export function seal(key, plaintext, aad = Buffer.alloc(0), nonce = random(12)) {
  requireThat([16, 32].includes(key.length) && nonce.length === 12, 'AEAD_PARAMETERS');
  const c = crypto.createCipheriv(`aes-${key.length * 8}-gcm`, key, nonce);
  c.setAAD(aad);
  const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
  return { nonce, ciphertext, tag: c.getAuthTag() };
}
export function open(key, value, aad = Buffer.alloc(0)) {
  requireThat(
    [16, 32].includes(key.length) && value.nonce.length === 12 && value.tag.length === 16,
    'AEAD_PARAMETERS',
  );
  const c = crypto.createDecipheriv(`aes-${key.length * 8}-gcm`, key, value.nonce);
  c.setAAD(aad);
  c.setAuthTag(value.tag);
  let p;
  try {
    p = c.update(value.ciphertext);
    const tail = c.final();
    return Buffer.concat([p, tail]);
  } catch {
    p?.fill(0);
    throw new ProtocolError('AEAD_AUTHENTICATION');
  }
}
export function wrapAES(key, plaintext, padded = false) {
  requireThat(
    key.length === 32 &&
      plaintext.length > 0 &&
      (padded || (plaintext.length >= 16 && plaintext.length % 8 === 0)),
    'KW_PARAMETERS',
  );
  const iv = padded ? Buffer.from('a65959a6', 'hex') : Buffer.alloc(8, 0xa6);
  const c = crypto.createCipheriv(padded ? 'id-aes256-wrap-pad' : 'id-aes256-wrap', key, iv);
  return Buffer.concat([c.update(plaintext), c.final()]);
}
export function unwrapAES(key, ciphertext, padded = false) {
  requireThat(
    key.length === 32 && ciphertext.length >= 16 && ciphertext.length % 8 === 0,
    'KW_PARAMETERS',
  );
  try {
    const c = crypto.createDecipheriv(
      padded ? 'id-aes256-wrap-pad' : 'id-aes256-wrap',
      key,
      padded ? Buffer.from('a65959a6', 'hex') : Buffer.alloc(8, 0xa6),
    );
    return Buffer.concat([c.update(ciphertext), c.final()]);
  } catch {
    throw new ProtocolError('KW_AUTHENTICATION');
  }
}
export const encapsulate = (publicKey) => crypto.encapsulate(publicKey);
export const decapsulate = (privateKey, ciphertext) => crypto.decapsulate(privateKey, ciphertext);
export const publicFromDER = (value) =>
  crypto.createPublicKey({ key: value, type: 'spki', format: 'der' });
