import {
  requireThat,
  sha256,
  equal,
  bytes,
  seq,
  octet,
  parseDER,
  oid,
  oidText,
  integer,
  sign,
  verify,
  b64u,
  now,
  sha512,
  H,
} from './core.mjs';
import {
  OID,
  RRA,
  profiles,
  algID,
  anchorName,
  tbsCertificate,
  certificateFromTBS,
  parseCertificate,
  validateKeyUsage,
} from './pki.mjs';
import { IndexedMerkleLog } from './storage/merkle.mjs';

export function uint(value, width) {
  let n = BigInt(value);
  requireThat(n >= 0n && n < 1n << BigInt(width * 8), 'TLS_UINT_RANGE');
  const b = Buffer.alloc(width);
  for (let i = width - 1; i >= 0; i--) {
    b[i] = Number(n & 255n);
    n >>= 8n;
  }
  return b;
}
export const vector = (b, width) => Buffer.concat([uint(b.length, width), b]);
export function validSubtree(start, end) {
  start = BigInt(start);
  end = BigInt(end);
  if (start < 0n || end < start || end > 0xffffffffffffffffn) return false;
  let ceil = 1n;
  while (ceil < end - start) ceil <<= 1n;
  return start % ceil === 0n;
}
export const leafHash = (entry) => sha256(Buffer.concat([Buffer.from([0]), entry]));
export const nodeHash = (left, right) => sha256(Buffer.concat([Buffer.from([1]), left, right]));
const split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
export function treeHash(entries) {
  if (!entries.length) return sha256(Buffer.alloc(0));
  if (entries.length === 1) return leafHash(entries[0]);
  const k = split(entries.length);
  return nodeHash(treeHash(entries.slice(0, k)), treeHash(entries.slice(k)));
}
export function inclusionProof(entries, index, start = 0, end = entries.length) {
  requireThat(
    validSubtree(start, end) && index >= start && index < end && end <= entries.length,
    'SUBTREE_RANGE',
  );
  function walk(a, i) {
    if (a.length === 1) return [];
    const k = split(a.length);
    return i < k
      ? [...walk(a.slice(0, k), i), treeHash(a.slice(k))]
      : [...walk(a.slice(k), i - k), treeHash(a.slice(0, k))];
  }
  return walk(entries.slice(start, end), index - start);
}
export function evaluateInclusion(entryHash, index, start, end, proof) {
  let fn = BigInt(index) - BigInt(start),
    sn = BigInt(end) - BigInt(start) - 1n;
  requireThat(
    validSubtree(start, end) &&
      fn >= 0n &&
      fn <= sn &&
      entryHash.length === 32 &&
      proof.length <= 64,
    'SUBTREE_RANGE',
  );
  let r = entryHash;
  for (const p of proof) {
    requireThat(sn !== 0n && p.length === 32, 'INCLUSION_LENGTH');
    if (fn & 1n || fn === sn) {
      r = nodeHash(p, r);
      while (!(fn & 1n)) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else r = nodeHash(r, p);
    fn >>= 1n;
    sn >>= 1n;
  }
  requireThat(sn === 0n, 'INCLUSION_SHORT');
  return r;
}
export function consistencyProof(entries, start, end) {
  requireThat(validSubtree(start, end) && end <= entries.length, 'SUBTREE_RANGE');
  if (start === end) return [];
  function sub(a, s, e, b) {
    const n = a.length;
    if (s === 0 && e === n) return b ? [] : [treeHash(a)];
    const k = split(n);
    if (e <= k) return [...sub(a.slice(0, k), s, e, b), treeHash(a.slice(k))];
    if (s >= k) return [...sub(a.slice(k), s - k, e - k, b), treeHash(a.slice(0, k))];
    requireThat(s === 0, 'SUBTREE_ALIGNMENT');
    return [...sub(a.slice(k), 0, e - k, false), treeHash(a.slice(0, k))];
  }
  return sub(entries, start, end, true);
}
export function verifyConsistency({ start, end, size, node, root, proof }) {
  start = BigInt(start);
  end = BigInt(end);
  size = BigInt(size);
  requireThat(validSubtree(start, end) && end <= size && proof.length <= 128, 'CONSISTENCY_RANGE');
  proof = [...proof];
  if (start === end) {
    requireThat(!proof.length && equal(node, sha256(Buffer.alloc(0))), 'EMPTY_CONSISTENCY');
    return true;
  }
  let fn = start,
    sn = end - 1n,
    tn = size - 1n;
  if (sn === tn) {
    while (fn !== sn) {
      fn >>= 1n;
      sn >>= 1n;
      tn >>= 1n;
    }
  } else {
    while (fn !== sn && sn & 1n) {
      fn >>= 1n;
      sn >>= 1n;
      tn >>= 1n;
    }
  }
  let fr, sr;
  if (fn === sn) fr = sr = node;
  else {
    requireThat(proof.length > 0, 'CONSISTENCY_SHORT');
    fr = sr = proof.shift();
  }
  for (const c of proof) {
    requireThat(tn !== 0n && c.length === 32, 'CONSISTENCY_LENGTH');
    if (sn & 1n || sn === tn) {
      if (fn < sn) fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (!(sn & 1n)) {
        fn >>= 1n;
        sn >>= 1n;
        tn >>= 1n;
      }
    } else sr = nodeHash(sr, c);
    fn >>= 1n;
    sn >>= 1n;
    tn >>= 1n;
  }
  requireThat(tn === 0n && equal(fr, node) && equal(sr, root), 'CONSISTENCY_HASH');
  return true;
}
export function coverInterval(start, end) {
  start = BigInt(start);
  end = BigInt(end);
  requireThat(start >= 0n && end >= start && end <= 0xffffffffffffffffn, 'INTERVAL');
  if (end - start <= 1n)
    return [
      [start, end],
      [end, end],
    ];
  const bits = (n) => (n === 0n ? 0n : BigInt(n.toString(2).length)),
    last = end - 1n,
    split = bits(start ^ last) - 1n,
    mask = (1n << split) - 1n,
    mid = last & ~mask,
    leftSplit = bits(~start & mask),
    leftStart = start & ~((1n << leftSplit) - 1n);
  return [
    [leftStart, mid],
    [mid, end],
  ];
}
export const anchorBytes = (id) => parseDER(oid(id, true)).value;
export function cosignedMessage({ cosignerID, caID, logNumber, start, end, root, timestamp = 0 }) {
  requireThat(
    validSubtree(start, end) && root.length === 32 && (!timestamp || BigInt(start) === 0n),
    'COSIGNATURE_RANGE',
  );
  const cn = Buffer.from(`oid/1.3.6.1.4.1.${cosignerID}`),
    ln = Buffer.from(`oid/1.3.6.1.4.1.${caID}.0.${logNumber}`);
  requireThat(cn.length > 0 && ln.length > 0, 'COSIGNATURE_NAME');
  return Buffer.concat([
    Buffer.from('subtree/v1\n\0'),
    vector(cn, 1),
    uint(timestamp, 8),
    vector(ln, 1),
    uint(start, 8),
    uint(end, 8),
    root,
  ]);
}
export function encodeProof({
  extensions = Buffer.alloc(0),
  start,
  end,
  inclusion,
  signatures = [],
}) {
  requireThat(
    validSubtree(start, end) && inclusion.every((h) => h.length === 32),
    'MTC_PROOF_RANGE',
  );
  const ss = signatures
    .map((s) => ({ id: anchorBytes(s.cosignerID), signature: s.signature }))
    .sort((a, b) => a.id.length - b.id.length || Buffer.compare(a.id, b.id));
  for (let i = 1; i < ss.length; i++)
    requireThat(!equal(ss[i - 1].id, ss[i].id), 'DUPLICATE_COSIGNER');
  return Buffer.concat([
    vector(extensions, 2),
    uint(start, 6),
    uint(end, 6),
    vector(Buffer.concat(inclusion), 2),
    vector(
      Buffer.concat(ss.map((s) => Buffer.concat([vector(s.id, 1), vector(s.signature, 2)]))),
      3,
    ),
  ]);
}
export function decodeProof(input) {
  const b = bytes(input);
  requireThat(b.length <= 2 * 1024 * 1024, 'MTC_SIZE');
  let p = 0;
  const read = (n) => {
    requireThat(p + n <= b.length, 'MTC_TRUNCATION');
    return b.subarray(p, (p += n));
  };
  const number = (n) => {
    let v = 0n;
    for (const x of read(n)) v = (v << 8n) | BigInt(x);
    return v;
  };
  const vec = (n) => read(Number(number(n)));
  const extensions = vec(2),
    start = number(6),
    end = number(6),
    v = vec(2);
  requireThat(v.length % 32 === 0, 'MTC_INCLUSION_SIZE');
  const inclusion = [];
  for (let i = 0; i < v.length; i += 32) inclusion.push(v.subarray(i, i + 32));
  const signatureLength = Number(number(3)),
    stop = p + signatureLength;
  requireThat(stop === b.length, 'MTC_SIGNATURES_LENGTH');
  const signatures = [];
  let previous;
  while (p < stop) {
    const id = vec(1),
      signature = vec(2);
    requireThat(
      id.length > 0 &&
        (!previous ||
          previous.length < id.length ||
          (previous.length === id.length && Buffer.compare(previous, id) < 0)),
      'MTC_COSIGNER_ORDER',
    );
    const cosignerID = oidText({ tag: 13, value: id });
    signatures.push({ cosignerID, signature });
    previous = id;
  }
  requireThat(validSubtree(start, end) && p === stop, 'MTC_PROOF_RANGE');
  let e = 0,
    last = -1;
  while (e < extensions.length) {
    requireThat(e + 4 <= extensions.length, 'MTC_EXTENSION');
    const t = extensions.readUInt16BE(e),
      n = extensions.readUInt16BE(e + 2);
    requireThat(t > last && e + 4 + n <= extensions.length, 'MTC_EXTENSION_ORDER');
    last = t;
    e += 4 + n;
  }
  return { extensions, start, end, inclusion, signatures };
}
export function logEntryFromTBS(tbs, extensions = Buffer.alloc(0)) {
  const t = parseDER(tbs).children;
  requireThat(equal(t[2].raw, algID(OID.mtc)), 'MTC_ALGORITHM');
  const pk = t[6];
  const entry = Buffer.concat([
    vector(extensions, 2),
    uint(1, 2),
    t[0].raw,
    t[3].raw,
    t[4].raw,
    t[5].raw,
    pk.children[0].raw,
    octet(sha256(pk.raw)),
    ...t.slice(7).map((n) => n.raw),
  ]);
  requireThat(entry.length <= 65535, 'MTC_ENTRY_SIZE');
  return entry;
}
export function createMTCTBS(options, { caID, logNumber, index }) {
  requireThat(
    Number.isInteger(logNumber) &&
      logNumber >= 1 &&
      logNumber <= 65535 &&
      BigInt(index) >= 0n &&
      BigInt(index) < 1n << 48n,
    'MTC_SERIAL',
  );
  return tbsCertificate({
    ...options,
    issuer: anchorName(caID),
    serial: (BigInt(logNumber) << 48n) | BigInt(index),
    signatureAlgorithm: OID.mtc,
  });
}
export function issueMTC(
  tbs,
  { entries, index, caID, logNumber, cosigners, start = 0, end = entries.length },
) {
  requireThat(equal(logEntryFromTBS(tbs), entries[index]), 'MTC_ENTRY_BINDING');
  const root = treeHash(entries.slice(start, end)),
    inclusion = inclusionProof(entries, index, start, end);
  const signatures = cosigners.map((c) => ({
    cosignerID: c.id,
    signature: sign(
      cosignedMessage({ cosignerID: c.id, caID, logNumber, start, end, root }),
      c.privateKey,
    ),
  }));
  return certificateFromTBS(tbs, OID.mtc, encodeProof({ start, end, inclusion, signatures }));
}
export function verifyMTC(
  raw,
  {
    caID,
    caPublicKey,
    members,
    threshold,
    at = now(),
    revokedRanges = [],
    trustedSubtrees = [],
    policyHash,
    membershipEpoch,
    rtmHash,
    mode = 'LIVE',
    profileID,
  },
) {
  requireThat(
    threshold > 0 &&
      threshold <= members.length &&
      policyHash &&
      rtmHash &&
      Number.isSafeInteger(membershipEpoch),
    'MTC_POLICY',
  );
  const c = parseCertificate(raw);
  requireThat(
    equal(c.issuer, anchorName(caID)) &&
      c.algorithm === OID.mtc &&
      equal(c.algorithmRaw, algID(OID.mtc)),
    'MTC_ISSUER',
  );
  requireThat(equal(c.extensions.get('2.5.29.19')?.value, seq()), 'MTC_CA_NOT_ALLOWED');
  const known = new Set([
    '2.5.29.19',
    '2.5.29.15',
    '2.5.29.14',
    '2.5.29.35',
    '2.5.29.37',
    ...Object.values(RRA),
  ]);
  for (const [id, e] of c.extensions)
    requireThat(!e.critical || known.has(id), 'MTC_UNKNOWN_CRITICAL_EXTENSION');
  if (c.extensions.has('2.5.29.15'))
    validateKeyUsage(c.extensions.get('2.5.29.15'), undefined, 'MTC_CERTIFICATE_PROFILE');
  if (profileID) {
    if (profileID === 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1')
      requireThat(
        c.publicKey.asymmetricKeyType === 'ec' &&
          c.publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
          c.extensions.get(RRA['id-pe-certconcordPasskeyBinding'])?.critical,
        'PASSKEY_CERTIFICATE_BINDING',
      );
    const p = profiles[profileID];
    requireThat(
      p && equal(c.extensions.get('2.5.29.37')?.value, seq(oid(p.eku))),
      'MTC_CERTIFICATE_PROFILE',
    );
    validateKeyUsage(c.extensions.get('2.5.29.15'), p.ku, 'MTC_CERTIFICATE_PROFILE');
  }
  requireThat(
    c.serial > 0n && c.serial <= 0xffffffffffffffffn && at >= c.notBefore && at < c.notAfter,
    'MTC_SERIAL_OR_TIME',
  );
  const logNumber = Number(c.serial >> 48n),
    index = c.serial & ((1n << 48n) - 1n);
  requireThat(
    logNumber > 0 &&
      !revokedRanges.some(
        (r) => r.logNumber === logNumber && index >= BigInt(r.start) && index < BigInt(r.end),
      ),
    'MTC_REVOKED',
  );
  const proof = decodeProof(c.signature),
    entry = logEntryFromTBS(c.tbs, proof.extensions),
    root = evaluateInclusion(leafHash(entry), index, proof.start, proof.end, proof.inclusion);
  const cache = trustedSubtrees.find(
    (s) =>
      s.caID === caID &&
      s.logNumber === logNumber &&
      BigInt(s.start) === proof.start &&
      BigInt(s.end) === proof.end &&
      s.membershipEpoch === membershipEpoch &&
      s.mode === mode &&
      equal(s.policyHash, policyHash) &&
      equal(s.rtmHash, rtmHash),
  );
  if (cache) {
    requireThat(
      Number.isSafeInteger(cache.validFrom) &&
        Number.isSafeInteger(cache.expiresAt) &&
        cache.validFrom <= at &&
        at < cache.expiresAt,
      'MTC_CACHE_FRESHNESS',
    );
    requireThat(equal(cache.root, root), 'MTC_CACHED_ROOT');
    return { certificate: c, root, mode: 'LANDMARK' };
  }
  let ca = false;
  const operators = new Set(),
    keys = new Set();
  for (const s of proof.signatures) {
    const member =
      s.cosignerID === caID
        ? { publicKey: caPublicKey, operatorID: 'CA' }
        : members.find((m) => m.id === s.cosignerID);
    if (!member) continue;
    requireThat(
      verify(
        cosignedMessage({
          cosignerID: s.cosignerID,
          caID,
          logNumber,
          start: proof.start,
          end: proof.end,
          root,
        }),
        s.signature,
        member.publicKey,
      ),
      'MTC_COSIGNATURE',
    );
    if (s.cosignerID === caID) ca = true;
    else {
      const key = b64u(sha512(member.publicKey.export({ type: 'spki', format: 'der' })));
      requireThat(
        !keys.has(key) &&
          !equal(
            member.publicKey.export({ type: 'spki', format: 'der' }),
            caPublicKey.export({ type: 'spki', format: 'der' }),
          ),
        'MTC_DUPLICATE_KEY',
      );
      keys.add(key);
      operators.add(member.operatorID);
    }
  }
  requireThat(ca && operators.size >= threshold, 'MTC_QUORUM');
  return { certificate: c, root, mode: 'STANDALONE' };
}
export class Mirror {
  constructor({ journal, id, privateKey }) {
    Object.assign(this, { journal, id, privateKey });
  }
  store(origin) {
    requireThat(!this.journal.get('mirror', origin)?.value.entries, 'LOG_MIGRATION_REQUIRED');
    return new IndexedMerkleLog(this.journal, 'mtc-mirror:' + origin);
  }
  cosignSubtree({ caID, logNumber, start, end }) {
    const store = this.store(`${caID}.0.${logNumber}`);
    requireThat(
      validSubtree(start, end) && start >= 0 && end <= store.head().size,
      'MIRROR_SUBTREE_UNAVAILABLE',
    );
    const root = store.root(Number(end), Number(start));
    return {
      cosignerID: this.id,
      signature: sign(
        cosignedMessage({ cosignerID: this.id, caID, logNumber, start, end, root }),
        this.privateKey,
      ),
    };
  }
  cosign({ caID, logNumber, entries, source, size = entries?.length }) {
    const origin = `${caID}.0.${logNumber}`,
      store = this.store(origin);
    const root = this.journal.transaction(() => {
      const old = store.head().size;
      requireThat(Number.isSafeInteger(size) && size >= old, 'MIRROR_FORK');
      const prefix = source ? source.root(old) : treeHash(entries.slice(0, old));
      requireThat(equal(prefix, store.root(old)), 'MIRROR_FORK');
      for (let at = old; at < size; at += 256) {
        const batch = source
          ? source.entries(at, Math.min(size, at + 256))
          : entries.slice(at, at + 256);
        for (const [i, entry] of batch.entries())
          requireThat(store.append(entry, String(at + i)) === at + i, 'MIRROR_INDEX');
      }
      const root = store.root(size);
      requireThat(equal(root, source ? source.root(size) : treeHash(entries)), 'MIRROR_ROOT');
      return root;
    });
    return {
      cosignerID: this.id,
      signature: sign(
        cosignedMessage({
          cosignerID: this.id,
          caID,
          logNumber,
          start: 0,
          end: size,
          root,
        }),
        this.privateKey,
      ),
    };
  }
}
