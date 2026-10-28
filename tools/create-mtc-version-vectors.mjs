// Fixed public certificates, assembled without the reference MTC/PKI encoder.
// Generation uses native ML-DSA and writes no private keys. The output must not exist.
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const output = process.argv[2];
if (!output) throw Error('Supply a new output JSON path');
const concat = (...items) => Buffer.concat(items);
const uint = (value, width) => {
  let n = BigInt(value);
  const out = Buffer.alloc(width);
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(n & 255n);
    n >>= 8n;
  }
  if (n) throw Error('Integer overflow');
  return out;
};
const vector = (value, width) => concat(uint(value.length, width), value);
const der = (tag, value) => {
  const length =
    value.length < 128
      ? uint(value.length, 1)
      : value.length < 256
        ? concat(Buffer.from([0x81]), uint(value.length, 1))
        : concat(Buffer.from([0x82]), uint(value.length, 2));
  return concat(Buffer.from([tag]), length, value);
};
const seq = (...values) => der(0x30, concat(...values));
const oidBytes = (values) =>
  concat(
    ...values.map((value) => {
      let n = BigInt(value);
      const out = [Number(n & 127n)];
      while ((n >>= 7n)) out.unshift(Number(n & 127n) | 128);
      return Buffer.from(out);
    }),
  );
const oid = (value) => {
  const [a, b, ...rest] = value.split('.').map(BigInt);
  return der(6, oidBytes([40n * a + b, ...rest]));
};
const relative = (value) => oidBytes(value.split('.'));
const sha256 = (value) => createHash('sha256').update(value).digest();
const alg = (value) => seq(oid(value));
const ext = (id, value, critical = false) =>
  seq(oid(id), ...(critical ? [Buffer.from('0101ff', 'hex')] : []), der(4, value));
const caID = '32473.1';
const keys = ['32473.1', '32473.10', '32473.11'].map((id) => ({
  id,
  ...generateKeyPairSync('ml-dsa-87'),
}));
const leaf = generateKeyPairSync('ml-dsa-65').publicKey.export({ type: 'spki', format: 'der' });
const leafAlgorithm = alg('2.16.840.1.101.3.4.3.18');
const ids = {
  'mtc-draft06': { mtc: '1.3.6.1.4.1.44363.47.0', anchor: '1.3.6.1.4.1.44363.47.3' },
  'mtc-draft07': { mtc: '1.3.6.1.5.5.7.6.67', anchor: '1.3.6.1.5.5.7.25.3' },
};
const publicKeys = keys.map(({ id, publicKey }, i) => ({
  id,
  operatorID: i === 0 ? 'CA' : `mirror-${i}`,
  spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
}));
const certificates = {};
const cases = [];
function build(id, profile, options = {}) {
  const selected = ids[profile];
  const anchorOID = options.anchorOID ?? selected.anchor;
  const signatureAlgorithm = options.algorithm ?? alg(selected.mtc);
  const issuer = seq(der(0x31, seq(oid(anchorOID), der(13, relative(caID)))));
  const version = Buffer.from('a003020102', 'hex');
  const validity = seq(
    der(24, Buffer.from('20261020000000Z')),
    der(24, Buffer.from('20261021000000Z')),
  );
  const subject = seq(der(0x31, seq(oid('2.5.4.3'), der(12, Buffer.from('MTC version vector')))));
  const extensions = der(
    0xa3,
    seq(
      ext('2.5.29.19', seq(), true),
      ext('2.5.29.15', Buffer.from('03020780', 'hex'), true),
      ext('2.5.29.37', seq(oid('2.25.194210630946043567986588520971235829030'))),
      ...(options.critical ? [ext('1.3.6.1.4.1.32473.99', seq(), true)] : []),
    ),
  );
  const tbs = seq(
    version,
    der(2, uint(1n << 48n, 7)),
    signatureAlgorithm,
    issuer,
    validity,
    subject,
    leaf,
    extensions,
  );
  const entryExtensions = options.entryExtensions ?? Buffer.alloc(0);
  const entry = concat(
    vector(entryExtensions, 2),
    uint(1, 2),
    version,
    issuer,
    validity,
    subject,
    leafAlgorithm,
    der(4, sha256(leaf)),
    extensions,
  );
  const root = sha256(concat(Buffer.from([0]), entry));
  let signatures = keys.map(({ id, privateKey }) => ({
    id: relative(id),
    signature: sign(
      null,
      concat(
        Buffer.from('subtree/v1\n\0'),
        vector(Buffer.from(`oid/1.3.6.1.4.1.${id}`), 1),
        uint(0, 8),
        vector(Buffer.from(`oid/1.3.6.1.4.1.${caID}.0.1`), 1),
        uint(0, 8),
        uint(1, 8),
        root,
      ),
      privateKey,
    ),
  }));
  const grease = { id: relative('32473.99'), signature: Buffer.from('00ff010203', 'hex') };
  if (options.grease)
    signatures.push(
      grease,
      { id: relative('1.1'), signature: Buffer.alloc(0) },
      { id: relative('1.128.1.1'), signature: Buffer.from([255]) },
    );
  if (options.onlyGrease) signatures = [grease];
  if (options.noCA) signatures = signatures.filter((s) => !s.id.equals(relative(caID)));
  if (options.oneMirror) signatures = signatures.filter((s) => !s.id.equals(relative('32473.11')));
  if (options.landmark) signatures = options.grease ? [grease] : [];
  signatures.sort((a, b) => a.id.length - b.id.length || Buffer.compare(a.id, b.id));
  if (options.duplicate) signatures.push(signatures.at(-1));
  if (options.unordered) signatures.reverse();
  if (options.fakeKnown)
    signatures = signatures.map((s) =>
      s.id.equals(relative(caID)) ? { ...s, signature: Buffer.from([0]) } : s,
    );
  if (options.lexicalOnly) signatures.sort((a, b) => Buffer.compare(a.id, b.id));
  const signedBytes = concat(
    ...signatures.map((s) => concat(vector(s.id, 1), vector(s.signature, 2))),
  );
  let proof = concat(
    vector(options.proofExtensions ?? entryExtensions, 2),
    uint(0, 6),
    uint(1, 6),
    vector(Buffer.alloc(0), 2),
    vector(signedBytes, 3),
  );
  if (options.trailing) proof = concat(proof, Buffer.from([0]));
  if (options.truncated) proof = proof.subarray(0, -1);
  const raw = seq(
    tbs,
    options.outerAlgorithm ?? signatureAlgorithm,
    der(3, concat(Buffer.from([0]), proof)),
  );
  certificates[id] = {
    wireProfile: profile,
    der: raw.toString('base64'),
    sha256: sha256(raw).toString('hex'),
    root: root.toString('hex'),
    entry: entry.toString('base64'),
  };
  return id;
}
function add(name, certificate, expected, options = {}) {
  cases.push({ name, certificate, expected, ...options });
}
for (const profile of Object.keys(ids)) {
  build(profile, profile);
  const legacy = profile === 'mtc-draft06';
  add(
    legacy ? 'rejects original draft06 bytes' : 'accepts draft07 original standalone bytes',
    profile,
    legacy ? 'MTC_ISSUER' : 'STANDALONE',
  );
  const landmark = build(profile + '-landmark', profile, { landmark: true, grease: true });
  add(
    legacy
      ? 'rejects draft06 even with an authenticated cached root'
      : 'accepts draft07 historical landmark with GREASE',
    landmark,
    legacy ? 'MTC_ISSUER' : 'LANDMARK',
    { cacheRoot: profile },
  );
}
add('rejects an old-version root for draft07', 'mtc-draft07-landmark', 'MTC_CACHED_ROOT', {
  cacheRoot: 'mtc-draft06',
});
add('accepts draft07 exact certificate notAfter', 'mtc-draft07', 'STANDALONE', {
  atOffset: 86400,
});
add('rejects an expired draft07 certificate', 'mtc-draft07', 'MTC_SERIAL_OR_TIME', {
  atOffset: 86401,
});
add('rejects a revoked draft07 range', 'mtc-draft07', 'MTC_REVOKED', { revoked: true });
for (const [id, options, expected] of [
  ['sorted-unknown-cosigner', { grease: true }, 'STANDALONE'],
  ['only-unknown-cosigner', { onlyGrease: true }, 'MTC_QUORUM'],
  ['unknown-cosigner-does-not-replace-ca', { grease: true, noCA: true }, 'MTC_QUORUM'],
  ['unknown-cosigner-does-not-add-quorum', { grease: true, oneMirror: true }, 'MTC_QUORUM'],
  ['duplicate-cosigner', { grease: true, duplicate: true }, 'MTC_COSIGNER_ORDER'],
  ['unordered-cosigners', { grease: true, unordered: true }, 'MTC_COSIGNER_ORDER'],
  [
    'cosigners-require-length-before-lexical-order',
    { grease: true, lexicalOnly: true },
    'MTC_COSIGNER_ORDER',
  ],
  ['invalid-known-cosigner', { grease: true, fakeKnown: true }, 'MTC_COSIGNATURE'],
  ['trailing-proof-data', { trailing: true }, 'MTC_SIGNATURES_LENGTH'],
  ['truncated-proof', { truncated: true }, 'MTC_SIGNATURES_LENGTH'],
  ['mixed-issuer-oid', { anchorOID: ids['mtc-draft06'].anchor }, 'MTC_ISSUER'],
  [
    'mixed-signature-oids',
    { outerAlgorithm: alg(ids['mtc-draft06'].mtc) },
    'CERTIFICATE_ALGORITHM',
  ],
  [
    'algorithm-null-parameters',
    { algorithm: seq(oid(ids['mtc-draft07'].mtc), Buffer.from('0500', 'hex')) },
    'MTC_ISSUER',
  ],
  ['unknown-critical-x509', { critical: true }, 'MTC_UNKNOWN_CRITICAL_EXTENSION'],
  [
    'unknown-entry-extension',
    { entryExtensions: Buffer.from('ff000003010203', 'hex') },
    'STANDALONE',
  ],
  [
    'modified-entry-extension',
    {
      entryExtensions: Buffer.from('ff000003010203', 'hex'),
      proofExtensions: Buffer.from('ff000003010204', 'hex'),
    },
    'MTC_COSIGNATURE',
  ],
  [
    'duplicate-entry-extension',
    { entryExtensions: Buffer.from('ff000000ff000000', 'hex') },
    'MTC_EXTENSION_ORDER',
  ],
])
  add(id, build(id, 'mtc-draft07', options), expected);
writeFileSync(
  output,
  JSON.stringify(
    {
      schemaVersion: 1,
      description:
        'Synthetic native ML-DSA certificates; separate byte assembler, not a second complete verifier or security assessment.',
      sources: ['draft-ietf-plants-merkle-tree-certs-06', 'draft-ietf-plants-merkle-tree-certs-07'],
      at: 1792454400,
      caID,
      publicKeys,
      certificates,
      cases,
    },
    null,
    2,
  ) + '\n',
  { flag: 'wx' },
);
console.log(`${Object.keys(certificates).length} certificates; ${cases.length} cases`);
