// Synthetic raw certificates and complete admission inputs. Private keys remain in memory.
import fs from 'node:fs';
import { X509Certificate } from 'node:crypto';
import * as c from '../reference/core.mjs';
import * as p from '../reference/pki.mjs';
import { encode, decode } from '../reference/cose.mjs';
import { androidFixture } from '../reference/attestation-fixtures.mjs';
import { examplePasskey } from '../reference/example-passkey.mjs';
import { createRawSigningKey } from '../reference/browser.mjs';

const at = 1800000000,
  challenge = 'synthetic identical-name rollover',
  appleNonceOID = '1.2.840.113635.100.8.11.1',
  osOID = '1.2.840.113635.100.8.10.1',
  os = Buffer.from('synthetic platform version');
const keys = Object.fromEntries(
  ['root', 'parent', 'roll', 'roll2', 'ordinary', 'ordinaryRoll', 'lower', 'holder', 'wrong'].map(
    (id) => [id, c.generate('ec')],
  ),
);
const names = Object.fromEntries(
  ['root', 'parent', 'ordinary', 'lower', 'holder'].map((id) => [
    id,
    p.name('Synthetic path count ' + id),
  ]),
);
const certificates = {},
  raw = {},
  cases = [];
let serial = 1;
function issue(id, key, signer, issuer, subject, options = {}) {
  const {
    ca = false,
    pathLen = 0,
    extensions = [],
    aki,
    ku,
    noKU = false,
    notBefore = at - 600,
    notAfter = at + 3600,
    actualSigner = signer,
    mathValid = true,
    serialNumber,
  } = options;
  const input = p.tbsCertificate({
    publicKey: key.publicKey,
    issuer,
    subject,
    serial: serialNumber ?? serial++,
    ca,
    notBefore,
    notAfter,
    signatureAlgorithm: 'ec',
    extraExtensions: extensions,
  });
  const fields = c.parseDER(input).children.map((node) => node.raw);
  let exts = c.parseDER(fields.at(-1)).children[0].children.map((node) => node.raw);
  exts = exts.flatMap((bytes) => {
    const oid = c.oidText(c.parseDER(bytes).children[0]);
    if (oid === '2.5.29.19' && ca)
      return [
        p.extension(
          oid,
          c.seq(c.der(1, Buffer.from([255])), ...(pathLen === null ? [] : [c.integer(pathLen)])),
          true,
        ),
      ];
    if (oid === '2.5.29.15' && noKU) return [];
    if (oid === '2.5.29.15' && ku) return [p.extension(oid, c.der(3, Buffer.from(ku)), true)];
    return [bytes];
  });
  if (aki) exts.push(p.extension('2.5.29.35', c.seq(c.der(0x80, aki))));
  fields[fields.length - 1] = c.der(0xa3, c.seq(...exts));
  const tbs = c.seq(...fields),
    certificate = p.certificateFromTBS(tbs, 'ec', c.sign(tbs, actualSigner.privateKey));
  if (new X509Certificate(certificate).verify(signer.publicKey) !== mathValid)
    throw Error('Synthetic signature control: ' + id);
  raw[id] = certificate;
  certificates[id] = {
    der: certificate.toString('base64'),
    sha256: c.sha256(certificate).toString('hex'),
    expectedSignerSPKI: c.spki(signer.publicKey).toString('base64'),
    signatureValid: mathValid,
  };
  return id;
}
const appleExtensions = [
  p.extension(appleNonceOID, c.sha256(Buffer.from(challenge))),
  p.extension(osOID, os),
];
const ca = (id, key, signer, issuer, subject, pathLen, more = {}) =>
  issue(id, key, signer, issuer, subject, { ca: true, pathLen, ...more });
const leaf = (id, signer, issuer, more = {}, key = keys.holder) =>
  issue(id, key, signer, issuer, names.holder, { extensions: appleExtensions, ...more });
ca('root3', keys.root, keys.root, names.root, names.root, 3);
ca('root0', keys.root, keys.root, names.root, names.root, 0);
ca('untrusted', keys.wrong, keys.wrong, names.root, names.root, 3);
ca('parent0', keys.parent, keys.root, names.root, names.parent, 0);
ca('parent1', keys.parent, keys.root, names.root, names.parent, 1, {
  serialNumber: p.parseCertificate(raw.parent0).serial,
});
ca('roll0', keys.roll, keys.parent, names.parent, names.parent, 0);
ca('roll1', keys.roll, keys.parent, names.parent, names.parent, 1);
ca('roll-unconstrained', keys.roll, keys.parent, names.parent, names.parent, null);
ca('roll-aki', keys.roll, keys.parent, names.parent, names.parent, 0, {
  aki: c.sha256(c.spki(keys.parent.publicKey)),
});
ca('roll2', keys.roll2, keys.roll, names.parent, names.parent, 0);
ca('ordinary0', keys.ordinary, keys.parent, names.parent, names.ordinary, 0);
ca('ordinary1', keys.ordinary, keys.parent, names.parent, names.ordinary, 1);
ca('ordinary-unconstrained', keys.ordinary, keys.parent, names.parent, names.ordinary, null);
ca('ordinary-roll', keys.ordinaryRoll, keys.ordinary, names.ordinary, names.ordinary, 0);
ca('ordinary-under-roll', keys.ordinary, keys.roll, names.parent, names.ordinary, 0);
ca('lower', keys.lower, keys.ordinary, names.ordinary, names.lower, 0);
leaf('leaf-root', keys.root, names.root);
leaf('leaf-parent', keys.parent, names.parent);
leaf('leaf-roll', keys.roll, names.parent);
leaf('leaf-roll2', keys.roll2, names.parent);
leaf('leaf-ordinary', keys.ordinary, names.ordinary);
leaf('leaf-ordinary-roll', keys.ordinaryRoll, names.ordinary);
leaf('leaf-lower', keys.lower, names.lower);
const add = (id, chain, accepted, error = [], extra = {}) =>
  cases.push({
    id,
    chain,
    root: 'root3',
    expected: { accepted, error: typeof error === 'string' ? [error] : error },
    ...extra,
  });
add('direct-root-path0', ['leaf-root', 'root0'], true, [], { root: 'root0' });
add('direct-parent-path0', ['leaf-parent', 'parent0', 'root3'], true);
add('one-identical-name-rollover-parent0', ['leaf-roll', 'roll0', 'parent0', 'root3'], true);
add('one-identical-name-rollover-parent1', ['leaf-roll', 'roll0', 'parent1', 'root3'], true);
add('two-identical-name-rollovers', ['leaf-roll2', 'roll2', 'roll0', 'parent0', 'root3'], true);
add('old-key-aki-new-key-ski', ['leaf-roll', 'roll-aki', 'parent0', 'root3'], true);
add('ordinary-intermediate-parent1', ['leaf-ordinary', 'ordinary0', 'parent1', 'root3'], true);
add(
  'rollover-below-ordinary',
  ['leaf-ordinary-roll', 'ordinary-roll', 'ordinary0', 'parent1', 'root3'],
  true,
);
add(
  'rollover-above-ordinary',
  ['leaf-ordinary', 'ordinary-under-roll', 'roll1', 'parent1', 'root3'],
  true,
);
add(
  'unconstrained-rollover-above-ordinary',
  ['leaf-ordinary', 'ordinary-under-roll', 'roll-unconstrained', 'parent1', 'root3'],
  true,
);
add('pinned-root-appended', ['leaf-roll', 'roll0', 'parent0'], true);
add(
  'ordinary-intermediate-parent0',
  ['leaf-ordinary', 'ordinary0', 'parent0', 'root3'],
  false,
  'KEY_ATTESTATION_PATH_LENGTH',
);
add(
  'mixed-chain-exceeds-parent0',
  ['leaf-ordinary', 'ordinary-under-roll', 'roll1', 'parent0', 'root3'],
  false,
  'KEY_ATTESTATION_PATH_LENGTH',
);
add(
  'exempt-ca-retains-own-path0',
  ['leaf-ordinary', 'ordinary-under-roll', 'roll0', 'parent1', 'root3'],
  false,
  'KEY_ATTESTATION_PATH_LENGTH',
);
add(
  'two-ordinary-intermediates-exceed-parent1',
  ['leaf-lower', 'lower', 'ordinary1', 'parent1', 'root3'],
  false,
  'KEY_ATTESTATION_PATH_LENGTH',
);
add(
  'missing-path-does-not-exempt-ordinary',
  ['leaf-lower', 'lower', 'ordinary-unconstrained', 'parent1', 'root3'],
  false,
  'KEY_ATTESTATION_PATH_LENGTH',
);
add(
  'root-retains-own-path0',
  ['leaf-roll', 'roll0', 'parent0', 'root0'],
  false,
  'KEY_ATTESTATION_PATH_LENGTH',
  { root: 'root0' },
);

const cn = (value, tag = 12) =>
  c.seq(c.set(c.seq(c.oid('2.5.4.3'), c.der(tag, Buffer.from(value)))));
const parentText = 'Synthetic path count parent';
for (const [id, subject] of [
  ['printable-versus-utf8', cn(parentText, 19)],
  ['case-variant', cn(parentText.toLowerCase())],
  ['space-variant', cn('  Synthetic   path count parent  ')],
  ['different-name', cn('Different path count parent')],
]) {
  ca(id, keys.roll, keys.parent, names.parent, subject, 0);
  leaf('leaf-' + id, keys.roll, subject);
  add(id, ['leaf-' + id, id, 'parent0', 'root3'], false, 'KEY_ATTESTATION_PATH_LENGTH', {
    nameExemption: 'not-selected-different-DER',
  });
}
const unicodeIssuer = cn('Synthetic cafe\u0301'),
  unicodeSubject = cn('Synthetic caf\u00e9');
ca('unicode-parent0', keys.parent, keys.root, names.root, unicodeIssuer, 0);
ca('unicode-roll', keys.roll, keys.parent, unicodeIssuer, unicodeSubject, 0);
leaf('leaf-unicode', keys.roll, unicodeSubject);
add(
  'unicode-normalization-variant',
  ['leaf-unicode', 'unicode-roll', 'unicode-parent0', 'root3'],
  false,
  'KEY_ATTESTATION_PATH_LENGTH',
  { nameExemption: 'not-selected-different-DER' },
);
const atv = (oid, value) => c.seq(c.oid(oid), c.der(12, Buffer.from(value)));
const common = atv('2.5.4.3', 'Synthetic CA'),
  org = atv('2.5.4.10', 'Synthetic Org');
const grouped = c.seq(c.set(...[common, org].sort(Buffer.compare))),
  split = c.seq(c.set(common), c.set(org)),
  reverse = c.seq(c.set(org), c.set(common));
for (const [id, issuer, subject] of [
  ['rdn-grouping', grouped, split],
  ['rdn-order', split, reverse],
]) {
  ca(id + '-parent0', keys.parent, keys.root, names.root, issuer, 0);
  ca(id, keys.roll, keys.parent, issuer, subject, 0);
  leaf('leaf-' + id, keys.roll, subject);
  add(id, ['leaf-' + id, id, id + '-parent0', 'root3'], false, 'KEY_ATTESTATION_PATH_LENGTH');
}

for (const [id, options, issuer, caValue, errors] of [
  [
    'wrong-parent-signature',
    { actualSigner: keys.wrong, mathValid: false },
    names.parent,
    true,
    ['KEY_ATTESTATION_CHAIN_SIGNATURE'],
  ],
  ['wrong-issuer-name', {}, names.ordinary, true, ['KEY_ATTESTATION_CHAIN_SIGNATURE']],
  [
    'wrong-aki',
    { aki: c.sha256(c.spki(keys.wrong.publicKey)) },
    names.parent,
    true,
    ['KEY_ATTESTATION_CHAIN_SIGNATURE'],
  ],
  [
    'non-ca',
    { ku: [1, 6] },
    names.parent,
    false,
    ['KEY_ATTESTATION_CA_USAGE', 'KEY_ATTESTATION_CHAIN_SIGNATURE'],
  ],
  [
    'no-key-cert-sign',
    { ku: [7, 128] },
    names.parent,
    true,
    ['KEY_ATTESTATION_CA_USAGE', 'KEY_ATTESTATION_CHAIN_SIGNATURE'],
  ],
  ['missing-key-usage', { noKU: true }, names.parent, true, ['KEY_ATTESTATION_KEY_USAGE']],
  ['expired', { notAfter: at }, names.parent, true, ['KEY_ATTESTATION_CERTIFICATE_TIME']],
  [
    'not-yet-valid',
    { notBefore: at + 1 },
    names.parent,
    true,
    ['KEY_ATTESTATION_CERTIFICATE_TIME'],
  ],
  [
    'unknown-critical',
    { extensions: [p.extension('1.3.6.1.4.1.55555.99', c.seq(), true)] },
    names.parent,
    true,
    ['KEY_ATTESTATION_CRITICAL_EXTENSION'],
  ],
]) {
  issue(id, keys.roll, keys.parent, issuer, names.parent, { ca: caValue, pathLen: 0, ...options });
  add(id, ['leaf-roll', id, 'parent1', 'root3'], false, errors);
}
for (const mode of ['revoked', 'stale', 'missing'])
  add(
    'status-' + mode,
    ['leaf-roll', 'roll0', 'parent0', 'root3'],
    false,
    'KEY_ATTESTATION_STATUS',
    { statusMode: mode },
  );
add(
  'untrusted-root',
  ['leaf-roll', 'roll0', 'parent0', 'root3'],
  false,
  'KEY_ATTESTATION_UNTRUSTED_ROOT',
  { root: 'untrusted' },
);
add(
  'duplicate-certificate',
  ['leaf-roll', 'roll0', 'roll0', 'parent0', 'root3'],
  false,
  'KEY_ATTESTATION_CHAIN_LOOP',
);
add(
  'input-chain-too-long',
  ['leaf-roll', 'roll0', 'roll0', 'roll0', 'roll0', 'parent0', 'root3'],
  false,
  'KEY_ATTESTATION_CHAIN',
);
leaf('leaf-ca', keys.roll, names.parent, { ca: true, pathLen: 0 });
add(
  'holder-is-not-ca',
  ['leaf-ca', 'roll0', 'parent0', 'root3'],
  false,
  'KEY_ATTESTATION_LEAF_USAGE',
);

const android = androidFixture(
  keys.holder.publicKey,
  challenge,
  {},
  {
    publicKey: keys.roll.publicKey,
    privateKey: keys.roll.privateKey,
    certificate: raw.roll0,
    subject: names.parent,
  },
);
const androidExtension = [...p.parseCertificate(android.evidence.x5c[0]).extensions]
  .filter(([oid]) => !['2.5.29.19', '2.5.29.15', '2.5.29.14', '2.5.29.37'].includes(oid))
  .map(([oid, ext]) => p.extension(oid, ext.value, ext.critical));
leaf('android-leaf-roll', keys.roll, names.parent, { extensions: androidExtension });
leaf('android-leaf-ordinary', keys.ordinary, names.ordinary, { extensions: androidExtension });
const androidPolicy = { ...android.policy.formats['android-key'] };
delete androidPolicy.roots;
delete androidPolicy.status;
const androidCases = [
  {
    id: 'android-rollover-parent0',
    chain: ['android-leaf-roll', 'roll-aki', 'parent0', 'root3'],
    accepted: true,
  },
  {
    id: 'android-ordinary-parent0',
    chain: ['android-leaf-ordinary', 'ordinary0', 'parent0', 'root3'],
    accepted: false,
    error: 'KEY_ATTESTATION_PATH_LENGTH',
  },
  {
    id: 'android-challenge-still-bound',
    chain: ['android-leaf-roll', 'roll0', 'parent0', 'root3'],
    challenge: 'different challenge',
    accepted: false,
    error: 'KEY_ATTESTATION_CHALLENGE',
  },
];

const origin = 'https://website.example',
  rpID = 'website.example',
  version = 'previewSign5-2026-09-09';
const fixture = examplePasskey({ origin, rpID, version });
const generationChallenge = c.random();
const generated = await createRawSigningKey(
  {
    challenge: generationChallenge,
    rp: { id: rpID, name: 'Synthetic' },
    user: { id: c.random(), name: 'synthetic', displayName: 'Synthetic' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    attestation: 'direct',
  },
  { version, algorithms: [-9], credentials: fixture.credentials },
);
const attestor = { publicKey: new X509Certificate(fixture.attestationCertificate).publicKey };
leaf('pscp-leaf-roll', keys.roll, names.parent, { extensions: [] }, attestor);
leaf('pscp-leaf-ordinary', keys.ordinary, names.ordinary, { extensions: [] }, attestor);
function replaceChain(bytes, chain) {
  const object = decode(bytes);
  object.get('attStmt').set(
    'x5c',
    chain.map((id) => raw[id]),
  );
  return encode(object);
}
const good = ['pscp-leaf-roll', 'roll-aki', 'parent0', 'root3'],
  bad = ['pscp-leaf-ordinary', 'ordinary0', 'parent0', 'root3'];
const pscpCases = [];
for (const [id, child, parent, accepted] of [
  ['pscp-both-rollovers', good, good, true],
  ['pscp-child-path-enforced', bad, good, false],
  ['pscp-parent-path-enforced', good, bad, false],
]) {
  const ceremony = structuredClone(generated.registration);
  ceremony.response.attestationObject = c.b64u(
    replaceChain(c.unb64u(ceremony.response.attestationObject), parent),
  );
  const key = Object.fromEntries(
    Object.entries(generated.key).map(([name, value]) => [
      name,
      name === 'algorithm' ? value : Buffer.from(value).toString('base64'),
    ]),
  );
  key.attestationObject = replaceChain(
    Buffer.from(generated.key.attestationObject),
    child,
  ).toString('base64');
  const model = {
    ...fixture.attestationPolicy.models[0],
    aaguid: fixture.aaguid.toString('base64'),
    rootHash: c.sha256(raw.root3).toString('base64'),
    expiresAt: at + 3600,
  };
  pscpCases.push({
    id,
    ceremony,
    generatedKey: key,
    challenge: generationChallenge.toString('base64'),
    origin,
    rpID,
    version,
    algorithms: [-9],
    model,
    root: 'root3',
    accepted,
    ...(accepted ? {} : { error: 'KEY_ATTESTATION_PATH_LENGTH' }),
  });
}
const corpus = {
  format: 'certconcord-identical-name-attestation-path-v1',
  qualification: 'SYNTHETIC_CONTROLLED_ROOTS_ONLY',
  contract:
    'Only byte-identical issuer/subject Name DER receives the counting exemption; complete RFC5280 section7.1 equivalence is not implemented.',
  at,
  challenge,
  holderSPKI: c.spki(keys.holder.publicKey).toString('base64'),
  apple: { osOID, os: os.toString('base64') },
  certificates,
  cases,
  android: { policy: androidPolicy, cases: androidCases },
  pscp: pscpCases,
};
const destination =
  process.argv[2] ?? new URL('../reference/vectors/attestation-pathlen.json', import.meta.url);
fs.writeFileSync(destination, JSON.stringify(corpus, null, 2) + '\n');
console.log(
  JSON.stringify({
    certificates: Object.keys(certificates).length,
    cases: cases.length,
    android: androidCases.length,
    pscp: pscpCases.length,
  }),
);
