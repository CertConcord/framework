// Synthetic attestation inputs. All private keys remain in memory.
import fs from 'node:fs';
import { X509Certificate } from 'node:crypto';
import * as c from '../reference/core.mjs';
import * as p from '../reference/pki.mjs';
import { encode, decode } from '../reference/cose.mjs';
import { androidFixture } from '../reference/attestation-fixtures.mjs';
import { examplePasskey } from '../reference/example-passkey.mjs';
import { createRawSigningKey } from '../reference/browser.mjs';

const at = 1800000000,
  challenge = 'synthetic attestation extension admission';
const nonceOID = '1.2.840.113635.100.8.11.1',
  osOID = '1.2.840.113635.100.8.10.1';
const os = Buffer.from('synthetic platform version');
const keys = Object.fromEntries(
  ['root', 'ca', 'leaf', 'wrong'].map((id) => [id, c.generate('ec')]),
);
const names = Object.fromEntries(
  ['root', 'ca', 'leaf'].map((id) => [id, p.name('Synthetic extension ' + id)]),
);
const raw = {},
  certificates = {},
  cases = [];
const appleExtensions = [
  p.extension(nonceOID, c.sha256(Buffer.from(challenge))),
  p.extension(osOID, os),
];
let serial = 1;
function issue(id, role, options = {}) {
  const signer = role === 'leaf' ? 'ca' : 'root';
  const key = options.key ?? keys[role];
  const input = p.tbsCertificate({
    publicKey: key.publicKey,
    issuer: names[signer],
    subject: names[role],
    serial: serial++,
    ca: role !== 'leaf',
    notBefore: at - 600,
    notAfter: at + 3600,
    signatureAlgorithm: 'ec',
    extraExtensions: options.extensions ?? (role === 'leaf' ? appleExtensions : []),
  });
  const fields = c.parseDER(input).children.map((node) => node.raw);
  const extensions = c.parseDER(fields.at(-1)).children[0].children.flatMap((node) => {
    const oid = c.oidText(node.children[0]);
    if (oid === '2.5.29.19') {
      if (Object.hasOwn(options, 'bc') && options.bc === null) return [];
      const value =
        options.bc ??
        (role === 'leaf'
          ? c.seq()
          : c.seq(c.der(1, Buffer.from([255])), c.integer(role === 'root' ? 1 : 0)));
      return [p.extension(oid, value, options.bcCritical ?? true)];
    }
    if (oid === '2.5.29.15' && Object.hasOwn(options, 'ku'))
      return options.ku === null ? [] : [p.extension(oid, options.ku, true)];
    return [node.raw];
  });
  fields[fields.length - 1] = c.der(0xa3, c.seq(...extensions));
  const tbs = c.seq(...fields),
    signatureValid = !options.wrongSigner;
  const certificate = p.certificateFromTBS(
    tbs,
    'ec',
    c.sign(tbs, keys[options.wrongSigner ? 'wrong' : signer].privateKey),
  );
  if (new X509Certificate(certificate).verify(keys[signer].publicKey) !== signatureValid)
    throw Error('Synthetic signature control: ' + id);
  raw[id] = certificate;
  certificates[id] = {
    der: certificate.toString('base64'),
    sha256: c.sha256(certificate).toString('hex'),
    expectedSignerSPKI: c.spki(keys[signer].publicKey).toString('base64'),
    signatureValid,
  };
  return id;
}
for (const role of ['root', 'ca', 'leaf']) issue(role, role);
const position = { leaf: 0, ca: 1, root: 2 };
function expected(accepted, error, statusCalls) {
  return { accepted, ...(!accepted && error ? { error } : {}), statusCalls };
}
function add(
  id,
  target,
  options,
  classification,
  accepted,
  error,
  count,
  anchorLookupRejects = false,
) {
  issue(id, target, options);
  const chain = ['leaf', 'ca', 'root'].map((role) => (role === target ? id : role));
  const included = expected(accepted, error, accepted ? 2 : count);
  const appended = anchorLookupRejects
    ? expected(false, 'KEY_ATTESTATION_UNTRUSTED_ROOT', 0)
    : { ...included };
  cases.push({
    id,
    target,
    classification,
    chain,
    root: chain.at(-1),
    expected: { included, appended },
  });
}
add('canonical-chain', 'leaf', {}, 'PRESERVED_ENCODING', true);
for (const target of ['leaf', 'ca', 'root']) {
  const bit = target === 'leaf' ? 128 : 4,
    unused = target === 'leaf' ? 7 : 2;
  for (const [label, bytes] of [
    ['one-role-bit', [unused, bit]],
    ['multiple-known-bits', target === 'leaf' ? [6, 192] : [1, 6]],
    ['ninth-bit-with-key-agreement', [7, bit | 8, 128]],
  ])
    add(
      target + '-ku-' + label,
      target,
      { ku: c.der(3, Buffer.from(bytes)) },
      'PRESERVED_ENCODING',
      true,
    );
  for (const [label, bytes, classification] of [
    ['trailing-zero-bits', [0, bit], 'DER_CANONICAL'],
    ['trailing-zero-octet', [0, bit, 0], 'DER_CANONICAL'],
    ['nonzero-unused-padding', [unused, bit | 1], 'DER_CANONICAL'],
    ['unsupported-bit-9', [6, bit, 64], 'PROFILE_LIMIT'],
    ['unsupported-bit-16', [7, bit, 0, 128], 'PROFILE_LIMIT'],
  ])
    add(
      target + '-ku-' + label,
      target,
      { ku: c.der(3, Buffer.from(bytes)) },
      classification,
      false,
      'KEY_ATTESTATION_KEY_USAGE',
      position[target],
    );
  for (const [label, value, classification] of [
    ['invalid-unused-count', c.der(3, Buffer.from([8, bit])), 'DER_STRUCTURE'],
    ['wrong-tag', c.der(4, Buffer.from([unused, bit])), 'DER_STRUCTURE'],
    [
      'missing-role-bit',
      c.der(3, Buffer.from(target === 'leaf' ? [5, 32] : [1, 2])),
      'ROLE_POLICY',
    ],
  ]) {
    const early = target !== 'leaf';
    const error = early
      ? 'KEY_ATTESTATION_CHAIN_SIGNATURE'
      : label === 'missing-role-bit'
        ? 'KEY_ATTESTATION_LEAF_USAGE'
        : 'KEY_ATTESTATION_KEY_USAGE';
    add(
      target + '-ku-' + label,
      target,
      { ku: value },
      classification,
      false,
      error,
      early ? position[target] - 1 : 0,
      early && (target === 'root' || label !== 'missing-role-bit'),
    );
  }
}
for (const target of ['ca', 'root'])
  for (const [label, value, early] of [
    ['true-one', c.seq(c.der(1, Buffer.from([1])), c.integer(1)), false],
    ['true-two', c.seq(c.der(1, Buffer.from([2])), c.integer(1)), false],
    ['two-path-lengths', c.seq(c.der(1, Buffer.from([255])), c.integer(1), c.integer(2)), true],
    [
      'wrong-container',
      c.der(0x31, Buffer.concat([c.der(1, Buffer.from([255])), c.integer(1)])),
      true,
    ],
    ['path-before-ca', c.seq(c.integer(1), c.der(1, Buffer.from([255]))), true],
    [
      'extra-null',
      c.seq(c.der(1, Buffer.from([255])), c.integer(1), c.der(5, Buffer.alloc(0))),
      true,
    ],
  ])
    add(
      target + '-bc-' + label,
      target,
      { bc: value },
      'DER_STRUCTURE',
      false,
      early ? 'KEY_ATTESTATION_CHAIN_SIGNATURE' : 'KEY_ATTESTATION_CA_CONSTRAINTS',
      position[target] - (early ? 1 : 0),
      early,
    );
add(
  'wrong-leaf-signature',
  'leaf',
  { wrongSigner: true },
  'SIGNATURE',
  false,
  'KEY_ATTESTATION_CHAIN_SIGNATURE',
  0,
);
for (const [id, target, value, classification, accepted, error, calls] of [
  ['leaf-bc-absent', 'leaf', null, 'PRESERVED_ENCODING', true],
  ['leaf-bc-empty', 'leaf', c.seq(), 'PRESERVED_ENCODING', true],
  ['ca-bc-no-path', 'ca', c.seq(c.der(1, Buffer.from([255]))), 'PRESERVED_ENCODING', true],
  ['root-bc-no-path', 'root', c.seq(c.der(1, Buffer.from([255]))), 'PRESERVED_ENCODING', true],
  [
    'leaf-bc-explicit-default-false',
    'leaf',
    c.seq(c.der(1, Buffer.from([0]))),
    'DER_CANONICAL',
    false,
    'KEY_ATTESTATION_CA_CONSTRAINTS',
    0,
  ],
  [
    'leaf-bc-false-with-path',
    'leaf',
    c.seq(c.der(1, Buffer.from([0])), c.integer(0)),
    'DER_CANONICAL_AND_PROFILE_SHAPE',
    false,
    'KEY_ATTESTATION_CA_CONSTRAINTS',
    0,
  ],
  [
    'leaf-bc-path-without-ca',
    'leaf',
    c.seq(c.integer(0)),
    'PROFILE_SHAPE',
    false,
    'KEY_ATTESTATION_CA_CONSTRAINTS',
    0,
  ],
  [
    'leaf-bc-true-one',
    'leaf',
    c.seq(c.der(1, Buffer.from([1]))),
    'DER_CANONICAL',
    false,
    'KEY_ATTESTATION_CA_CONSTRAINTS',
    0,
  ],
  [
    'ca-bc-negative-path',
    'ca',
    c.seq(c.der(1, Buffer.from([255])), c.der(2, Buffer.from([255]))),
    'PROFILE_SHAPE',
    false,
    'KEY_ATTESTATION_CHAIN_SIGNATURE',
    0,
  ],
  [
    'ca-bc-padded-path',
    'ca',
    c.seq(c.der(1, Buffer.from([255])), c.der(2, Buffer.from([0, 0]))),
    'DER_CANONICAL',
    false,
    'KEY_ATTESTATION_CHAIN_SIGNATURE',
    0,
  ],
  [
    'ca-bc-two-byte-true',
    'ca',
    c.seq(c.der(1, Buffer.from([255, 255]))),
    'DER_STRUCTURE',
    false,
    'KEY_ATTESTATION_CHAIN_SIGNATURE',
    0,
  ],
])
  add(
    id,
    target,
    { bc: value },
    classification,
    accepted,
    error,
    calls,
    target === 'ca' && error === 'KEY_ATTESTATION_CHAIN_SIGNATURE',
  );
for (const boolean of [255, 1])
  for (const critical of [true, false])
    for (const keyCertSign of [false, true]) {
      const accepted = boolean === 255 && !keyCertSign;
      add(
        'leaf-bc-role-' + boolean + '-' + critical + '-' + keyCertSign,
        'leaf',
        {
          bc: c.seq(c.der(1, Buffer.from([boolean]))),
          bcCritical: critical,
          ku: c.der(3, Buffer.from(keyCertSign ? [2, 132] : [7, 128])),
        },
        boolean === 255 ? 'PRESERVED_NATIVE_ROLE' : 'DER_CANONICAL',
        accepted,
        boolean === 255 ? 'KEY_ATTESTATION_LEAF_USAGE' : 'KEY_ATTESTATION_CA_CONSTRAINTS',
        0,
      );
    }
for (const target of ['leaf', 'ca', 'root'])
  add(
    target + '-ku-absent',
    target,
    { ku: null },
    'REQUIRED_EXTENSION',
    false,
    'KEY_ATTESTATION_KEY_USAGE',
    position[target],
  );
for (const [label, bc, error] of [
  [
    'negative-path',
    c.seq(c.der(1, Buffer.from([255])), c.der(2, Buffer.from([255]))),
    'EXPECTED_UINT',
  ],
  [
    'padded-path',
    c.seq(c.der(1, Buffer.from([255])), c.der(2, Buffer.from([0, 0]))),
    'DER_INTEGER',
  ],
  ['two-byte-true', c.seq(c.der(1, Buffer.from([255, 255]))), 'KEY_ATTESTATION_CA_CONSTRAINTS'],
  [
    'wrong-container',
    c.der(0x31, Buffer.concat([c.der(1, Buffer.from([255])), c.integer(0)])),
    'KEY_ATTESTATION_CA_CONSTRAINTS',
  ],
  [
    'two-paths',
    c.seq(c.der(1, Buffer.from([255])), c.integer(0), c.integer(1)),
    'KEY_ATTESTATION_CA_CONSTRAINTS',
  ],
  [
    'extra-null',
    c.seq(c.der(1, Buffer.from([255])), c.integer(0), c.der(5, Buffer.alloc(0))),
    'KEY_ATTESTATION_CA_CONSTRAINTS',
  ],
  [
    'two-booleans',
    c.seq(c.der(1, Buffer.from([255])), c.der(1, Buffer.from([255]))),
    'KEY_ATTESTATION_CA_CONSTRAINTS',
  ],
])
  add(
    'leaf-bc-' + label,
    'leaf',
    { bc },
    label === 'negative-path' ? 'PROFILE_SHAPE' : 'DER_STRUCTURE',
    false,
    error,
    0,
  );

const android = androidFixture(
  keys.leaf.publicKey,
  challenge,
  {},
  {
    publicKey: keys.ca.publicKey,
    privateKey: keys.ca.privateKey,
    certificate: raw.ca,
    subject: names.ca,
  },
);
const androidExtensions = [...p.parseCertificate(android.evidence.x5c[0]).extensions]
  .filter(([oid]) => !['2.5.29.19', '2.5.29.15', '2.5.29.14', '2.5.29.37'].includes(oid))
  .map(([oid, ext]) => p.extension(oid, ext.value, ext.critical));
issue('android-leaf', 'leaf', { extensions: androidExtensions });
issue('android-leaf-bad-ku', 'leaf', {
  extensions: androidExtensions,
  ku: c.der(3, Buffer.from([0, 128])),
});
const androidPolicy = { ...android.policy.formats['android-key'] };
delete androidPolicy.roots;
delete androidPolicy.status;
const androidCases = [
  {
    id: 'android-valid',
    chain: ['android-leaf', 'ca', 'root'],
    expected: expected(true, null, 2),
  },
  {
    id: 'android-leaf-ku',
    chain: ['android-leaf-bad-ku', 'ca', 'root'],
    expected: expected(false, 'KEY_ATTESTATION_KEY_USAGE', 0),
  },
  {
    id: 'android-ca-ku',
    chain: ['android-leaf', 'ca-ku-trailing-zero-bits', 'root'],
    expected: expected(false, 'KEY_ATTESTATION_KEY_USAGE', 1),
  },
  {
    id: 'android-ca-bc',
    chain: ['android-leaf', 'ca-bc-true-one', 'root'],
    expected: expected(false, 'KEY_ATTESTATION_CA_CONSTRAINTS', 1),
  },
  {
    id: 'android-root-ku',
    chain: ['android-leaf', 'ca', 'root-ku-unsupported-bit-9'],
    expected: expected(false, 'KEY_ATTESTATION_KEY_USAGE', 2),
  },
  {
    id: 'android-challenge',
    chain: ['android-leaf', 'ca', 'root'],
    challenge: 'different',
    expected: expected(false, 'KEY_ATTESTATION_CHALLENGE', 2),
  },
];
for (const row of androidCases) row.root = row.chain.at(-1);
const origin = 'https://website.example',
  rpID = 'website.example',
  version = 'previewSign5-2026-09-09';
const fixture = examplePasskey({ origin, rpID, version }),
  generationChallenge = c.random();
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
const attestor = {
  publicKey: new X509Certificate(fixture.attestationCertificate).publicKey,
};
issue('pscp-leaf', 'leaf', { key: attestor, extensions: [] });
issue('pscp-leaf-bad-ku', 'leaf', {
  key: attestor,
  extensions: [],
  ku: c.der(3, Buffer.from([0, 128])),
});
function replaceChain(bytes, ids) {
  const object = decode(bytes);
  object.get('attStmt').set(
    'x5c',
    ids.map((id) => raw[id]),
  );
  return encode(object);
}
const good = ['pscp-leaf', 'ca', 'root'],
  badKU = ['pscp-leaf-bad-ku', 'ca', 'root'],
  badBC = ['pscp-leaf', 'ca-bc-true-one', 'root'];
const pscp = [];
for (const [id, child, parent, accepted, error, childCalls, parentCalls] of [
  ['pscp-valid', good, good, true, null, 2, 2],
  ['pscp-child-ku', badKU, good, false, 'KEY_ATTESTATION_KEY_USAGE', 0, 0],
  ['pscp-parent-ku', good, badKU, false, 'KEY_ATTESTATION_KEY_USAGE', 2, 0],
  ['pscp-child-bc', badBC, good, false, 'KEY_ATTESTATION_CA_CONSTRAINTS', 1, 0],
  ['pscp-parent-bc', good, badBC, false, 'KEY_ATTESTATION_CA_CONSTRAINTS', 2, 1],
]) {
  const ceremony = structuredClone(generated.registration);
  ceremony.response.attestationObject = c.b64u(
    replaceChain(c.unb64u(ceremony.response.attestationObject), parent),
  );
  const generatedKey = Object.fromEntries(
    Object.entries(generated.key).map(([name, value]) => [
      name,
      name === 'algorithm' ? value : Buffer.from(value).toString('base64'),
    ]),
  );
  generatedKey.attestationObject = replaceChain(
    Buffer.from(generated.key.attestationObject),
    child,
  ).toString('base64');
  pscp.push({
    id,
    ceremony,
    generatedKey,
    childChain: child,
    parentChain: parent,
    challenge: generationChallenge.toString('base64'),
    origin,
    rpID,
    version,
    algorithms: [-9],
    root: 'root',
    expected: { accepted, error, childCalls, parentCalls },
    model: {
      ...fixture.attestationPolicy.models[0],
      aaguid: fixture.aaguid.toString('base64'),
      rootHash: c.sha256(raw.root).toString('base64'),
      expiresAt: at + 3600,
    },
  });
}
const corpus = {
  format: 'certconcord-attestation-extension-admission-v1',
  qualification: 'SYNTHETIC_CONTROLLED_ROOTS_ONLY',
  contract:
    'Canonical KU encoding with supported bits 0..8; bounded BC empty or canonical TRUE with optional nonnegative path; native role policy retained. Unsupported KU bits and path-only BC are profile limits, not DER encoding errors alone.',
  at,
  challenge,
  holderSPKI: c.spki(keys.leaf.publicKey).toString('base64'),
  apple: { osOID, os: os.toString('base64') },
  certificates,
  cases,
  android: { policy: androidPolicy, cases: androidCases },
  pscp,
};
const destination =
  process.argv[2] ??
  new URL('../reference/vectors/attestation-extension-admission.json', import.meta.url);
fs.writeFileSync(destination, JSON.stringify(corpus, null, 2) + '\n');
console.log(
  JSON.stringify({
    certificates: Object.keys(certificates).length,
    cases: cases.length,
    android: androidCases.length,
    pscp: pscp.length,
  }),
);
