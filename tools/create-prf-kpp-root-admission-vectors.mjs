import fs from 'node:fs';
import * as crypto from 'node:crypto';
import { D, dcbor } from '../reference/core.mjs';

// Native cryptographic fixture producer; only domain framing/CBOR is shared.
const random = crypto.randomBytes;
const key = (prf, h, label) =>
  Buffer.from(crypto.hkdfSync('sha256', prf, h.kdfSalt, D(label, h), 32));
const header = (aead) => ({
  schemaVersion: 1,
  trustDomainID: random(32),
  subjectID: random(32),
  credentialIDHash: random(32),
  rpID: 'prf-root-admission.example',
  purpose: 'ACCOUNT_WRAP',
  epoch: 0,
  contextID: random(32),
  prfSalt: random(32),
  wrapperID: random(32),
  kdfSalt: random(32),
  kdf: 'HKDF-SHA-256',
  aead,
  amkVersion: 1,
});
function tag(prf, h, ciphertext) {
  const m = key(prf, h, 'WrapperMACKey');
  try {
    return crypto
      .createHmac('sha256', m)
      .update(D('WrapperMAC', { header: h, ciphertext }))
      .digest();
  } finally {
    m.fill(0);
  }
}
function envelope(prf, root, h) {
  const k = key(prf, h, 'WrapperKDF');
  try {
    if (h.aead === 'AES-256-GCM') {
      const nonce = random(12),
        c = crypto.createCipheriv('aes-256-gcm', k, nonce);
      c.setAAD(D('WrapperAAD', h));
      return {
        schemaVersion: 1,
        header: h,
        nonce,
        ciphertext: Buffer.concat([c.update(root), c.final()]),
        tag: c.getAuthTag(),
      };
    }
    const padded = h.aead === 'AES-256-KWP';
    const c = crypto.createCipheriv(
      padded ? 'id-aes256-wrap-pad' : 'id-aes256-wrap',
      k,
      padded ? Buffer.from('a65959a6', 'hex') : Buffer.alloc(8, 0xa6),
    );
    const ciphertext = Buffer.concat([c.update(root), c.final()]);
    return { schemaVersion: 1, header: h, ciphertext, tag: tag(prf, h, ciphertext) };
  } finally {
    k.fill(0);
  }
}
const cases = [];
function add(algorithm, length, kind = 'authenticated') {
  const prf = random(32),
    root = random(length),
    wrapper = envelope(prf, root, header(algorithm));
  if (kind.includes('integrity')) {
    wrapper.ciphertext[0] ^= 1;
    wrapper.tag = tag(prf, wrapper.header, wrapper.ciphertext);
  }
  if (kind.includes('tag')) wrapper.tag[0] ^= 1;
  const wire = dcbor(wrapper);
  cases.push({
    id: algorithm + '-' + length + '-' + kind,
    algorithm,
    kind,
    syntheticPRF: prf.toString('hex'),
    syntheticRoot: root.toString('hex'),
    wire: wire.toString('base64'),
    bytes: wire.length,
    sha256: crypto.createHash('sha256').update(wire).digest('hex'),
  });
}
for (const [algorithm, lengths] of [
  ['AES-256-GCM', [0, 1, 31, 32, 33]],
  ['AES-256-KW', [16, 24, 32, 40]],
  ['AES-256-KWP', [1, 31, 32, 33]],
])
  for (const length of lengths) add(algorithm, length);
for (const [algorithm, length] of [
  ['AES-256-GCM', 31],
  ['AES-256-KW', 16],
  ['AES-256-KWP', 1],
]) {
  add(algorithm, length, 'bad-tag');
  if (algorithm !== 'AES-256-GCM') {
    add(algorithm, length, 'bad-integrity');
    add(algorithm, length, 'bad-tag-and-integrity');
  }
}
fs.writeFileSync(
  new URL('../reference/vectors/prf-kpp-root-admission.json', import.meta.url),
  JSON.stringify(
    {
      schema: 'certconcord-prf-kpp-root-admission-v1',
      description:
        'Synthetic authenticated root boundaries and separated authentication failures. Native crypto producer; shared D/CBOR framing.',
      cases,
    },
    null,
    2,
  ) + '\n',
  { flag: 'wx' },
);
console.log(JSON.stringify({ cases: cases.length }));
