import fs from 'node:fs';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify, X509Certificate } from 'node:crypto';

// Fresh synthetic keys exist only during generation. No private key is serialized.
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
function tlv(tag, value) {
  const bytes = Buffer.from(value);
  let length;
  if (bytes.length < 128) length = Buffer.from([bytes.length]);
  else {
    const octets = [];
    for (let n = bytes.length; n; n >>>= 8) octets.unshift(n & 255);
    length = Buffer.from([128 | octets.length, ...octets]);
  }
  return Buffer.concat([Buffer.from([tag]), length, bytes]);
}
const seq = (...values) => tlv(0x30, Buffer.concat(values));
const set = (...values) => tlv(0x31, Buffer.concat(values));
const bit = (value) => tlv(3, Buffer.concat([Buffer.from([0]), value]));
const alg = Buffer.from('300a06082a8648ce3d040302', 'hex');
const extensionRequest = Buffer.from('06092a864886f70d01090e', 'hex');
const sanOID = Buffer.from('0603551d11', 'hex');
const name = (value) =>
  seq(set(seq(Buffer.from('0603550403', 'hex'), tlv(12, Buffer.from(value)))));
const pair = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const issuer = pair(),
  holder = pair();
const holderSPKI = holder.publicKey.export({ format: 'der', type: 'spki' });
const issuerSPKI = issuer.publicKey.export({ format: 'der', type: 'spki' });
const subject = name('Synthetic ACME DNS Subject');
const issuerName = name('Synthetic ACME DNS Issuer');
const alpha = 'alpha.example.invalid',
  beta = 'beta.example.invalid';
const dns = (value) => ({ tag: 0x82, value: Buffer.from(value) });
function high(value, index) {
  const b = Buffer.from(value);
  b[index] |= 0x80;
  return { tag: 0x82, value: b };
}
const definitions = [
  { id: 'ascii-single', identifiers: [alpha], names: [dns(alpha)], expected: 'valid' },
  {
    id: 'ascii-multiple-reordered',
    identifiers: [alpha, beta],
    names: [dns(beta), dns(alpha)],
    expected: 'valid',
  },
  {
    id: 'ascii-idna-alabel',
    identifiers: ['xn--bcher-kva.example.invalid'],
    names: [dns('xn--bcher-kva.example.invalid')],
    expected: 'valid',
  },
  { id: 'different-signed-dns', identifiers: [alpha], names: [dns(beta)] },
  { id: 'joined-name-alias', identifiers: [alpha, beta], names: [dns(alpha + ',' + beta)] },
  { id: 'high-bit-first-byte', identifiers: [alpha], names: [high(alpha, 0)] },
  { id: 'high-bit-interior-byte', identifiers: [alpha], names: [high(alpha, 2)] },
  { id: 'high-bit-label-separator', identifiers: [alpha], names: [high(alpha, 5)] },
  {
    id: 'high-bit-later-general-name',
    identifiers: [alpha, beta],
    names: [dns(alpha), high(beta, 0)],
  },
  {
    id: 'high-byte-ff',
    identifiers: [alpha],
    names: [{ tag: 0x82, value: Buffer.concat([Buffer.from([255]), Buffer.from(alpha.slice(1))]) }],
  },
  {
    id: 'high-byte-80',
    identifiers: [alpha],
    names: [{ tag: 0x82, value: Buffer.concat([Buffer.from([128]), Buffer.from(alpha.slice(1))]) }],
  },
  {
    id: 'ascii-7f-not-ordered-name',
    identifiers: [alpha],
    names: [{ tag: 0x82, value: Buffer.concat([Buffer.from([127]), Buffer.from(alpha.slice(1))]) }],
  },
  { id: 'empty-dns-name', identifiers: [alpha], names: [dns('')] },
  { id: 'missing-san', identifiers: [alpha], names: null },
  { id: 'empty-san-sequence', identifiers: [alpha], names: [] },
  {
    id: 'non-dns-general-name',
    identifiers: [alpha],
    names: [{ tag: 0x81, value: Buffer.from(alpha) }],
  },
  { id: 'duplicate-dns-name', identifiers: [alpha], names: [dns(alpha), dns(alpha)] },
  { id: 'extra-dns-name', identifiers: [alpha], names: [dns(alpha), dns(beta)] },
];
const vectors = definitions.map((definition, index) => {
  const san =
    definition.names === null ? null : seq(...definition.names.map((n) => tlv(n.tag, n.value)));
  const extensions = san === null ? [] : [seq(sanOID, tlv(4, san))];
  const info = seq(
    Buffer.from('020100', 'hex'),
    subject,
    holderSPKI,
    tlv(0xa0, extensions.length ? seq(extensionRequest, set(seq(...extensions))) : Buffer.alloc(0)),
  );
  const signature = sign('sha256', info, holder.privateKey);
  assert(verify('sha256', info, holder.publicKey, signature));
  const csr = seq(info, alg, bit(signature));
  const tbs = seq(
    Buffer.from('a003020102', 'hex'),
    tlv(2, Buffer.from([index + 1])),
    alg,
    issuerName,
    seq(tlv(23, Buffer.from('260101000000Z')), tlv(23, Buffer.from('270101000000Z'))),
    subject,
    holderSPKI,
    ...(extensions.length ? [tlv(0xa3, seq(...extensions))] : []),
  );
  const certificate = seq(tbs, alg, bit(sign('sha256', tbs, issuer.privateKey)));
  const native = new X509Certificate(certificate);
  assert(native.verify(issuer.publicKey));
  assert.deepEqual(native.publicKey.export({ format: 'der', type: 'spki' }), holderSPKI);
  return {
    id: definition.id,
    identifiers: definition.identifiers,
    expected: definition.expected ?? 'ACME_CSR_IDENTIFIERS',
    generalNames:
      definition.names?.map((n) => ({ tag: n.tag, valueHex: n.value.toString('hex') })) ?? null,
    sanDERHex: san?.toString('hex') ?? null,
    csrDERBase64: csr.toString('base64'),
    csrSHA256: sha256(csr),
    csrInfoSHA256: sha256(info),
    certificateDERBase64: certificate.toString('base64'),
    certificateSHA256: sha256(certificate),
  };
});
const output =
  process.argv[2] ?? new URL('../reference/vectors/acme-dns-ia5.json', import.meta.url);
const packet = {
  format: 'certconcord-acme-dns-ia5-v1',
  scope:
    'Synthetic signed CSR GeneralName octets and matching synthetic certificates. No DNS control, RA, CA, or production qualification is implied.',
  holderSPKIBase64: holderSPKI.toString('base64'),
  issuerSPKIBase64: issuerSPKI.toString('base64'),
  vectors,
};
fs.writeFileSync(output, JSON.stringify(packet, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ vectors: vectors.length, sha256: sha256(fs.readFileSync(output)) }));
