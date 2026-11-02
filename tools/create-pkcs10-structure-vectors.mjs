import fs from 'node:fs';
import assert from 'node:assert/strict';
import * as c from '../reference/core.mjs';
import * as p from '../reference/pki.mjs';
import { createCSR } from '../reference/enrollment.mjs';

const holder = c.generate('ml-dsa-65'), wrong = c.generate('ml-dsa-65');
const subject = p.name('Synthetic CSR Structure Subject'), at = 1800000000;
const attribute = p.attribute('1.2.840.113549.1.9.7', c.der(12, Buffer.from('synthetic')));
const direct = createCSR({ subject, ...holder, attributes: [attribute] });
const [info, algorithm, signature] = c.parseDER(direct).children;
const retag = (raw, tag) => { const copy = Buffer.from(raw); copy[0] = tag; return copy; };
const infoWith = (info, index, replacement) => c.seq(...info.children.map((row, i) => i === index ? replacement : row.raw));
const signed = (info, key = holder.privateKey, alg = algorithm.raw) => c.seq(info, alg, c.bit(c.sign(info, key)));
const directInfo = (index, replacement) => signed(infoWith(info, index, replacement));
const attrs = (...rows) => c.der(0xa0, c.parseDER(c.set(...rows)).value);
const [attrOID, attrValues] = c.parseDER(attribute).children;
const nameATV = c.parseDER(subject).children[0].children[0];
const nameWith = raw => directInfo(1, raw);
const changedSignature = Buffer.from(signature.value); changedSignature[5] ^= 1;
const keys = {}, rows = [];
const encode = bytes => ({ base64: bytes.toString('base64'), bytes: bytes.length, sha256: c.sha256(bytes).toString('hex') });
const publicKey = (id, key) => { keys[id] = encode(c.spki(key)); };
publicKey('holder', holder.publicKey); publicKey('wrong', wrong.publicKey);
function add(id, raw, { accepted = false, error, signer = 'holder', signatureValid = true, mode = 'DIRECT_SIGNATURE', policyCalls = 0, ...options } = {}) {
  rows.push({ id, raw: encode(raw), signer, expected: { accepted, ...(error ? { error } : {}), signatureValid, mode, policyCalls }, ...options });
}
add('direct/valid', direct, { accepted: true });
for (const [id, raw] of [
  ['outer-context', retag(direct, 0xa3)],
  ['info-context', signed(retag(info.raw, 0xa3))],
  ['signature-octet', c.seq(info.raw, algorithm.raw, retag(signature.raw, 4))],
  ['outer-primitive', retag(direct, 4)],
  ['info-primitive', signed(retag(info.raw, 4))],
  ['algorithm-context', c.seq(info.raw, retag(algorithm.raw, 0xa3), signature.raw)],
]) add('direct/' + id, raw, { error: 'CSR_STRUCTURE', signatureValid: id === 'outer-primitive' ? null : true });
for (const [id, raw] of [
  ['name-context', retag(subject, 0xa3)],
  ['rdn-context', c.seq(retag(c.parseDER(subject).children[0].raw, 0xa1))],
  ['rdn-empty', c.seq(c.set())],
  ['atv-context', c.seq(c.set(retag(nameATV.raw, 0xa1)))],
  ['atv-missing-value', c.seq(c.set(c.seq(nameATV.children[0].raw)))],
  ['atv-extra-value', c.seq(c.set(c.seq(...nameATV.children.map(n => n.raw), c.octet(Buffer.from('extra')))))],
  ['atv-relative-oid', c.seq(c.set(c.seq(retag(nameATV.children[0].raw, 13), nameATV.children[1].raw)))],
]) add('direct/' + id, nameWith(raw), { error: 'CSR_SUBJECT_STRUCTURE' });
for (const [id, oid, error] of [
  ['atv-empty-oid', c.der(6, Buffer.alloc(0)), 'BAD_OID'],
  ['atv-unterminated-oid', c.der(6, Buffer.from([0x81])), 'BAD_OID'],
]) add('direct/' + id, nameWith(c.seq(c.set(c.seq(oid, nameATV.children[1].raw)))), { error });
for (const [id, raw] of [
  ['attribute-context', retag(attribute, 0xa1)],
  ['attribute-values-context', c.seq(attrOID.raw, retag(attrValues.raw, 0xa1))],
  ['attribute-relative-oid', c.seq(retag(attrOID.raw, 13), attrValues.raw)],
  ['attribute-extra-member', c.seq(attrOID.raw, attrValues.raw, c.octet(Buffer.from('extra')))],
]) add('direct/' + id, directInfo(3, attrs(raw)), { error: 'CSR_ATTRIBUTE_STRUCTURE' });
for (const [id, raw] of [
  ['empty-name', c.seq()],
  ['two-rdns', c.seq(...c.parseDER(subject).children.map(n => n.raw), ...c.parseDER(p.name('Second RDN')).children.map(n => n.raw))],
  ['multi-valued-rdn', c.seq(c.set(nameATV.raw, c.seq(c.oid('2.5.4.10'), c.der(12, Buffer.from('Synthetic Organization')))))],
  ['unknown-name-oid-open-value', c.seq(c.set(c.seq(c.oid('1.2.3.4'), c.octet(Buffer.from('opaque')))))],
]) add('direct/' + id, nameWith(raw), { accepted: true });
add('direct/no-attributes', directInfo(3, attrs()), { accepted: true });
add('direct/duplicate-attribute', directInfo(3, attrs(attribute, attribute)), { error: 'CSR_DUPLICATE_ATTRIBUTE' });
add('direct/multiple-attribute-values', directInfo(3, attrs(c.seq(attrOID.raw, c.set(c.der(12, Buffer.from('a')), c.der(12, Buffer.from('b')))))), { error: 'CSR_DUPLICATE_ATTRIBUTE' });
add('direct/empty-attribute-values', directInfo(3, attrs(c.seq(attrOID.raw, c.set()))), { error: 'CSR_DUPLICATE_ATTRIBUTE' });
add('direct/attributes-context1', directInfo(3, retag(info.children[3].raw, 0xa1)), { error: 'CSR_ATTRIBUTES' });
add('direct/version-one', directInfo(0, c.integer(1)), { error: 'CSR_STRUCTURE' });
add('direct/spki-context', directInfo(2, retag(info.children[2].raw, 0xa1)));
add('direct/wrong-signature', c.seq(info.raw, algorithm.raw, c.der(3, changedSignature)), { error: 'CSR_SIGNATURE', signatureValid: false });
add('direct/wrong-signing-key', signed(info.raw, wrong.privateKey), { error: 'CSR_SIGNATURE', signatureValid: false });
add('direct/info-not-resigned', c.seq(infoWith(info, 1, p.name('Changed Subject')), algorithm.raw, signature.raw), { error: 'CSR_SIGNATURE', signatureValid: false });
add('direct/wrong-algorithm', c.seq(info.raw, p.algID('ml-dsa-87'), signature.raw), { error: 'CSR_SIGNATURE' });
add('direct/unused-bits', c.seq(info.raw, algorithm.raw, c.der(3, Buffer.concat([Buffer.from([1]), signature.value.subarray(1)]))), { error: 'CSR_SIGNATURE' });
add('direct/truncated', direct.subarray(0, direct.length - 1), { signatureValid: null });
add('direct/expected-subject-mismatch', direct, { error: 'CSR_SUBJECT', expectedSubject: encode(p.name('Different Subject')) });
add('direct/expected-spki-mismatch', direct, { error: 'CSR_SPKI', expectedSPKI: keys.wrong });
for (const alg of ['ml-dsa-87', 'ec', 'ed25519']) {
  const pair = c.generate(alg); publicKey(alg, pair.publicKey);
  add('direct/valid-' + alg, createCSR({ subject, ...pair }), { accepted: true, signer: alg });
}

const issuer = c.generate('ml-dsa-87'), kem = c.generate('ml-kem-768');
publicKey('issuer', issuer.publicKey);
const certificate = p.issueCertificate({ publicKey: holder.publicKey, subject, issuer: p.name('Synthetic Possession Issuer'), serial: 7, notBefore: at - 60, notAfter: at + 86400 }, issuer.privateKey);
const statement = createCSR({ subject, publicKey: kem.publicKey, privateKey: holder.privateKey, possessionCertificate: certificate });
const [ki, ka, ks] = c.parseDER(statement).children, possession = ki.children[3].children[0];
const ksign = raw => signed(raw, holder.privateKey, ka.raw);
const kinfo = (index, raw) => ksign(infoWith(ki, index, raw));
const badStatementSignature = Buffer.from(ks.value); badStatementSignature[5] ^= 1;
const stmt = (id, raw, options) => add('statement/' + id, raw, { mode: 'SIGNED_STATEMENT', ...options });
stmt('valid', statement, { accepted: true, policyCalls: 1 });
stmt('outer-context', retag(statement, 0xa3), { error: 'CSR_STRUCTURE' });
stmt('info-context', ksign(retag(ki.raw, 0xa3)), { error: 'CSR_STRUCTURE' });
stmt('signature-octet', c.seq(ki.raw, ka.raw, retag(ks.raw, 4)), { error: 'CSR_STRUCTURE' });
stmt('attribute-context', kinfo(3, attrs(retag(possession.raw, 0xa1))), { error: 'CSR_ATTRIBUTE_STRUCTURE' });
stmt('values-context', kinfo(3, attrs(c.seq(possession.children[0].raw, retag(possession.children[1].raw, 0xa1)))), { error: 'CSR_ATTRIBUTE_STRUCTURE' });
stmt('name-context', kinfo(1, retag(subject, 0xa3)), { error: 'CSR_SUBJECT_STRUCTURE' });
stmt('wrong-signature', c.seq(ki.raw, ka.raw, c.der(3, badStatementSignature)), { error: 'CSR_SIGNATURE', signatureValid: false, policyCalls: 1 });
stmt('trust-rejected', statement, { error: 'CSR_POSSESSION_TRUST', policyCalls: 1, trust: false });
for (const row of rows) {
  let valid = null;
  try { const [i,,s] = c.parseDER(Buffer.from(row.raw.base64, 'base64')).children; valid = c.verify(i.raw, s.value.subarray(1), c.publicFromDER(Buffer.from(keys[row.signer].base64, 'base64'))); } catch {}
  assert.equal(valid, row.expected.signatureValid, row.id);
}
const corpus = { schemaVersion: 1, profile: 'PKCS10 typed admission draft reference', at, keys, certificate: encode(certificate), cases: rows };
const output = process.argv[2] ?? new URL('../reference/vectors/pkcs10-structure.json', import.meta.url);
fs.writeFileSync(output, JSON.stringify(corpus, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ cases: rows.length, keys: Object.keys(keys).length }));
