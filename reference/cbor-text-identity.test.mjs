import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, X509Certificate } from 'node:crypto';
import { dcbor, decodeCBOR } from './core.mjs';
import { encode, decode, get } from './cose.mjs';
import { issuerCertificate, verifyIssuerSigned } from './mdoc.mjs';

const vectors = JSON.parse(readFileSync(new URL('../spec/external/mdoc-signing/vectors/cbor-text.json', import.meta.url)));
const raw = hex => Buffer.from(hex, 'hex');
for (const codec of [
  { name: 'DCBOR', encode: dcbor, decode: decodeCBOR, duplicate: 'CBOR_MAP_ORDER_OR_DUPLICATE', text: 'NONCANONICAL_TEXT', size: 'SIZE_LIMIT' },
  { name: 'Pinned mdoc CBOR', encode, decode, duplicate: 'CBOR_DUPLICATE', text: 'CBOR_TEXT', size: 'CBOR_SIZE' },
]) {
  for (const row of vectors.text) test(codec.name + ' text preserves code points: ' + row.id, () => {
    assert.equal(codec.decode(raw(row.hex)), row.value);
    assert.deepEqual(codec.encode(row.value), raw(row.hex));
  });
  test(codec.name + ' preserves every nested string and opaque byte string', () => {
    assert.deepEqual(codec.decode(raw(vectors.nested.hex)), vectors.nested.value);
    assert.deepEqual(codec.encode(vectors.nested.value), raw(vectors.nested.hex));
    assert.deepEqual(codec.decode(raw(vectors.opaque.hex)), raw(vectors.opaque.valueHex));
    assert.deepEqual(codec.encode(raw(vectors.opaque.valueHex)), raw(vectors.opaque.hex));
  });
  for (const row of vectors.duplicateMaps) test(codec.name + ' rejects duplicate text keys: ' + row.id, () => {
    assert.throws(() => codec.decode(raw(row.hex)), { code: codec.duplicate });
  });
  for (const row of vectors.invalidUTF8) test(codec.name + ' text rejects malformed UTF-8: ' + row.id, () => {
    assert.throws(() => codec.decode(raw(row.hex)), { code: 'ERR_ENCODING_INVALID_ENCODED_DATA' });
  });
  for (const row of vectors.invalidUTF16) test(codec.name + ' text rejects lone UTF-16 surrogate: ' + row.id, () => {
    assert.throws(() => codec.encode(row.value), { code: codec.text });
  });
  test(codec.name + ' text rejects truncated payload', () => {
    assert.throws(() => codec.decode(raw(vectors.truncated.hex)), { code: 'CBOR_TRUNCATED' });
  });
  test(codec.name + ' text retains byte and item budgets', () => {
    assert.equal(codec.decode(raw('64efbbbf41'), { maxBytes: 5, maxItems: 1 }), '\ufeffA');
    assert.throws(() => codec.decode(raw('64efbbbf41'), { maxBytes: 4 }), { code: codec.size });
    assert.deepEqual(codec.decode(raw(vectors.nested.hex), { maxItems: 5 }), vectors.nested.value);
    assert.throws(() => codec.decode(raw(vectors.nested.hex), { maxItems: 4 }), { code: 'CBOR_ITEM_BUDGET' });
  });
}
for (const row of vectors.maps) test('Pinned mdoc CBOR map preserves exact keys: ' + row.id, () => {
  const expected = new Map(row.entries), actual = decode(raw(row.hex));
  assert.deepEqual(actual, expected);
  assert.equal(actual.size, row.entries.length);
  assert.deepEqual(encode(expected), raw(row.hex));
});
test('Pinned mdoc CBOR lookup does not alias a BOM-prefixed key', () => {
  const map = decode(raw('a167efbbbf726f6c656178'));
  assert.equal(get(map, '\ufeffrole'), 'x');
  assert.equal(map.has('role'), false);
  assert.throws(() => get(map, 'role'), { code: 'CBOR_FIELD_role' });
});
test('DCBOR rejects non-NFC text', () => {
  assert.throws(() => dcbor(vectors.nonNFC.value), { code: 'NONCANONICAL_TEXT' });
  assert.throws(() => decodeCBOR(raw(vectors.nonNFC.hex)), { code: 'NONCANONICAL_TEXT' });
});
test('DCBOR retains ASCII-only map keys without aliasing BOM-prefixed names', () => {
  assert.deepEqual(decodeCBOR(raw('a164726f6c656178')), Object.assign(Object.create(null), { role: 'x' }));
  for (const row of vectors.maps.filter(row => row.id !== 'ordinary')) {
    assert.throws(() => dcbor(Object.fromEntries(row.entries)), { code: 'NONASCII_KEY' });
    assert.throws(() => decodeCBOR(raw(row.hex)), { code: 'NONASCII_KEY' });
  }
});

test('CBOR trailing-byte policy remains explicit for BOM-prefixed text', () => {
  const input = raw('64efbbbf4100');
  assert.deepEqual(decode(input, { allowTrailing: true }), { value: '\ufeffA', bytesRead: 5 });
  assert.throws(() => decode(input), { code: 'CBOR_TRAILING' });
  assert.throws(() => decodeCBOR(input), { code: 'NONCANONICAL_CBOR' });
});

const documentBytes = Buffer.from(readFileSync(new URL('./vectors/document-acceptance-mtc07-rar2-mdoc2/files/42f0563cb513a04c0c1d325d4730ababfe7cce1deb3e0a33cf30cfdab20e32d0.cbor.b64', import.meta.url), 'utf8').trim(), 'base64');
assert.equal(createHash('sha256').update(documentBytes).digest('hex'), '42f0563cb513a04c0c1d325d4730ababfe7cce1deb3e0a33cf30cfdab20e32d0');
const retainedCredential = decodeCBOR(documentBytes).objects.find(item => item.type === 'PersonalMdoc').payload;
for (const row of vectors.outerFields) test('Framework IssuerSigned rejects BOM-prefixed outer field: ' + row.name, () => {
  const credential = Buffer.from(retainedCredential), certificate = issuerCertificate(credential);
  const options = { issuerKey: new X509Certificate(certificate).publicKey, certificate,
    docType: 'org.certconcord.signer.1', at: 1792454400, allowPartial: false };
  const verified = verifyIssuerSigned(credential, options);
  assert.equal(verified.certificateBound, true);
  const key = raw(row.keyHex), replacement = raw(row.bomKeyHex), offset = credential.indexOf(key);
  assert(offset >= 0);
  assert.equal(credential.indexOf(key, offset + key.length), -1);
  // The existing signature, payload and disclosed items remain byte-identical.
  const changed = Buffer.concat([credential.subarray(0, offset), replacement, credential.subarray(offset + key.length)]);
  assert.throws(() => verifyIssuerSigned(changed, options), { code: 'MDOC_FIELDS' });
  const before = decode(credential), after = decode(changed);
  assert.equal(after.has(row.name), false);
  assert.deepEqual(after.get('\ufeff' + row.name), before.get(row.name));
  const other = row.name === 'issuerAuth' ? 'nameSpaces' : 'issuerAuth';
  assert.deepEqual(after.get(other), before.get(other));
});
