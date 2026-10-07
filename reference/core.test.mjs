import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';

test('draft 03 domain has fixed bytes and rejects another domain revision', () => {
  const value = { test: true }, input = c.D('example', value);
  assert.equal(input.toString('hex'), '846b43657274436f6e636f726403676578616d706c65a16474657374f5');
  const key = c.generate('ml-dsa-87'), signature = c.sign(input, key.privateKey);
  assert(c.verify(input, signature, key.publicKey));
  assert(!c.verify(c.dcbor(['CertConcord', 2, 'example', value]), signature, key.publicKey));
});

test('DCBOR fixed bytes and integer boundaries', () => {
  assert.equal(c.dcbor({ a: 1, b: Buffer.from([1, 2]) }).toString('hex'), 'a26161016162420102');
  for (const n of [0, 23, 24, 255, 256, 65535, 65536, 4294967296n, 0xffffffffffffffffn, -1, -24])
    assert.equal(
      c.decodeCBOR(c.dcbor(n)),
      typeof n === 'bigint' && n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n,
    );
  assert.throws(() => c.dcbor(Number.MAX_SAFE_INTEGER + 1));
  assert.throws(() => c.dcbor(1.5));
  assert.throws(() => c.dcbor('e\u0301'));
});
test('DCBOR rejects malformed, duplicate, unsorted, nonminimal and trailing bytes', () => {
  for (const hex of [
    '1817',
    '9fff',
    'c001',
    'fa00000000',
    'a2616101616102',
    'a2616201616102',
    '0000',
    '61ff',
    '59000100',
  ])
    assert.throws(() => c.decodeCBOR(Buffer.from(hex, 'hex')), hex);
});
test('DER UUID arcs are exact beyond uint64', () => {
  const text = '2.25.43665819381632101883451524414537163796';
  assert.equal(c.oidText(c.parseDER(c.oid(text))), text);
  assert.equal(c.intValue(c.parseDER(c.integer(0xffffffffffffffffn))), 0xffffffffffffffffn);
  for (const hex of ['02810101', '02020001', '30800000'])
    assert.throws(() => c.parseDER(Buffer.from(hex, 'hex')));
});
test('RFC 5869 test case 1', () => {
  const actual = c.hkdf(
    Buffer.alloc(22, 0x0b),
    Buffer.from('000102030405060708090a0b0c', 'hex'),
    Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'),
    42,
  );
  assert.equal(
    actual.toString('hex'),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  );
});
for (const algorithm of ['ml-dsa-65', 'ml-dsa-87', 'ec', 'ed25519'])
  test(`${algorithm}: actual signature and substitution rejection`, () => {
    const k = c.generate(algorithm),
      message = Buffer.from('VeriCommons public test');
    const s = c.sign(message, k.privateKey);
    assert(c.verify(message, s, k.publicKey));
    assert(!c.verify(Buffer.from('changed'), s, k.publicKey));
    if (c.ALG[algorithm].signatureLength) assert.equal(s.length, c.ALG[algorithm].signatureLength);
  });
for (const algorithm of ['ml-kem-768', 'ml-kem-1024'])
  test(`${algorithm}: real encapsulation and implicit rejection`, () => {
    const k = c.generate(algorithm),
      e = c.encapsulate(k.publicKey);
    assert(c.equal(e.sharedKey, c.decapsulate(k.privateKey, e.ciphertext)));
    e.ciphertext[20] ^= 1;
    assert(!c.equal(e.sharedKey, c.decapsulate(k.privateKey, e.ciphertext)));
  });
test('GCM releases plaintext only after tag verification', () => {
  const k = c.random(),
    p = c.random(100),
    a = c.random(32),
    e = c.seal(k, p, a);
  assert(c.equal(c.open(k, e, a), p));
  e.tag[0] ^= 1;
  assert.throws(() => c.open(k, e, a), /AEAD_AUTHENTICATION/);
});
test('RFC3394 AES256KW known answer and KWP round trip', () => {
  const k = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
  const p = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  assert.equal(c.wrapAES(k, p).toString('hex'), '64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7');
  for (const padded of [false, true]) {
    const data = c.random(padded ? 21 : 32),
      w = c.wrapAES(k, data, padded);
    assert(c.equal(c.unwrapAES(k, w, padded), data));
    w[0] ^= 1;
    assert.throws(() => c.unwrapAES(k, w, padded));
  }
});
