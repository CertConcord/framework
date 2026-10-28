import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { issueCRL, verifyCRL } from './revocation.mjs';

const at = 1793188800;
function fixture(authorityKeyIdentifier) {
  const key = c.generate('ec'), issuer = p.name('Synthetic CRL key identifier issuer');
  const raw = issueCRL({ issuer, privateKey: key.privateKey, number: 3,
    thisUpdate: at - 60, nextUpdate: at + 600, authorityKeyIdentifier });
  return { key, issuer, raw };
}
function identifier(raw) {
  const root = c.parseDER(raw), extensions = root.children[0].children.at(-1).children[0].children;
  const matches = extensions.filter((e) => c.oidText(e.children[0]) === '2.5.29.35');
  assert.equal(matches.length, 1);
  const extension = matches[0];
  assert.equal(extension.children.length, 2, 'AKI must be noncritical');
  assert.equal(extension.children[1].tag, 4);
  const value = c.parseDER(extension.children[1].value);
  assert.equal(value.tag, 48);
  assert.equal(value.children.length, 1);
  assert.equal(value.children[0].tag, 0x80, 'keyIdentifier uses primitive implicit [0]');
  return value.children[0].value;
}
function certificateSKI(value, subjectKeyIdentifier) {
  const certificate = p.issueCertificate({ publicKey: value.key.publicKey,
    issuer: value.issuer, subject: value.issuer, serial: 1, ca: true,
    notBefore: at - 600, notAfter: at + 3600, subjectKeyIdentifier }, value.key.privateKey);
  return c.parseDER(p.parseCertificate(certificate).extensions.get('2.5.29.14').value).value;
}
test('CRL issuer defaults AKI to the existing certificate SKI method', () => {
  const value = fixture();
  assert.deepEqual(identifier(value.raw), certificateSKI(value));
  assert.equal(verifyCRL(value.raw, { issuer: value.issuer, publicKey: value.key.publicKey, at, serial: 9 }).status, 'GOOD');
});
test('CRL issuer preserves the selected custom certificate SKI', () => {
  const selected = Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex'), value = fixture(selected);
  assert.notDeepEqual(selected, c.sha256(c.spki(value.key.publicKey)));
  assert.deepEqual(identifier(value.raw), certificateSKI(value, selected));
});
test('CRL issuer uses exactly a Uint8Array subview', () => {
  const storage = Uint8Array.from([99, 98, 1, 2, 0, 4, 97]), selected = storage.subarray(2, 6);
  const value = fixture(selected);
  assert.deepEqual(identifier(value.raw), Buffer.from([1, 2, 0, 4]));
  storage.fill(7);
  assert.deepEqual(identifier(value.raw), Buffer.from([1, 2, 0, 4]));
});
for (const length of [1, 20, 64]) {
  test('CRL issuer preserves a ' + length + '-byte explicit identifier', () => {
    const selected = Buffer.alloc(length, 0xa5), value = fixture(selected);
    assert.deepEqual(identifier(value.raw), selected);
  });
}
for (const [label, value] of [
  ['null', null], ['empty Buffer', Buffer.alloc(0)], ['empty Uint8Array', new Uint8Array()],
  ['string', '0102'], ['array', [1, 2]], ['number', 1], ['object', {}],
  ['DataView', new DataView(new ArrayBuffer(2))], ['Uint16Array', new Uint16Array([1])],
]) {
  test('CRL issuer rejects ' + label + ' as an explicit identifier', () => {
    assert.throws(() => fixture(value), { code: 'CRL_AUTHORITY_KEY_IDENTIFIER' });
  });
}
test('CRL signature covers the complete encoded authority key identifier', () => {
  const selected = Buffer.from('112233445566778899aabbccddeeff', 'hex'), value = fixture(selected);
  const old = c.parseDER(value.raw), fields = old.children[0].children;
  const extensions = fields.at(-1).children[0].children.map((e) =>
    c.oidText(e.children[0]) === '2.5.29.35'
      ? p.extension('2.5.29.35', c.seq(c.der(0x80, Buffer.from('ff', 'hex')))) : e.raw);
  const changed = c.seq(c.seq(...fields.slice(0, -1).map((n) => n.raw), c.der(0xa0, c.seq(...extensions))), old.children[1].raw, old.children[2].raw);
  assert.equal(verifyCRL(changed, { issuer: value.issuer, publicKey: value.key.publicKey, at, serial: 9 }).reason, 'CRL_SIGNATURE');
});
