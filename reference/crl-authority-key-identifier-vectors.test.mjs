import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { verifyCRL } from './revocation.mjs';

const corpus = JSON.parse(readFileSync(new URL('./vectors/crl-authority-key-identifier.json', import.meta.url)));
assert.deepEqual(corpus.cases.map((v) => v.id), ['ec-default', 'ec-custom', 'ed25519-default', 'ed25519-custom', 'legacy-default-certificate-ski', 'legacy-custom-certificate-ski']);
for (const vector of corpus.cases) {
  const raw = Buffer.from(vector.crl, 'base64');
  const certificate = parseCertificate(Buffer.from(vector.certificate, 'base64'));
  const options = { issuer: certificate.subject, publicKey: certificate.publicKey, at: corpus.at, serial: corpus.serial };
  test('raw CRL key identifier ' + vector.id + ' binds its declared certificate SKI', () => {
    const extensions = c.parseDER(raw).children[0].children.at(-1).children[0].children;
    const values = extensions.filter((e) => c.oidText(e.children[0]) === '2.5.29.35');
    if (vector.expectedKeyIdentifier === null) {
      assert.equal(vector.kind, 'legacy-direct-verifier');
      assert.equal(values.length, 0);
    } else {
      assert.equal(vector.kind, 'issuer-aki');
      assert.equal(values.length, 1);
      assert.equal(values[0].children.length, 2);
      assert.equal(values[0].children[1].tag, 4);
      const value = c.parseDER(values[0].children[1].value);
      assert.equal(value.tag, 48);
      assert.equal(value.children.length, 1);
      assert.equal(value.children[0].tag, 0x80);
      assert.equal(value.children[0].value.toString('hex'), vector.expectedKeyIdentifier);
      assert.deepEqual(value.children[0].value, c.parseDER(certificate.extensions.get('2.5.29.14').value).value);
    }
  });
  test('raw CRL key identifier ' + vector.id + ' verifies its original signed bytes', () => {
    const result = verifyCRL(raw, options);
    assert.equal(result.status, 'GOOD');
    assert.equal(result.number, 7n);
    assert.equal(result.thisUpdate, corpus.at - 60);
    assert.equal(result.nextUpdate, corpus.at + 600);
  });
  test('raw CRL key identifier ' + vector.id + ' rejects tamper and truncation', () => {
    const changed = Buffer.from(raw); changed[changed.length - 1] ^= 1;
    assert.equal(verifyCRL(changed, options).reason, 'CRL_SIGNATURE');
    assert.notEqual(verifyCRL(raw.subarray(0, -1), options).status, 'GOOD');
  });
}
