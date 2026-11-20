import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { der, generate, octet, seq } from './core.mjs';
import { extension, name } from './pki.mjs';
import { issueOCSP, ocspRequest, parseOCSPRequest, verifyOCSP } from './revocation.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/ocsp-requester-nonce.json', import.meta.url)));
const sha256 = data => createHash('sha256').update(data).digest('hex');

test('frozen OCSP requests retain 32- and 16-octet nonce parser interoperability', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'ocsp-requester-nonce');
  assert.deepEqual(vectors.cases.map(row => row.id), ['positive32', 'negative16']);
  assert.deepEqual(vectors.cases.map(row => row.requestSHA256), [
    '22c4b29004d20e1c98fd473ae8db1f97633d2943848e1e3733a92fd4ca090864',
    'f0fab3164578a8f34331a46dbe7c9a4f64077f3e497c1311f6d4ee10d8edf610',
  ]);
  const certIDs = [];
  for (const row of vectors.cases) {
    const request = Buffer.from(row.request, 'base64');
    const nonce = Buffer.from(row.nonce, 'base64');
    assert.equal(sha256(request), row.requestSHA256);
    assert.equal(sha256(nonce), row.nonceSHA256);
    const parsed = parseOCSPRequest(request);
    assert.deepEqual(parsed.nonce, nonce);
    certIDs.push(parsed.certID);
  }
  assert.deepEqual(certIDs[0], certIDs[1]);
});

test('OCSP requester emits only 32-octet nonces while responder accepts 16', () => {
  const issuer = name('Synthetic OCSP nonce issuer');
  const key = generate('ed25519');
  const options = {issuer, issuerPublicKey: key.publicKey, serial: 19n};
  const explicit = Buffer.alloc(32, 0x71);
  const request = ocspRequest(options, {nonce: explicit});
  assert.deepEqual(request.nonce, explicit);
  assert.equal(ocspRequest(options).nonce.length, 32);
  for (const length of [0, 1, 15, 16, 31, 33, 128]) {
    assert.throws(() => ocspRequest(options, {nonce: Buffer.alloc(length)}), {code: 'OCSP_NONCE'});
  }
  for (const nonce of ['x'.repeat(32), 'é'.repeat(32), Array(32).fill(0)]) {
    assert.throws(() => ocspRequest(options, {nonce}), {code: 'OCSP_NONCE'});
  }
  const legacyNonce = Buffer.alloc(16, 0x71);
  const legacyRequest = seq(seq(seq(seq(request.certID)),
    der(0xa2, seq(extension('1.3.6.1.5.5.7.48.1.2', octet(legacyNonce))))));
  assert.deepEqual(parseOCSPRequest(legacyRequest).nonce, legacyNonce);
  const at = 1800000040;
  const response = issueOCSP(legacyRequest, {
    issuer,
    issuerPublicKey: key.publicKey,
    privateKey: key.privateKey,
    records: new Map([['19', {status: 'GOOD'}]]),
    thisUpdate: at - 40,
    nextUpdate: at + 300,
  });
  const result = verifyOCSP(response, {request: legacyRequest, issuerPublicKey: key.publicKey, at, knowledgeTime: at});
  assert.equal(result.status, 'GOOD');
  assert.equal(result.overall, 'VALID');
});
