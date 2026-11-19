import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generate } from './core.mjs';
import { name, issueCertificate } from './pki.mjs';
import { createCSR } from './enrollment.mjs';
import { ACMEClient } from './acme.mjs';

const directoryURL = 'https://acme.example/directory';
const finalizeURL = 'https://acme.example/finalize/one';
const certificateURL = 'https://acme.example/certificate/one';
const vector = JSON.parse(readFileSync(new URL('./vectors/acme-pem-chain.json', import.meta.url)));

function fixture(body, mediaType = 'application/pem-certificate-chain') {
  const account = generate('ec');
  const holder = generate('ec');
  const issuer = generate('ec');
  const csr = createCSR({
    subject: name('PEM chain holder'), publicKey: holder.publicKey, privateKey: holder.privateKey,
  });
  const leaf = issueCertificate({
    publicKey: holder.publicKey, subject: name('PEM chain holder'),
    issuer: name('PEM chain issuer'), serial: 1,
  }, issuer.privateKey);
  const root = issueCertificate({
    publicKey: issuer.publicKey, subject: name('PEM chain issuer'),
    issuer: name('PEM chain issuer'), serial: 2,
  }, issuer.privateKey);
  const pem = (der) => new X509Certificate(der).toString().trimEnd() + '\n';
  const chain = Buffer.from(pem(leaf) + pem(root));
  const client = new ACMEClient({ directoryURL, privateKey: account.privateKey });
  const calls = [];
  client.post = async (url) => {
    calls.push(url);
    if (url === finalizeURL)
      return { json: { status: 'valid', certificate: certificateURL } };
    if (url === certificateURL)
      return { status: 200, headers: new Headers({ 'content-type': mediaType }), body: body?.(chain) ?? chain };
    assert.fail(`Unexpected ACME URL: ${url}`);
  };
  const complete = () => client.complete({ authorizations: [], finalize: finalizeURL }, { csr });
  return { chain, calls, complete };
}

test('ACME client accepts an exact two-certificate PEM chain', async () => {
  const { chain, calls, complete } = fixture();
  assert.deepEqual(await complete(), chain);
  assert.deepEqual(calls, [finalizeURL, certificateURL]);
});

test('ACME client accepts strict CRLF PEM and a case-insensitive media type', async () => {
  const { chain, complete } = fixture(
    (value) => Buffer.from(value.toString('ascii').replace(/\n/g, '\r\n')),
    'Application/PEM-Certificate-Chain',
  );
  assert.deepEqual(await complete(), Buffer.from(chain.toString('ascii').replace(/\n/g, '\r\n')));
});

test('ACME client replays fixed synthetic PEM-chain positive and negative bytes', async () => {
  assert.equal(vector.format, 'certconcord-acme-pem-chain-v1');
  assert.deepEqual(vector.cases.map((row) => row.id), [
    'two-certificates', 'private-key-after-chain',
  ]);
  for (const row of vector.cases) {
    const body = Buffer.from(row.bodyBase64, 'base64');
    assert.equal(createHash('sha256').update(body).digest('hex'), row.bodySHA256);
    const { complete } = fixture(() => body, row.mediaType);
    if (row.expected === 'ACCEPT') assert.deepEqual(await complete(), body);
    else await assert.rejects(complete(), new RegExp(row.expected));
  }
});

test('ACME client rejects a non-certificate PEM block after a valid chain', async () => {
  const { complete } = fixture((chain) => Buffer.concat([
    chain, Buffer.from('-----BEGIN ' + 'PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n'),
  ]));
  await assert.rejects(complete(), /ACME_CERTIFICATE_CHAIN/);
});

test('ACME client rejects a chain response with the wrong media type', async () => {
  const { complete } = fixture(undefined, 'application/json');
  await assert.rejects(complete(), /ACME_CERTIFICATE_MEDIA_TYPE/);
});

test('ACME client rejects malformed or explanatory certificate-chain text', async (t) => {
  const cases = [
    ['empty body', () => Buffer.alloc(0)],
    ['leading explanation', (chain) => Buffer.concat([Buffer.from('certificate follows\n'), chain])],
    ['non-base64 character', (chain) => Buffer.from(chain.toString('ascii').replace(/\n[A-Za-z0-9+/]/, '\n!'))],
    ['missing final line ending', (chain) => chain.subarray(0, -1)],
  ];
  for (const [label, mutate] of cases)
    await t.test(label, async () => {
      const { complete } = fixture(mutate);
      await assert.rejects(complete(), /ACME_CERTIFICATE_CHAIN/);
    });
});
