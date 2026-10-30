import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { ACMEClient, ACMEService } from './acme.mjs';

const corpus = JSON.parse(
  fs.readFileSync(new URL('./vectors/acme-profile-metadata.json', import.meta.url)),
);
const identifiers = [{ type: 'dns', value: 'document.example.test' }];
const hash = (text) => createHash('sha256').update(text).digest('hex');
const keyPair = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

function verifyRequest(raw, { publicKey, nonce, origin, row }) {
  const wire = JSON.parse(raw);
  assert.deepEqual(Object.keys(wire).sort(), ['payload', 'protected', 'signature']);
  assert(
    verify(
      'sha256',
      Buffer.from(wire.protected + '.' + wire.payload),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(wire.signature, 'base64url'),
    ),
    'Independent fixture rejects a changed signature, payload or key',
  );
  const header = JSON.parse(Buffer.from(wire.protected, 'base64url'));
  const payload = JSON.parse(Buffer.from(wire.payload, 'base64url'));
  assert.deepEqual(Object.keys(header).sort(), ['alg', 'kid', 'nonce', 'url']);
  assert.equal(header.alg, 'ES256');
  assert.equal(header.kid, origin + '/account/synthetic');
  assert.equal(header.url, origin + '/new-order');
  assert.equal(header.nonce, nonce);
  assert.deepEqual(payload.identifiers, identifiers);
  assert.deepEqual(
    Object.keys(payload).sort(),
    row.omitProfile ? ['identifiers'] : ['identifiers', 'profile'],
  );
  if (!row.omitProfile) assert.deepEqual(payload.profile, row.profile);
  return { wire, header, payload };
}

async function fixture(t, row) {
  const keys = keyPair(),
    requests = [],
    failures = [],
    activeNonces = new Set();
  let origin,
    body,
    nonceSequence = 0;
  const server = http.createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const raw = Buffer.concat(chunks);
      assert(raw.length < 65536);
      const entry = { method: req.method, path: req.url, raw: raw.toString('utf8') };
      requests.push(entry);
      if (req.method === 'GET' && req.url === '/directory') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(body);
        return;
      }
      if (req.method === 'HEAD' && req.url === '/new-nonce') {
        const nonce = 'synthetic-nonce-' + ++nonceSequence;
        activeNonces.add(nonce);
        res.writeHead(200, { 'replay-nonce': nonce });
        res.end();
        return;
      }
      assert.equal(req.method, 'POST');
      assert.equal(req.url, '/new-order');
      assert.equal(req.headers['content-type'], 'application/jose+json');
      const nonce = 'synthetic-nonce-' + nonceSequence;
      assert(activeNonces.delete(nonce), 'A nonce is consumed once');
      entry.verified = verifyRequest(entry.raw, { publicKey: keys.publicKey, nonce, origin, row });
      entry.nonce = nonce;
      res.writeHead(201, { 'content-type': 'application/json', location: origin + '/order/one' });
      res.end(
        JSON.stringify({
          status: 'pending',
          identifiers,
          ...(row.omitProfile ? {} : { profile: row.profile }),
          authorizations: [],
          finalize: origin + '/finalize/one',
        }),
      );
    } catch (error) {
      failures.push(error);
      res.writeHead(500, { 'content-type': 'application/problem+json' });
      res.end(JSON.stringify({ type: 'urn:example:fixture-rejected' }));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  origin = 'http://127.0.0.1:' + server.address().port;
  const endpoints = {
    newNonce: origin + '/new-nonce',
    newAccount: origin + '/new-account',
    newOrder: origin + '/new-order',
    revokeCert: origin + '/revoke-cert',
    keyChange: origin + '/key-change',
  };
  // Keep the frozen metadata bytes, including duplicate members, verbatim.
  const fragment = row.metadataJSON.slice(1, -1);
  body = JSON.stringify(endpoints).slice(0, -1) + (fragment ? ',' + fragment : '') + '}';
  assert.equal(hash(row.metadataJSON), row.metadataSHA256);
  const client = new ACMEClient({
    directoryURL: origin + '/directory',
    privateKey: keys.privateKey,
    allowLoopback: true,
  });
  client.accountURL = origin + '/account/synthetic';
  return { client, requests, failures, keys, origin, body };
}

for (const row of corpus.rows) {
  test(`ACME profile metadata: ${row.id}`, async (t) => {
    const f = await fixture(t, row);
    if (row.expected.error === 'JSON_DUPLICATE') {
      await assert.rejects(f.client.discover(), { message: 'JSON_DUPLICATE' });
    } else {
      await f.client.discover();
      const input = { identifiers, ...(row.omitProfile ? {} : { profile: row.profile }) };
      if (row.expected.error) {
        await assert.rejects(f.client.newOrder(input), { message: row.expected.error });
      } else {
        const order = await f.client.newOrder(input);
        assert.equal(order.status, 'pending');
        assert.equal(order.url, f.origin + '/order/one');
        assert.deepEqual(
          order.identifiers.map((entry) => ({ ...entry })),
          identifiers,
        );
        assert.equal(order.profile, row.omitProfile ? undefined : row.profile);
        assert.equal(f.requests[2].verified.header.alg, 'ES256');
      }
    }
    assert.deepEqual(f.failures, []);
    assert.deepEqual(
      f.requests.map(({ method, path }) => [method, path]),
      row.expected.error
        ? [['GET', '/directory']]
        : [
            ['GET', '/directory'],
            ['HEAD', '/new-nonce'],
            ['POST', '/new-order'],
          ],
    );
  });
}

test('ACME profile metadata corpus retains exact independently specified bytes', () => {
  assert.equal(corpus.schemaVersion, 1);
  assert.equal(corpus.rows.length, 35);
  assert.equal(new Set(corpus.rows.map((row) => row.id)).size, corpus.rows.length);
  for (const row of corpus.rows) {
    assert.equal(hash(row.metadataJSON), row.metadataSHA256);
    assert(row.metadataJSON.startsWith('{') && row.metadataJSON.endsWith('}'));
    assert(
      row.expected.accepted === true ||
        ['ACME_PROFILE', 'JSON_DUPLICATE'].includes(row.expected.error),
    );
  }
});

for (const terms of [undefined, 'https://policy.example.test/terms']) {
  test(`ACME service advertises profiles in metadata ${terms ? 'with' : 'without'} terms`, () => {
    const forbidden = () => assert.fail('Directory discovery cannot authorize issuance');
    const service = new ACMEService({
      baseURL: 'https://ca.example.test',
      journal: {},
      profiles: ['synthetic-document', 'constructor', '__proto__'],
      termsOfService: terms,
      authorizeFinalize: forbidden,
      issue: forbidden,
      revoke: forbidden,
    });
    const actual = JSON.parse(JSON.stringify(service.directory()));
    assert.equal(Object.hasOwn(actual, 'profiles'), false);
    assert.deepEqual(
      Object.keys(actual.meta).sort(),
      terms ? ['profiles', 'termsOfService'] : ['profiles'],
    );
    assert.deepEqual(
      actual.meta.profiles,
      Object.fromEntries(
        ['synthetic-document', 'constructor', '__proto__'].map((name) => [
          name,
          'https://ca.example.test/profiles/' + name,
        ]),
      ),
    );
    assert.equal(actual.meta.termsOfService, terms);
    for (const key of ['newNonce', 'newAccount', 'newOrder', 'revokeCert', 'keyChange'])
      assert.equal(new URL(actual[key]).origin, 'https://ca.example.test');
  });
}

test('ACME service preserves an empty configured profile map', () => {
  const forbidden = () => assert.fail('Directory discovery cannot authorize issuance');
  const service = new ACMEService({
    baseURL: 'https://ca.example.test',
    journal: {},
    profiles: [],
    authorizeFinalize: forbidden,
    issue: forbidden,
    revoke: forbidden,
  });
  const actual = service.directory();
  assert.equal(Object.hasOwn(actual, 'profiles'), false);
  assert.deepEqual(actual.meta, { profiles: {} });
});

test('ACME independent profile fixture rejects signature, payload, key and nonce substitution', async (t) => {
  const row = corpus.rows.find((entry) => entry.id === 'omitted-without-metadata'),
    f = await fixture(t, row);
  await f.client.discover();
  await f.client.newOrder({ identifiers });
  const original = f.requests[2],
    options = { publicKey: f.keys.publicKey, nonce: original.nonce, origin: f.origin, row };
  verifyRequest(original.raw, options);
  const signature = JSON.parse(original.raw),
    bytes = Buffer.from(signature.signature, 'base64url');
  bytes[0] ^= 1;
  signature.signature = bytes.toString('base64url');
  assert.throws(() => verifyRequest(JSON.stringify(signature), options));
  const payload = JSON.parse(original.raw);
  payload.payload = Buffer.from(JSON.stringify({ identifiers, profile: 'substituted' })).toString(
    'base64url',
  );
  assert.throws(() => verifyRequest(JSON.stringify(payload), options));
  assert.throws(() => verifyRequest(original.raw, { ...options, publicKey: keyPair().publicKey }));
  assert.throws(() => verifyRequest(original.raw, { ...options, nonce: 'a-different-nonce' }));
  assert.deepEqual(f.failures, []);
});
