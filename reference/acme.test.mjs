import test from 'node:test';
import assert from 'node:assert/strict';
import { generate, b64u, seq, der } from './core.mjs';
import { name, extension, attribute } from './pki.mjs';
import { createCSR } from './enrollment.mjs';
import { Journal } from './state.mjs';
import { ACMEClient, ACMEService } from './acme.mjs';
import { signJWS, publicJWK, thumbprint } from './jose.mjs';

function flat(token) {
  const [protectedHeader, payload, signature] = token.split('.');
  return { protected: protectedHeader, payload, signature };
}

function fixture(t, options = {}) {
  const journal = new Journal(),
    old = generate('ec'),
    next = generate('ec'),
    baseURL = 'https://ca.example',
    kid = baseURL + '/account/one';
  t.after(() => journal.close());
  const forbidden = () => assert.fail('Account operations cannot authorize certificate issuance');
  const service = new ACMEService({
    baseURL,
    journal,
    profiles: ['synthetic-document'],
    authorizeFinalize: forbidden,
    issue: forbidden,
    revoke: forbidden,
    ...options,
  });
  journal.put('acme-account', kid, {
    status: 'valid',
    contact: ['mailto:synthetic@example.org'],
    jwk: publicJWK(old.publicKey),
  });
  const signed = (path, payload, key = old.privateKey) =>
    flat(
      signJWS(payload === null ? Buffer.alloc(0) : payload, key, {
        url: baseURL + path,
        kid,
        nonce: service.nonce(),
      }),
    );
  const post = (path, payload, key) => service.handle(path, signed(path, payload, key));
  const rollover = (key = next, headers = {}) =>
    flat(
      signJWS({ account: kid, oldKey: publicJWK(old.publicKey) }, key.privateKey, {
        url: baseURL + '/key-change',
        jwk: publicJWK(key.publicKey),
        ...headers,
      }),
    );
  return { journal, old, next, baseURL, kid, service, signed, post, rollover };
}

test('ACME rollover rejects registered replacement keys and preserves both accounts', async (t) => {
  const f = fixture(t),
    other = f.baseURL + '/account/two',
    before = f.journal.get('acme-account', f.kid);
  f.journal.put('acme-account', other, { status: 'valid', jwk: publicJWK(f.next.publicKey) });
  for (const status of ['valid', 'deactivated']) {
    const row = f.journal.get('acme-account', other);
    f.journal.put('acme-account', other, { ...row.value, status }, row.revision);
    const existing = f.journal.get('acme-account', other),
      request = f.signed('/key-change', f.rollover()),
      result = await f.service.handle('/key-change', request);
    assert.equal(result.status, 409);
    assert.equal(result.headers.location, other);
    assert.equal(result.headers['content-type'], 'application/problem+json');
    assert.equal(result.json.type, 'urn:ietf:params:acme:error:malformed');
    assert(result.headers['replay-nonce']);
    assert.deepEqual(f.journal.get('acme-account', f.kid), before);
    assert.deepEqual(f.journal.get('acme-account', other), existing);
    await assert.rejects(f.service.handle('/key-change', request), /badNonce/);
  }
});

test('ACME rollover enforces the account algorithm and protected-header profile', async (t) => {
  const f = fixture(t),
    before = f.journal.get('acme-account', f.kid);
  for (const payload of [
    f.rollover(generate('ed25519')),
    f.rollover(f.next, { crit: ['b64'], b64: true }),
    f.rollover(f.next, { kid: '' }),
    f.rollover(f.next, { nonce: '' }),
    f.rollover(f.next, { url: f.baseURL + '/new-account' }),
  ]) {
    await assert.rejects(f.post('/key-change', payload), /ACME_KEY_CHANGE_HEADER/);
    assert.deepEqual(f.journal.get('acme-account', f.kid), before);
  }
  await assert.rejects(f.post('/key-change', f.rollover(f.old)), /ACME_KEY_CHANGE/);
});

test('ACME rollover preserves orders, rejects old-key requests and consumes each nonce once', async (t) => {
  const f = fixture(t, { verifyChallenge: async () => true }),
    orders = [];
  for (const domain of ['pending.example', 'ready.example']) {
    const order = await f.post('/new-order', {
      identifiers: [{ type: 'dns', value: domain }],
      profile: 'synthetic-document',
    });
    orders.push(order);
  }
  const readyAuthorization = (
    await f.post(new URL(orders[1].json.authorizations[0]).pathname, null)
  ).json;
  await f.post(new URL(readyAuthorization.challenges[0].url).pathname, {});
  const snapshots = ['acme-order', 'acme-authorization'].map((namespace) =>
    f.journal.list(namespace).map(({ id }) => ({ id, ...f.journal.get(namespace, id) })),
  );
  const request = f.signed('/key-change', f.rollover());
  await assert.rejects(f.service.handle('/new-order', request), /ACME_PROTECTED_HEADER/);
  const rotated = await f.service.handle('/key-change', request);
  assert.equal(rotated.status, 200);
  assert.equal(
    thumbprint(f.journal.get('acme-account', f.kid).value.jwk),
    thumbprint(publicJWK(f.next.publicKey)),
  );
  await assert.rejects(f.service.handle('/key-change', request), /badNonce/);
  await assert.rejects(f.post('/account/one', null), /JWS_SIGNATURE/);
  assert.deepEqual((await f.post('/account/one', null, f.next.privateKey)).json.contact, [
    'mailto:synthetic@example.org',
  ]);
  for (const [index, namespace] of ['acme-order', 'acme-authorization'].entries()) {
    assert.deepEqual(
      f.journal.list(namespace).map(({ id }) => ({ id, ...f.journal.get(namespace, id) })),
      snapshots[index],
    );
  }
  for (const [index, order] of orders.entries()) {
    const result = await f.post(new URL(order.headers.location).pathname, null, f.next.privateKey);
    assert.equal(result.json.status, index === 0 ? 'pending' : 'ready');
  }
  await f.post('/account/one', { status: 'deactivated' }, f.next.privateKey);
  await assert.rejects(f.post('/key-change', f.rollover(), f.next.privateKey), /ACME_ACCOUNT/);
});

test('ACME finalization rejects any registered account key before invoking the RA', async (t) => {
  const f = fixture(t, { verifyChallenge: async () => true }),
    other = generate('ec');
  f.journal.put('acme-account', f.baseURL + '/account/two', {
    status: 'deactivated',
    jwk: publicJWK(other.publicKey),
  });
  const order = await f.post('/new-order', {
    identifiers: [{ type: 'dns', value: 'document.example' }],
    profile: 'synthetic-document',
  });
  const authorization = (await f.post(new URL(order.json.authorizations[0]).pathname, null)).json;
  await f.post(new URL(authorization.challenges[0].url).pathname, {});
  const orderID = new URL(order.headers.location).pathname.split('/').at(-1),
    before = f.journal.get('acme-order', orderID);
  for (const key of [f.old, other]) {
    const csr = createCSR({
      subject: name('Synthetic Subject'),
      publicKey: key.publicKey,
      privateKey: key.privateKey,
      attributes: [
        attribute(
          '1.2.840.113549.1.9.14',
          seq(extension('2.5.29.17', seq(der(0x82, Buffer.from('document.example'))))),
        ),
      ],
    });
    await assert.rejects(
      f.post(new URL(order.json.finalize).pathname, { csr: b64u(csr) }),
      /badCSR/,
    );
    assert.deepEqual(f.journal.get('acme-order', orderID), before);
  }
});

test('ACME client rejects its account key before submitting a CSR', async () => {
  const account = generate('ec'),
    client = new ACMEClient({
      directoryURL: 'https://ca.example/directory',
      privateKey: account.privateKey,
    }),
    csr = createCSR({
      subject: name('Synthetic Subject'),
      publicKey: account.publicKey,
      privateKey: account.privateKey,
    });
  client.post = async () => assert.fail('An account-key CSR cannot be submitted for issuance');
  await assert.rejects(
    client.complete({ authorizations: [], finalize: 'https://ca.example/finalize/one' }, { csr }),
    /badCSR/,
  );
});
