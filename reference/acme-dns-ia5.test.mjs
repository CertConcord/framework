import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  X509Certificate,
} from 'node:crypto';
import { parseDER } from './core.mjs';
import { ACMEService } from './acme.mjs';
import { Journal } from './state.mjs';
import { issueCertificate, name } from './pki.mjs';

const packet = JSON.parse(fs.readFileSync(new URL('./vectors/acme-dns-ia5.json', import.meta.url)));
const digest = (bytes, algorithm = 'sha256') => createHash(algorithm).update(bytes).digest('hex');
const keyPair = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const publicKey = (raw) =>
  createPublicKey({ key: Buffer.from(raw, 'base64'), format: 'der', type: 'spki' });
const holder = publicKey(packet.holderSPKIBase64),
  issuer = publicKey(packet.issuerSPKIBase64);
const vector = (id) => packet.vectors.find((v) => v.id === id);
const csrBytes = (v) => Buffer.from(v.csrDERBase64, 'base64');
const certificateBytes = (v) => Buffer.from(v.certificateDERBase64, 'base64');

async function fixture(t, v, options = {}) {
  const journal = new Journal(),
    account = keyPair(),
    baseURL = 'https://acme.example.invalid';
  const calls = { challenge: 0, authorize: 0, issue: 0 };
  const approval = { syntheticApproval: true };
  let kid,
    expectedCSR = csrBytes(v);
  t.after(() => journal.close());
  const service = new ACMEService({
    baseURL,
    journal,
    profiles: ['synthetic-dns'],
    verifyChallenge: async ({ identifier }) => {
      assert(v.identifiers.includes(identifier.value));
      calls.challenge++;
      return true;
    },
    authorizeFinalize: async ({ csr, order, accountID, deviceProofs }) => {
      assert.deepEqual(csr, expectedCSR);
      assert.equal(accountID, kid);
      assert.deepEqual(
        order.identifiers.map((identifier) => ({ ...identifier })),
        v.identifiers.map((value) => ({ type: 'dns', value })),
      );
      assert.deepEqual(deviceProofs, []);
      calls.authorize++;
      return options.deny ? false : approval;
    },
    issue: async ({ csr, approval: actual, profile }) => {
      assert.deepEqual(csr, expectedCSR);
      assert.strictEqual(actual, approval);
      assert.equal(profile, 'synthetic-dns');
      calls.issue++;
      return options.certificate ?? certificateBytes(v);
    },
    revoke: () => assert.fail('DNS admission cannot revoke certificates'),
  });
  const signed = (path, payload, key = account.privateKey, headers = {}) => {
    const protectedHeader = Buffer.from(
      JSON.stringify({
        alg: 'ES256',
        url: baseURL + path,
        nonce: service.nonce(),
        ...(kid ? { kid } : { jwk: account.publicKey.export({ format: 'jwk' }) }),
        ...headers,
      }),
    ).toString('base64url');
    const body = (
      payload === null ? Buffer.alloc(0) : Buffer.from(JSON.stringify(payload))
    ).toString('base64url');
    const input = Buffer.from(protectedHeader + '.' + body);
    const signature = sign('sha256', input, { key, dsaEncoding: 'ieee-p1363' });
    assert(
      verify('sha256', input, { key: createPublicKey(key), dsaEncoding: 'ieee-p1363' }, signature),
    );
    return {
      protected: protectedHeader,
      payload: body,
      signature: signature.toString('base64url'),
    };
  };
  const post = (path, payload) => service.handle(path, signed(path, payload));
  kid = (await post('/new-account', {})).headers.location;
  const order = await post('/new-order', {
    profile: 'synthetic-dns',
    identifiers: v.identifiers.map((value) => ({ type: 'dns', value })),
  });
  const authorizations = [];
  for (const url of order.json.authorizations) {
    const authPath = new URL(url).pathname,
      a = await post(authPath, null);
    if (options.ready !== false) await post(new URL(a.json.challenges[0].url).pathname, {});
    authorizations.push(authPath.split('/').at(-1));
  }
  const id = new URL(order.headers.location).pathname.split('/').at(-1);
  return {
    journal,
    service,
    account,
    calls,
    kid,
    signed,
    post,
    id,
    authorizations,
    path: new URL(order.json.finalize).pathname,
    orderPath: new URL(order.headers.location).pathname,
    setExpectedCSR: (csr) => {
      expectedCSR = csr;
    },
    snapshot: () => journal.get('acme-order', id),
    authSnapshot: () => authorizations.map((id) => journal.get('acme-authorization', id)),
  };
}

test('ACME DNS frozen CSR and certificate signatures bind the exact raw SAN octets', () => {
  assert.equal(packet.format, 'certconcord-acme-dns-ia5-v1');
  assert.equal(new Set(packet.vectors.map((v) => v.id)).size, packet.vectors.length);
  const wrong = keyPair();
  for (const v of packet.vectors) {
    const csr = csrBytes(v),
      [info, algorithm, signature] = parseDER(csr).children;
    assert.equal(digest(csr), v.csrSHA256);
    assert.equal(digest(info.raw), v.csrInfoSHA256);
    assert.equal(algorithm.raw.toString('hex'), '300a06082a8648ce3d040302');
    assert.deepEqual(info.children[2].raw, Buffer.from(packet.holderSPKIBase64, 'base64'));
    assert.equal(signature.value[0], 0);
    assert(verify('sha256', info.raw, holder, signature.value.subarray(1)), v.id);
    assert.equal(verify('sha256', info.raw, wrong.publicKey, signature.value.subarray(1)), false);
    const changedInfo = Buffer.from(info.raw);
    changedInfo[changedInfo.length - 1] ^= 1;
    assert.equal(verify('sha256', changedInfo, holder, signature.value.subarray(1)), false);
    const attributes = info.children[3].children;
    const extensions = attributes[0]?.children[1].children[0].children;
    const san = extensions?.[0].children.at(-1).value;
    assert.equal(san?.toString('hex') ?? null, v.sanDERHex);
    assert.deepEqual(
      san
        ? parseDER(san).children.map((n) => ({ tag: n.tag, valueHex: n.value.toString('hex') }))
        : null,
      v.generalNames,
    );
    const raw = certificateBytes(v),
      certificate = new X509Certificate(raw);
    assert.equal(digest(raw), v.certificateSHA256);
    assert(certificate.verify(issuer));
    assert.equal(certificate.verify(wrong.publicKey), false);
    assert.deepEqual(
      certificate.publicKey.export({ format: 'der', type: 'spki' }),
      info.children[2].raw,
    );
    const certSAN = parseDER(raw)
      .children[0].children.find((n) => n.tag === 0xa3)
      ?.children[0].children[0].children.at(-1).value;
    assert.equal(certSAN?.toString('hex') ?? null, v.sanDERHex);
  }
});

for (const v of packet.vectors) {
  test('ACME DNS raw CSR: ' + v.id, async (t) => {
    const f = await fixture(t, v),
      before = f.snapshot(),
      authBefore = f.authSnapshot();
    const accountBefore = f.journal.get('acme-account', f.kid);
    const request = f.signed(f.path, { csr: csrBytes(v).toString('base64url') });
    if (v.expected === 'valid') {
      const result = await f.service.handle(f.path, request);
      assert.equal(result.status, 200);
      assert.equal(result.json.status, 'valid');
      assert.equal(f.snapshot().revision, before.revision + 2);
      assert.equal(f.snapshot().value.status, 'valid');
      assert.equal(f.calls.authorize, 1);
      assert.equal(f.calls.issue, 1);
      const downloaded = await f.post(new URL(result.json.certificate).pathname, null);
      assert.deepEqual(new X509Certificate(downloaded.body).raw, certificateBytes(v));
      assert(new X509Certificate(downloaded.body).verify(issuer));
      await assert.rejects(f.post(f.path, { csr: csrBytes(v).toString('base64url') }), {
        message: 'ACME_FINALIZE_STATE',
      });
    } else {
      await assert.rejects(f.service.handle(f.path, request), { message: v.expected });
      assert.deepEqual(f.snapshot(), before);
      assert.equal((await f.post(f.orderPath, null)).json.status, 'ready');
      assert.equal(f.calls.authorize, 0);
      assert.equal(f.calls.issue, 0);
    }
    assert.equal(f.calls.challenge, v.identifiers.length);
    assert.deepEqual(f.authSnapshot(), authBefore);
    assert.deepEqual(f.journal.get('acme-account', f.kid), accountBefore);
    const settled = f.snapshot(),
      callsBeforeReplay = { ...f.calls };
    await assert.rejects(f.service.handle(f.path, request), {
      message: 'urn:ietf:params:acme:error:badNonce',
    });
    assert.deepEqual(f.snapshot(), settled);
    assert.deepEqual(f.calls, callsBeforeReplay);
  });
}

test('ACME DNS rejects equal-length duplicate names without replacing an ordered identifier', async (t) => {
  const v = {
    ...vector('duplicate-dns-name'),
    identifiers: ['alpha.example.invalid', 'beta.example.invalid'],
  };
  const f = await fixture(t, v),
    before = f.snapshot(),
    authBefore = f.authSnapshot();
  const accountBefore = f.journal.get('acme-account', f.kid);
  await assert.rejects(f.post(f.path, { csr: csrBytes(v).toString('base64url') }), {
    message: 'ACME_CSR_IDENTIFIERS',
  });
  assert.deepEqual(f.snapshot(), before);
  assert.deepEqual(f.authSnapshot(), authBefore);
  assert.deepEqual(f.journal.get('acme-account', f.kid), accountBefore);
  assert.deepEqual(f.calls, { challenge: 2, authorize: 0, issue: 0 });
});

test('ACME DNS rejected octets leave the order ready for a fresh valid finalization', async (t) => {
  const invalid = vector('high-bit-first-byte'),
    valid = vector('ascii-single');
  const f = await fixture(t, invalid, { certificate: certificateBytes(valid) }),
    before = f.snapshot();
  await assert.rejects(f.post(f.path, { csr: csrBytes(invalid).toString('base64url') }), {
    message: 'ACME_CSR_IDENTIFIERS',
  });
  assert.deepEqual(f.snapshot(), before);
  assert.deepEqual(f.calls, { challenge: 1, authorize: 0, issue: 0 });
  f.setExpectedCSR(csrBytes(valid));
  const result = await f.post(f.path, { csr: csrBytes(valid).toString('base64url') });
  assert.equal(result.json.status, 'valid');
  assert.deepEqual(f.calls, { challenge: 1, authorize: 1, issue: 1 });
  assert.equal(f.snapshot().revision, before.revision + 2);
});

for (const [id, error] of [
  ['signature', 'CSR_SIGNATURE'],
  ['truncation', 'DER_TRUNCATED'],
]) {
  test('ACME DNS rejects CSR ' + id + ' before callbacks or order mutation', async (t) => {
    const v = vector('high-bit-first-byte'),
      f = await fixture(t, v),
      before = f.snapshot();
    let csr = csrBytes(v);
    if (id === 'signature') csr[csr.length - 1] ^= 1;
    else csr = csr.subarray(0, csr.length - 1);
    await assert.rejects(f.post(f.path, { csr: csr.toString('base64url') }), { message: error });
    assert.deepEqual(f.snapshot(), before);
    assert.deepEqual(f.calls, { challenge: 1, authorize: 0, issue: 0 });
  });
}

for (const id of ['signature', 'payload', 'protected-url']) {
  test('ACME DNS preserves JWS ' + id + ' authentication before CSR admission', async (t) => {
    const v = vector('high-bit-first-byte'),
      f = await fixture(t, v),
      before = f.snapshot();
    const request = f.signed(f.path, { csr: csrBytes(v).toString('base64url') });
    if (id === 'signature') {
      const signature = Buffer.from(request.signature, 'base64url');
      signature[0] ^= 1;
      request.signature = signature.toString('base64url');
    } else if (id === 'payload')
      request.payload = Buffer.from(
        JSON.stringify({ csr: vector('different-signed-dns').csrDERBase64 }),
      ).toString('base64url');
    else {
      const header = JSON.parse(Buffer.from(request.protected, 'base64url'));
      header.url += '/other';
      request.protected = Buffer.from(JSON.stringify(header)).toString('base64url');
    }
    await assert.rejects(f.service.handle(f.path, request), {
      message: id === 'protected-url' ? 'ACME_PROTECTED_HEADER' : 'JWS_SIGNATURE',
    });
    assert.deepEqual(f.snapshot(), before);
    assert.deepEqual(f.calls, { challenge: 1, authorize: 0, issue: 0 });
  });
}

test('ACME DNS preserves registered account-key rejection before RA approval', async (t) => {
  const v = vector('high-bit-first-byte'),
    f = await fixture(t, v),
    before = f.snapshot();
  f.journal.put('acme-account', 'https://acme.example.invalid/account/other', {
    status: 'deactivated',
    jwk: holder.export({ format: 'jwk' }),
  });
  await assert.rejects(f.post(f.path, { csr: csrBytes(v).toString('base64url') }), {
    message: 'urn:ietf:params:acme:error:badCSR',
  });
  assert.deepEqual(f.snapshot(), before);
  assert.deepEqual(f.calls, { challenge: 1, authorize: 0, issue: 0 });
});

test('ACME DNS preserves challenge readiness before CSR admission', async (t) => {
  const v = vector('high-bit-first-byte'),
    f = await fixture(t, v, { ready: false }),
    before = f.snapshot();
  await assert.rejects(f.post(f.path, { csr: csrBytes(v).toString('base64url') }), {
    message: 'ACME_FINALIZE_STATE',
  });
  assert.deepEqual(f.snapshot(), before);
  assert.deepEqual(f.calls, { challenge: 0, authorize: 0, issue: 0 });
});

test('ACME DNS preserves order ownership before CSR admission', async (t) => {
  const v = vector('high-bit-first-byte'),
    f = await fixture(t, v),
    before = f.snapshot(),
    other = keyPair();
  const kid = 'https://acme.example.invalid/account/other';
  f.journal.put('acme-account', kid, {
    status: 'valid',
    jwk: other.publicKey.export({ format: 'jwk' }),
  });
  const request = f.signed(f.path, { csr: csrBytes(v).toString('base64url') }, other.privateKey, {
    kid,
  });
  await assert.rejects(f.service.handle(f.path, request), { message: 'ACME_ORDER_STATE' });
  assert.deepEqual(f.snapshot(), before);
  assert.deepEqual(f.calls, { challenge: 1, authorize: 0, issue: 0 });
});

test('ACME DNS still requires RA approval after exact identifier admission', async (t) => {
  const v = vector('ascii-single'),
    f = await fixture(t, v, { deny: true }),
    before = f.snapshot();
  await assert.rejects(f.post(f.path, { csr: csrBytes(v).toString('base64url') }), {
    message: 'ACME_RA_DENIED',
  });
  assert.deepEqual(f.calls, { challenge: 1, authorize: 1, issue: 0 });
  assert.equal(f.snapshot().revision, before.revision + 1);
  assert.equal(f.snapshot().value.status, 'processing');
  assert.equal(f.snapshot().value.certificatePEM, undefined);
});

test('ACME DNS still binds the issued certificate SAN to the exact CSR bytes', async (t) => {
  const v = vector('ascii-single'),
    f = await fixture(t, v, { certificate: certificateBytes(vector('different-signed-dns')) });
  await assert.rejects(f.post(f.path, { csr: csrBytes(v).toString('base64url') }), {
    message: 'ACME_CERTIFICATE_IDENTIFIERS',
  });
  assert.deepEqual(f.calls, { challenge: 1, authorize: 1, issue: 1 });
  assert.equal(f.snapshot().value.status, 'processing');
  assert.equal(f.snapshot().value.certificatePEM, undefined);
});

test('ACME DNS still binds the issued certificate public key to the CSR', async (t) => {
  const v = vector('ascii-single'),
    wrong = keyPair(),
    ca = keyPair();
  const certificate = issueCertificate(
    {
      publicKey: wrong.publicKey,
      issuer: name('Synthetic Issuer'),
      subject: name('Synthetic Subject'),
      serial: 1,
    },
    ca.privateKey,
  );
  const f = await fixture(t, v, { certificate });
  await assert.rejects(f.post(f.path, { csr: csrBytes(v).toString('base64url') }), {
    message: 'ACME_CERTIFICATE_KEY',
  });
  assert.deepEqual(f.calls, { challenge: 1, authorize: 1, issue: 1 });
  assert.equal(f.snapshot().value.status, 'processing');
  assert.equal(f.snapshot().value.certificatePEM, undefined);
});
