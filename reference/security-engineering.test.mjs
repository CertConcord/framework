import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import {
  dcbor,
  decodeCBOR,
  parseDER,
  sha256,
  seq,
  set,
  der,
  oid,
  oidText,
  octet,
  sign,
  random,
} from './core.mjs';
import { decode as isoDecode } from './cose.mjs';
import { validateResult } from './interop/import-result.mjs';
import { generate } from './core.mjs';
import { issueCertificate, name, OID, RRA, attribute, signCMS, verifyCMS } from './pki.mjs';
import { StatusList } from './openid.mjs';
import { Journal } from './state.mjs';
import { ACMEService } from './acme.mjs';
import { signJWS, publicJWK, thumbprint } from './jose.mjs';
import { fuzz as fuzzParsers } from './fuzz/parsers.mjs';

test('CBOR differential decoding preserves special map keys without prototype mutation', () => {
  const input = Buffer.from('AKJhaQFpX19wcm90b19fcXFxcXFxcQMAAHFxcXFxcXEA', 'base64');
  const value = decodeCBOR(input.subarray(1));
  assert.equal(Object.getPrototypeOf(value), null);
  assert(Object.hasOwn(value, '__proto__'));
  assert.equal(Object.hasOwn(value, '__proto_'), false);
  assert.doesNotThrow(() => fuzzParsers(input));
});

test('ACME key-change routing cannot bypass old-account authentication or nested new-key proof', async () => {
  const journal = new Journal(),
    old = generate('ec'),
    next = generate('ec'),
    attacker = generate('ec'),
    baseURL = 'https://ca.example',
    kid = baseURL + '/account/one',
    url = baseURL + '/key-change';
  const forbidden = () =>
    assert.fail('Key rotation cannot call an issuance or revocation authority');
  const service = new ACMEService({
    journal,
    baseURL,
    profiles: [],
    authorizeFinalize: forbidden,
    issue: forbidden,
    revoke: forbidden,
  });
  const flat = (jwt) => {
    const [protectedHeader, payload, signature] = jwt.split('.');
    return { protected: protectedHeader, payload, signature };
  };
  journal.put('acme-account', kid, { status: 'valid', jwk: publicJWK(old.publicKey) });
  const inner = (payload = {}, headers = {}, key = next.privateKey) =>
    flat(
      signJWS({ account: kid, oldKey: publicJWK(old.publicKey), ...payload }, key, {
        url,
        jwk: publicJWK(next.publicKey),
        ...headers,
      }),
    );
  const outer = (body, key = old.privateKey, route = url) =>
    flat(signJWS(body, key, { url: route, kid, nonce: service.nonce() }));
  try {
    await assert.rejects(
      service.handle('/key-change', outer(inner(), attacker.privateKey)),
      /JWS_SIGNATURE/,
    );
    await assert.rejects(
      service.handle('/key-change', outer(inner({}, {}, attacker.privateKey))),
      /JWS_SIGNATURE/,
    );
    await assert.rejects(
      service.handle('/key-change', outer(inner({ account: baseURL + '/account/other' }))),
      /ACME_KEY_CHANGE/,
    );
    await assert.rejects(
      service.handle('/key-change', outer(inner({ oldKey: publicJWK(attacker.publicKey) }))),
      /ACME_KEY_CHANGE/,
    );
    await assert.rejects(
      service.handle('/key-change', outer(inner({}, { nonce: '' }))),
      /ACME_KEY_CHANGE_HEADER/,
    );
    await assert.rejects(service.handle('/other', outer(inner())), /ACME_PROTECTED_HEADER/);
    assert.equal(
      thumbprint(journal.get('acme-account', kid).value.jwk),
      thumbprint(publicJWK(old.publicKey)),
    );
    assert.equal((await service.handle('/key-change', outer(inner()))).status, 200);
    assert.equal(
      thumbprint(journal.get('acme-account', kid).value.jwk),
      thumbprint(publicJWK(next.publicKey)),
    );
  } finally {
    journal.close();
  }
});

test('status allocation selects the sole remaining index without random retry loops', () => {
  const journal = new Journal(),
    uri = 'https://issuer.example/status',
    missing = 4711;
  try {
    journal.put('status-list', uri, {
      bytes: Buffer.alloc(1024),
      used: Array.from({ length: 8192 }, (_, i) => i).filter((i) => i !== missing),
    });
    const list = new StatusList({ journal, uri, size: 1024 });
    assert.equal(list.allocate().status_list.idx, missing);
    assert.throws(() => list.allocate(), /STATUS_LIST_FULL/);
  } finally {
    journal.close();
  }
});

test(
  'PDF mutation regression preserves caller responsiveness and bounded rejection',
  { timeout: 12000 },
  async () => {
    const { fuzz } = await import('./fuzz/documents.mjs');
    let ticks = 0;
    const timer = setInterval(() => ticks++, 20);
    try {
      await fuzz(Buffer.from('wiIiLg==', 'base64'));
      assert(ticks > 0);
    } finally {
      clearInterval(timer);
    }
  },
);

test('CMS rejects tag substitution in nested SignedData and encapsulated content', () => {
  const key = generate(),
    certificate = issueCertificate(
      {
        publicKey: key.publicKey,
        subject: name('Synthetic'),
        issuer: name('Synthetic'),
        serial: 1,
      },
      key.privateKey,
    );
  const cms = signCMS({ content: Buffer.from('synthetic'), certificate }, key.privateKey);
  const root = parseDER(cms),
    sd = root.children[1].children[0];
  for (const node of [
    root,
    root.children[1],
    sd,
    sd.children[1],
    sd.children[2],
    sd.children[2].children[1],
    sd.children[4],
  ]) {
    const changed = Buffer.from(cms),
      offset = node.raw.byteOffset - cms.byteOffset;
    changed[offset] = node.tag === 0x30 ? 0xa2 : 0x30;
    assert.throws(() => verifyCMS(changed), /CMS_/);
  }
});

test('CMS SignedData rejects version substitution for data and non-data content', async () => {
  const key = generate(),
    content = Buffer.from('Synthetic CMS version regression'),
    certificate = issueCertificate(
      {
        publicKey: key.publicKey,
        subject: name('Synthetic'),
        issuer: name('Synthetic'),
        serial: 1,
      },
      key.privateKey,
    );
  for (const contentType of [OID.data, OID.tstInfo]) {
    const cms = signCMS({ content, certificate, contentType }, key.privateKey),
      options = { expectedCertificate: certificate, expectedContentType: contentType };
    assert.equal(verifyCMS(cms, options).cryptographicValidity, 'VALID');
    const version = parseDER(cms).children[1].children[0].children[0],
      mutated = Buffer.from(cms);
    mutated[version.value.byteOffset - cms.byteOffset] = contentType === OID.data ? 3 : 1;
    assert.throws(() => verifyCMS(mutated, options), /CMS_VERSION/);
  }
  const { fuzz } = await import('./fuzz/containers.mjs');
  await fuzz(Buffer.from('CwAZAgsAAAAgedY=', 'base64'));
});

test('CMS rejects relative OIDs and wrong signed-attribute value types even with a valid signature', () => {
  const key = generate();
  const certificate = issueCertificate(
    { publicKey: key.publicKey, subject: name('Synthetic'), issuer: name('Synthetic'), serial: 1 },
    key.privateKey,
  );
  const content = Buffer.from('Synthetic CMS schema regression');
  const options = {
    expectedCertificate: certificate,
    context: { schemaVersion: 1 },
    simHash: random(64),
    policyHash: random(64),
  };
  const cms = signCMS({ content, certificate, ...options }, key.privateKey);
  assert.equal(verifyCMS(cms, options).cryptographicValidity, 'VALID');
  const root = parseDER(cms);
  const sd = root.children[1].children[0].children;
  const wrap = (parts) => seq(oid(OID.signed), der(0xa0, seq(...parts)));
  assert.throws(
    () => verifyCMS(seq(oid(OID.signed, true), root.children[1].raw), options),
    /CMS_CONTENT_TYPE/,
  );
  const enc = sd[2].children;
  assert.throws(
    () =>
      verifyCMS(
        wrap(sd.map((node, i) => (i === 2 ? seq(oid(OID.data, true), enc[1].raw) : node.raw))),
        options,
      ),
    /CMS_CONTENT_TYPE/,
  );
  const si = sd[4].children[0].children;
  const attrs = si[3].children;
  for (const [id, change] of [
    [OID.messageDigest, (a) => seq(oid(OID.messageDigest, true), a.children[1].raw)],
    [OID.contentType, () => attribute(OID.contentType, oid(OID.data, true))],
    ...[
      OID.messageDigest,
      RRA['id-aa-certconcordSignatureContext'],
      RRA['id-aa-certconcordSigningIntent'],
      RRA['id-aa-certconcordSignaturePolicy'],
    ].map((id) => [id, (a) => attribute(id, der(0x80, a.children[1].children[0].value))]),
  ]) {
    const tbs = set(...attrs.map((a) => (oidText(a.children[0]) === id ? change(a) : a.raw)));
    const signed = seq(
      ...si.map((node, i) =>
        i === 3
          ? der(0xa0, parseDER(tbs).value)
          : i === 5
            ? octet(sign(tbs, key.privateKey))
            : node.raw,
      ),
    );
    const changed = wrap(sd.map((node, i) => (i === 4 ? set(signed) : node.raw)));
    assert.throws(() => verifyCMS(changed, options), /CMS_|CERTCONCORD_SIGNED_BINDING/, id);
  }
});

test('CBOR collection lengths are bounded before allocation; DER rejects redundant negative sign octets', () => {
  for (const hex of ['9a00ffffff', 'ba00ffffff', '9a00010000']) {
    assert.throws(() => decodeCBOR(Buffer.from(hex, 'hex')), /ITEM_BUDGET/);
    assert.throws(() => isoDecode(Buffer.from(hex, 'hex')), /ITEM_BUDGET|CBOR_LENGTH/);
  }
  assert.throws(() => parseDER(Buffer.from('0202ffff', 'hex')), /DER_INTEGER/);
  assert.equal(parseDER(Buffer.from('0201ff', 'hex')).value[0], 255);
});
test('external assessment imports verify artifact integrity without creating assessor authority', async () => {
  const dir = '.runtime/assessment-test';
  await mkdir(dir, { recursive: true });
  const bytes = Buffer.from('Synthetic external test result');
  await writeFile(dir + '/result.txt', bytes);
  const record = {
    schemaVersion: 1,
    category: 'EXTERNAL_EXECUTION',
    assessor: 'synthetic-test-assessor',
    sourceCommit: 'a'.repeat(40),
    manifestSHA256: 'b'.repeat(64),
    role: 'VERIFIER',
    suite: { name: 'synthetic-suite', revision: 'c'.repeat(40) },
    profile: 'synthetic-profile',
    configurationSHA256: 'd'.repeat(64),
    startedAt: '2026-10-03T00:00:00Z',
    completedAt: '2026-10-03T00:01:00Z',
    tests: [{ id: 'synthetic-1', result: 'PASS', artifact: 'result.txt' }],
    artifacts: [{ path: 'result.txt', sha256: sha256(bytes).toString('hex') }],
  };
  assert.equal((await validateResult(record, dir)).authority, 'REQUIRES_EXTERNAL_AUTHENTICATION');
  await assert.rejects(
    validateResult({ ...record, category: 'CERTIFIED_BY_TEST_COUNT' }, dir),
    /CATEGORY/,
  );
  await assert.rejects(
    validateResult(
      { ...record, artifacts: [{ path: '../escape.txt', sha256: '0'.repeat(64) }] },
      dir,
    ),
    /PATH/,
  );
  await writeFile(dir + '/result.txt', Buffer.from('tampered'));
  await assert.rejects(validateResult(record, dir), /DIGEST/);
});
