import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal } from './state.mjs';
import { createAuthorityResolver, requireAuthority } from './authority-history.mjs';
import { TimestampAuthority, timestampRequest, tokenFromResponse, verifyTimestampToken } from './timestamp.mjs';
import { createRetainedAuthorityResolver, authenticateRetainedAuthorityEntry, manifestPublicationImprint, ArchivePublicationStore, ArchiveRenewalCoordinator } from './retained-authorities.mjs';

function fixture(t) {
  const start = 1800000000, journal = new Journal();
  t.after(() => journal.close());
  const root = c.generate('ml-dsa-87'), successor = c.generate('ml-dsa-87'), key = c.generate('ml-dsa-87');
  const cert = (key, serial, profileID) => p.issueCertificate({ publicKey: key.publicKey,
    issuer: p.name('Synthetic retained governance'), subject: p.name('Retained authority ' + serial),
    serial, profileID, notBefore: start - 100, notAfter: start + 2000 }, root.privateKey);
  const certificate = cert(key, 1, 'CERTCONCORD-EVIDENCE-SIGN-v1');
  const tsaKey = c.generate('ml-dsa-87'), tsaCertificate = cert(tsaKey, 2, 'CERTCONCORD-TSA-v1');
  let clock = start;
  const tsa = new TimestampAuthority({ certificate: tsaCertificate, privateKey: tsaKey.privateKey,
    journal, clock: () => clock, accuracySeconds: 0, policy: '1.3.6.1.4.1.32473.99.1' });
  const trustDomainID = c.random();
  const record = { certificate, mode: 'CERTIFICATE', knownAt: start,
    validFrom: start, validUntil: start + 1000, roles: ['PERMIT_AUTHORITY'], scopes: [{ trustDomainID }],
    status: { scope: 'AUTHORITY', authorityID: c.keyID(key.publicKey), trustDomainID,
      status: 'GOOD', publishedAt: start, nextUpdate: start + 200 } };
  const policy = (key, validUntil = start + 1000) => ({ roots: [{ publicKeyDER: c.spki(key.publicKey), validFrom: start - 100, validUntil }], threshold: 1 });
  const snapshot = ({ previous, published = start, records = [record], successorPolicy, signers = [root] } = {}) => {
    const manifest = { schemaVersion: 2, trustDomainID, serial: previous ? previous.manifest.serial + 1 : 0,
      previousHash: previous ? c.H('RootTrustManifest', previous.manifest) : null,
      issuedAt: published, notBefore: published, notAfter: published + 500,
      coverageUntil: published + 200, authorities: records,
      ...(successorPolicy ? { successor: successorPolicy } : {}) };
    const signatures = signers.map((signer) => ({ keyID: c.keyID(signer.publicKey), signature: c.sign(c.D('RootTrustManifest', manifest), signer.privateKey) }));
    clock = published;
    const entry = { manifest, signatures };
    const request = timestampRequest(manifestPublicationImprint(entry), { policy: tsa.policy });
    return { ...entry, publicationProof: tokenFromResponse(tsa.issue(request.der)) };
  };
  const configuration = { trustDomainID, governance: policy(root), algorithmDeadlines: { 'ml-dsa-87': start + 1500 },
    validationTime: start + 1000,
    verifyPublication: ({ imprint, proof, at }) => ({ overall: 'VALID', ...verifyTimestampToken(proof,
      { certificate: tsaCertificate, issuerKey: root.publicKey, policy: tsa.policy, imprint, at, maxFutureSkew: 0 }) }) };
  const query = { certificate, role: 'PERMIT_AUTHORITY', scope: { trustDomainID }, stateTime: start + 10, knowledgeTime: start + 20 };
  return { start, root, successor, key, record, certificate, trustDomainID, policy, snapshot, configuration, query,
    tsa, setTime: (value) => { clock = value; },
    tsaTrust: { certificate: tsaCertificate, issuerKey: root.publicKey, policy: tsa.policy, trustDomainID,
      authorityResolver: createAuthorityResolver({ trustDomainID, authorities: [{ ...record,
        certificate: tsaCertificate, roles: ['TIMESTAMP_AUTHORITY'],
        status: { ...record.status, authorityID: c.keyID(tsaKey.publicKey), nextUpdate: start + 1000 } }] }) },
    resolver: (history, overrides = {}) => createRetainedAuthorityResolver({ ...configuration, history, ...overrides }) };
}

test('retained publication accepts authenticated data decisions and exact fractional knowledge bounds', (t) => {
  const f = fixture(t), entry = f.snapshot(), published = f.start + 0.5;
  for (const prototype of [Object.prototype, null]) {
    const verifyPublication = (input) => Object.assign(Object.create(prototype),
      f.configuration.verifyPublication(input), { poeUpperBound: published });
    const authenticate = (knowledgeTime) => authenticateRetainedAuthorityEntry({
      ...f.configuration, entry, knowledgeTime, verifyPublication, strictRecords: true });
    assert.equal(authenticate(published - 0.25), null);
    for (const knowledgeTime of [published, published + 0.25]) {
      const admitted = authenticate(knowledgeTime);
      assert.equal(admitted.published, published);
      assert.equal(admitted.serial, 0);
      assert.deepEqual(admitted.hash, c.H('RootTrustManifest', entry.manifest));
    }
    assert.deepEqual(f.resolver([entry], { verifyPublication })(f.query), f.resolver([entry])(f.query));
  }
});

test('retained publication rejects VALID decisions without a finite own time bound', (t) => {
  const f = fixture(t), entry = f.snapshot();
  const decisions = [{ overall: 'VALID' }, ...[undefined, null, NaN, Infinity, -Infinity, String(f.start)]
    .map((poeUpperBound) => ({ overall: 'VALID', poeUpperBound }))];
  for (const decision of decisions) {
    const verifyPublication = () => decision;
    const resolve = f.resolver([entry], { verifyPublication });
    assert.deepEqual(resolve(f.query), { overall: 'INDETERMINATE', reason: 'HISTORY_PUBLICATION_PROOF_REQUIRED' });
    assert.throws(() => requireAuthority(resolve, f.query), { code: 'HISTORY_PUBLICATION_PROOF_REQUIRED' });
    assert.throws(() => authenticateRetainedAuthorityEntry({ ...f.configuration, entry,
      knowledgeTime: f.query.knowledgeTime, verifyPublication, strictRecords: true }),
    { overall: 'INDETERMINATE', code: 'HISTORY_PUBLICATION_PROOF_REQUIRED' });
  }
});

test('retained publication rejects inherited accessor and proxy decisions without executing hooks', (t) => {
  const f = fixture(t), entry = f.snapshot();
  let hooks = 0;
  const hook = () => { hooks++; return f.start; };
  const decisions = [
    Object.create({ overall: 'VALID', poeUpperBound: f.start }),
    { get overall() { hooks++; return 'VALID'; }, poeUpperBound: f.start },
    { overall: 'VALID', get poeUpperBound() { return hook(); } },
    { overall: 'VALID', poeUpperBound: f.start, get then() { return hook(); } },
    new Proxy({ overall: 'VALID', poeUpperBound: f.start }, {
      get: hook, getPrototypeOf: hook, getOwnPropertyDescriptor: hook, has: hook,
    }),
  ];
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  decisions.push(revoked.proxy);
  for (const decision of decisions) {
    assert.deepEqual(f.resolver([entry], { verifyPublication: () => decision })(f.query),
      { overall: 'INDETERMINATE', reason: 'HISTORY_PUBLICATION_PROOF_REQUIRED' });
  }
  assert.equal(hooks, 0);
});

test('retained publication preserves explicit negative decisions and rejects malformed verdicts', (t) => {
  const f = fixture(t), entry = f.snapshot();
  for (const overall of ['INVALID', 'INDETERMINATE', 'UNSUPPORTED']) {
    const decision = { overall, reason: 'PUBLICATION_PROOF_DENIED' };
    assert.deepEqual(f.resolver([entry], { verifyPublication: () => decision })(f.query), decision);
  }
  let hooks = 0;
  for (const decision of [undefined, null, true, 'VALID', {}, { overall: 'UNKNOWN' },
    Object.assign([], { overall: 'VALID', poeUpperBound: f.start }),
    Object.assign(() => {}, { overall: 'VALID', poeUpperBound: f.start }),
    { overall: 'VALID', poeUpperBound: f.start, then() { hooks++; } },
    { overall: 'VALID', poeUpperBound: f.start, then: null }]) {
    assert.deepEqual(f.resolver([entry], { verifyPublication: () => decision })(f.query),
      { overall: 'INDETERMINATE', reason: 'HISTORY_PUBLICATION_PROOF_REQUIRED' });
  }
  const denied = { overall: 'INVALID', get reason() { hooks++; return 'UNREAD'; } };
  assert.deepEqual(f.resolver([entry], { verifyPublication: () => denied })(f.query),
    { overall: 'INVALID', reason: 'HISTORY_PUBLICATION_PROOF_REQUIRED' });
  assert.equal(hooks, 0);
});

test('retained publication rejects native promises and observes ordinary rejected results', async (t) => {
  const f = fixture(t), entry = f.snapshot();
  let hooks = 0;
  for (const decision of [Promise.resolve({ overall: 'VALID', poeUpperBound: f.start }),
    Promise.reject(Error('publication unavailable'))]) {
    Object.assign(decision, { overall: 'VALID', poeUpperBound: f.start });
    Object.defineProperty(decision, 'then', { get() { hooks++; throw Error('unread then'); } });
    assert.deepEqual(f.resolver([entry], { verifyPublication: () => decision })(f.query),
      { overall: 'INDETERMINATE', reason: 'HISTORY_PUBLICATION_PROOF_REQUIRED' });
  }
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(hooks, 0);
});

test('retained publication exceptions cannot supply a positive or unknown authority verdict', (t) => {
  const f = fixture(t), entry = f.snapshot();
  for (const overall of ['VALID', 'UNKNOWN']) {
    const resolve = f.resolver([entry], { verifyPublication: () => {
      throw { overall, code: 'PUBLICATION_CALLBACK_FAILED' };
    } });
    assert.deepEqual(resolve(f.query), { overall: 'INVALID', reason: 'PUBLICATION_CALLBACK_FAILED' });
    assert.throws(() => requireAuthority(resolve, f.query), { code: 'PUBLICATION_CALLBACK_FAILED' });
  }
});

test('retained publication rejects promises even when custom species prevents rejection observation', () => {
  const child = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    import { authenticateRetainedAuthorityEntry } from ${JSON.stringify(new URL('./retained-authorities.mjs', import.meta.url).href)};
    const unhandled = [];
    process.on('unhandledRejection', (error) => unhandled.push(error.message));
    class ThrowingSpecies extends Promise {
      static get [Symbol.species]() { throw Error('species getter'); }
    }
    const decision = ThrowingSpecies.reject(Error('publication unavailable'));
    Object.assign(decision, { overall: 'VALID', poeUpperBound: 1 });
    let admitted = false, failure;
    try {
      authenticateRetainedAuthorityEntry({
        entry: { manifest: {}, signatures: [], publicationProof: Buffer.alloc(0) },
        verifyPublication: () => decision,
      });
      admitted = true;
    } catch (error) { failure = { overall: error.overall, code: error.code }; }
    await new Promise((resolve) => setImmediate(resolve));
    console.log(JSON.stringify({ admitted, failure, unhandled }));
  `], { encoding: 'utf8', timeout: 10000 });
  assert.equal(child.error, undefined);
  assert.equal(child.signal, null);
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), {
    admitted: false,
    failure: { overall: 'INDETERMINATE', code: 'HISTORY_PUBLICATION_PROOF_REQUIRED' },
    unhandled: ['publication unavailable'],
  });
});

test('retained publication normalizes thrown getters proxies and nonstring reasons without executing hooks', (t) => {
  const f = fixture(t), entry = f.snapshot();
  let hooks = 0;
  const hook = () => { hooks++; throw Error('unread exception hook'); };
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  const errors = [
    { get overall() { return hook(); } },
    { overall: 'INVALID', get code() { return hook(); } },
    new Proxy({}, { get: hook, getPrototypeOf: hook, getOwnPropertyDescriptor: hook }),
    revoked.proxy,
    { overall: 'INVALID', code: {} },
    { overall: 'INVALID', code: 1 },
    Object.create({ overall: 'INDETERMINATE', code: 'INHERITED_FAILURE' }),
    undefined, null, 'failure', 0,
  ];
  for (const error of errors) {
    const resolve = f.resolver([entry], { verifyPublication: () => { throw error; } });
    assert.deepEqual(resolve(f.query), { overall: 'INVALID', reason: 'HISTORY_INVALID' });
    assert.throws(() => requireAuthority(resolve, f.query), { code: 'HISTORY_INVALID' });
  }
  for (const overall of ['INVALID', 'INDETERMINATE', 'UNSUPPORTED']) {
    const error = Object.assign(Error('publication failed'), { overall, code: 'PUBLICATION_CALLBACK_FAILED' });
    assert.deepEqual(f.resolver([entry], { verifyPublication: () => { throw error; } })(f.query),
      { overall, reason: 'PUBLICATION_CALLBACK_FAILED' });
  }
  assert.equal(hooks, 0);
});

test('retained publication data decisions still require signed manifest authorization', (t) => {
  const f = fixture(t), entry = f.snapshot();
  const verifyPublication = () => ({ overall: 'VALID', poeUpperBound: f.start });
  entry.signatures[0].signature[0] ^= 1;
  assert.equal(f.resolver([entry], { verifyPublication })(f.query).reason, 'HISTORY_ROOT_AUTHORIZATION');
  assert.throws(() => authenticateRetainedAuthorityEntry({ ...f.configuration, entry,
    knowledgeTime: f.query.knowledgeTime, verifyPublication, strictRecords: true }),
  { code: 'HISTORY_ROOT_AUTHORIZATION' });
});

test('retained RTM and RFC3161 evidence support offline role history and late compromise', (t) => {
  const f = fixture(t), first = f.snapshot();
  const incident = { ...f.record, status: { ...f.record.status, status: 'REVOKED',
    publishedAt: f.start + 100, nextUpdate: f.start + 300, effectiveTime: f.start + 100, compromiseStart: f.start + 5 } };
  const later = f.snapshot({ previous: first, published: f.start + 100, records: [incident] });
  const resolve = f.resolver([first, later]);
  assert.equal(resolve(f.query).overall, 'VALID');
  assert.equal(resolve({ ...f.query, knowledgeTime: f.start + 150 }).reason, 'AUTHORITY_REVOKED');
  assert.equal(f.resolver([first])({ ...f.query, knowledgeTime: f.start + 300 }).reason, 'HISTORY_KNOWLEDGE_COVERAGE');
  assert.equal(resolve({ ...f.query, knowledgeTime: f.start + 400 }).overall, 'INVALID');
  const erased = f.snapshot({ previous: later, published: f.start + 150,
    records: [{ ...f.record, status: { ...f.record.status, publishedAt: f.start + 150, nextUpdate: f.start + 350 } }] });
  assert.equal(f.resolver([first, later, erased])({ ...f.query, knowledgeTime: f.start + 160 }).reason, 'AUTHORITY_REVOKED');
});

test('lost renewal responses reconcile the exact retained timestamp without another TSA execution', async (t) => {
  const f = fixture(t), directory = mkdtempSync(join(tmpdir(), 'certconcord-renewal-')), path = join(directory, 'journal.sqlite');
  let journal = new Journal(path), calls = 0, retainedToken;
  const dataHash = c.sha512(Buffer.from('retained operation'));
  const request = { operationID: c.random(), archiveID: 'document', previousHash: null,
    timestampRequest: timestampRequest(dataHash, { policy: f.tsa.policy }).der,
    protectionDeadline: f.start + 100 };
  const create = () => {
    const store = new ArchivePublicationStore(journal, { validatePublication: () => ({ overall: 'VALID' }) });
    return new ArchiveRenewalCoordinator({ journal, store, clock: () => f.start + 200, timestampTrust: f.tsaTrust,
      requestTimestamp: async (der) => { calls++; retainedToken = tokenFromResponse(f.tsa.issue(der)); throw Error('response lost'); },
      buildPublication: (request, token) => ({ archiveID: request.archiveID, previousHash: request.previousHash,
        dataHash, evidenceRecord: token, history: [] }) });
  };
  try {
    let coordinator = create();
    coordinator.clock = () => f.start;
    await assert.rejects(coordinator.renew(request), /response lost/);
    assert.equal(calls, 1);
    journal.close(); journal = new Journal(path);
    coordinator = create();
    await assert.rejects(coordinator.renew(request), /ARCHIVE_RENEWAL_UNKNOWN/);
    assert.equal(calls, 1);
    const completed = coordinator.reconcile(request.operationID, retainedToken);
    assert.equal(coordinator.result(request.operationID).status, 'COMPLETED');
    assert.deepEqual((await coordinator.renew(request)).digest, completed.digest);
    assert.equal(calls, 1);
    const wrong = timestampRequest(c.random(64), { policy: f.tsa.policy });
    assert.throws(() => coordinator.reconcile(request.operationID, tokenFromResponse(f.tsa.issue(wrong.der))), /TSA_REQUEST_BINDING/);
  } finally { journal.close(); rmSync(directory, { recursive: true, force: true }); }
});



test('archive renewal rejects malformed authority decisions and reconciles retained tokens without another TSA execution', async (t) => {
  const f = fixture(t);
  const cases = [
    ['inherited', () => Object.create({ overall: 'VALID' })],
    ['thenable', (hook) => ({ overall: 'VALID', then: hook })],
    ['promise', () => Object.assign(Promise.resolve({ overall: 'INVALID' }), { overall: 'VALID' })],
    ['accessor', (hook) => ({ get overall() { hook(); return 'VALID'; } })],
    ['proxy', (hook) => new Proxy({}, { get() { hook(); return 'VALID'; } })],
  ];
  for (const [name, decision] of cases) {
    const journal = new Journal();
    try {
      let calls = 0, builds = 0, validations = 0, hooks = 0, token;
      const queries = [], dataHash = c.sha512(Buffer.from('unchanged document bytes'));
      const store = new ArchivePublicationStore(journal, {
        validatePublication: () => { validations++; return { overall: 'VALID' }; },
      });
      const original = store.publish({ archiveID: name, previousHash: null, dataHash,
        evidenceRecord: Buffer.from('previous retained archive'), history: [] });
      validations = 0;
      const request = { operationID: c.random(), archiveID: name, previousHash: original.digest,
        timestampRequest: timestampRequest(dataHash, { policy: f.tsa.policy }).der,
        protectionDeadline: f.start + 100 };
      const coordinator = new ArchiveRenewalCoordinator({ journal, store, clock: () => f.start + 20,
        timestampTrust: { ...f.tsaTrust, authorityResolver: (query) => {
          queries.push(query); return decision(() => { hooks++; });
        } },
        requestTimestamp: async (der) => { calls++; token = tokenFromResponse(f.tsa.issue(der)); return token; },
        buildPublication: (saved, retained) => { builds++; return { archiveID: saved.archiveID,
          previousHash: saved.previousHash, dataHash, evidenceRecord: retained, history: [] }; } });
      await assert.rejects(coordinator.renew(request),
        { overall: 'INDETERMINATE', code: 'AUTHORITY_DECISION_MISSING' }, name);
      assert.equal(coordinator.result(request.operationID).status, 'UNKNOWN_EXECUTION', name);
      assert.deepEqual(c.dcbor(store.read(name)), c.dcbor(original), name);
      assert.deepEqual([calls, builds, validations, hooks], [1, 0, 0, 0], name);
      assert.deepEqual(queries[0], { certificate: f.tsaTrust.certificate, role: 'TIMESTAMP_AUTHORITY',
        scope: { trustDomainID: f.trustDomainID, purpose: 'ARCHIVE_PRESERVATION' },
        stateTime: f.start, knowledgeTime: f.start + 20 });
      await assert.rejects(coordinator.renew(request), { code: 'ARCHIVE_RENEWAL_UNKNOWN' });
      coordinator.clock = () => f.start + 200;
      coordinator.timestampTrust.authorityResolver = (query) => { queries.push(query); return f.tsaTrust.authorityResolver(query); };
      const recovered = coordinator.reconcile(request.operationID, token);
      assert.equal(coordinator.result(request.operationID).status, 'COMPLETED', name);
      assert.deepEqual(c.dcbor(store.read(name)), c.dcbor(recovered), name);
      assert.deepEqual(recovered.publication.previousHash, original.digest);
      assert.deepEqual(recovered.publication.evidenceRecord, token);
      assert.equal(queries.length, 2);
      assert.equal(queries[1].stateTime, f.start);
      assert.equal(queries[1].knowledgeTime, f.start + 200);
      assert.deepEqual(c.dcbor(await coordinator.renew(request)), c.dcbor(recovered), name);
      assert.deepEqual([calls, builds, validations, hooks], [1, 1, 1, 0], name);
    } finally { journal.close(); }
  }
});

test('a new late timestamp cannot repair an uncertain renewal after the protection deadline', async (t) => {
  const f = fixture(t), journal = new Journal();
  t.after(() => journal.close());
  const dataHash = c.sha512(Buffer.from('retained operation'));
  const store = new ArchivePublicationStore(journal, { validatePublication: () => ({ overall: 'VALID' }) });
  const request = { operationID: c.random(), archiveID: 'late-document', previousHash: null,
    timestampRequest: timestampRequest(dataHash, { policy: f.tsa.policy }).der, protectionDeadline: f.start + 100 };
  const coordinator = new ArchiveRenewalCoordinator({ journal, store, clock: () => f.start,
    timestampTrust: f.tsaTrust, requestTimestamp: async () => { throw Error('unavailable response'); },
    buildPublication: () => { throw Error('must not publish'); } });
  await assert.rejects(coordinator.renew(request), /unavailable response/);
  f.setTime(f.start + 101); coordinator.clock = () => f.start + 102;
  const late = tokenFromResponse(f.tsa.issue(request.timestampRequest));
  assert.throws(() => coordinator.reconcile(request.operationID, late), /ARCHIVE_RENEWAL_LATE/);
  assert.equal(coordinator.result(request.operationID).status, 'UNKNOWN_EXECUTION');
  assert.equal(store.read(request.archiveID), undefined);
});

test('archive renewal binds one detached publication snapshot before publishing', async (t) => {
  const f = fixture(t);
  for (const [changing, seeded] of [
    ['archiveID', false], ['archiveID', true], ['previousHash', false], ['previousHash', true],
  ]) {
    const journal = new Journal();
    try {
      let calls = 0, builds = 0, reads = 0, validations = 0, token;
      const dataHash = c.sha512(Buffer.from('immutable document'));
      const store = new ArchivePublicationStore(journal, {
        validatePublication: () => { validations++; return { overall: 'VALID' }; },
      });
      const original = seeded ? store.publish({ archiveID: changing, previousHash: null, dataHash,
        evidenceRecord: Buffer.from('original archive'), history: [] }) : undefined;
      validations = 0;
      const request = { operationID: c.random(), archiveID: changing, previousHash: original?.digest ?? null,
        timestampRequest: timestampRequest(dataHash, { policy: f.tsa.policy }).der,
        protectionDeadline: f.start + 100 };
      const coordinator = new ArchiveRenewalCoordinator({ journal, store, clock: () => f.start,
        timestampTrust: f.tsaTrust,
        requestTimestamp: async (der) => { calls++; token = tokenFromResponse(f.tsa.issue(der)); return token; },
        buildPublication: (saved, retained) => {
          builds++;
          const publication = { archiveID: saved.archiveID, previousHash: saved.previousHash,
            dataHash, evidenceRecord: retained, history: [] };
          Object.defineProperty(publication, changing, { enumerable: true, get: () => {
            reads++;
            return reads === 1 ? saved[changing] : changing === 'archiveID' ? 'different-archive' : c.random(64);
          } });
          return publication;
        } });
      const completed = await coordinator.renew(request);
      assert.deepEqual(c.dcbor(completed.publication), c.dcbor({ archiveID: request.archiveID,
        previousHash: original?.digest ?? null, dataHash, evidenceRecord: token, history: [] }), changing);
      assert.deepEqual(c.dcbor(store.read(changing)), c.dcbor(completed), changing);
      assert.equal(store.read('different-archive'), undefined, changing);
      assert.equal(coordinator.result(request.operationID).status, 'COMPLETED', changing);
      assert.deepEqual(coordinator.result(request.operationID).result, c.dcbor(completed), changing);
      assert.deepEqual(c.dcbor(await coordinator.renew(request)), c.dcbor(completed), changing);
      assert.deepEqual([calls, builds, reads, validations], [1, 1, 1, 1], changing);
    } finally { journal.close(); }
  }
});

test('archive renewal rejects mismatched publication snapshots and recovers with the original token', async (t) => {
  const f = fixture(t);
  for (const changing of ['archiveID', 'previousHash']) {
    const journal = new Journal();
    try {
      let calls = 0, validations = 0, token;
      const dataHash = c.sha512(Buffer.from('retained document'));
      const store = new ArchivePublicationStore(journal, {
        validatePublication: () => { validations++; return { overall: 'VALID' }; },
      });
      const original = store.publish({ archiveID: changing, previousHash: null, dataHash,
        evidenceRecord: Buffer.from('original archive'), history: [] });
      validations = 0;
      const request = { operationID: c.random(), archiveID: changing, previousHash: original.digest,
        timestampRequest: timestampRequest(dataHash, { policy: f.tsa.policy }).der,
        protectionDeadline: f.start + 100 };
      const build = (saved, retained) => ({ archiveID: saved.archiveID, previousHash: saved.previousHash,
        dataHash, evidenceRecord: retained, history: [] });
      const coordinator = new ArchiveRenewalCoordinator({ journal, store, clock: () => f.start,
        timestampTrust: f.tsaTrust,
        requestTimestamp: async (der) => { calls++; token = tokenFromResponse(f.tsa.issue(der)); return token; },
        buildPublication: (saved, retained) => ({ ...build(saved, retained),
          [changing]: changing === 'archiveID' ? 'different-archive' : c.random(64) }) });
      await assert.rejects(coordinator.renew(request), { code: 'ARCHIVE_RENEWAL_PUBLICATION_BINDING' });
      assert.equal(coordinator.result(request.operationID).status, 'UNKNOWN_EXECUTION', changing);
      assert.deepEqual(c.dcbor(store.read(changing)), c.dcbor(original), changing);
      assert.equal(store.read('different-archive'), undefined, changing);
      assert.deepEqual([calls, validations], [1, 0], changing);
      coordinator.buildPublication = build;
      coordinator.clock = () => f.start + 200;
      const completed = coordinator.reconcile(request.operationID, token);
      assert.deepEqual(c.dcbor(completed.publication), c.dcbor(build(request, token)), changing);
      assert.deepEqual(c.dcbor(store.read(changing)), c.dcbor(completed), changing);
      assert.equal(coordinator.result(request.operationID).status, 'COMPLETED', changing);
      assert.deepEqual([calls, validations], [1, 1], changing);
    } finally { journal.close(); }
  }
});

function renewalRecovery(f, journal, savedRequest) {
  const dataHash = c.sha512(Buffer.from('reserved recovery document'));
  const context = { clock: f.start, token: null,
    calls: { tsa: 0, authority: 0, build: 0, validation: 0 } };
  const store = new ArchivePublicationStore(journal, { validatePublication: () => {
    context.calls.validation++;
    context.onValidation?.();
    return { overall: 'VALID' };
  } });
  const original = store.read('reserved-document') ?? store.publish({ archiveID: 'reserved-document',
    previousHash: null, dataHash, evidenceRecord: Buffer.from('original archive'), history: [] });
  context.calls.validation = 0;
  const request = savedRequest ?? { operationID: c.random(), archiveID: 'reserved-document',
    previousHash: original.digest, timestampRequest: timestampRequest(dataHash, { policy: f.tsa.policy }).der,
    protectionDeadline: f.start + 100 };
  context.build = (saved, token) => ({ archiveID: saved.archiveID, previousHash: saved.previousHash,
    dataHash, evidenceRecord: token, history: [] });
  const coordinator = new ArchiveRenewalCoordinator({ journal, store, clock: () => context.clock,
    timestampTrust: { ...f.tsaTrust, authorityResolver: (query) => {
      context.calls.authority++;
      return f.tsaTrust.authorityResolver(query);
    } },
    requestTimestamp: async (der) => {
      context.calls.tsa++;
      context.token = tokenFromResponse(f.tsa.issue(der));
      throw Error('response lost');
    },
    buildPublication: (saved, token) => {
      context.calls.build++;
      context.onBuild?.();
      return context.build(saved, token);
    } });
  return Object.assign(context, { coordinator, store, original, request, dataHash,
    id: 'archive-renewal:' + c.b64u(request.operationID) });
}

test('archive renewal rejects changed persisted requests before invoking recovery callbacks', async (t) => {
  const f = fixture(t);
  const changes = {
    operationID: () => c.random(), archiveID: () => 'different-archive', previousHash: () => c.random(64),
    timestampRequest: () => timestampRequest(c.random(64), { policy: f.tsa.policy }).der,
    protectionDeadline: () => f.start + 300,
  };
  for (const [field, change] of Object.entries(changes)) {
    const journal = new Journal();
    try {
      f.setTime(f.start);
      const r = renewalRecovery(f, journal);
      await assert.rejects(r.coordinator.renew(r.request), /response lost/);
      const saved = journal.get('archive-renewal-request', r.id);
      journal.put('archive-renewal-request', r.id, { ...saved.value, [field]: change() }, saved.revision);
      let suppliedToken = r.token;
      if (field === 'protectionDeadline') {
        f.setTime(f.start + 101);
        suppliedToken = tokenFromResponse(f.tsa.issue(r.request.timestampRequest));
      }
      r.clock = f.start + 200;
      assert.throws(() => r.coordinator.reconcile(r.request.operationID, suppliedToken),
        { code: 'IDEMPOTENCY_CONFLICT' }, field);
      assert.deepEqual(r.calls, { tsa: 1, authority: 0, build: 0, validation: 0 }, field);
      assert.equal(r.coordinator.result(r.request.operationID).status, 'UNKNOWN_EXECUTION', field);
      assert.deepEqual(c.dcbor(r.store.read(r.request.archiveID)), c.dcbor(r.original), field);
      assert.equal(r.store.read('different-archive'), undefined, field);
      journal.put('archive-renewal-request', r.id, saved.value,
        journal.get('archive-renewal-request', r.id).revision);
      if (field === 'protectionDeadline')
        assert.throws(() => r.coordinator.reconcile(r.request.operationID, suppliedToken),
          { code: 'ARCHIVE_RENEWAL_LATE' });
      const completed = r.coordinator.reconcile(r.request.operationID, r.token);
      assert.deepEqual(c.dcbor(completed.publication), c.dcbor(r.build(r.request, r.token)), field);
      assert.equal(r.coordinator.result(r.request.operationID).status, 'COMPLETED', field);
      assert.equal(r.calls.tsa, 1, field);
    } finally { journal.close(); }
  }
});

test('archive renewal refuses an orphan saved request without creating a reservation', (t) => {
  const f = fixture(t), journal = new Journal();
  t.after(() => journal.close());
  const r = renewalRecovery(f, journal);
  journal.put('archive-renewal-request', r.id, r.request);
  const token = tokenFromResponse(f.tsa.issue(r.request.timestampRequest));
  assert.throws(() => r.coordinator.reconcile(r.request.operationID, token),
    { code: 'ARCHIVE_RENEWAL_REQUEST_MISSING' });
  assert.equal(r.coordinator.result(r.request.operationID), undefined);
  assert.deepEqual(r.calls, { tsa: 0, authority: 0, build: 0, validation: 0 });
  assert.deepEqual(c.dcbor(r.store.read(r.request.archiveID)), c.dcbor(r.original));
  assert.deepEqual(c.dcbor(journal.get('archive-renewal-request', r.id).value), c.dcbor(r.request));
});

test('archive renewal rolls back publication when callbacks change the reserved request', async (t) => {
  const f = fixture(t);
  for (const hook of ['onBuild', 'onValidation']) {
    const journal = new Journal();
    try {
      const r = renewalRecovery(f, journal);
      await assert.rejects(r.coordinator.renew(r.request), /response lost/);
      const saved = journal.get('archive-renewal-request', r.id);
      r[hook] = () => {
        const current = journal.get('archive-renewal-request', r.id);
        journal.put('archive-renewal-request', r.id,
          { ...current.value, protectionDeadline: f.start + 300 }, current.revision);
      };
      assert.throws(() => r.coordinator.reconcile(r.request.operationID, r.token),
        { code: 'ARCHIVE_RENEWAL_REQUEST_BINDING' }, hook);
      assert.equal(r.coordinator.result(r.request.operationID).status, 'UNKNOWN_EXECUTION', hook);
      assert.deepEqual(c.dcbor(r.store.read(r.request.archiveID)), c.dcbor(r.original), hook);
      assert.equal(journal.get('archive-publication', r.request.archiveID).revision, 0, hook);
      assert.deepEqual(r.calls, { tsa: 1, authority: 1, build: 1,
        validation: hook === 'onValidation' ? 1 : 0 }, hook);
      if (hook === 'onValidation')
        assert.deepEqual(journal.get('archive-renewal-request', r.id), saved);
      else journal.put('archive-renewal-request', r.id, saved.value,
        journal.get('archive-renewal-request', r.id).revision);
      r[hook] = undefined;
      const completed = r.coordinator.reconcile(r.request.operationID, r.token);
      assert.deepEqual(c.dcbor(completed.publication), c.dcbor(r.build(r.request, r.token)), hook);
      assert.equal(journal.get('archive-publication', r.request.archiveID).revision, 1, hook);
      assert.equal(r.coordinator.result(r.request.operationID).status, 'COMPLETED', hook);
      assert.equal(r.calls.tsa, 1, hook);
    } finally { journal.close(); }
  }
});

test('archive renewal restores request and publication bindings across restart without another TSA request', async (t) => {
  const f = fixture(t), directory = mkdtempSync(join(tmpdir(), 'certconcord-renewal-bindings-'));
  const path = join(directory, 'journal.sqlite');
  let journal = new Journal(path);
  try {
    const first = renewalRecovery(f, journal);
    await assert.rejects(first.coordinator.renew(first.request), /response lost/);
    const token = Buffer.from(first.token), request = first.request, original = c.dcbor(first.original);
    journal.close(); journal = new Journal(path);
    const recovered = renewalRecovery(f, journal, request), saved = journal.get('archive-renewal-request', recovered.id);
    journal.put('archive-renewal-request', recovered.id,
      { ...saved.value, protectionDeadline: f.start + 300 }, saved.revision);
    recovered.clock = f.start + 200;
    assert.throws(() => recovered.coordinator.reconcile(request.operationID, token),
      { code: 'IDEMPOTENCY_CONFLICT' });
    assert.deepEqual(c.dcbor(recovered.store.read(request.archiveID)), original);
    assert.equal(recovered.coordinator.result(request.operationID).status, 'UNKNOWN_EXECUTION');
    assert.deepEqual(recovered.calls, { tsa: 0, authority: 0, build: 0, validation: 0 });
    journal.put('archive-renewal-request', recovered.id, saved.value,
      journal.get('archive-renewal-request', recovered.id).revision);
    let reads = 0;
    recovered.build = (saved, retained) => ({
      get archiveID() { return ++reads === 1 ? saved.archiveID : 'different-archive'; },
      previousHash: saved.previousHash, dataHash: recovered.dataHash, evidenceRecord: retained, history: [],
    });
    const completed = recovered.coordinator.reconcile(request.operationID, token);
    assert.deepEqual(c.dcbor(completed.publication), c.dcbor({ archiveID: request.archiveID,
      previousHash: request.previousHash, dataHash: recovered.dataHash, evidenceRecord: token, history: [] }));
    assert.deepEqual(c.dcbor(recovered.store.read(request.archiveID)), c.dcbor(completed));
    assert.equal(recovered.store.read('different-archive'), undefined);
    assert.deepEqual([first.calls.tsa, recovered.calls.tsa, reads], [1, 0, 1]);
    journal.close(); journal = new Journal(path);
    const final = renewalRecovery(f, journal, request);
    assert.equal(final.coordinator.result(request.operationID).status, 'COMPLETED');
    assert.deepEqual(final.coordinator.result(request.operationID).result, c.dcbor(completed));
    assert.deepEqual(c.dcbor(await final.coordinator.renew(request)), c.dcbor(completed));
    assert.deepEqual(final.calls, { tsa: 0, authority: 0, build: 0, validation: 0 });
  } finally { journal.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('root succession needs both quorums, retained links and explicit algorithm lifetimes', (t) => {
  const f = fixture(t), first = f.snapshot();
  const successorPolicy = f.policy(f.successor);
  const transfer = f.snapshot({ previous: first, published: f.start + 50, successorPolicy, signers: [f.root, f.successor] });
  const final = f.snapshot({ previous: transfer, published: f.start + 100, signers: [f.successor] });
  const query = { ...f.query, knowledgeTime: f.start + 110 };
  assert.equal(f.resolver([first, transfer, final])(query).overall, 'VALID');
  assert.equal(f.resolver([first, final])(query).overall, 'INVALID');
  const unilateral = f.snapshot({ previous: first, published: f.start + 50, successorPolicy });
  assert.equal(f.resolver([first, unilateral])(query).reason, 'HISTORY_ROOT_AUTHORIZATION');
  assert.equal(f.resolver([first], { algorithmDeadlines: {} })(query).overall, 'INDETERMINATE');
  assert.equal(f.resolver([first], { algorithmDeadlines: { 'ml-dsa-87': f.start } })(query).overall, 'INVALID');
});

test('publication time and authority admission cannot be supplied by backdated content', (t) => {
  const f = fixture(t);
  const late = f.snapshot({ published: f.start + 100 });
  assert.equal(f.resolver([late])({ ...f.query, knowledgeTime: f.start + 120 }).overall, 'INVALID');
  const first = f.snapshot();
  const tampered = c.decodeCBOR(c.dcbor(first));
  tampered.manifest.coverageUntil += 10000;
  assert.equal(f.resolver([tampered])(f.query).overall, 'INVALID');
  assert.equal(f.resolver([first], { verifyPublication: () => ({ overall: 'INDETERMINATE' }) })(f.query).overall, 'INDETERMINATE');
});

test('later authority rotation retains the earlier appointment and requires fresh old-key status', (t) => {
  const f = fixture(t), first = f.snapshot();
  const laterKey = c.generate('ml-dsa-87');
  const later = { mode: 'RAW_KEY', publicKeyDER: c.spki(laterKey.publicKey), knownAt: f.start + 50,
    validFrom: f.start + 50, validUntil: f.start + 1000,
    roles: ['PERMIT_AUTHORITY'], scopes: [{ trustDomainID: f.trustDomainID }],
    status: { ...f.record.status, authorityID: c.keyID(laterKey.publicKey),
      publishedAt: f.start + 50, nextUpdate: f.start + 250 } };
  const rotation = f.snapshot({ previous: first, published: f.start + 50, records: [later] });
  assert.equal(f.resolver([first, rotation])({ ...f.query, knowledgeTime: f.start + 60 }).overall, 'VALID');
  assert.equal(f.resolver([first, rotation])({ ...f.query, knowledgeTime: f.start + 220 }).overall, 'INDETERMINATE');
  assert.equal(f.resolver([first, rotation])({ ...f.query, stateTime: f.start + 60,
    knowledgeTime: f.start + 60 }).overall, 'INDETERMINATE');
});

test('archive history and ERS head publish atomically, survive restart and reject competing heads', () => {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord-archive-')), path = join(directory, 'journal.sqlite');
  let journal = new Journal(path);
  const options = { validatePublication: () => ({ overall: 'VALID' }) };
  const first = { archiveID: 'retained-document', previousHash: null, dataHash: c.sha512(Buffer.from('document')),
    evidenceRecord: Buffer.from('opaque previously validated RFC4998 record'), history: [{ serial: 0 }] };
  try {
    let store = new ArchivePublicationStore(journal, options);
    const initial = store.publish(first);
    const second = { ...first, previousHash: initial.digest,
      evidenceRecord: Buffer.from('validated renewed RFC4998 record'), history: [{ serial: 0 }, { serial: 1, custodian: 'successor' }] };
    store = new ArchivePublicationStore(journal, { ...options, crash: (point) => {
      if (point === 'after-publication-before-commit') throw Error('simulated crash');
    } });
    assert.throws(() => store.publish(second), /simulated crash/);
    journal.close(); journal = new Journal(path);
    store = new ArchivePublicationStore(journal, options);
    assert.deepEqual(store.read(first.archiveID).digest, initial.digest);
    const completed = store.publish(second);
    journal.close(); journal = new Journal(path);
    store = new ArchivePublicationStore(journal, options);
    assert.deepEqual(store.read(first.archiveID).publication.history, c.decodeCBOR(c.dcbor(second.history)));
    assert.deepEqual(store.publish(second).digest, completed.digest);
    assert.throws(() => store.publish({ ...second, evidenceRecord: Buffer.from('competing record') }), /ARCHIVE_PUBLICATION_CONFLICT/);
    assert.throws(() => store.publish({ ...second, previousHash: completed.digest, dataHash: c.random(64) }), /ARCHIVE_PUBLICATION_CONFLICT/);
  } finally { journal.close(); rmSync(directory, { recursive: true, force: true }); }
});

function terminateAtPublicationBoundary({
  cwd,
  path,
  snapshot,
  publication,
  observePending,
  mode = 'publish',
}) {
  return new Promise((resolve, reject) => {
    const childPath = fileURLToPath(
      new URL('./retained-authorities-crash-child.mjs', import.meta.url),
    );
    const worker = spawn(process.execPath, [childPath, path, snapshot, mode], {
      cwd,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '',
      stderr = '',
      ready,
      failure,
      killAcknowledged = false;
    const stop = (error) => {
      failure ??= error;
      worker.kill('SIGKILL');
    };
    const timer = setTimeout(
      () => stop(new Error('Archive child did not finish the crash protocol within 10 seconds')),
      10000,
    );
    worker.stdout.setEncoding('utf8');
    worker.stderr.setEncoding('utf8');
    worker.once('error', (error) => {
      failure ??= error;
    });
    worker.stderr.on('data', (chunk) => {
      stderr += chunk;
      if (stderr.length > 16384) stop(new Error('Archive child stderr exceeded its bound'));
    });
    worker.stdout.on('data', (chunk) => {
      stdout += chunk;
      try {
        assert.ok(stdout.length <= 16384, 'Archive child stdout exceeded its bound');
        if (!stdout.includes('\n')) return;
        assert.equal(ready, undefined, 'Archive child emitted more than one boundary observation');
        assert.equal(
          stdout.indexOf('\n'),
          stdout.length - 1,
          'Archive child emitted unexpected output',
        );
        ready = JSON.parse(stdout);
        assert.deepEqual(ready, {
          event: 'publication-pending',
          point: 'after-publication-before-commit',
          pid: worker.pid,
          archiveID: publication.archiveID,
          digest: c.sha512(c.dcbor(publication)).toString('hex'),
          revision: 1,
          transactionDepth: 1,
        });
        observePending();
        killAcknowledged = worker.kill('SIGKILL');
        assert.equal(
          killAcknowledged,
          true,
          'The parent must successfully request forcible termination',
        );
      } catch (error) {
        stop(error);
      }
    });
    worker.once('close', (exitCode, signal) => {
      clearTimeout(timer);
      try {
        if (failure) throw failure;
        if (!ready) {
          throw Object.assign(
            new Error('Archive child exited before the transaction boundary: ' + stderr),
            {
              code: 'ARCHIVE_CRASH_BOUNDARY_NOT_REACHED',
              exitCode,
              signal,
              killAcknowledged,
            },
          );
        }
        assert.equal(killAcknowledged, true);
        if (process.platform === 'win32' && signal === null) {
          assert.ok(
            Number.isInteger(exitCode) && exitCode !== 0,
            'Forced Windows termination must not be normal success',
          );
        } else {
          assert.equal(signal, 'SIGKILL', stderr);
          assert.equal(exitCode, null);
        }
        resolve({ ready, exitCode, signal, killAcknowledged });
      } catch (error) {
        reject(error);
      }
    });
  });
}

test('process termination between archive write and SQLite commit cannot publish half a renewal', async (t) => {
  const workingDirectories = [
    ['reference working directory', fileURLToPath(new URL('.', import.meta.url))],
    ['repository root working directory', fileURLToPath(new URL('..', import.meta.url))],
    ['unrelated working directory with spaces', null],
  ];
  for (const [name, configuredCwd] of workingDirectories) {
    await t.test(name, async (subtest) => {
      const directory = mkdtempSync(join(tmpdir(), 'certconcord archive crash ')),
        path = join(directory, 'journal.sqlite');
      const snapshot = join(directory, 'publication.cbor');
      let journal = new Journal(path);
      const options = { validatePublication: () => ({ overall: 'VALID' }) };
      const first = {
        archiveID: 'process-crash',
        previousHash: null,
        dataHash: c.sha512(Buffer.from('document')),
        evidenceRecord: Buffer.from('validated initial ERS'),
        history: [{ serial: 0 }],
      };
      try {
        const initial = new ArchivePublicationStore(journal, options).publish(first);
        const previousRow = { revision: 0, value: c.decodeCBOR(c.dcbor(initial)) };
        assert.deepEqual(journal.get('archive-publication', first.archiveID), previousRow);
        const second = {
          ...first,
          previousHash: initial.digest,
          evidenceRecord: Buffer.from('validated renewal'),
          history: [{ serial: 0 }, { serial: 1, custodian: 'successor' }],
        };
        writeFileSync(snapshot, c.dcbor(second));
        const termination = await terminateAtPublicationBoundary({
          cwd: configuredCwd ?? directory,
          path,
          snapshot,
          publication: second,
          observePending: () =>
            assert.deepEqual(journal.get('archive-publication', first.archiveID), previousRow),
        });
        subtest.diagnostic(JSON.stringify({ phase: 'forced-termination', ...termination }));
        journal.close();
        journal = new Journal(path);
        assert.deepEqual(journal.get('archive-publication', first.archiveID), previousRow);
        const completed = new ArchivePublicationStore(journal, options).publish(second);
        const expected = {
          digest: c.sha512(c.dcbor(second)),
          publication: c.decodeCBOR(c.dcbor(second)),
        };
        assert.deepEqual(completed, expected);
        journal.close();
        journal = new Journal(path);
        const renewedRow = { revision: 1, value: c.decodeCBOR(c.dcbor(expected)) };
        assert.deepEqual(journal.get('archive-publication', first.archiveID), renewedRow);
        assert.deepEqual(
          new ArchivePublicationStore(journal, options).publish(second),
          renewedRow.value,
        );
        assert.deepEqual(journal.get('archive-publication', first.archiveID), renewedRow);
        subtest.diagnostic(
          JSON.stringify({ phase: 'restart-verified', previousRevision: 0, renewedRevision: 1 }),
        );
      } finally {
        journal.close();
        rmSync(directory, { recursive: true, force: true });
      }
    });
  }
});

test('archive crash harness rejects an exit before the transaction boundary', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord archive early exit '));
  let observed = false;
  try {
    await assert.rejects(
      terminateAtPublicationBoundary({
        cwd: directory,
        path: join(directory, 'unused.sqlite'),
        snapshot: join(directory, 'unused.cbor'),
        publication: {},
        mode: 'exit-before-publication',
        observePending: () => {
          observed = true;
        },
      }),
      {
        code: 'ARCHIVE_CRASH_BOUNDARY_NOT_REACHED',
        exitCode: 23,
        signal: null,
        killAcknowledged: false,
      },
    );
    assert.equal(observed, false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});


test('archive publication accepts explicit synchronous decisions and preserves idempotent results', (t) => {
  const journal = new Journal();
  t.after(() => journal.close());
  let calls = 0;
  const publication = { archiveID: 'explicit-decision', previousHash: null, dataHash: c.sha512(Buffer.from('document')),
    evidenceRecord: Buffer.from('opaque authenticated test record'), history: [{ serial: 0 }] };
  const store = new ArchivePublicationStore(journal, { validatePublication: (candidate) => {
    calls++;
    assert.deepEqual(candidate, c.decodeCBOR(c.dcbor(publication)));
    candidate.evidenceRecord.fill(0);
    return Object.assign(Object.create(null), { overall: 'VALID' });
  } });
  const completed = store.publish(publication);
  assert.deepEqual(completed, { digest: c.sha512(c.dcbor(publication)), publication: c.decodeCBOR(c.dcbor(publication)) });
  assert.deepEqual(store.read(publication.archiveID), c.decodeCBOR(c.dcbor(completed)));
  assert.deepEqual(store.publish(publication), c.decodeCBOR(c.dcbor(completed)));
  assert.equal(journal.get('archive-publication', publication.archiveID).revision, 0);
  assert.equal(calls, 1);
});

test('archive publication rejects inherited and accessor decisions without invoking getters', (t) => {
  const journal = new Journal();
  t.after(() => journal.close());
  let reads = 0;
  const decisions = [
    Object.create({ overall: 'VALID' }),
    Object.defineProperty({}, 'overall', { get() { reads++; return 'VALID'; } }),
    Object.defineProperty({ overall: 'VALID' }, 'then', { get() { reads++; return null; } }),
    Object.assign(Object.create({ then() { reads++; } }), { overall: 'VALID' }),
  ];
  for (const [index, decision] of decisions.entries()) {
    const publication = { archiveID: 'inherited-' + index, previousHash: null, dataHash: Buffer.alloc(64, 1),
      evidenceRecord: Buffer.from('opaque test record'), history: [] };
    const store = new ArchivePublicationStore(journal, { validatePublication: () => decision });
    assert.throws(() => store.publish(publication), { code: 'ARCHIVE_PUBLICATION_VALIDATION' });
    assert.equal(store.read(publication.archiveID), undefined);
  }
  assert.equal(reads, 0);
});

test('archive publication rejects malformed and thenable decisions before storing a record', (t) => {
  const journal = new Journal();
  t.after(() => journal.close());
  let invoked = 0;
  const decisions = [undefined, null, true, false, {}, { overall: 'GOOD' },
    { overall: 'INVALID' }, { overall: 'INDETERMINATE' }, { overall: 'UNSUPPORTED' },
    Object.assign([], { overall: 'VALID' }), Object.assign(() => {}, { overall: 'VALID' }),
    { overall: 'VALID', then: null }, { overall: 'VALID', then: undefined },
    { overall: 'VALID', then() { invoked++; } }];
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  decisions.push(revoked.proxy);
  for (const [index, decision] of decisions.entries()) {
    const publication = { archiveID: 'malformed-' + index, previousHash: null, dataHash: Buffer.alloc(64, 1),
      evidenceRecord: Buffer.from('opaque test record'), history: [] };
    const store = new ArchivePublicationStore(journal, { validatePublication: () => decision });
    assert.throws(() => store.publish(publication), { code: 'ARCHIVE_PUBLICATION_VALIDATION' });
    assert.equal(store.read(publication.archiveID), undefined);
  }
  assert.equal(invoked, 0);
});

test('archive publication rejects native promises and observes rejected validation results', async (t) => {
  const journal = new Journal();
  t.after(() => journal.close());
  const decisions = [() => Promise.resolve({ overall: 'VALID' }),
    () => Object.assign(Promise.resolve({ overall: 'INVALID' }), { overall: 'VALID', then: null }),
    () => Object.assign(Promise.reject(Error('validator unavailable')), { overall: 'VALID', then: null })];
  for (const [index, decision] of decisions.entries()) {
    const publication = { archiveID: 'async-' + index, previousHash: null, dataHash: Buffer.alloc(64, 1),
      evidenceRecord: Buffer.from('opaque test record'), history: [] };
    const store = new ArchivePublicationStore(journal, { validatePublication: decision });
    assert.throws(() => store.publish(publication), { code: 'ARCHIVE_PUBLICATION_VALIDATION' });
    assert.equal(store.read(publication.archiveID), undefined);
  }
  await new Promise((resolve) => setImmediate(resolve));
});

test('archive publication rejects proxy decisions before invoking reflection traps', (t) => {
  const journal = new Journal();
  t.after(() => journal.close());
  let traps = 0;
  const target = {};
  const forged = new Proxy(target, {
    getPrototypeOf() { traps++; return Object.prototype; },
    getOwnPropertyDescriptor(_target, key) {
      traps++;
      return key === 'overall' ? { value: 'VALID', configurable: true } : undefined;
    },
    has() { traps++; return false; },
  });
  assert.equal(Object.hasOwn(target, 'overall'), false);
  const decisions = [forged, new Proxy({ overall: 'VALID' }, {}), new Proxy(Promise.resolve(), {})];
  for (const [index, decision] of decisions.entries()) {
    const publication = { archiveID: 'proxy-' + index, previousHash: null, dataHash: Buffer.alloc(64, 1),
      evidenceRecord: Buffer.from('opaque test record'), history: [] };
    const store = new ArchivePublicationStore(journal, { validatePublication: () => decision });
    assert.throws(() => store.publish(publication), { code: 'ARCHIVE_PUBLICATION_VALIDATION' });
    assert.equal(store.read(publication.archiveID), undefined);
  }
  assert.equal(traps, 0);
});

test('archive publication rejects promises when rejection observation throws', (t) => {
  const journal = new Journal();
  t.after(() => journal.close());
  let reads = 0;
  class ThrowingSpecies extends Promise {
    static get [Symbol.species]() { reads++; throw Error('species getter'); }
  }
  const constructorFailure = Promise.resolve();
  Object.defineProperty(constructorFailure, 'constructor', { get() { reads++; throw Error('constructor getter'); } });
  for (const [index, decision] of [ThrowingSpecies.resolve(), constructorFailure].entries()) {
    const publication = { archiveID: 'observer-' + index, previousHash: null, dataHash: Buffer.alloc(64, 1),
      evidenceRecord: Buffer.from('opaque test record'), history: [] };
    const store = new ArchivePublicationStore(journal, { validatePublication: () => decision });
    assert.throws(() => store.publish(publication), { code: 'ARCHIVE_PUBLICATION_VALIDATION' });
    assert.equal(store.read(publication.archiveID), undefined);
  }
  assert.equal(reads, 2);

  // Isolate the unsupported rejection so node:test does not consume the event.
  const child = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    import { ArchivePublicationStore } from ${JSON.stringify(new URL('./retained-authorities.mjs', import.meta.url).href)};
    import { Journal } from ${JSON.stringify(new URL('./state.mjs', import.meta.url).href)};
    const unhandled = [];
    process.on('unhandledRejection', (error) => unhandled.push(error.message));
    class ThrowingSpecies extends Promise {
      static get [Symbol.species]() { throw Error('species getter'); }
    }
    const decision = ThrowingSpecies.reject(Error('validator rejected'));
    Object.defineProperty(decision, 'then', { value: null });
    const journal = new Journal();
    const store = new ArchivePublicationStore(journal, { validatePublication: () => decision });
    let code;
    try {
      store.publish({ archiveID: 'unsupported-observer', previousHash: null,
        dataHash: Buffer.alloc(64), evidenceRecord: Buffer.from('opaque'), history: [] });
    } catch (error) { code = error.code ?? error.message; }
    const stored = store.read('unsupported-observer') !== undefined;
    journal.close();
    await new Promise((resolve) => setImmediate(resolve));
    console.log(JSON.stringify({ code, stored, unhandled }));
  `], { encoding: 'utf8', timeout: 10000 });
  assert.equal(child.error, undefined);
  assert.equal(child.signal, null);
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), {
    code: 'ARCHIVE_PUBLICATION_VALIDATION', stored: false, unhandled: ['validator rejected'],
  });
});

test('archive publication retains the committed head when renewal validation is denied or throws', (t) => {
  const journal = new Journal();
  t.after(() => journal.close());
  const first = { archiveID: 'retained-on-denial', previousHash: null, dataHash: c.sha512(Buffer.from('document')),
    evidenceRecord: Buffer.from('opaque authenticated initial record'), history: [{ serial: 0 }] };
  let validate = () => ({ overall: 'VALID' });
  const store = new ArchivePublicationStore(journal, { validatePublication: () => validate() });
  const initial = store.publish(first);
  const next = { ...first, previousHash: initial.digest,
    evidenceRecord: Buffer.from('opaque authenticated renewal'), history: [{ serial: 0 }, { serial: 1 }] };
  for (const overall of ['INVALID', 'INDETERMINATE', 'UNSUPPORTED']) {
    validate = () => ({ overall });
    assert.throws(() => store.publish(next), { code: 'ARCHIVE_PUBLICATION_VALIDATION' });
    assert.deepEqual(store.read(first.archiveID), c.decodeCBOR(c.dcbor(initial)));
    assert.equal(journal.get('archive-publication', first.archiveID).revision, 0);
  }
  const unavailable = Error('publication validation unavailable');
  validate = () => { throw unavailable; };
  assert.throws(() => store.publish(next), (error) => error === unavailable);
  assert.deepEqual(store.read(first.archiveID), c.decodeCBOR(c.dcbor(initial)));
  validate = () => ({ overall: 'VALID' });
  const completed = store.publish(next);
  assert.deepEqual(completed, { digest: c.sha512(c.dcbor(next)), publication: c.decodeCBOR(c.dcbor(next)) });
  assert.equal(journal.get('archive-publication', first.archiveID).revision, 1);
});
