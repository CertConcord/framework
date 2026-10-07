import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal } from './state.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { TimestampAuthority, timestampRequest, tokenFromResponse, verifyTimestampToken } from './timestamp.mjs';
import { createRetainedAuthorityResolver, manifestPublicationImprint, ArchivePublicationStore, ArchiveRenewalCoordinator } from './retained-authorities.mjs';

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

test('process termination between archive write and SQLite commit cannot publish half a renewal', () => {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord-archive-crash-')), path = join(directory, 'journal.sqlite');
  let journal = new Journal(path);
  const first = { archiveID: 'process-crash', previousHash: null, dataHash: c.sha512(Buffer.from('document')),
    evidenceRecord: Buffer.from('validated initial ERS'), history: [{ serial: 0 }] };
  try {
    const store = new ArchivePublicationStore(journal, { validatePublication: () => ({ overall: 'VALID' }) });
    const initial = store.publish(first);
    journal.close(); journal = undefined;
    const second = { ...first, previousHash: initial.digest, evidenceRecord: Buffer.from('validated renewal'),
      history: [{ serial: 0 }, { serial: 1 }] };
    const worker = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import { Journal } from './state.mjs';
      import { decodeCBOR } from './core.mjs';
      import { ArchivePublicationStore } from './retained-authorities.mjs';
      const journal = new Journal(process.argv[1]);
      const store = new ArchivePublicationStore(journal, {
        validatePublication: () => ({ overall: 'VALID' }),
        crash: (point) => { if (point === 'after-publication-before-commit') process.kill(process.pid, 'SIGKILL'); }
      });
      store.publish(decodeCBOR(Buffer.from(process.argv[2], 'base64')));
    `, path, c.dcbor(second).toString('base64')], { encoding: 'utf8', windowsHide: true });
    assert.equal(worker.signal, 'SIGKILL', worker.stderr);
    journal = new Journal(path);
    const restarted = new ArchivePublicationStore(journal, { validatePublication: () => ({ overall: 'VALID' }) });
    assert.deepEqual(restarted.read(first.archiveID).digest, initial.digest);
    assert.equal(restarted.read(first.archiveID).publication.history.length, 1);
    assert.equal(restarted.publish(second).publication.history.length, 2);
  } finally { journal?.close(); rmSync(directory, { recursive: true, force: true }); }
});
