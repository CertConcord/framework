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
