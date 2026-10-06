import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as c from './core.mjs';
import { Journal, TrustStore, assertRecoverySeparation, readControl } from './state.mjs';
import { issueCertificate, signCMS, name } from './pki.mjs';
import { EpochTransition, wrapperHeader, wrapRoot, unwrapRoot } from './protection.mjs';

test('signed control reader requires the selected draft domain revision', () => {
  const key = c.generate('ml-dsa-87');
  const certificate = issueCertificate({
    publicKey: key.publicKey, issuer: name('Synthetic issuer'), subject: name('Synthetic control'),
    serial: 1n, ca: true,
  }, key.privateKey);
  const value = { schemaVersion: 1, purpose: 'synthetic' };
  const current = signCMS({ content: c.D('ControlExample', value), certificate }, key.privateKey);
  assert.deepEqual({ ...readControl(current, 'ControlExample', certificate) }, value);
  const incompatible = signCMS({
    content: c.dcbor(['CertConcord', 1, 'ControlExample', value]), certificate,
  }, key.privateKey);
  assert.throws(() => readControl(incompatible, 'ControlExample', certificate), /CONTROL_DOMAIN/);
});

test('trust bootstrap rejects duplicate roots and threshold overrides; restart preserves fork detection', () => {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord-trust-'));
  const path = join(directory, 'state.sqlite');
  let journal = new Journal(path);
  const root = c.generate('ml-dsa-87');
  const other = c.generate('ml-dsa-87');
  const pins = [root.publicKey];
  const configuration = { domain: c.random(), pins, threshold: 1 };
  const at = c.now();
  const manifest = {
    trustDomainID: configuration.domain,
    serial: 2,
    issuedAt: at - 1,
    notBefore: at - 1,
    notAfter: at + 120,
  };
  const signatures = (value, key = root) => [
    {
      keyID: c.keyID(key.publicKey),
      signature: c.sign(c.D('RootTrustManifest', value), key.privateKey),
    },
  ];
  try {
    for (const threshold of [0, -1, 0.5, 2, NaN])
      assert.throws(
        () => new TrustStore(journal, { ...configuration, threshold }),
        /ROOT_THRESHOLD/,
      );
    assert.throws(
      () =>
        new TrustStore(journal, {
          ...configuration,
          pins: [root.publicKey, root.publicKey],
          threshold: 2,
        }),
      /ROOT_THRESHOLD/,
    );
    let store = new TrustStore(journal, configuration);
    pins[0] = other.publicKey;
    assert.throws(
      () => store.verify(manifest, signatures(manifest, other)),
      /ROOT_SIGNATURE_THRESHOLD/,
    );
    assert.throws(() => store.verify(manifest, [], [], 0), /ROOT_SIGNATURE_THRESHOLD/);
    store.accept(manifest, signatures(manifest));
    journal.close();
    journal = new Journal(path);
    store = new TrustStore(journal, { ...configuration, pins: [root.publicKey] });
    const fork = { ...manifest, notAfter: at + 119 };
    assert.throws(() => store.accept(fork, signatures(fork)), /TRUST_FORK/);
    const old = { ...manifest, serial: 1 };
    store.accept(old, signatures(old), { mode: 'HISTORICAL' });
    assert.throws(() => store.accept(old, signatures(old)), /STALE_RTM/);
  } finally {
    journal.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('recovery separation rejects omitted or misspelled signing targets and reaches through cycles', () => {
  const graph = {
    nodes: ['admin', 'backup', 'encryption', 'signing'],
    edges: [
      { from: ['admin', 'backup'], threshold: 2, to: 'encryption' },
      { from: ['encryption'], threshold: 1, to: 'backup' },
    ],
  };
  assert.equal(assertRecoverySeparation(graph, ['admin', 'backup'], ['signing']), true);
  for (const targets of [[], ['signnig'], ['signing', 'signing']])
    assert.throws(() => assertRecoverySeparation(graph, ['admin'], targets), /RCG_SIGNING_TARGETS/);
  assert.throws(
    () =>
      assertRecoverySeparation(
        { ...graph, nodes: [...graph.nodes, 'signing'] },
        ['admin'],
        ['signing'],
      ),
    /RCG_GRAPH/,
  );
  assert.throws(
    () => assertRecoverySeparation(graph, ['unknown'], ['signing']),
    /RCG_UNKNOWN_NODE/,
  );
  graph.edges.push({ from: ['encryption'], threshold: 1, to: 'signing' });
  assert.throws(
    () => assertRecoverySeparation(graph, ['admin', 'backup'], ['signing']),
    /SIGNING_ESCROW_PATH/,
  );
});

test('wrapper verification and commit are atomic across write failure, restart and stale retirement', () => {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord-wrapper-'));
  const path = join(directory, 'state.sqlite');
  let journal = new Journal(path);
  const oldPRF = c.random(),
    newPRF = c.random(),
    root = c.random();
  const header = wrapperHeader({
    trustDomainID: c.random(),
    subjectID: c.random(),
    credentialIDHash: c.random(),
    contextID: c.random(),
    rpID: 'example.org',
    purpose: 'ACCOUNT_WRAP',
  });
  const nextHeader = {
    ...header,
    epoch: 1,
    prfSalt: c.random(),
    kdfSalt: c.random(),
    wrapperID: c.random(),
  };
  try {
    let transition = new EpochTransition(journal);
    transition.prepare('rewrap', {
      oldWrapper: wrapRoot(oldPRF, root, header),
      newWrapper: wrapRoot(newPRF, root, nextHeader),
    });
    const write = journal.put.bind(journal);
    journal.put = (...args) => {
      const revision = write(...args);
      if (args[0] === 'epoch' && args[2].state === 'COMMITTED')
        throw Error('storage failure after write');
      return revision;
    };
    assert.throws(() => transition.commit('rewrap', newPRF, oldPRF), /storage failure/);
    journal.close();
    journal = new Journal(path);
    transition = new EpochTransition(journal);
    const prepared = journal.get('epoch', 'rewrap');
    assert.equal(prepared.value.state, 'PREPARED');
    assert(c.equal(unwrapRoot(oldPRF, prepared.value.oldWrapper), root));
    assert.throws(() => transition.commit('rewrap', newPRF, c.random()));
    assert.equal(journal.get('epoch', 'rewrap').revision, prepared.revision);
    const revision = transition.commit('rewrap', newPRF, oldPRF);
    journal.close();
    journal = new Journal(path);
    transition = new EpochTransition(journal);
    const committed = journal.get('epoch', 'rewrap');
    assert.equal(committed.value.state, 'COMMITTED');
    assert(c.equal(unwrapRoot(newPRF, committed.value.newWrapper), root));
    assert.throws(() => transition.commit('rewrap', newPRF, oldPRF), /EPOCH_STATE/);
    assert.throws(() => transition.retire('rewrap', prepared.revision), /EPOCH_STATE/);
    transition.retire('rewrap', revision);
    assert.throws(() => transition.retire('rewrap', revision), /EPOCH_STATE/);
    transition.prepare('substitution', {
      oldWrapper: wrapRoot(oldPRF, root, header),
      newWrapper: wrapRoot(newPRF, c.random(), nextHeader),
    });
    assert.throws(() => transition.commit('substitution', newPRF, oldPRF), /EPOCH_ROOT_CHANGED/);
    assert.equal(journal.get('epoch', 'substitution').value.state, 'PREPARED');
    const legacy = journal.get('epoch', 'substitution');
    journal.put(
      'epoch',
      'substitution',
      { ...legacy.value, state: 'NEW_WRAPPER_VERIFIED' },
      legacy.revision,
    );
    assert.throws(() => transition.commit('substitution', newPRF, oldPRF), /EPOCH_STATE/);
  } finally {
    journal.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
