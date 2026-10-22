import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as m from './mtc.mjs';
import * as tlog from './transparency.mjs';
import { Journal } from './state.mjs';
import { verifyCredentialLog } from './credential-log.mjs';

test('fixed three-leaf consistency bytes do not authenticate an absolute tree size', () => {
  const entries = ['61', '62', '63'].map((hex) => Buffer.from(hex, 'hex')),
    node = Buffer.from('b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb', 'hex'),
    root = Buffer.from('36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1', 'hex'),
    proof = [
      Buffer.from('597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8', 'hex'),
    ];
  assert.deepEqual(m.treeHash(entries.slice(0, 2)), node);
  assert.deepEqual(m.treeHash(entries), root);
  assert.deepEqual(m.consistencyProof(entries, 0, 2), proof);
  for (const size of [3, 4])
    assert.equal(m.verifyConsistency({ start: 0, end: 2, size, node, root, proof }), true);
  const signer = c.generate('ml-dsa-87'),
    message = (end) =>
      m.cosignedMessage({ cosignerID: '42', caID: '43', logNumber: 1, start: 0, end, root }),
    signature = c.sign(message(3), signer.privateKey);
  assert.equal(c.verify(message(3), signature, signer.publicKey), true);
  assert.equal(c.verify(message(4), signature, signer.publicKey), false);
});

for (const mode of ['STANDALONE', 'LANDMARK']) {
  test(`${mode} certificate verification rejects a substituted subtree end despite hash compatibility`, () => {
    const ca = { id: '32473.1', ...c.generate('ml-dsa-87') },
      mirror = { id: '32473.2', operatorID: 'range-mirror', ...c.generate('ml-dsa-87') },
      leaf = c.generate('ml-dsa-65'),
      tbs = m.createMTCTBS(
        { publicKey: leaf.publicKey, subject: p.name('Range contract') },
        { caID: ca.id, logNumber: 1, index: 0 },
      ),
      entries = [m.logEntryFromTBS(tbs), Buffer.from('b'), Buffer.from('c')],
      certificate = m.issueMTC(tbs, {
        entries,
        index: 0,
        caID: ca.id,
        logNumber: 1,
        cosigners: [ca, mirror],
      }),
      proof = m.decodeProof(p.parseCertificate(certificate).signature),
      root = m.treeHash(entries),
      options = {
        caID: ca.id,
        caPublicKey: ca.publicKey,
        members: [mirror],
        threshold: 1,
        policyHash: c.random(64),
        rtmHash: c.random(64),
        membershipEpoch: 1,
      };
    assert.equal(m.verifyMTC(certificate, options).mode, 'STANDALONE');
    assert.deepEqual(m.evaluateInclusion(m.leafHash(entries[0]), 0, 0, 4, proof.inclusion), root);
    if (mode === 'LANDMARK') {
      options.trustedSubtrees = [
        {
          ...options,
          logNumber: 1,
          start: 0,
          end: 3,
          root,
          mode: 'LIVE',
          validFrom: c.now() - 1,
          expiresAt: c.now() + 60,
        },
      ];
      proof.signatures = [];
    }
    const original = p.certificateFromTBS(tbs, p.OID.mtc, m.encodeProof(proof)),
      substituted = p.certificateFromTBS(tbs, p.OID.mtc, m.encodeProof({ ...proof, end: 4 }));
    assert.equal(m.verifyMTC(original, options).mode, mode);
    assert.throws(() => m.verifyMTC(substituted, options), {
      code: mode === 'LANDMARK' ? 'MTC_QUORUM' : 'MTC_COSIGNATURE',
    });
  });
}

test('a signed four-entry claim over three leaves cannot complete mirror custody or credential-log acceptance', () => {
  const journal = new Journal(),
    log = { ...c.generate('ed25519'), name: 'log.example/range', scheme: 'ed25519-log' },
    witnessKey = {
      ...c.generate('ed25519'),
      name: 'witness.example/range',
      scheme: 'ed25519-cosign',
    },
    mirrorKey = {
      ...generateKeyPairSync('ml-dsa-44'),
      name: 'mirror.example/range',
      scheme: 'mldsa44-cosign',
      operatorID: 'range-mirror',
    },
    expectedEntry = { credential: Buffer.from('credential') },
    entries = [c.D('PersonalMdocLogEntry', expectedEntry), Buffer.from('b'), Buffer.from('c')],
    root = m.treeHash(entries),
    logs = new Map([[log.name, log]]),
    mirror = new tlog.TlogMirror({ journal, signer: mirrorKey, logs }),
    witness = new tlog.TlogWitness({ journal, signer: witnessKey, logs }),
    body = tlog.checkpointBody(log.name, 4, root),
    checkpoint = body + '\n' + tlog.noteSignature(body, log);
  try {
    assert.equal(tlog.verifyPublishedCheckpoint(checkpoint, log).size, 4n);
    assert.equal(witness.addCheckpoint(tlog.witnessRequest(0, [], checkpoint)).status, 200);
    assert.equal(mirror.addCheckpoint(tlog.witnessRequest(0, [], checkpoint)).status, 200);
    assert.equal(mirror.addEntries(tlog.mirrorUpload(log.name, entries, 0)).status, 409);
    assert.throws(() => mirror.checkpoint(log.name), { code: 'MIRROR_UNCOMMITTED' });
    const proof = {
        schemaVersion: 1,
        adapterID: 'certconcord-mdoc-issuance-log-v1',
        entry: entries[0],
        index: 0,
        size: 4,
        root,
        path: m.inclusionProof(entries, 0),
        checkpoint,
        receipts: [],
      },
      trust = { log, members: [mirrorKey], threshold: 1 };
    assert.deepEqual(m.evaluateInclusion(m.leafHash(proof.entry), 0, 0, 4, proof.path), root);
    assert.throws(() => verifyCredentialLog(proof, expectedEntry, trust), {
      code: 'CREDENTIAL_LOG_QUORUM',
    });
    const actualBody = tlog.checkpointBody(log.name, 3, root),
      actualCheckpoint = actualBody + '\n' + tlog.noteSignature(actualBody, log),
      receipt = {
        operatorID: mirrorKey.operatorID,
        note: actualBody + '\n' + tlog.noteSignature(actualBody, mirrorKey),
      };
    assert.equal(
      verifyCredentialLog(
        { ...proof, size: 3, checkpoint: actualCheckpoint, receipts: [receipt] },
        expectedEntry,
        trust,
      ).status,
      'VALID',
    );
    assert.throws(
      () =>
        verifyCredentialLog(
          { ...proof, checkpoint: actualCheckpoint, receipts: [receipt] },
          expectedEntry,
          trust,
        ),
      { code: 'CREDENTIAL_LOG_INCLUSION' },
    );
    assert.throws(
      () => verifyCredentialLog({ ...proof, receipts: [receipt] }, expectedEntry, trust),
      { code: 'CREDENTIAL_LOG_MIRROR_PROOF' },
    );
  } finally {
    journal.close();
  }
});
