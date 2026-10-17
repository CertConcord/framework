import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadOrganizationHistoryVectorCorpus } from './organization-vector-corpus.mjs';
import { Journal } from './state.mjs';
import * as c from './core.mjs';
import { createIndependentOrganizationHistoryFixture } from './fixtures-history-independent.mjs';
import { TimestampAuthority, timestampRequest, tokenFromResponse } from './timestamp.mjs';
import { manifestPublicationImprint } from './retained-authorities.mjs';
import {
  createOrganizationHistorySource,
  createOrganizationHistoryVerifier,
} from './sdk/index.mjs';

const corpus = loadOrganizationHistoryVectorCorpus(
  fileURLToPath(new URL('./vectors/organization-history', import.meta.url)),
);
const saved = (id) => corpus.input(corpus.manifest.cases.find((row) => row.id === id));
const valid = () => saved('expired-issuer-scoped-successor');
const malformed = (i, size = 5) => {
  const originalBytes = Buffer.alloc(size, 0xff);
  originalBytes.writeUInt32BE(i, 1);
  return { originalBytes, evidenceRecord: Buffer.from([0xff]) };
};
function harness(t, value = valid()) {
  const directory = mkdtempSync(join(tmpdir(), 'organization-admission-'));
  const databasePath = join(directory, 'history.sqlite');
  const sources = [];
  const open = () => {
    const source = createOrganizationHistorySource({
      configuration: value.configuration,
      readKnowledge: () => value.knowledge,
      databasePath,
    });
    sources.push(source);
    return { source, verifier: createOrganizationHistoryVerifier({ source }) };
  };
  const head = () => {
    const db = new Journal(databasePath);
    try {
      return db.get('organization-history-v1', 'head');
    } finally {
      db.close();
    }
  };
  t.after(() => {
    for (const source of sources) source.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return { value, open, head };
}
function retained(head) {
  const { selectedKnowledge, ...material } = head.value;
  return material;
}

test('unauthenticated originals advance only K without exhausting durable evidence capacity', (t) => {
  const value = valid(),
    full = value.knowledge,
    K = full.knowledgeTime;
  value.knowledge = {
    knowledgeTime: K,
    authorityHistory: [],
    statusMaterial: [],
    certificateStatusMaterial: [],
  };
  const h = harness(t, value),
    first = h.open(),
    before = h.head();
  for (let i = 0; i < 1025; i++) {
    const result = first.verifier.verify(malformed(i));
    assert.equal(result.overall, 'INVALID');
    assert.equal(result.reason, 'CBOR_SIMPLE');
    assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
    assert.equal(result.knowledgeReceipt.evidenceID, null);
    assert.equal(result.knowledgeReceipt.revision, before.revision + 1);
  }
  assert.deepEqual(retained(h.head()), retained(before));
  value.knowledge.knowledgeTime++;
  const advanced = first.verifier.verify(malformed(1025, 4 * 1024 * 1024));
  assert.equal(advanced.knowledgeReceipt.evidenceID, null);
  assert.equal(advanced.knowledgeReceipt.revision, before.revision + 2);
  assert.equal(h.head().value.selectedKnowledge, K + 1);
  assert.deepEqual(retained(h.head()), retained(before));
  first.source.close();
  value.knowledge = { ...full, knowledgeTime: K + 1 };
  const reopened = h.open(),
    restored = reopened.verifier.verify({
      originalBytes: value.originalBytes,
      evidenceRecord: value.evidenceRecord,
    });
  assert.equal(restored.overall, 'VALID', JSON.stringify(restored));
  assert.equal(restored.knowledgeReceipt.state, 'COMMITTED');
  assert.match(restored.knowledgeReceipt.evidenceID, /^[a-f0-9]{64}$/);
  const raw = reopened.source.readEvidence(restored.knowledgeReceipt.evidenceID);
  assert.equal(raw.classification, 'UNVERIFIED_BYTES');
  assert.deepEqual(raw.originalBytes, value.originalBytes);
  assert.deepEqual(raw.evidenceRecord, value.evidenceRecord);
  value.knowledge.knowledgeTime = K;
  const rollback = reopened.verifier.verify({
    originalBytes: value.originalBytes,
    evidenceRecord: value.evidenceRecord,
  });
  assert.equal(rollback.overall, 'INVALID');
  assert.equal(rollback.reason, 'ORG_KNOWLEDGE_ROLLBACK');
  assert.equal(rollback.knowledgeReceipt.state, 'NOT_COMMITTED');
  assert.equal(h.head().value.selectedKnowledge, K + 1);
});

test('repeated authenticated knowledge does not retain each malformed pair or create K-only frames', (t) => {
  const h = harness(t),
    first = h.open(),
    original = malformed(0);
  const learned = first.verifier.verify(original);
  assert.equal(learned.overall, 'INVALID');
  assert.equal(learned.reason, 'CBOR_SIMPLE');
  assert.equal(learned.knowledgeReceipt.state, 'COMMITTED');
  const before = h.head();
  assert.equal(before.value.frames.length, 1);
  assert.equal(before.value.artifacts.length, 0);
  assert.equal(learned.knowledgeReceipt.evidenceID, null);
  assert.equal(before.value.historySemantics.length, 2);
  assert.equal(before.value.observations.length, 1);
  const identical = first.verifier.verify(original);
  assert.deepEqual(identical.knowledgeReceipt, learned.knowledgeReceipt);
  for (const input of [malformed(1), malformed(2, 4 * 1024 * 1024)]) {
    const result = first.verifier.verify(input);
    assert.equal(result.overall, 'INVALID');
    assert.equal(result.reason, 'CBOR_SIMPLE');
    assert.equal(result.knowledgeReceipt.evidenceID, null);
    assert.equal(result.knowledgeReceipt.revision, before.revision);
    assert.deepEqual(h.head(), before);
  }
  h.value.knowledge.knowledgeTime++;
  const advanced = first.verifier.verify(malformed(3));
  assert.equal(advanced.knowledgeReceipt.revision, before.revision + 1);
  assert.equal(advanced.knowledgeReceipt.evidenceID, null);
  assert.deepEqual(retained(h.head()), retained(before));
  first.source.close();
  const reopened = h.open();
  const result = reopened.verifier.verify({
    originalBytes: h.value.originalBytes,
    evidenceRecord: h.value.evidenceRecord,
  });
  assert.equal(result.overall, 'VALID', JSON.stringify(result));
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(h.head().value.frames.length, 2);
  assert.equal(h.head().value.overflow, false);
  const replay = reopened.verifier.verify({
    originalBytes: h.value.originalBytes,
    evidenceRecord: h.value.evidenceRecord,
  });
  assert.deepEqual(replay, result);
});

test('new authenticated certificate compromise on an invalid original remains sticky after restart', (t) => {
  const negative = saved('credential-compromise'),
    h = harness(t, negative),
    first = h.open();
  const learned = first.verifier.verify(malformed(0));
  assert.equal(learned.overall, 'INVALID');
  assert.equal(learned.reason, 'CBOR_SIMPLE');
  assert.equal(learned.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(learned.knowledgeReceipt.evidenceID, null);
  assert.equal(h.head().value.artifacts.length, 0);
  first.source.close();
  const good = valid();
  h.value.knowledge = { ...good.knowledge, knowledgeTime: good.knowledge.knowledgeTime + 1 };
  const reopened = h.open(),
    result = reopened.verifier.verify({
      originalBytes: good.originalBytes,
      evidenceRecord: good.evidenceRecord,
    });
  assert.equal(result.overall, 'INVALID', JSON.stringify(result));
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
  const clean = harness(t, { ...good, knowledge: h.value.knowledge });
  assert.equal(
    clean
      .open()
      .verifier.verify({ originalBytes: good.originalBytes, evidenceRecord: good.evidenceRecord })
      .overall,
    'VALID',
  );
});

test('earlier authenticated RTM publication is retained while later duplicate proofs are ignored', async (t) => {
  const f = await createIndependentOrganizationHistoryFixture();
  t.after(() => f.close());
  const configuration = c.decodeCBOR(c.dcbor(f.publicSourceConfiguration));
  const pin = configuration.preservation.timestampAuthorities[1];
  configuration.retainedAuthorities.publication.timestampAuthorities = [
    { ...pin, validFrom: f.A - 60, knowledgeValidUntil: f.end },
  ];
  const knowledge = {
    ...c.decodeCBOR(c.dcbor(f.knowledge)),
    authorityHistory: f.history.map((entry) => ({
      manifest: c.dcbor(entry.manifest),
      signatures: entry.signatures,
      publicationProof: entry.publicationProof,
    })),
  };
  const journal = new Journal();
  t.after(() => journal.close());
  let published;
  const tsa = new TimestampAuthority({
    certificate: f.renewalTSA.certificate,
    privateKey: f.renewalTSA.privateKey,
    policy: f.renewalTSA.policy,
    journal,
    clock: () => published,
    accuracySeconds: 0,
  });
  const proof = (entry, at) => {
    published = at;
    const imprint = manifestPublicationImprint({
      manifest: c.decodeCBOR(entry.manifest),
      signatures: entry.signatures,
    });
    return tokenFromResponse(
      tsa.issue(timestampRequest(imprint, { policy: f.renewalTSA.policy }).der),
    );
  };
  const genesis = knowledge.authorityHistory[0];
  const earlier = proof(genesis, f.A - 25);
  const later = proof(genesis, f.A - 23);
  genesis.publicationProof = proof(genesis, f.A - 20);
  knowledge.authorityHistory[1].publicationProof = proof(knowledge.authorityHistory[1], f.K - 1);
  const h = harness(t, { configuration, knowledge, ...f.input }),
    first = h.open();
  const initial = first.verifier.verify(malformed(0));
  assert.equal(initial.overall, 'INVALID');
  assert.equal(initial.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(initial.knowledgeReceipt.evidenceID, null);
  const before = h.head();
  assert.equal(before.value.frames.length, 1);
  assert.equal(before.value.historySemantics.length, 2);
  genesis.publicationProof = earlier;
  const updated = first.verifier.verify(malformed(1));
  assert.equal(updated.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(updated.knowledgeReceipt.evidenceID, null);
  const after = h.head();
  assert.equal(after.value.frames.length, 2);
  assert.equal(after.value.historySemantics.length, 2);
  assert.equal(after.value.artifacts.length, 0);
  assert(after.value.bytes > before.value.bytes);
  genesis.publicationProof = later;
  const duplicate = first.verifier.verify(malformed(2));
  assert.deepEqual(duplicate.knowledgeReceipt, updated.knowledgeReceipt);
  assert.deepEqual(h.head(), after);
  first.source.close();
  h.value.knowledge.authorityHistory = [];
  const restored = h.open().verifier.verify(f.input);
  assert.equal(restored.overall, 'VALID', JSON.stringify(restored));
  assert.equal(restored.historicalAuthorization.overall, 'VALID');
  assert.equal(restored.knowledgeReceipt.state, 'COMMITTED');
});
