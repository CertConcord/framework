import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { serialize, deserialize } from 'node:v8';
import { dcbor, decodeCBOR, equal, parseDER } from './core.mjs';
import { readControl } from './state.mjs';
import { OID, verifyCMS } from './pki.mjs';
import { parseTSTInfo } from './timestamp.mjs';
import { OrganizationHistoryKnowledgeStore } from './organization-history-knowledge.mjs';
import {
  createOrganizationHistorySource,
  createOrganizationHistoryVerifier,
} from './sdk/index.mjs';
import { runOrganizationHistoryVectors } from './verify-organization-vectors.mjs';
import { loadOrganizationHistoryVectorCorpus, vectorHash } from './organization-vector-corpus.mjs';
import {
  preservedCertificateStatusSemantics,
  assertPreservedCertificateStatusOutcome,
} from './preserved-certificate-status-semantics.mjs';

const directory = fileURLToPath(
  new URL('./vectors/preserved-certificate-status-rar2/', import.meta.url),
);
const corpus = loadOrganizationHistoryVectorCorpus(directory);
const saved = (id) => corpus.input(corpus.manifest.cases.find((entry) => entry.id === id));
const clone = (value) => decodeCBOR(dcbor(value));
const input = (entry) => ({
  originalBytes: entry.originalBytes,
  evidenceRecord: entry.evidenceRecord,
});
const childPath = fileURLToPath(
  new URL('./organization-history-durable-independent-child.mjs', import.meta.url),
);
function area(t) {
  const parent = resolve(process.env.CERTCONCORD_PRESERVED_STATUS_ARTIFACT_DIR ?? tmpdir());
  const path = fs.mkdtempSync(join(parent, 'preserved-certificate-status-'));
  t.after(() => {
    assert.equal(dirname(resolve(path)), parent);
    assert(basename(path).startsWith('preserved-certificate-status-'));
    if (!process.env.CERTCONCORD_PRESERVED_STATUS_ARTIFACT_DIR)
      fs.rmSync(path, { recursive: true, force: true });
  });
  return { path, databasePath: join(path, 'history.sqlite'), sequence: 0 };
}
function child(a, entry, selectedInput = input(entry)) {
  const id = ++a.sequence,
    request = join(a.path, id + '.request.bin'),
    responsePath = join(a.path, id + '.response.bin');
  fs.writeFileSync(
    request,
    serialize({
      configuration: entry.configuration,
      knowledge: entry.knowledge,
      input: selectedInput,
      databasePath: a.databasePath,
    }),
  );
  const processResult = spawnSync(process.execPath, [childPath, request, responsePath], {
    encoding: 'utf8',
    timeout: 180000,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  assert.equal(processResult.error, undefined, processResult.error?.message);
  assert.equal(processResult.status, 0, processResult.stderr);
  const response = deserialize(fs.readFileSync(responsePath));
  assert.equal(response.error, undefined);
  assert.equal(response.clockReads, 0);
  assert.equal(response.forbiddenActions, 0);
  assert.equal(response.reads, 1);
  assert.notEqual(response.pid, process.pid);
  assert.equal(response.result.knowledgeReceipt.state, 'COMMITTED');
  return response;
}
function inspect(a, configuration) {
  const store = new OrganizationHistoryKnowledgeStore(a.databasePath, configuration);
  try {
    const head = store.head();
    return { head, frames: head.value.frames.map((id) => store.frame(id, head.value)) };
  } finally {
    store.journal.close();
  }
}
function memory(entry) {
  const source = createOrganizationHistorySource({
    configuration: entry.configuration,
    readKnowledge: () => entry.knowledge,
  });
  try {
    return createOrganizationHistoryVerifier({ source }).verify(input(entry));
  } finally {
    source.close();
  }
}

test('saved preserved certificate status vectors satisfy the frozen full-result matrix', async (t) => {
  assert.deepEqual(
    corpus.manifest.cases.map((entry) => entry.id),
    preservedCertificateStatusSemantics.map((spec) => spec.id),
  );
  const results = runOrganizationHistoryVectors({ directory });
  for (const [index, entry] of corpus.manifest.cases.entries())
    await t.test(entry.id, () => {
      const value = corpus.input(entry),
        actual = results[index].actual;
      assert.equal(results[index].id, value.id);
      assertPreservedCertificateStatusOutcome(value, actual);
      assert.deepEqual(actual, corpus.expected(entry));
    });
});

test('saved CMS and ERS distinguish status proof time from document proof and incident time', () => {
  const ordinary = saved('ordinary-revocation-after-document-proof'),
    compromised = saved('compromise-before-document-proof');
  for (const entry of [ordinary, compromised]) {
    const member = entry.knowledge.certificateStatusMaterial[0];
    const cms = verifyCMS(member.cms);
    assert(equal(cms.certificate, member.issuerCertificate));
    const body = readControl(member.cms, 'CertificateStatus', member.issuerCertificate);
    assert.equal(body.publishedAt, 1_800_000_020);
    const record = parseDER(member.evidenceRecord),
      first = record.children[2].children[0].children[0];
    const token = first.children.at(-1).raw;
    const info = parseTSTInfo(verifyCMS(token, { expectedContentType: OID.tstInfo }).content);
    assert.equal(info.poeUpperBound, 1_800_000_030);
    assert(body.publishedAt > 1_800_000_001 && body.publishedAt <= info.poeUpperBound);
    if (entry.id === ordinary.id) {
      assert.equal(body.effectiveTime, 1_800_000_002);
      assert.equal(body.compromiseStart, undefined);
    } else {
      assert.equal(body.effectiveTime, 1_800_000_020);
      assert.equal(body.compromiseStart, 1_800_000_000);
    }
  }
});

test('saved status corpus replays without authoring, network, clock reads or byte changes', () => {
  const sdk = fileURLToPath(new URL('./sdk/index.mjs', import.meta.url)),
    consumer = fileURLToPath(new URL('./sdk/organization-consumer.mjs', import.meta.url));
  const before = new Map(
    ['manifest.json', ...corpus.manifest.files.map((f) => f.path)].map((path) => [
      path,
      vectorHash(fs.readFileSync(join(directory, path))),
    ]),
  );
  const replay = spawnSync(process.execPath, [consumer, sdk, sdk, directory], {
    encoding: 'utf8',
    timeout: 300000,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  assert.equal(replay.error, undefined, replay.error?.message);
  assert.equal(replay.status, 0, replay.stderr);
  const result = JSON.parse(replay.stdout);
  assert.equal(result.cases, preservedCertificateStatusSemantics.length);
  assert.deepEqual(result.calls, {
    source: result.cases,
    verifier: result.cases,
    verify: result.cases,
  });
  assert.deepEqual(result.forbiddenCalls, []);
  assert.equal(result.unchangedFiles, before.size);
  for (const [path, hash] of before)
    assert.equal(vectorHash(fs.readFileSync(join(directory, path))), hash);
});

test('future status proof fails the selected-knowledge bound with otherwise current inputs', () => {
  const future = saved('current-successor-proof-after-knowledge'),
    atKnowledge = saved('proof-at-selected-knowledge');
  assert.deepEqual(future.configuration, atKnowledge.configuration);
  assert.deepEqual(future.knowledge.authorityHistory, atKnowledge.knowledge.authorityHistory);
  assert.deepEqual(future.originalBytes, atKnowledge.originalBytes);
  assert.deepEqual(future.evidenceRecord, atKnowledge.evidenceRecord);
  const bodies = [];
  for (const [entry, proofTime] of [
    [future, 1_800_007_300],
    [atKnowledge, 1_800_007_200],
  ]) {
    const member = entry.knowledge.certificateStatusMaterial[0];
    const body = readControl(member.cms, 'CertificateStatus', member.issuerCertificate);
    assert.equal(body.publishedAt, 1_800_007_199);
    assert(body.nextUpdate > proofTime);
    bodies.push(body);
    const record = parseDER(member.evidenceRecord);
    const token = record.children[2].children[0].children[0].children.at(-1).raw;
    const info = parseTSTInfo(verifyCMS(token, { expectedContentType: OID.tstInfo }).content);
    assert.equal(info.poeUpperBound, proofTime);
  }
  assert.deepEqual(bodies[0], bodies[1]);
  const actual = memory(future);
  assert.equal(actual.historicalAuthorization.overall, 'VALID');
  assert.equal(actual.preservation.overall, 'VALID');
  assert.equal(actual.currentAdmissibility.overall, 'INVALID');
  assert.equal(actual.currentAdmissibility.reason, 'HISTORY_TIME');
  assert.equal(memory(atKnowledge).overall, 'VALID');
});

test('independently preserved compromise admits without an original and remains sticky after restart', (t) => {
  const a = area(t),
    incident = saved('compromise-before-document-proof');
  const first = child(a, incident, {
    originalBytes: Buffer.from([0xff]),
    evidenceRecord: Buffer.from([0xff]),
  });
  assert.equal(first.result.overall, 'INVALID');
  assert.equal(first.result.knowledgeReceipt.evidenceID, null);
  const retained = inspect(a, incident.configuration);
  assert.deepEqual(retained.head.value.artifacts, []);
  assert(retained.head.value.observations.length > 0);
  assert.equal(retained.frames.length, 1);
  assert.equal(retained.frames[0].evidenceID, null);
  assert.deepEqual(retained.frames[0].statusMaterial, []);
  assert.equal(retained.frames[0].certificateStatusMaterial.length, 1);
  const stored = retained.frames[0].certificateStatusMaterial[0],
    submitted = incident.knowledge.certificateStatusMaterial[0];
  assert.deepEqual(Object.keys(stored).sort(), Object.keys(submitted).sort());
  for (const field of ['cms', 'issuerCertificate', 'evidenceRecord'])
    assert.deepEqual(stored[field], submitted[field]);
  const newer = saved('unpreserved-current-successor');
  newer.knowledge.authorityHistory = [];
  const reopened = child(a, newer);
  assert.notEqual(reopened.pid, first.pid);
  assert.equal(reopened.result.overall, 'INVALID');
  assert.equal(reopened.result.currentAdmissibility.overall, 'INVALID');
  assert.equal(reopened.result.currentAdmissibility.reason, 'STATUS_REVOKED');
  assert(reopened.result.knowledgeReceipt.revision >= first.result.knowledgeReceipt.revision);
  assert.equal(memory(saved('unpreserved-current-successor')).overall, 'VALID');
});

test('preserved GOOD never replaces missing current certificate coverage after restart', (t) => {
  const a = area(t),
    good = saved('preserved-good');
  const first = child(a, good);
  assert.equal(first.result.overall, 'VALID');
  const missing = clone(good);
  missing.knowledge.authorityHistory = [];
  missing.knowledge.certificateStatusMaterial = [];
  const reopened = child(a, missing);
  assert.notEqual(reopened.pid, first.pid);
  assert.equal(reopened.result.overall, 'INDETERMINATE');
  assert.equal(reopened.result.currentAdmissibility.reason, 'STATUS_STALE');
  assert.equal(reopened.result.historicalAuthorization.overall, 'VALID');
});

test('unverified status proofs never enter a durable independent replay frame', (t) => {
  const a = area(t),
    bad = saved('current-successor-invalid-proof');
  const result = child(a, bad, {
    originalBytes: Buffer.from([0xff]),
    evidenceRecord: Buffer.from([0xff]),
  });
  assert.equal(result.result.overall, 'INVALID');
  assert.equal(result.result.knowledgeReceipt.evidenceID, null);
  const retained = inspect(a, bad.configuration);
  assert.deepEqual(retained.head.value.observations, []);
  assert.deepEqual(retained.head.value.artifacts, []);
  assert(retained.frames.every((frame) => frame.certificateStatusMaterial.length === 0));
});

test('a certificate-status ERS cannot substitute for a delegation-status CMS proof', () => {
  const entry = saved('preserved-good');
  entry.knowledge.statusMaterial[0].evidenceRecord =
    entry.knowledge.certificateStatusMaterial[0].evidenceRecord;
  const actual = memory(entry);
  assert.equal(actual.overall, 'INVALID');
  assert.equal(actual.reason, 'TSA_REQUEST_BINDING');
});

test('the declarative source rejects unknown certificate status fields', () => {
  const entry = saved('preserved-good');
  entry.knowledge.certificateStatusMaterial[0].accepted = true;
  const actual = memory(entry);
  assert.equal(actual.overall, 'INDETERMINATE');
  assert.equal(actual.reason, 'ORG_HISTORY_KNOWLEDGE_UNAVAILABLE');
});
