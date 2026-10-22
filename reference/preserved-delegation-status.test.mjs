import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { serialize, deserialize } from 'node:v8';
import { dcbor, decodeCBOR, equal, parseDER, H } from './core.mjs';
import { readControl, Journal } from './state.mjs';
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
  preservedDelegationStatusSemantics,
  assertPreservedDelegationStatusOutcome,
} from './preserved-delegation-status-semantics.mjs';

const directory = fileURLToPath(new URL('./vectors/preserved-delegation-status-rar2/', import.meta.url));
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
  const parent = resolve(process.env.CERTCONCORD_PRESERVED_DELEGATION_ARTIFACT_DIR ?? tmpdir());
  const path = fs.mkdtempSync(join(parent, 'preserved-delegation-status-'));
  t.after(() => {
    assert.equal(dirname(resolve(path)), parent);
    assert(basename(path).startsWith('preserved-delegation-status-'));
    if (!process.env.CERTCONCORD_PRESERVED_DELEGATION_ARTIFACT_DIR)
      fs.rmSync(path, { recursive: true, force: true });
  });
  return { path, databasePath: join(path, 'history.sqlite'), sequence: 0 };
}
function child(a, entry, selectedInput = input(entry), receiptState = 'COMMITTED') {
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
  assert.equal(response.result.knowledgeReceipt.state, receiptState);
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

test('saved preserved delegation status vectors satisfy the frozen full-result matrix', async (t) => {
  assert.deepEqual(
    corpus.manifest.cases.map((entry) => entry.id),
    preservedDelegationStatusSemantics.map((spec) => spec.id),
  );
  const results = runOrganizationHistoryVectors({ directory });
  for (const [index, entry] of corpus.manifest.cases.entries())
    await t.test(entry.id, () => {
      const value = corpus.input(entry),
        actual = results[index].actual;
      assert.equal(results[index].id, value.id);
      assertPreservedDelegationStatusOutcome(value, actual);
      assert.deepEqual(actual, corpus.expected(entry));
    });
});

test('saved complete CMS proofs cover each exact delegation target type', () => {
  for (const [id, type] of [
    ['preserved-grant', 'GRANT'],
    ['preserved-approver-registration', 'APPROVER_REGISTRATION'],
    ['preserved-final-authorization', 'FINAL_AUTHORIZATION'],
  ]) {
    const entry = saved(id),
      member = entry.knowledge.statusMaterial.find((m) => Object.hasOwn(m, 'evidenceRecord')),
      cms = verifyCMS(member.cms),
      body = readControl(member.cms, 'OrganizationDelegationStatus', member.issuerCertificate);
    assert(equal(cms.certificate, member.issuerCertificate));
    assert.equal(body.objectType, type);
    assert.equal(body.publishedAt, 1_800_000_020);
    const record = parseDER(member.evidenceRecord),
      token = record.children[2].children[0].children[0].children.at(-1).raw,
      info = parseTSTInfo(verifyCMS(token, { expectedContentType: OID.tstInfo }).content);
    assert.equal(info.poeUpperBound, 1_800_000_030);
    assert(body.publishedAt > 1_800_000_001 && body.publishedAt <= info.poeUpperBound);
  }
});

test('saved delegation corpus replays without authoring, network, clocks or byte changes', () => {
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
  assert.equal(result.cases, preservedDelegationStatusSemantics.length);
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

test('every duplicate proof is validated regardless of source order', () => {
  const entry = saved('duplicate-invalid-proof');
  for (const reversed of [false, true]) {
    const selected = clone(entry);
    if (reversed) selected.knowledge.statusMaterial.reverse();
    const actual = memory(selected);
    assert.equal(actual.currentAdmissibility.overall, 'INVALID');
    assert.equal(actual.currentAdmissibility.reason, 'CMS_SIGNATURE');
  }
});

test('original-matching CMS needs both the attached proof and package-P authority', () => {
  const denied = saved('original-copy-role-retired-at-package-proof');
  const original = decodeCBOR(denied.originalBytes),
    collection = decodeCBOR(
      original.objects.find((leaf) => leaf.type === 'OrganizationDelegationStatus').payload,
    );
  for (const member of collection.statements) {
    const external = denied.knowledge.statusMaterial.find((m) => equal(m.cms, member.cms));
    assert(external?.evidenceRecord);
    const record = parseDER(external.evidenceRecord),
      token = record.children[2].children[0].children[0].children.at(-1).raw;
    assert.equal(
      parseTSTInfo(verifyCMS(token, { expectedContentType: OID.tstInfo }).content).poeUpperBound,
      1_800_000_010,
    );
  }
  const actual = memory(denied);
  assert.equal(actual.proofOfExistenceUpperBound, 1_800_000_020);
  assert.equal(actual.preservation.overall, 'VALID');
  assert.equal(actual.currentAdmissibility.overall, 'INVALID');
  assert.equal(actual.currentAdmissibility.reason, 'AUTHORITY_EXPIRED');
  assert.equal(memory(saved('original-copy-valid-proof')).overall, 'VALID');
  assert.equal(
    memory(saved('original-copy-invalid-proof')).currentAdmissibility.reason,
    'CMS_SIGNATURE',
  );
});

test('preserved compromise retains its original and exact proof across fresh processes', (t) => {
  const a = area(t),
    incident = saved('compromise-followed-by-current-good'),
    first = child(a, incident);
  assert.equal(first.result.currentAdmissibility.reason, 'ORG_STATUS_REVOKED');
  assert.match(first.result.knowledgeReceipt.evidenceID, /^[a-f0-9]{64}$/);
  const retained = inspect(a, incident.configuration),
    submitted = incident.knowledge.statusMaterial.find((m) => Object.hasOwn(m, 'evidenceRecord')),
    frame = retained.frames.find((f) => f.statusMaterial.some((m) => equal(m.cms, submitted.cms))),
    stored = frame.statusMaterial.find((m) => equal(m.cms, submitted.cms));
  assert.equal(frame.evidenceID, first.result.knowledgeReceipt.evidenceID);
  for (const field of ['cms', 'issuerCertificate', 'evidenceRecord'])
    assert.deepEqual(stored[field], submitted[field]);
  const newer = clone(incident);
  newer.knowledge.statusMaterial = newer.knowledge.statusMaterial.filter(
    (m) => !Object.hasOwn(m, 'evidenceRecord'),
  );
  assert.equal(memory(newer).overall, 'VALID');
  newer.knowledge.authorityHistory = [];
  const reopened = child(a, newer);
  assert.notEqual(reopened.pid, first.pid);
  assert.equal(reopened.result.historicalAuthorization.overall, 'VALID');
  assert.equal(reopened.result.currentAdmissibility.overall, 'INVALID');
  assert.equal(reopened.result.currentAdmissibility.reason, 'ORG_STATUS_REVOKED');
});

test('saved GOOD does not supply current status coverage after restart', (t) => {
  const a = area(t),
    good = saved('preserved-grant'),
    first = child(a, good),
    missing = clone(good);
  assert.equal(first.result.overall, 'VALID');
  missing.knowledge.authorityHistory = [];
  missing.knowledge.statusMaterial = [];
  const reopened = child(a, missing);
  assert.notEqual(reopened.pid, first.pid);
  assert.equal(reopened.result.historicalAuthorization.overall, 'VALID');
  assert.equal(reopened.result.currentAdmissibility.overall, 'INDETERMINATE');
  assert.equal(reopened.result.currentAdmissibility.reason, 'STATUS_STALE');
});

test('an independent status proof cannot admit an organization target without an original proof', (t) => {
  const a = area(t),
    entry = saved('compromise-followed-by-current-good'),
    actual = child(a, entry, {
      originalBytes: Buffer.from([0xff]),
      evidenceRecord: Buffer.from([0xff]),
    });
  assert.equal(actual.result.overall, 'INVALID');
  assert.equal(actual.result.knowledgeReceipt.evidenceID, null);
  const retained = inspect(a, entry.configuration);
  assert.deepEqual(retained.head.value.artifacts, []);
  assert(retained.frames.every((frame) => frame.statusMaterial.length === 0));
});

test('unverified external proof bytes are excluded from admitted raw replay', (t) => {
  const a = area(t),
    bad = saved('proof-signature-tampered'),
    submitted = bad.knowledge.statusMaterial.find((m) => Object.hasOwn(m, 'evidenceRecord')),
    result = child(a, bad);
  assert.equal(result.result.currentAdmissibility.reason, 'CMS_SIGNATURE');
  const retained = inspect(a, bad.configuration);
  assert(
    retained.frames.every((frame) =>
      frame.statusMaterial.every((m) => !equal(m.cms, submitted.cms)),
    ),
  );
});

test('hash-consistent altered ERS bytes are reauthenticated during durable replay', (t) => {
  const accepted = area(t),
    forged = area(t),
    good = saved('preserved-grant');
  assert.equal(child(accepted, good).result.overall, 'VALID');
  const retained = inspect(accepted, good.configuration);
  assert.equal(retained.frames.length, 1);
  const frame = clone(retained.frames[0]),
    member = frame.statusMaterial.find((m) => Object.hasOwn(m, 'evidenceRecord'));
  member.evidenceRecord[member.evidenceRecord.length - 1] ^= 1;
  const store = new OrganizationHistoryKnowledgeStore(forged.databasePath, good.configuration);
  try {
    // This internal storage test intentionally bypasses admission. append still
    // computes valid chunk, frame and content identities for the forged bytes.
    const committed = store.transact((row) =>
      store.append(row, input(good), good.knowledge.knowledgeTime, {
        authorityHistory: frame.authorityHistory,
        statusMaterial: frame.statusMaterial,
        certificateStatusMaterial: frame.certificateStatusMaterial,
        observations: retained.head.value.observations,
        historySemantics: retained.head.value.historySemantics,
        originalRequired: true,
      }),
    );
    assert.equal(committed.overflow, false);
    assert.deepEqual(
      store.frame(store.head().value.frames[0], store.head().value).statusMaterial,
      frame.statusMaterial,
    );
  } finally {
    store.journal.close();
  }
  const reopened = child(forged, good, input(good), 'NOT_COMMITTED');
  assert.equal(reopened.result.overall, 'INDETERMINATE');
  assert.equal(reopened.result.reason, 'ORG_HISTORY_KNOWLEDGE_UNAVAILABLE');
  assert.deepEqual(
    reopened.result.checks.find((check) => check.check === 'durable-knowledge'),
    {
      check: 'durable-knowledge',
      overall: 'INDETERMINATE',
      reason: 'ORG_HISTORY_REPLAY_AUTHENTICATION',
    },
  );
});

test('the new raw-member capability refuses a prior durable configuration binding', (t) => {
  const a = area(t),
    good = saved('preserved-grant'),
    store = new OrganizationHistoryKnowledgeStore(a.databasePath, good.configuration);
  store.journal.close();
  const db = new Journal(a.databasePath);
  try {
    const binding = db.get('organization-history-v1', 'binding').value;
    binding.configurationID = H('OrganizationHistoryConfiguration', {
      revision: 1,
      capability: 'organization-history-sqlite-v1',
      configuration: good.configuration,
    }).toString('hex');
    db.db
      .prepare('UPDATE state SET value=? WHERE namespace=? AND id=?')
      .run(dcbor(binding), 'organization-history-v1', 'binding');
  } finally {
    db.close();
  }
  assert.throws(
    () =>
      createOrganizationHistorySource({
        configuration: good.configuration,
        readKnowledge: () => good.knowledge,
        databasePath: a.databasePath,
      }),
    { code: 'ORG_HISTORY_CONFIGURATION_MISMATCH' },
  );
});

test('external status proof shape and the complete snapshot remain bounded', () => {
  for (const value of [null, Buffer.alloc(0), Buffer.alloc(16 * 1024 * 1024 + 1)]) {
    const entry = saved('preserved-grant');
    entry.knowledge.statusMaterial.find((m) => Object.hasOwn(m, 'evidenceRecord')).evidenceRecord =
      value;
    const actual = memory(entry);
    assert.equal(actual.overall, 'INDETERMINATE');
    assert.equal(actual.reason, 'ORG_HISTORY_KNOWLEDGE_UNAVAILABLE');
  }
  const entry = saved('preserved-grant');
  entry.knowledge.statusMaterial[0].accepted = true;
  assert.equal(memory(entry).reason, 'ORG_HISTORY_KNOWLEDGE_UNAVAILABLE');
});
