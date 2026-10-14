import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { serialize, deserialize } from 'node:v8';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { dcbor, decodeCBOR } from './core.mjs';
import {
  createOrganizationHistorySource,
  createOrganizationHistoryVerifier,
} from './sdk/index.mjs';
import { copy } from './organization-delegation-fixtures.mjs';
import {
  createIndependentDurableHistoryMaterials,
  createIndependentDurableCapacityMaterials,
  assertPublicHistoryData,
} from './fixtures-history-durable-independent.mjs';

const childPath = fileURLToPath(
  new URL('./organization-history-durable-independent-child.mjs', import.meta.url),
);
const artifactRoot = process.env.CERTCONCORD_INDEPENDENT_ARTIFACT_DIR;
let materialPromise;
const material = () => (materialPromise ??= createIndependentDurableHistoryMaterials());
const hash = (value) => createHash('sha256').update(value).digest('hex');
function area(t) {
  const parent = artifactRoot ? resolve(artifactRoot) : resolve(tmpdir());
  const directory = fs.mkdtempSync(join(parent, 'certconcord-independent-history-'));
  if (artifactRoot) t.diagnostic('Public reproduction artifacts: ' + directory);
  const children = new Set();
  t.after(async () => {
    for (const child of children)
      if (child.exitCode === null && child.signalCode === null) {
        const exited = new Promise((done) => child.once('close', done));
        child.kill('SIGKILL');
        await exited;
      }
    assert.equal(dirname(resolve(directory)), parent);
    assert(basename(directory).startsWith('certconcord-independent-history-'));
    if (!artifactRoot) fs.rmSync(directory, { recursive: true, force: true });
  });
  let sequence = 0;
  const paths = () => {
    const id = String(++sequence);
    return {
      requestPath: join(directory, id + '.input.bin'),
      responsePath: join(directory, id + '.output.bin'),
      readyPath: join(directory, id + '.ready.json'),
      releasePath: join(directory, id + '.release'),
      beginPath: join(directory, id + '.begin.json'),
    };
  };
  return { directory, databasePath: join(directory, 'knowledge.sqlite'), children, paths };
}
function request(f, knowledge, input = f.first, extra = {}) {
  const value = { configuration: f.configuration, knowledge, input, ...extra };
  assertPublicHistoryData(value);
  return value;
}
function run(a, value, { allowError = false } = {}) {
  const paths = a.paths();
  assertPublicHistoryData(value);
  fs.writeFileSync(paths.requestPath, serialize(value));
  const child = spawnSync(process.execPath, [childPath, paths.requestPath, paths.responsePath], {
    encoding: 'utf8',
    timeout: 120000,
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  });
  assert.equal(child.error, undefined, child.error?.message);
  const response =
    fs.existsSync(paths.responsePath) && deserialize(fs.readFileSync(paths.responsePath));
  assert(response, child.stderr);
  if (!allowError) assert.equal(child.status, 0, JSON.stringify(response) + child.stderr);
  else assert.notEqual(child.status, null);
  assert.notEqual(response.pid, process.pid);
  assert.equal(response.forbiddenActions, 0);
  return response;
}
function withoutReceipt(result) {
  const { knowledgeReceipt, ...assessment } = result;
  return assessment;
}
function memory(f, steps) {
  let current;
  const source = createOrganizationHistorySource({
    configuration: f.configuration,
    readKnowledge: () => current,
  });
  const verifier = createOrganizationHistoryVerifier({ source });
  try {
    return steps.map(({ knowledge, input = f.first }) => {
      current = knowledge;
      return verifier.verify(input);
    });
  } finally {
    source.close();
  }
}
function committed(response, input) {
  const receipt = response.result.knowledgeReceipt;
  assert.deepEqual(Object.keys(receipt).sort(), [
    'configurationID',
    'evidenceID',
    'mode',
    'revision',
    'scopeID',
    'state',
  ]);
  assert.equal(receipt.mode, 'SQLITE');
  assert.equal(receipt.state, 'COMMITTED');
  assert.match(receipt.scopeID, /^[a-f0-9]{128}$/);
  assert.match(receipt.configurationID, /^[a-f0-9]{128}$/);
  assert.match(receipt.evidenceID, /^[a-f0-9]{64}$/);
  assert(Number.isSafeInteger(receipt.revision) && receipt.revision >= 1);
  assert.equal(response.reads, 1);
  assert.equal(response.clockReads, 0);
  assert.equal(response.forbiddenActions, 0);
  assert.equal(response.evidence.classification, 'UNVERIFIED_BYTES');
  assert.deepEqual(response.evidence.originalBytes, input.originalBytes);
  assert.deepEqual(response.evidence.evidenceRecord, input.evidenceRecord);
}
function scoped(result, overall, current = overall) {
  assert.equal(
    result.overall,
    overall,
    JSON.stringify({
      reason: result.reason,
      historical: result.historicalAuthorization.overall,
      current: result.currentAdmissibility.overall,
      currentReason: result.currentAdmissibility.reason,
      preservation: result.preservation.overall,
    }),
  );
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.preservation.overall, 'VALID');
  assert.equal(result.currentAdmissibility.overall, current);
  assert.equal(result.purpose, 'RETAINED_EVIDENCE_VERIFICATION');
  assert(result.limitations.includes('NO_CURRENT_EXECUTION_PERMISSION'));
}

function start(a, value, seam) {
  const paths = a.paths(),
    payload = {
      ...value,
      seam,
      readyPath: paths.readyPath,
      releasePath: paths.releasePath,
      beginPath: paths.beginPath,
    };
  assertPublicHistoryData(payload);
  fs.writeFileSync(paths.requestPath, serialize(payload));
  const child = spawn(process.execPath, [childPath, paths.requestPath, paths.responsePath], {
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  a.children.add(child);
  let diagnostics = '';
  child.stdout.on('data', (chunk) => {
    diagnostics += chunk;
  });
  child.stderr.on('data', (chunk) => {
    diagnostics += chunk;
  });
  const exited = new Promise((resolveExit, rejectExit) => {
    child.once('error', rejectExit);
    child.once('close', (code, signal) => resolveExit({ code, signal }));
  });
  const response = () => deserialize(fs.readFileSync(paths.responsePath));
  return {
    child,
    paths,
    exited,
    response,
    async ready() {
      const deadline = performance.now() + 60000;
      while (!fs.existsSync(paths.readyPath)) {
        assert.equal(child.exitCode, null, diagnostics);
        assert.equal(child.signalCode, null, diagnostics);
        assert(performance.now() < deadline, 'Child did not reach boundary: ' + diagnostics);
        await new Promise((resolveWait) => setTimeout(resolveWait, 20));
      }
      const marker = JSON.parse(fs.readFileSync(paths.readyPath, 'utf8'));
      assert.equal(marker.pid, child.pid);
      assert.equal(marker.name, seam);
      assert.equal(marker.reads, 1);
      return marker;
    },
    async beginning() {
      const deadline = performance.now() + 60000;
      while (!fs.existsSync(paths.beginPath)) {
        assert.equal(child.exitCode, null, diagnostics);
        assert(performance.now() < deadline, diagnostics);
        await new Promise((resolveWait) => setTimeout(resolveWait, 20));
      }
      const marker = JSON.parse(fs.readFileSync(paths.beginPath, 'utf8'));
      assert.equal(marker.pid, child.pid);
      assert.equal(marker.name, 'before-begin');
      return marker;
    },
    release() {
      fs.writeFileSync(paths.releasePath, 'continue');
    },
  };
}

test('independent durable negative observations survive a different process', async (t) => {
  const f = await material();
  for (const [kind, knowledge] of Object.entries(f.incidents))
    await t.test(kind, (t) => {
      const a = area(t),
        expected = memory(f, [{ knowledge }, { knowledge: f.newerGood }]);
      scoped(expected[0], 'INVALID');
      scoped(expected[1], 'INVALID');
      const first = run(a, request(f, knowledge, f.first, { databasePath: a.databasePath }));
      committed(first, f.first);
      assert.deepEqual(withoutReceipt(first.result), expected[0]);
      const reopened = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
      assert.notEqual(first.pid, reopened.pid);
      committed(reopened, f.first);
      assert.deepEqual(withoutReceipt(reopened.result), expected[1]);
      assert(reopened.result.knowledgeReceipt.revision > first.result.knowledgeReceipt.revision);
      assert.deepEqual(
        reopened.result.knowledgeReceipt.scopeID,
        first.result.knowledgeReceipt.scopeID,
      );
      assert.deepEqual(
        reopened.result.knowledgeReceipt.configurationID,
        first.result.knowledgeReceipt.configurationID,
      );
      scoped(reopened.result, 'INVALID');
      const control = run(
        a,
        request(f, f.newerGood, f.first, { databasePath: join(a.directory, 'fresh.sqlite') }),
      );
      scoped(control.result, 'VALID');
    });
});

test('independent durable key compromise crosses final authorization identifiers', async (t) => {
  const f = await material(),
    a = area(t);
  assert.notDeepEqual(f.facts.firstTarget.objectID, f.facts.secondTarget.objectID);
  assert.notDeepEqual(f.facts.firstTarget.objectHash, f.facts.secondTarget.objectHash);
  assert.deepEqual(f.facts.firstTarget.subjectKeyID, f.facts.secondTarget.subjectKeyID);
  assert(f.facts.secondTargetIDs.every((id) => !id.equals(f.facts.firstTarget.objectID)));
  assert.equal(f.facts.firstSigningCalls, 1);
  assert.equal(f.facts.secondSigningCalls, 1);
  const clean = run(
    a,
    request(f, f.secondGood, f.second, { databasePath: join(a.directory, 'fresh.sqlite') }),
  );
  scoped(clean.result, 'VALID');
  const first = run(
    a,
    request(f, f.incidents.organization, f.first, { databasePath: a.databasePath }),
  );
  committed(first, f.first);
  scoped(first.result, 'INVALID');
  const second = run(a, request(f, f.secondGood, f.second, { databasePath: a.databasePath }));
  committed(second, f.second);
  assert.notEqual(first.pid, second.pid);
  scoped(second.result, 'INVALID');
  assert.equal(second.result.currentAdmissibility.reason, 'ORG_KEY_COMPROMISED');
  const expected = memory(f, [
    { knowledge: f.incidents.organization },
    { knowledge: f.secondGood, input: f.second },
  ])[1];
  assert.deepEqual(withoutReceipt(second.result), expected);
  assert.notEqual(
    first.result.knowledgeReceipt.evidenceID,
    second.result.knowledgeReceipt.evidenceID,
  );
});

test('independent durable rejected siblings cannot poison a later clean process', async (t) => {
  const f = await material();
  for (const [kind, knowledge] of Object.entries(f.rejected))
    await t.test(kind, (t) => {
      const a = area(t),
        current = run(a, request(f, knowledge, f.first, { databasePath: a.databasePath }));
      assert.notEqual(current.result.overall, 'VALID');
      committed(current, f.first);
      const reopened = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
      committed(reopened, f.first);
      scoped(reopened.result, 'VALID');
      assert.deepEqual(withoutReceipt(reopened.result), memory(f, [{ knowledge: f.newerGood }])[0]);
    });
});

test('independent durable crashes respect transaction boundaries', async (t) => {
  const f = await material();
  for (const seam of ['before-append', 'before-commit', 'after-commit'])
    await t.test(seam, async (t) => {
      const a = area(t),
        baseline = run(a, request(f, f.initial, f.first, { databasePath: a.databasePath }));
      committed(baseline, f.first);
      scoped(baseline.result, 'VALID');
      const writer = start(
        a,
        request(f, f.incidents.organization, f.first, { databasePath: a.databasePath }),
        seam,
      );
      const marker = await writer.ready();
      assert.equal(marker.outerTransactions, 1);
      if (seam === 'before-append') assert.equal(marker.writes, 0);
      else assert(marker.writes > 0, 'The transaction actually wrote data before the boundary');
      assert.equal(
        fs.existsSync(writer.paths.responsePath),
        false,
        'No result was exposed before termination',
      );
      assert.equal(writer.child.kill('SIGKILL'), true);
      const exit = await writer.exited;
      assert(exit.signal === 'SIGKILL' || (exit.code !== null && exit.code !== 0));
      assert.equal(fs.existsSync(writer.paths.responsePath), false);
      const reopened = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
      assert.notEqual(reopened.pid, marker.pid);
      committed(reopened, f.first);
      const steps = [
        { knowledge: f.initial },
        ...(seam === 'after-commit' ? [{ knowledge: f.incidents.organization }] : []),
        { knowledge: f.newerGood },
      ];
      scoped(reopened.result, seam === 'after-commit' ? 'INVALID' : 'VALID');
      assert.deepEqual(withoutReceipt(reopened.result), memory(f, steps).at(-1));
    });
});

test('independent durable invalid assessment still commits authenticated incidents', async (t) => {
  const f = await material();
  for (const kind of ['missingSIM', 'invalidApproval'])
    await t.test(kind, (t) => {
      const a = area(t),
        input = f[kind];
      const admitted = run(
        a,
        request(f, f.incidents.organization, input, { databasePath: a.databasePath }),
      );
      assert.notEqual(admitted.result.overall, 'VALID');
      if (kind === 'invalidApproval') assert.equal(admitted.result.overall, 'INVALID');
      committed(admitted, input);
      const reopened = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
      committed(reopened, f.first);
      scoped(reopened.result, 'INVALID');
      // The complete original authenticates exactly the same legitimate incident for
      // the memory control; legacy memory need not admit facts from a missing SIM.
      const expected = memory(f, [
        { knowledge: f.incidents.organization },
        { knowledge: f.newerGood },
      ]).at(-1);
      assert.deepEqual(withoutReceipt(reopened.result), expected);
    });
});

test('independent durable memory cannot supply missing fresh coverage', async (t) => {
  const f = await material();
  for (const negative of [false, true])
    await t.test(
      negative
        ? 'retained incident dominates missing coverage'
        : 'old positive cannot grant freshness',
      (t) => {
        const a = area(t),
          initial = negative ? f.incidents.organization : f.initial;
        const admitted = run(a, request(f, initial, f.first, { databasePath: a.databasePath }));
        committed(admitted, f.first);
        const missing = { ...copy(f.newerGood), statusMaterial: [], certificateStatusMaterial: [] };
        const reopened = run(a, request(f, missing, f.first, { databasePath: a.databasePath }));
        committed(reopened, f.first);
        scoped(reopened.result, negative ? 'INVALID' : 'INDETERMINATE');
        if (!negative)
          assert.deepEqual(withoutReceipt(reopened.result), memory(f, [{ knowledge: missing }])[0]);
      },
    );
});

test('independent durable source rejects configuration rebinding and knowledge rollback', async (t) => {
  const f = await material(),
    a = area(t);
  const initial = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
  committed(initial, f.first);
  const altered = copy(f.configuration);
  altered.preservation.dataValidUntil--;
  const mismatch = run(
    a,
    {
      ...request(f, f.newerGood, f.first, { databasePath: a.databasePath }),
      configuration: altered,
    },
    { allowError: true },
  );
  assert.equal(mismatch.error.code, 'ORG_HISTORY_CONFIGURATION_MISMATCH');
  assert.equal(mismatch.reads, 0);
  const rollback = run(a, request(f, f.initial, f.first, { databasePath: a.databasePath }));
  assert.equal(rollback.result.overall, 'INVALID');
  assert.equal(rollback.result.reason, 'ORG_KNOWLEDGE_ROLLBACK');
  assert.equal(rollback.result.knowledgeReceipt.state, 'NOT_COMMITTED');
  assert.equal(rollback.result.knowledgeReceipt.revision, null);
  const duplicate = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
  committed(duplicate, f.first);
  scoped(duplicate.result, 'VALID');
  assert.deepEqual(duplicate.result, initial.result);
});

test('independent durable lost commit acknowledgement poisons only the uncertain instance', async (t) => {
  const f = await material();
  for (const negative of [false, true])
    await t.test(negative ? 'known invalid' : 'otherwise valid', (t) => {
      const a = area(t);
      const lost = run(
        a,
        request(f, negative ? f.incidents.organization : f.initial, f.first, {
          databasePath: a.databasePath,
          seam: 'lost-commit-ack',
        }),
      );
      assert.equal(lost.result.overall, negative ? 'INVALID' : 'INDETERMINATE');
      assert.equal(lost.result.knowledgeReceipt.state, 'UNKNOWN');
      assert.equal(lost.result.knowledgeReceipt.revision, null);
      assert.notEqual(lost.followup.overall, 'VALID');
      assert.equal(lost.followup.knowledgeReceipt.state, 'NOT_COMMITTED');
      assert.equal(lost.reads, 1);
      const reopened = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
      committed(reopened, f.first);
      scoped(reopened.result, negative ? 'INVALID' : 'VALID');
    });
});

test('independent durable invalid target bindings cannot poison a different original', async (t) => {
  const f = await material();
  const controlArea = area(t);
  const control = run(
    controlArea,
    request(f, f.secondGood, f.second, { databasePath: controlArea.databasePath }),
  );
  committed(control, f.second);
  scoped(control.result, 'VALID');
  for (const [kind, candidate] of Object.entries(f.malformedTargets).filter(
    ([kind]) => kind !== 'grant-future-original-negative',
  ))
    await t.test(kind, (t) => {
      const a = area(t);
      assert(f.facts.secondTargetIDs.every((id) => !id.equals(candidate.adverse.objectID)));
      if (kind.endsWith('future')) assert(candidate.target.validFrom > f.facts.P);
      if (kind.endsWith('empty-interval'))
        assert.equal(candidate.target.validFrom, candidate.target.validUntil);
      const admitted = run(
        a,
        request(f, candidate.knowledge, candidate.input, { databasePath: a.databasePath }),
      );
      assert.notEqual(admitted.result.overall, 'VALID');
      committed(admitted, candidate.input);
      const reopened = run(a, request(f, f.secondGood, f.second, { databasePath: a.databasePath }));
      committed(reopened, f.second);
      scoped(reopened.result, 'VALID');
      assert.deepEqual(
        withoutReceipt(reopened.result),
        memory(f, [{ knowledge: f.secondGood, input: f.second }])[0],
      );
    });
});

test('independent durable raw original replay cannot create a rejected target incident', async (t) => {
  const f = await material(),
    a = area(t),
    candidate = f.malformedTargets['grant-future-original-negative'];
  assert.equal(candidate.knowledge.statusMaterial.length, 0);
  assert(candidate.knowledge.authorityHistory.length > 0);
  assert(candidate.knowledge.certificateStatusMaterial.length > 0);
  assert(candidate.target.validFrom > f.facts.P);
  assert(candidate.adverse.publishedAt < f.facts.P);
  assert(f.facts.secondTargetIDs.every((id) => !id.equals(candidate.adverse.objectID)));
  const baseline = run(
    a,
    request(f, f.secondGood, f.second, { databasePath: join(a.directory, 'fresh.sqlite') }),
  );
  scoped(baseline.result, 'VALID');
  const admitted = run(
    a,
    request(f, candidate.knowledge, candidate.input, { databasePath: a.databasePath }),
  );
  committed(admitted, candidate.input);
  assert.notEqual(admitted.result.overall, 'VALID');
  const reopened = run(a, request(f, f.secondGood, f.second, { databasePath: a.databasePath }));
  committed(reopened, f.second);
  scoped(reopened.result, 'VALID');
  assert.deepEqual(withoutReceipt(reopened.result), withoutReceipt(baseline.result));
});

test('independent durable concurrent writers retain both negative classes in either order', async (t) => {
  const f = await material();
  for (const order of [
    ['organization', 'certificate'],
    ['certificate', 'organization'],
  ])
    await t.test(order.join(' then '), async (t) => {
      const a = area(t);
      scoped(
        run(a, request(f, f.initial, f.first, { databasePath: a.databasePath })).result,
        'VALID',
      );
      const writers = order.map((kind) =>
        start(
          a,
          request(f, f.incidents[kind], f.first, { databasePath: a.databasePath }),
          'after-snapshot',
        ),
      );
      const markers = await Promise.all(writers.map((writer) => writer.ready()));
      assert.notEqual(markers[0].pid, markers[1].pid);
      assert(writers.every((writer) => writer.child.exitCode === null));
      writers[0].release();
      assert.deepEqual(await writers[0].exited, { code: 0, signal: null });
      committed(writers[0].response(), f.first);
      writers[1].release();
      assert.deepEqual(await writers[1].exited, { code: 0, signal: null });
      committed(writers[1].response(), f.first);
      const reopened = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
      committed(reopened, f.first);
      scoped(reopened.result, 'INVALID');
      for (const check of ['retained-organization-incidents', 'retained-certificate-incidents'])
        assert(
          reopened.result.currentAdmissibility.checks.some(
            (item) => item.check === check && item.overall === 'INVALID',
          ),
          check,
        );
      const expected = memory(f, [
        { knowledge: f.initial },
        ...order.map((kind) => ({ knowledge: f.incidents[kind] })),
        { knowledge: f.newerGood },
      ]).at(-1);
      assert.deepEqual(withoutReceipt(reopened.result), expected);
    });
});

test('independent durable stale positive reloads a concurrent negative commit', async (t) => {
  const f = await material(),
    a = area(t);
  scoped(run(a, request(f, f.initial, f.first, { databasePath: a.databasePath })).result, 'VALID');
  const positive = start(
    a,
    request(f, f.newerGood, f.first, { databasePath: a.databasePath }),
    'after-snapshot',
  );
  await positive.ready();
  const negative = start(
    a,
    request(f, f.incidents.organization, f.first, { databasePath: a.databasePath }),
    'before-commit',
  );
  const marker = await negative.ready();
  assert(marker.writes > 0);
  positive.release();
  await positive.beginning();
  assert.equal(positive.child.exitCode, null);
  negative.release();
  assert.deepEqual(await negative.exited, { code: 0, signal: null });
  assert.deepEqual(await positive.exited, { code: 0, signal: null });
  const response = positive.response();
  committed(response, f.first);
  scoped(response.result, 'INVALID');
  assert.deepEqual(
    withoutReceipt(response.result),
    memory(f, [
      { knowledge: f.initial },
      { knowledge: f.incidents.organization },
      { knowledge: f.newerGood },
    ]).at(-1),
  );
});

test('independent durable same-epoch conflict survives either concurrent writer order', async (t) => {
  const f = await material();
  for (const knowledge of Object.values(f.concurrentConflict))
    scoped(memory(f, [{ knowledge }])[0], 'VALID');
  for (const order of [
    ['good', 'revoked'],
    ['revoked', 'good'],
  ])
    await t.test(order.join(' then '), async (t) => {
      const a = area(t);
      const empty = createOrganizationHistorySource({
        configuration: f.configuration,
        databasePath: a.databasePath,
        readKnowledge: () => assert.fail('Opening an empty source must not admit knowledge'),
      });
      empty.close();
      const writers = order.map((kind) =>
        start(
          a,
          request(f, f.concurrentConflict[kind], f.first, { databasePath: a.databasePath }),
          'after-snapshot',
        ),
      );
      const markers = await Promise.all(writers.map((writer) => writer.ready()));
      assert.notEqual(markers[0].pid, markers[1].pid);
      assert(writers.every((writer) => writer.child.exitCode === null));
      writers[0].release();
      assert.deepEqual(await writers[0].exited, { code: 0, signal: null });
      const first = writers[0].response();
      committed(first, f.first);
      scoped(first.result, 'VALID');
      writers[1].release();
      assert.deepEqual(await writers[1].exited, { code: 0, signal: null });
      const second = writers[1].response();
      committed(second, f.first);
      scoped(second.result, 'INVALID');
      assert.equal(second.result.currentAdmissibility.reason, 'ORG_STATUS_CONFLICT');
      assert(second.result.knowledgeReceipt.revision > first.result.knowledgeReceipt.revision);
      const reopened = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
      committed(reopened, f.first);
      scoped(reopened.result, 'INVALID');
      assert.equal(reopened.result.currentAdmissibility.reason, 'ORG_STATUS_CONFLICT');
      const expected = memory(f, [
        ...order.map((kind) => ({ knowledge: f.concurrentConflict[kind] })),
        { knowledge: f.newerGood },
      ]).at(-1);
      assert.deepEqual(withoutReceipt(reopened.result), expected);
    });
});

test('independent durable malformed knowledge never advances the selected time', async (t) => {
  const f = await material();
  for (const kind of ['missing array', 'wrong array type', 'status list overflow'])
    await t.test(kind, (t) => {
      const a = area(t),
        malformed = copy(f.initial);
      malformed.knowledgeTime += 1000;
      if (kind === 'missing array') delete malformed.certificateStatusMaterial;
      if (kind === 'wrong array type') malformed.certificateStatusMaterial = {};
      if (kind === 'status list overflow')
        malformed.statusMaterial = Array.from({ length: 65 }, () =>
          copy(f.initial.statusMaterial[0]),
        );
      const failed = run(a, request(f, malformed, f.first, { databasePath: a.databasePath }));
      assert.notEqual(failed.result.overall, 'VALID');
      assert.equal(failed.result.knowledgeReceipt.state, 'NOT_COMMITTED');
      assert.equal(failed.result.knowledgeReceipt.revision, null);
      assert.equal(failed.clockReads, 0);
      const clean = run(a, request(f, f.initial, f.first, { databasePath: a.databasePath }));
      committed(clean, f.first);
      scoped(clean.result, 'VALID');
      assert.deepEqual(withoutReceipt(clean.result), memory(f, [{ knowledge: f.initial }])[0]);
    });
});

test('independent durable RTM quota failure is sticky across reopen without evicting an incident', async (t) => {
  const f = await createIndependentDurableCapacityMaterials(),
    a = area(t);
  const persisted = () => {
    const database = new DatabaseSync(a.databasePath);
    try {
      const rows = database.prepare('SELECT * FROM state ORDER BY namespace,id').all();
      const head = rows.find((row) => row.id === 'head');
      assert(head);
      return {
        revision: head.revision,
        head: decodeCBOR(Buffer.from(head.value)),
        records: rows
          .filter((row) => row.id !== 'head')
          .map((row) => ({
            namespace: row.namespace,
            id: row.id,
            revision: row.revision,
            sha256: hash(row.value),
          })),
      };
    } finally {
      database.close();
    }
  };
  const admitted = run(a, request(f, f.firstKnowledge, f.first, { databasePath: a.databasePath }));
  committed(admitted, f.first);
  scoped(admitted.result, 'INVALID');
  const full = run(a, request(f, f.atLimit, f.unverifiableInput, { databasePath: a.databasePath }));
  committed(full, f.unverifiableInput);
  assert.notEqual(full.result.overall, 'VALID');
  assert(!full.result.checks.some((item) => item.reason === 'ORG_HISTORY_KNOWLEDGE_LIMIT'));
  const overflow = run(
    a,
    request(f, f.beyondLimit, f.unverifiableInput, { databasePath: a.databasePath }),
  );
  assert.notEqual(overflow.result.overall, 'VALID');
  assert.equal(overflow.result.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(overflow.result.knowledgeReceipt.evidenceID, null);
  assert(overflow.result.knowledgeReceipt.revision > full.result.knowledgeReceipt.revision);
  assert(overflow.result.checks.some((item) => item.reason === 'ORG_HISTORY_KNOWLEDGE_LIMIT'));
  const before = persisted();
  assert.equal(before.head.overflow, true);
  assert.equal(before.head.selectedKnowledge, f.beyondLimit.knowledgeTime);
  const reopened = run(
    a,
    request(f, f.afterLimit, f.first, {
      databasePath: a.databasePath,
      readEvidenceID: admitted.result.knowledgeReceipt.evidenceID,
    }),
  );
  assert.equal(reopened.result.overall, 'INVALID');
  assert.equal(reopened.result.currentAdmissibility.overall, 'INVALID');
  assert(reopened.result.checks.some((item) => item.reason === 'ORG_HISTORY_KNOWLEDGE_LIMIT'));
  assert.equal(reopened.result.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(reopened.result.knowledgeReceipt.evidenceID, null);
  const after = persisted();
  assert.equal(after.head.selectedKnowledge, f.afterLimit.knowledgeTime);
  assert(after.revision > before.revision);
  assert.equal(reopened.result.knowledgeReceipt.revision, after.revision);
  assert.deepEqual(
    { ...after.head, selectedKnowledge: before.head.selectedKnowledge },
    { ...before.head },
  );
  assert.deepEqual(after.records, before.records);
  assert.equal(reopened.retainedEvidence.classification, 'UNVERIFIED_BYTES');
  assert.deepEqual(reopened.retainedEvidence.originalBytes, f.first.originalBytes);
  assert.deepEqual(reopened.retainedEvidence.evidenceRecord, f.first.evidenceRecord);
  const retry = run(a, request(f, f.afterLimit, f.first, { databasePath: a.databasePath }));
  assert.deepEqual(retry.result, reopened.result);
  assert.deepEqual(persisted(), after);
  const rollback = run(a, request(f, f.initial, f.first, { databasePath: a.databasePath }));
  assert.equal(rollback.result.overall, 'INVALID');
  assert.equal(rollback.result.reason, 'ORG_KNOWLEDGE_ROLLBACK');
  assert.equal(rollback.result.knowledgeReceipt.state, 'NOT_COMMITTED');
  assert.equal(rollback.result.knowledgeReceipt.revision, null);
  assert.deepEqual(persisted(), after);
});

test('independent durable latest authority coverage cannot be supplied by cached results', async (t) => {
  const f = await material();
  for (const negative of [false, true])
    await t.test(negative ? 'known incident' : 'previously valid', (t) => {
      const a = area(t),
        first = negative ? f.incidents.organization : f.initial;
      committed(run(a, request(f, first, f.first, { databasePath: a.databasePath })), f.first);
      const stale = { ...copy(f.newerGood), knowledgeTime: f.facts.K + 300, authorityHistory: [] };
      const reopened = run(a, request(f, stale, f.first, { databasePath: a.databasePath }));
      committed(reopened, f.first);
      assert.equal(reopened.result.historicalAuthorization.overall, 'VALID');
      assert.equal(reopened.result.proofOfExistenceUpperBound, f.facts.P);
      assert.equal(reopened.result.preservation.overall, 'INDETERMINATE');
      assert.equal(
        reopened.result.currentAdmissibility.overall,
        negative ? 'INVALID' : 'INDETERMINATE',
      );
      assert.equal(reopened.result.overall, negative ? 'INVALID' : 'INDETERMINATE');
    });
});

test('independent durable corrupted exact bytes never reset trusted memory', async (t) => {
  const f = await material(),
    a = area(t);
  const initial = run(
    a,
    request(f, f.incidents.organization, f.first, { databasePath: a.databasePath }),
  );
  committed(initial, f.first);
  const database = new DatabaseSync(a.databasePath);
  let count;
  try {
    const row = database
      .prepare("SELECT namespace,id,value FROM state WHERE id LIKE 'chunk:%' ORDER BY id LIMIT 1")
      .get();
    assert(row);
    const corrupted = Buffer.from(row.value),
      before = hash(corrupted);
    corrupted[corrupted.length - 1] ^= 1;
    assert.notEqual(hash(corrupted), before);
    database
      .prepare('UPDATE state SET value=? WHERE namespace=? AND id=?')
      .run(corrupted, row.namespace, row.id);
    count = database.prepare('SELECT COUNT(*) AS count FROM state').get().count;
  } finally {
    database.close();
  }
  const reopened = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
  assert.equal(reopened.result.overall, 'INDETERMINATE');
  assert.equal(reopened.result.knowledgeReceipt.state, 'NOT_COMMITTED');
  assert.equal(reopened.result.knowledgeReceipt.revision, null);
  assert(reopened.result.checks.some((item) => item.reason === 'ORG_HISTORY_STORAGE_CORRUPT'));
  const retry = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
  assert.deepEqual(retry.result, reopened.result);
  const check = new DatabaseSync(a.databasePath);
  try {
    assert.equal(check.prepare('SELECT COUNT(*) AS count FROM state').get().count, count);
  } finally {
    check.close();
  }
});

test('independent durable failed writes cannot claim committed validity or retention', async (t) => {
  const f = await material();
  for (const negative of [false, true])
    await t.test(negative ? 'known invalid' : 'otherwise valid', (t) => {
      const a = area(t);
      const failed = run(
        a,
        request(f, negative ? f.incidents.organization : f.initial, f.first, {
          databasePath: a.databasePath,
          seam: 'write-failure',
        }),
      );
      assert.equal(failed.result.overall, negative ? 'INVALID' : 'INDETERMINATE');
      assert.equal(failed.result.knowledgeReceipt.state, 'NOT_COMMITTED');
      assert.equal(failed.result.knowledgeReceipt.revision, null);
      assert.equal(failed.result.knowledgeReceipt.evidenceID, null);
      assert(
        failed.result.checks.some((item) => item.reason === 'ORG_HISTORY_STORAGE_UNAVAILABLE'),
      );
      const reopened = run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath }));
      committed(reopened, f.first);
      scoped(reopened.result, 'VALID');
    });
});

test('independent durable artifact identifiers bind the exact original and record pair', async (t) => {
  const f = await material(),
    a = area(t);
  const first = run(a, request(f, f.initial, f.first, { databasePath: a.databasePath }));
  const second = run(a, request(f, f.secondGood, f.second, { databasePath: a.databasePath }));
  committed(first, f.first);
  committed(second, f.second);
  const firstID = first.result.knowledgeReceipt.evidenceID,
    secondID = second.result.knowledgeReceipt.evidenceID;
  assert.notEqual(firstID, secondID);
  assert.notDeepEqual(f.first.originalBytes, f.second.originalBytes);
  const exact = run(
    a,
    request(f, f.secondGood, f.first, {
      databasePath: a.databasePath,
      onlyReadEvidence: true,
      readEvidenceID: firstID,
    }),
  );
  assert.equal(exact.reads, 0);
  assert.equal(exact.retainedEvidence.classification, 'UNVERIFIED_BYTES');
  assert.deepEqual(exact.retainedEvidence.originalBytes, f.first.originalBytes);
  assert.deepEqual(exact.retainedEvidence.evidenceRecord, f.first.evidenceRecord);
  const database = new DatabaseSync(a.databasePath);
  try {
    const row = database.prepare("SELECT namespace,value FROM state WHERE id='head'").get();
    assert(row);
    const head = decodeCBOR(Buffer.from(row.value));
    const original = head.artifacts.find((entry) => entry.id === firstID);
    const replacement = head.artifacts.find((entry) => entry.id === secondID);
    assert(original && replacement);
    original.original = replacement.original;
    original.record = replacement.record;
    database
      .prepare("UPDATE state SET value=? WHERE namespace=? AND id='head'")
      .run(dcbor(head), row.namespace);
  } finally {
    database.close();
  }
  const rejected = run(
    a,
    request(f, f.secondGood, f.first, {
      databasePath: a.databasePath,
      onlyReadEvidence: true,
      readEvidenceID: firstID,
    }),
    { allowError: true },
  );
  assert.equal(rejected.reads, 0);
  assert.equal(rejected.error?.code, 'ORG_HISTORY_STORAGE_CORRUPT');
  assert.equal(rejected.retainedEvidence, undefined);
});

test('independent durable explicitly submitted lower epoch is not hidden by an admitted newer head', async (t) => {
  const f = await material(),
    a = area(t);
  committed(run(a, request(f, f.newerGood, f.first, { databasePath: a.databasePath })), f.first);
  const lower = {
    ...copy(f.newerGood),
    knowledgeTime: f.facts.K + 2,
    statusMaterial: copy(f.initial.statusMaterial),
  };
  const rollback = run(a, request(f, lower, f.first, { databasePath: a.databasePath }));
  committed(rollback, f.first);
  scoped(rollback.result, 'INVALID');
  assert.equal(rollback.result.currentAdmissibility.reason, 'ORG_STATUS_ROLLBACK');
  const restored = { ...copy(f.newerGood), knowledgeTime: f.facts.K + 3 };
  const reopened = run(a, request(f, restored, f.first, { databasePath: a.databasePath }));
  committed(reopened, f.first);
  scoped(reopened.result, 'VALID');
  assert.deepEqual(withoutReceipt(reopened.result), memory(f, [{ knowledge: restored }])[0]);
});
