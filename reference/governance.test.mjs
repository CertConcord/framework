import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, rmdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  digest,
  byteDigest,
  validateRegistry,
  openRegister,
  contributionDigest,
  checkContribution,
  checkMark,
  validateTransition,
} from './governance/registry.mjs';

const at = '2026-01-01T00:00:00.000Z',
  now = Date.parse('2026-04-01T00:00:00.000Z');
const h = 'a'.repeat(64),
  sha = 'b'.repeat(40);
const ref = { uri: 'https://example.test/synthetic-receipt', sha256: h };
const review = { reviewer: 'Synthetic registrar', reviewedAt: at, receipt: ref };
const scope = {
  name: 'CertConcord',
  edition: 'synthetic-test',
  sha256: h,
};
const event = { at, state: 'ACTIVE', reason: 'Synthetic test grant', receipt: ref };
const clone = structuredClone;
function fixture() {
  const submission = {
    files: [
      { path: 'spec/bindings/DTI-draft-02.md', sha, status: 'modified', previousPath: null },
      { path: 'synthetic.mjs', sha, status: 'added', previousPath: null },
    ],
    commits: [
      {
        sha,
        name: 'Synthetic Author',
        email: 'synthetic@example.test',
        message:
          'Synthetic contribution\n\nSigned-off-by: Synthetic Author <synthetic@example.test>',
      },
    ],
    additionalNormativePaths: [],
  };
  const r = {
    schemaVersion: 1,
    framework: 'CertConcord',
    holders: [
      { id: 'synthetic-holder', legalName: 'Synthetic Test Holder', authority: ref, review },
    ],
    agreements: [
      {
        id: 'synthetic-cla',
        kind: 'OWF_CLA_1_0',
        holderId: 'synthetic-holder',
        specification: scope,
        instrument: ref,
        signedAt: at,
        contributorEmails: ['synthetic@example.test'],
        review,
      },
    ],
    contributions: [
      {
        id: 'synthetic-contribution',
        agreementId: 'synthetic-cla',
        digest: contributionDigest(submission.files),
        receivedAt: at,
        withdrawnAt: null,
        withdrawalNotice: null,
        review,
      },
    ],
    marks: [],
    plans: [],
    grants: [],
  };
  return { r: clone(r), submission };
}
async function markFixture() {
  const { r } = fixture(),
    dir = await mkdtemp(join(tmpdir(), 'certconcord-governance-'));
  const bytes = Buffer.from('synthetic test evidence\n');
  await writeFile(join(dir, 'result.txt'), bytes);
  const report = {
    schemaVersion: 1,
    category: 'LOCAL_ADAPTER',
    assessor: 'synthetic-assessor',
    sourceCommit: sha,
    manifestSHA256: h,
    role: 'VERIFIER',
    suite: { name: 'synthetic-suite', revision: '1' },
    profile: 'synthetic-profile',
    configurationSHA256: h,
    startedAt: at,
    completedAt: at,
    tests: [
      { id: 'positive', result: 'PASS', artifact: 'result.txt' },
      { id: 'rejection', result: 'PASS', artifact: 'result.txt' },
    ],
    artifacts: [{ path: 'result.txt', sha256: byteDigest(bytes) }],
  };
  r.marks.push({
    id: 'synthetic-mark',
    text: 'Synthetic Test Designation',
    holderId: 'synthetic-holder',
    policySHA256: h,
    instrument: ref,
    events: [event],
    review,
  });
  r.plans.push({
    id: 'synthetic-plan',
    markId: 'synthetic-mark',
    specification: scope,
    role: 'VERIFIER',
    profile: report.profile,
    suite: report.suite,
    assessors: [report.assessor],
    category: report.category,
    requirements: [{ id: 'validation', tests: ['positive', 'rejection'] }],
    review,
  });
  r.grants.push({
    id: 'synthetic-grant',
    planId: 'synthetic-plan',
    granteeId: 'synthetic-holder',
    implementation: {
      name: 'Synthetic Implementation',
      version: '1',
      environment: 'Synthetic environment',
    },
    sourceCommit: sha,
    manifestSHA256: h,
    configurationSHA256: h,
    reportSHA256: digest(report),
    validFrom: at,
    validUntil: '2027-01-01T00:00:00.000Z',
    instrument: ref,
    events: [event],
    review,
  });
  return { r: clone(r), report: clone(report), dir };
}

test('rights register starts without inferred patent signatories or awarded marks', async () => {
  const bytes = await readFile('governance/registry.json');
  const r = openRegister(bytes, byteDigest(bytes));
  assert.equal(r.agreements.length, 0);
  assert.equal(r.holders.length, 0);
  assert.equal(r.grants.length, 0);
  assert.throws(() => openRegister(bytes, '0'.repeat(64)), /UNTRUSTED_REGISTRY/);
  assert.throws(() => r.holders.push({}), TypeError);
  await assert.rejects(checkMark(r, 'self-awarded', {}, '.', { now }), /MARK_GRANT_INACTIVE/);
});
test('DCO requires actual matching author and co-author trailers', () => {
  const { r, submission } = fixture();
  assert.equal(checkContribution(r, submission, { now }).origin, 'DCO_PRESENT');
  const broken = clone(submission);
  broken.commits[0].message = 'Signed-off-by: Different <different@example.test>';
  assert.throws(() => checkContribution(r, broken, { now }), /DCO_REQUIRED/);
  broken.commits[0].message = submission.commits[0].message + '\n\nNot a trailer';
  assert.throws(() => checkContribution(r, broken, { now }), /DCO_REQUIRED/);
  broken.commits[0].message =
    submission.commits[0].message + '\nCo-authored-by: Other <other@example.test>';
  assert.throws(() => checkContribution(r, broken, { now }), /DCO_REQUIRED/);
});
test('normative changes bind exact content and cannot self-register', () => {
  const { r, submission } = fixture();
  assert.equal(checkContribution(r, submission, { now }).specification, 'SETTLED_CONTRIBUTION');
  const changed = clone(submission);
  changed.files[0].sha = 'c'.repeat(40);
  assert.throws(() => checkContribution(r, changed, { now }), /SPECIFICATION_AGREEMENT_REQUIRED/);
  const base = clone(r);
  base.contributions = [];
  assert.throws(
    () => checkContribution(base, submission, { now }),
    /SPECIFICATION_AGREEMENT_REQUIRED/,
  );
  r.agreements[0].kind = 'OWFA_PATENT_ONLY_1_0';
  assert.throws(() => validateRegistry(r), /REGISTRY_CONTRIBUTION/);
});
test('rename out of normative paths and declared normative documents remain covered', () => {
  const { submission } = fixture();
  const files = [
    {
      ...submission.files[0],
      path: 'notes.md',
      previousPath: 'spec/bindings/DTI-draft-02.md',
      status: 'renamed',
    },
  ];
  assert.ok(contributionDigest(files));
  files[0].previousPath = null;
  assert.equal(contributionDigest(files), null);
  assert.ok(contributionDigest(files, ['notes.md']));
  assert.throws(() => contributionDigest(files, ['not-changed.md']), /CONTRIBUTION_DECLARATION/);
});
test('finalization observes 45 days and rejects withdrawn contributions', () => {
  const { r, submission } = fixture(),
    boundary = Date.parse(at) + 45 * 86400000;
  assert.equal(
    checkContribution(r, submission, { now: boundary }).specification,
    'WITHDRAWAL_WINDOW_OPEN',
  );
  assert.throws(
    () => checkContribution(r, submission, { now: boundary, final: true }),
    /CONTRIBUTION_WITHDRAWAL_WINDOW/,
  );
  assert.equal(
    checkContribution(r, submission, { now: boundary + 1, final: true }).specification,
    'SETTLED_CONTRIBUTION',
  );
  r.contributions[0].withdrawnAt = '2026-01-02T00:00:00.000Z';
  r.contributions[0].withdrawalNotice = ref;
  assert.throws(
    () => checkContribution(r, submission, { now, final: true }),
    /SPECIFICATION_AGREEMENT_REQUIRED/,
  );
});
test('trusted grant requires exact report, required results and intact artifacts', async () => {
  const { r, report, dir } = await markFixture();
  try {
    assert.equal(
      (await checkMark(r, 'synthetic-grant', report, dir, { now })).authorization,
      'ACTIVE_RECORDED_GRANT',
    );
    const edited = clone(report);
    edited.configurationSHA256 = 'c'.repeat(64);
    await assert.rejects(
      checkMark(r, 'synthetic-grant', edited, dir, { now }),
      /MARK_REPORT_BINDING/,
    );
    for (const result of ['FAIL', 'INAPPLICABLE', 'INDETERMINATE']) {
      const rr = clone(r),
        modified = clone(report);
      modified.tests[1].result = result;
      rr.grants[0].reportSHA256 = digest(modified);
      await assert.rejects(
        checkMark(rr, 'synthetic-grant', modified, dir, { now }),
        /MARK_(?:REQUIRED|NONPASSING)_RESULT/,
      );
    }
    const rr = clone(r),
      missing = clone(report);
    missing.tests.pop();
    rr.grants[0].reportSHA256 = digest(missing);
    await assert.rejects(
      checkMark(rr, 'synthetic-grant', missing, dir, { now }),
      /MARK_REQUIRED_RESULT/,
    );
    await writeFile(join(dir, 'result.txt'), 'modified');
    await assert.rejects(
      checkMark(r, 'synthetic-grant', report, dir, { now }),
      /ASSESSMENT_ARTIFACT_DIGEST/,
    );
  } finally {
    await rm(join(dir, 'result.txt'), { force: true });
    await rmdir(dir);
  }
});
test('mark lifecycle and assessor scope cannot be inferred from passing results', async () => {
  const { r, report, dir } = await markFixture();
  try {
    await assert.rejects(
      checkMark(r, 'synthetic-grant', report, dir, { now: Date.parse(r.grants[0].validUntil) }),
      /MARK_GRANT_INACTIVE/,
    );
    const rr = clone(r);
    rr.marks[0].events.push({ ...event, at: '2026-03-01T00:00:00.000Z', state: 'SUSPENDED' });
    await assert.rejects(checkMark(rr, 'synthetic-grant', report, dir, { now }), /MARK_AUTHORITY/);
    rr.marks[0].events.pop();
    rr.plans[0].assessors = ['another-assessor'];
    await assert.rejects(
      checkMark(rr, 'synthetic-grant', report, dir, { now }),
      /MARK_ASSESSMENT_SCOPE/,
    );
    rr.plans[0].assessors = [report.assessor];
    rr.grants[0].events.push({ ...event, at: '2026-03-01T00:00:00.000Z', state: 'REVOKED' });
    await assert.rejects(
      checkMark(rr, 'synthetic-grant', report, dir, { now }),
      /MARK_GRANT_INACTIVE/,
    );
    rr.grants[0].events.push({ ...event, at: '2026-03-02T00:00:00.000Z' });
    assert.throws(() => validateRegistry(rr), /REGISTRY_EVENT/);
  } finally {
    await rm(join(dir, 'result.txt'), { force: true });
    await rmdir(dir);
  }
});
test('registry updates preserve previous instruments and cannot erase withdrawal', () => {
  const { r } = fixture(),
    next = clone(r);
  next.agreements[0].specification.sha256 = 'd'.repeat(64);
  assert.throws(() => validateTransition(r, next), /REGISTRY_HISTORY_REWRITE/);
  next.agreements = [];
  assert.throws(() => validateTransition(r, next));
  const withdrawn = clone(r);
  withdrawn.contributions[0].withdrawnAt = '2026-01-02T00:00:00.000Z';
  withdrawn.contributions[0].withdrawalNotice = ref;
  withdrawn.contributions[0].review = { ...review, reviewedAt: '2026-01-03T00:00:00.000Z' };
  assert.equal(validateTransition(r, withdrawn).transition, 'VALID');
  assert.throws(() => validateTransition(withdrawn, r), /REGISTRY_HISTORY_REWRITE/);
});
test('governance CLI runs without installed dependencies and invents no grants', () => {
  const result = spawnSync(
    process.execPath,
    ['governance/cli.mjs', 'validate', 'governance/registry.json'],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { structure: 'VALID', agreements: 0, markGrants: 0 });
});

test('specification snapshots bind the selected composition without importing RRA into alternatives', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'certconcord-snapshot-'));
  const names = [
    'selection.json',
    'rra.json',
    'alternative.json',
    'missing.json',
    'framework.md',
    'composition.md',
    'assessment.md',
  ];
  const run = (source, output) =>
    spawnSync(
      process.execPath,
      ['governance/cli.mjs', 'snapshot', join(dir, 'selection.json'), source, join(dir, output)],
      { encoding: 'utf8' },
    );
  const selection = {
    name: 'CertConcord',
    edition: 'synthetic-test',
    sourceCommit: '0'.repeat(40),
    roles: ['VERIFIER'],
    profiles: [],
    adapters: [],
    framework: { edition: 'draft-02', document: 'spec/architecture.md' },
    composition: {
      id: 'certconcord-governed-draft-02',
      specification: 'spec/bindings/DTI-draft-02.md',
      conformance: 'spec/conformance.md',
    },
    requiredPortions: [
      'spec/architecture.md',
      'spec/bindings/DTI-draft-02.md',
      'spec/conformance.md',
    ].map((path) => ({ path, sections: ['all'] })),
  };
  const save = () => writeFile(join(dir, 'selection.json'), JSON.stringify(selection));
  try {
    await save();
    assert.match(run('..', 'missing.json').stderr, /SPECIFICATION_REQUIRED_PORTIONS/);
    selection.requiredPortions.push({
      path: 'spec/bindings/COMMON-draft-02.md',
      sections: ['all'],
    });
    await save();
    const rra = run('..', 'rra.json');
    assert.equal(rra.status, 0, rra.stderr);
    assert.equal(JSON.parse(rra.stdout).authority, 'REQUIRES_SCOPE_REVIEW_AND_EXECUTED_AGREEMENT');
    selection.composition.conformance = 'README.md';
    await save();
    assert.match(run('..', 'missing.json').stderr, /SPECIFICATION_COMPOSITION/);

    for (const name of ['framework.md', 'composition.md', 'assessment.md'])
      await writeFile(join(dir, name), '# Synthetic ' + name + '\n');
    selection.framework = { edition: 'synthetic-test', document: 'framework.md' };
    selection.composition = {
      id: 'urn:example:synthetic-composition:1',
      specification: 'composition.md',
      conformance: 'assessment.md',
    };
    selection.requiredPortions = ['framework.md', 'composition.md', 'assessment.md'].map(
      (path) => ({ path, sections: ['all'] }),
    );
    await save();
    const alternative = run(dir, 'alternative.json');
    assert.equal(alternative.status, 0, alternative.stderr);
    const snapshot = JSON.parse(await readFile(join(dir, 'alternative.json'), 'utf8'));
    assert.equal(snapshot.composition.id, selection.composition.id);
    assert.deepEqual(snapshot.requiredPortions.map((p) => p.path).sort(), [
      'assessment.md',
      'composition.md',
      'framework.md',
    ]);
    for (const portion of snapshot.requiredPortions)
      assert.equal(portion.sha256, byteDigest(await readFile(join(dir, portion.path))));
    assert.equal(JSON.parse(alternative.stdout).snapshotDigest, digest(snapshot));
    assert.notEqual(run(dir, 'alternative.json').status, 0);
    selection.requiredPortions.pop();
    await save();
    assert.match(run(dir, 'missing.json').stderr, /SPECIFICATION_REQUIRED_PORTIONS/);
  } finally {
    for (const name of names) await rm(join(dir, name), { force: true });
    await rmdir(dir);
  }
});
