import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { runDemo } from '../demo.mjs';
import { runFoundationDemo } from '../foundation-demo.mjs';
import { runDocumentDemo } from '../document-demo.mjs';
import { dcbor, decodeCBOR } from '../core.mjs';
import { runDocumentVectors } from '../verify-vectors.mjs';
import { createIndependentOrganizationHistoryFixture } from '../fixtures-history-independent.mjs';
const cwd = resolve('.runtime/sdk-consumer');
const sdkPackage = JSON.parse(await readFile('sdk/package.json'));
assert.equal(sdkPackage.private, true);
await mkdir(cwd, { recursive: true });
await writeFile(cwd + '/package.json', JSON.stringify({ private: true, type: 'module' }));
const install = spawnSync(
  process.execPath,
  [
    process.env.npm_execpath,
    'install',
    '--offline',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    resolve('dist/certconcord-verifier-' + sdkPackage.version + '.tgz'),
  ],
  { cwd, encoding: 'utf8' },
);
assert.equal(install.status, 0, install.stderr);
const require = createRequire(cwd + '/package.json');
const entry = cwd + '/load.mjs';
await writeFile(entry, "export * from '@certconcord/verifier';\n");
const sdk = await import(pathToFileURL(entry));
assert.deepEqual(Object.keys(sdk).sort(), [
  'createOrganizationHistorySource',
  'createOrganizationHistoryVerifier',
  'createVerifier',
  'profiles',
]);
assert.throws(() => require.resolve('@certconcord/verifier/core.mjs'), /not defined|not exported/);
assert.throws(() => sdk.createVerifier({ format: 'CMS', trust: {} }), /SDK_TRUST/);
const publicVectors = runDocumentVectors({ createVerifier: sdk.createVerifier });
const savedHistoryReplay = spawnSync(
  process.execPath,
  [
    resolve('sdk/organization-consumer.mjs'),
    entry,
    cwd + '/node_modules/@certconcord/verifier/index.mjs',
  ],
  { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
);
assert.equal(savedHistoryReplay.status, 0, savedHistoryReplay.stderr || savedHistoryReplay.stdout);
const savedHistory = JSON.parse(savedHistoryReplay.stdout);
assert(savedHistory.cases > 0);
assert.deepEqual(savedHistory.forbiddenCalls, []);
console.log(JSON.stringify({ installedOrganizationCorpus: savedHistory }));

const preservedStatusReplay = spawnSync(
  process.execPath,
  [
    resolve('sdk/organization-consumer.mjs'),
    entry,
    cwd + '/node_modules/@certconcord/verifier/index.mjs',
    resolve('vectors/preserved-certificate-status-rar2'),
  ],
  { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, windowsHide: true },
);
assert.equal(
  preservedStatusReplay.status,
  0,
  preservedStatusReplay.stderr || preservedStatusReplay.stdout,
);
const preservedStatus = JSON.parse(preservedStatusReplay.stdout);
assert(preservedStatus.cases > 0);
assert.deepEqual(preservedStatus.forbiddenCalls, []);
assert.equal(preservedStatus.installedBundleSHA256, savedHistory.installedBundleSHA256);
console.log(JSON.stringify({ installedPreservedCertificateStatusCorpus: preservedStatus }));

const durableDirectory = await mkdtemp(cwd + '/organization-durable-');
const durableReplay = [];
for (const [phase, database] of [
  ['record-compromise', 'compromise.sqlite'],
  ['reopen-compromise', 'compromise.sqlite'],
  ['record-positive', 'positive.sqlite'],
  ['reopen-missing', 'positive.sqlite'],
]) {
  const child = spawnSync(
    process.execPath,
    [
      resolve('sdk/organization-durable-consumer.mjs'),
      entry,
      cwd + '/node_modules/@certconcord/verifier/index.mjs',
      durableDirectory + '/' + database,
      phase,
    ],
    { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
  );
  assert.equal(child.status, 0, child.stderr || child.stdout);
  const observed = JSON.parse(child.stdout);
  assert.equal(observed.phase, phase);
  assert.deepEqual(observed.forbiddenCalls, []);
  assert.equal(observed.installedBundleSHA256, savedHistory.installedBundleSHA256);
  assert.equal(observed.unchangedFiles, 201);
  durableReplay.push(observed);
}
assert.equal(new Set(durableReplay.map((row) => row.pid)).size, 4);
for (const first of [0, 2]) {
  const old = durableReplay[first].receipt,
    reopened = durableReplay[first + 1].receipt;
  for (const field of ['scopeID', 'configurationID', 'evidenceID'])
    assert.equal(reopened[field], old[field]);
  assert(reopened.revision >= old.revision);
}
console.log(JSON.stringify({ installedOrganizationDurableReplay: durableReplay }));

const preservedDurableDirectory = await mkdtemp(cwd + '/preserved-certificate-status-');
const preservedDurableReplay = [];
for (const [phase, database] of [
  ['record-compromise', 'compromise.sqlite'],
  ['reopen-compromise', 'compromise.sqlite'],
  ['record-positive', 'positive.sqlite'],
  ['reopen-missing', 'positive.sqlite'],
]) {
  const child = spawnSync(
    process.execPath,
    [
      resolve('sdk/preserved-certificate-status-consumer.mjs'),
      entry,
      cwd + '/node_modules/@certconcord/verifier/index.mjs',
      preservedDurableDirectory + '/' + database,
      phase,
    ],
    { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, windowsHide: true },
  );
  assert.equal(child.status, 0, child.stderr || child.stdout);
  const observed = JSON.parse(child.stdout);
  assert.equal(observed.phase, phase);
  assert.deepEqual(observed.forbiddenCalls, []);
  assert.equal(observed.installedBundleSHA256, preservedStatus.installedBundleSHA256);
  assert.equal(observed.unchangedFiles, preservedStatus.unchangedFiles);
  preservedDurableReplay.push(observed);
}
assert.equal(new Set(preservedDurableReplay.map((row) => row.pid)).size, 4);
for (const first of [0, 2]) {
  const old = preservedDurableReplay[first].receipt,
    reopened = preservedDurableReplay[first + 1].receipt;
  for (const field of ['scopeID', 'configurationID']) assert.equal(reopened[field], old[field]);
  assert(reopened.revision >= old.revision);
}
assert.equal(preservedDurableReplay[0].receipt.evidenceID, null);
assert.equal(
  preservedDurableReplay[3].receipt.evidenceID,
  preservedDurableReplay[2].receipt.evidenceID,
);
console.log(
  JSON.stringify({ installedPreservedCertificateStatusDurableReplay: preservedDurableReplay }),
);

const preservedDelegationReplay = spawnSync(
  process.execPath,
  [
    resolve('sdk/organization-consumer.mjs'),
    entry,
    cwd + '/node_modules/@certconcord/verifier/index.mjs',
    resolve('vectors/preserved-delegation-status-rar2'),
  ],
  { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, windowsHide: true },
);
assert.equal(
  preservedDelegationReplay.status,
  0,
  preservedDelegationReplay.stderr || preservedDelegationReplay.stdout,
);
const preservedDelegation = JSON.parse(preservedDelegationReplay.stdout);
assert.equal(preservedDelegation.cases, 50);
assert.deepEqual(preservedDelegation.forbiddenCalls, []);
assert.equal(preservedDelegation.installedBundleSHA256, savedHistory.installedBundleSHA256);
console.log(JSON.stringify({ installedPreservedDelegationStatusCorpus: preservedDelegation }));
const delegationDurableDirectory = await mkdtemp(cwd + '/preserved-delegation-status-');
const delegationDurableReplay = [];
for (const [phase, database] of [
  ['record-compromise', 'compromise.sqlite'],
  ['reopen-compromise', 'compromise.sqlite'],
  ['record-positive', 'positive.sqlite'],
  ['reopen-missing', 'positive.sqlite'],
]) {
  const child = spawnSync(
    process.execPath,
    [
      resolve('sdk/preserved-delegation-status-consumer.mjs'),
      entry,
      cwd + '/node_modules/@certconcord/verifier/index.mjs',
      delegationDurableDirectory + '/' + database,
      phase,
    ],
    { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, windowsHide: true },
  );
  assert.equal(child.status, 0, child.stderr || child.stdout);
  const observed = JSON.parse(child.stdout);
  assert.equal(observed.phase, phase);
  assert.deepEqual(observed.forbiddenCalls, []);
  assert.equal(observed.installedBundleSHA256, preservedDelegation.installedBundleSHA256);
  assert.equal(observed.unchangedFiles, preservedDelegation.unchangedFiles);
  delegationDurableReplay.push(observed);
}
assert.equal(new Set(delegationDurableReplay.map((row) => row.pid)).size, 4);
for (const first of [0, 2]) {
  const old = delegationDurableReplay[first].receipt,
    reopened = delegationDurableReplay[first + 1].receipt;
  for (const field of ['scopeID', 'configurationID', 'evidenceID'])
    assert.equal(reopened[field], old[field]);
  assert(reopened.revision >= old.revision);
}
console.log(
  JSON.stringify({ installedPreservedDelegationStatusDurableReplay: delegationDurableReplay }),
);

for (const [format, executionBinding, trustedTime = false] of [
  ['CMS', false],
  ['MDOC', false],
  ['CMS', true],
  ['MDOC', true],
  ['CMS', false, true],
  ['MDOC', false, true],
]) {
  const r =
    format === 'CMS'
      ? await runDemo({ executionBinding, trustedTime })
      : await runFoundationDemo({ executionBinding, trustedTime });
  const verifier = sdk.createVerifier({ format, trust: r.trust });
  const verified = verifier.verify(dcbor(r.bundle));
  assert.equal(verified.overall, 'VALID');
  assert.equal(verified.coreRevision, 'draft-03');
  for (const suffix of ['attested-v1', 'passkey-v1', 'execution-draft-02', 'attested-draft-02']) {
    const profile = 'certconcord-ecp-' + format.toLowerCase() + '-' + suffix;
    assert.equal(
      verifier.verify(dcbor({ ...r.bundle, plan: { ...r.bundle.plan, profile } })).overall,
      'UNSUPPORTED',
      profile,
    );
  }
  assert.equal(verifier.verify(dcbor({ ...r.bundle, schemaVersion: 1 })).overall, 'UNSUPPORTED');
  const changed = decodeCBOR(dcbor(r.bundle));
  changed.objects.find((object) => object.type === 'Document').payload[0] ^= 1;
  assert.equal(verifier.verify(dcbor(changed)).overall, 'INVALID');
  assert.equal(verifier.verify(Buffer.from('not evidence')).overall, 'INVALID');
  assert.equal(verifier.verify(dcbor({ ...r.bundle, extra: true })).overall, 'INVALID');
  const wrong = sdk.createVerifier({
    format,
    trust: { ...r.trust, trustDomainID: Buffer.alloc(32) },
  });
  assert.equal(wrong.verify(dcbor(r.bundle)).overall, 'INVALID');
}
const sealed = await runDocumentDemo();
assert.equal(
  sdk.createVerifier({ format: 'CMS', trust: sealed.trust }).verify(dcbor(sealed.bundle))
    .organizationAuthorization,
  'AUTHORITY_ATTESTED_OPERATION',
);
const history = await createIndependentOrganizationHistoryFixture({ firstAccuracyMillis: 500 });
try {
  const verifier = sdk.createOrganizationHistoryVerifier(history.options);
  const result = verifier.verify(history.input);
  assert.equal(result.overall, 'VALID', JSON.stringify(result));
  assert.equal(result.coreRevision, 'draft-03');
  assert.equal(result.purpose, 'RETAINED_EVIDENCE_VERIFICATION');
  assert.equal(result.proofOfExistenceUpperBound, history.P);
  assert.equal(result.historicalAuthorization.scope, 'AS_KNOWN_AT_PROOF_TIME');
  assert.equal(result.historicalAuthorization.knowledgeTime, history.P);
  assert.equal(result.currentAdmissibility.scope, 'HISTORICAL_EVIDENCE_UNDER_CURRENT_KNOWLEDGE');
  assert.equal(result.currentAdmissibility.knowledgeTime, history.K);
  assert.equal(result.preservation.overall, 'VALID');
  history.knowledge.statusMaterial[0] = history.organizationStatus(
    history.originalStatusMembers[0],
    {
      status: 'REVOKED',
      effectiveTime: history.A,
    },
  );
  const revoked = verifier.verify(history.input);
  assert.equal(revoked.overall, 'INVALID', revoked.reason);
  assert.equal(revoked.historicalAuthorization.overall, 'VALID');
  assert.equal(revoked.currentAdmissibility.overall, 'INVALID');
  assert.equal(history.source.calls.sign, 1);
  assert.notEqual(verifier.verify({ ...history.input, overall: 'VALID' }).overall, 'VALID');
} finally {
  history.close();
}
console.log(
  'SDK archive install, export boundary, trust binding, document evidence, execution and organization history plans passed; ' +
    publicVectors.length +
    ' public document vectors and ' +
    savedHistory.cases +
    ' saved organization history vectors reproduced through the installed package',
);
