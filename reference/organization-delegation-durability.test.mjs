import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as c from './core.mjs';
import { issueExecutionBinding } from './execution-binding.mjs';
import { OrganizationDelegationApplication } from './organization-delegation.mjs';
import { createOrganizationFixture } from './organization-delegation-fixtures.mjs';

function valid(result) {
  assert.equal(result.overall, 'VALID', JSON.stringify(result.checks));
  return result;
}
function noOutput(result, expected) {
  assert.equal(result.overall, expected, JSON.stringify(result.checks));
  for (const field of ['authorization', 'permit', 'signature', 'receipt', 'cms', 'bundle'])
    assert.equal(Object.hasOwn(result, field), false);
  return result;
}
function authorize(f, app) {
  const prepared = valid(app.prepare(f.prepareInput()));
  f.persons.forEach((person, i) =>
    valid(
      app.approve({
        operationID: f.operationID,
        personID: person.body.personID,
        ...f.assertion(prepared.request, i),
      }),
    ),
  );
  return valid(app.authorize({ operationID: f.operationID }));
}
async function crash(args, seam) {
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL('./organization-delegation-crash-child.mjs', import.meta.url)), ...args],
    { stdio: ['ignore', 'pipe', 'pipe'], env: process.env },
  );
  let stdout = '',
    stderr = '',
    reached = false;
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
    if (stdout.includes(JSON.stringify({ seam }))) {
      reached = true;
      child.kill('SIGKILL');
    }
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });
  const result = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  }).finally(() => clearTimeout(timer));
  assert.equal(reached, true, stdout + stderr);
  assert.equal(result.signal, 'SIGKILL');
}

test('organization actual process death rolls back counter and approval as one SQLite transaction', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'org-approval-crash-'));
  const database = join(dir, 'journal.sqlite'),
    snapshot = join(dir, 'fixture.cbor');
  let f = createOrganizationFixture({ path: database });
  try {
    let app = new OrganizationDelegationApplication(f.applicationOptions);
    const original = valid(app.prepare(f.prepareInput()));
    writeFileSync(snapshot, f.snapshot());
    f.close();
    f = null;
    await crash(
      ['approval-transaction', snapshot, database, join(dir, 'candidate'), join(dir, 'effects')],
      'counter-written-before-commit',
    );
    f = createOrganizationFixture({ snapshot: readFileSync(snapshot), path: database });
    app = new OrganizationDelegationApplication(f.applicationOptions);
    const retained = app.getOperationResult({ operationID: f.operationID });
    assert.equal(retained.record.approvals.length, 0);
    assert.equal(retained.record.serverNonceConsumed, false);
    assert.equal(f.journal.list('organization-delegation-counter').length, 0);
    assert.deepEqual(c.dcbor(retained.record.request), c.dcbor(original.request));
    valid(
      app.approve({
        operationID: f.operationID,
        personID: f.persons[0].body.personID,
        ...f.assertion(original.request, 0, { counter: 7 }),
      }),
    );
    assert.equal(
      app.getOperationResult({ operationID: f.operationID }).record.approvals[0].counterBefore,
      0,
    );
    assert.equal(f.calls.sign, 0);
  } finally {
    f?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('organization actual process death after signing reconciles exact bytes without another private action', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'org-signature-crash-'));
  const database = join(dir, 'journal.sqlite'),
    snapshot = join(dir, 'fixture.cbor'),
    candidate = join(dir, 'candidate.bin'),
    effects = join(dir, 'effects.txt');
  let f = createOrganizationFixture({ path: database });
  try {
    let app = new OrganizationDelegationApplication(f.applicationOptions);
    authorize(f, app);
    writeFileSync(snapshot, f.snapshot());
    f.close();
    f = null;
    await crash(
      ['after-signature', snapshot, database, candidate, effects],
      'document-signed-before-completion',
    );
    assert.equal(readFileSync(effects, 'utf8'), 'document-sign\n');
    f = createOrganizationFixture({ snapshot: readFileSync(snapshot), path: database });
    app = new OrganizationDelegationApplication(f.applicationOptions);
    assert.equal(
      app.getOperationResult({ operationID: f.operationID }).originalStatus,
      'UNKNOWN_EXECUTION',
    );
    noOutput(await app.execute({ operationID: f.operationID }), 'INDETERMINATE');
    assert.equal(f.calls.sign, 0);
    const signature = readFileSync(candidate),
      recovered = valid(await app.reconcile({ operationID: f.operationID, signature }));
    assert.deepEqual(recovered.signature, signature);
    assert.equal(f.calls.sign, 0);
    assert.equal(readFileSync(effects, 'utf8'), 'document-sign\n');
    f.advance(121);
    const retained = app.getOperationResult({ operationID: f.operationID });
    assert.equal(retained.status, 'RETRIEVED');
    assert.equal(retained.originalStatus, 'COMPLETED');
    assert.equal(retained.admission, 'NOT_REEVALUATED');
    assert.equal(Object.hasOwn(retained, 'overall'), false);
    noOutput(await app.reconcile({ operationID: f.operationID, signature }), 'INVALID');
    assert.equal(f.calls.sign, 0);
  } finally {
    f?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('organization package commit rollback leaves COMPLETED retrievable and does not repeat signing', async () => {
  const f = createOrganizationFixture();
  let failPackage = true;
  try {
    const put = f.journal.put;
    f.journal.put = function (namespace, id, value, revision) {
      if (failPackage && namespace === 'organization-delegation-operation' && value.bundle)
        throw new Error('package storage unavailable');
      return put.call(this, namespace, id, value, revision);
    };
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    authorize(f, app);
    const pending = noOutput(await app.execute({ operationID: f.operationID }), 'INDETERMINATE');
    assert.equal(pending.status, 'OUTPUT_PENDING');
    assert.equal(pending.executionStatus, 'COMPLETED');
    assert.equal(pending.reason, 'ORG_PACKAGE_PERSISTENCE_UNAVAILABLE');
    assert.equal(f.calls.sign, 1);
    const stored = app.getOperationResult({ operationID: f.operationID });
    assert.equal(stored.originalStatus, 'COMPLETED');
    assert.equal(Object.hasOwn(stored.record, 'bundle'), false);
    const signature = c.decodeCBOR(f.journal.result(c.b64u(f.operationID)).result).signature;
    failPackage = false;
    valid(await app.reconcile({ operationID: f.operationID, signature }));
    assert.equal(f.calls.sign, 1);
  } finally {
    f.close();
  }
});

test('organization final application admission withholds an already committed gateway result', async () => {
  const f = createOrganizationFixture();
  try {
    for (const method of ['complete', 'reconcile']) {
      const original = f.journal[method];
      f.journal[method] = function (...args) {
        const result = original.apply(this, args);
        queueMicrotask(() => {
          f.context.operator.active = false;
        });
        return result;
      };
    }
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    authorize(f, app);
    const withheld = noOutput(await app.execute({ operationID: f.operationID }), 'INVALID');
    assert.equal(withheld.status, 'OUTPUT_WITHHELD');
    assert.equal(withheld.executionStatus, 'COMPLETED');
    assert.equal(withheld.effectMayHaveOccurred, true);
    assert.equal(f.calls.sign, 1);
    assert.equal(
      app.getOperationResult({ operationID: f.operationID }).originalStatus,
      'COMPLETED',
    );
  } finally {
    f.close();
  }
});

test('organization retrieval after restart uses stored scope without reading unavailable current context', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'org-retrieve-')),
    database = join(dir, 'journal.sqlite');
  let f = createOrganizationFixture({ path: database });
  try {
    let app = new OrganizationDelegationApplication(f.applicationOptions);
    authorize(f, app);
    const result = valid(await app.execute({ operationID: f.operationID }));
    const snapshot = f.snapshot();
    f.close();
    f = null;
    f = createOrganizationFixture({ snapshot, path: database });
    f.advance(121);
    f.context.operator.active = false;
    app = new OrganizationDelegationApplication(f.applicationOptions);
    f.hooks.context = () => {
      throw new Error('current source unavailable');
    };
    const stored = app.getOperationResult({ operationID: f.operationID });
    assert.equal(stored.admission, 'NOT_REEVALUATED');
    assert.equal(stored.originalStatus, 'COMPLETED');
    assert.deepEqual(stored.record.bundle, result.bundle);
    assert.equal(f.calls.sign, 0);
  } finally {
    f?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('organization retains the earliest effective revocation through later heads and an actual restart', () => {
  const dir = mkdtempSync(join(tmpdir(), 'org-revocation-')),
    database = join(dir, 'journal.sqlite');
  let f = createOrganizationFixture({ path: database });
  try {
    let app = new OrganizationDelegationApplication(f.applicationOptions);
    const tails = f.context.statusMaterial.slice(1);
    f.context.statusMaterial = [
      f.status('GRANT', f.grants[0], {
        epoch: 2,
        status: 'REVOKED',
        effectiveTime: f.at - 1,
        compromiseStart: f.at + 5000,
      }),
      f.status('GRANT', f.grants[0], {
        epoch: 3,
        status: 'REVOKED',
        effectiveTime: f.at + 2000,
        compromiseStart: f.at + 3000,
      }),
      f.status('GRANT', f.grants[0], {
        epoch: 4,
        status: 'REVOKED',
        effectiveTime: f.at + 3000,
        compromiseStart: f.at + 4000,
      }),
      ...tails,
    ];
    noOutput(app.prepare(f.prepareInput()), 'INVALID');
    f.context.statusMaterial = [f.status('GRANT', f.grants[0], { epoch: 5 }), ...tails];
    const snapshot = f.snapshot();
    f.close();
    f = null;
    f = createOrganizationFixture({ snapshot, path: database });
    app = new OrganizationDelegationApplication(f.applicationOptions);
    noOutput(app.prepare(f.prepareInput()), 'INVALID');
    assert.equal(f.calls.sign, 0);
  } finally {
    f?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('organization optional compromiseStart on GOOD cannot create a key incident across restart', () => {
  const dir = mkdtempSync(join(tmpdir(), 'org-good-status-')),
    database = join(dir, 'journal.sqlite');
  let f = createOrganizationFixture({ path: database });
  try {
    f.context.statusMaterial[0] = f.status('GRANT', f.grants[0], { compromiseStart: f.at - 1 });
    let app = new OrganizationDelegationApplication(f.applicationOptions);
    valid(app.prepare(f.prepareInput()));
    assert.equal(f.journal.list('organization-delegation-key-incident').length, 0);
    const snapshot = f.snapshot();
    f.close();
    f = null;
    f = createOrganizationFixture({ snapshot, path: database });
    app = new OrganizationDelegationApplication(f.applicationOptions);
    valid(app.prepare(f.prepareInput()));
    assert.equal(f.journal.list('organization-delegation-key-incident').length, 0);
    assert.equal(f.calls.sign, 0);
  } finally {
    f?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('organization retains a newly learned lower-epoch revoked execution head through restart', () => {
  const dir = mkdtempSync(join(tmpdir(), 'org-execution-revocation-'));
  const database = join(dir, 'journal.sqlite');
  let f = createOrganizationFixture({ path: database });
  try {
    const active = issueExecutionBinding({ ...f.bindingBody, epoch: 5 }, f.keys.binding);
    f.context.executionCurrent.binding = active;
    let app = new OrganizationDelegationApplication(f.applicationOptions);
    valid(app.prepare(f.prepareInput()));
    f.context.executionCurrent.binding = issueExecutionBinding(
      { ...f.bindingBody, epoch: 4, status: 'REVOKED' },
      f.keys.binding,
    );
    noOutput(app.prepare(f.prepareInput()), 'INVALID');
    f.context.executionCurrent.binding = active;
    const snapshot = f.snapshot();
    f.close();
    f = null;
    f = createOrganizationFixture({ snapshot, path: database });
    app = new OrganizationDelegationApplication(f.applicationOptions);
    noOutput(app.prepare(f.prepareInput()), 'INVALID');
    assert.equal(f.calls.sign, 0);
  } finally {
    f?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

for (const boundary of ['capabilities', 'after signature']) {
  test(`organization unknown backend failure at ${boundary} is unavailable with no new output`, async () => {
    const f = createOrganizationFixture();
    try {
      const app = new OrganizationDelegationApplication(f.applicationOptions);
      authorize(f, app);
      const unavailable = () => {
        throw new Error('backend unavailable');
      };
      if (boundary === 'capabilities') f.hooks.capabilities = unavailable;
      else f.hooks.afterSign = unavailable;
      const result = noOutput(await app.execute({ operationID: f.operationID }), 'INDETERMINATE');
      assert.equal(result.effectMayHaveOccurred, boundary === 'after signature');
      assert.equal(f.calls.sign, boundary === 'after signature' ? 1 : 0);
      if (boundary === 'after signature') assert.equal(result.status, 'UNKNOWN_EXECUTION');
    } finally {
      f.close();
    }
  });
}

for (const field of ['issuerID', 'controlTrust', 'credentialTrust']) {
  test(`organization changed immutable ${field} cannot retrieve an existing operation after restart`, () => {
    const dir = mkdtempSync(join(tmpdir(), 'org-config-restart-'));
    const database = join(dir, 'journal.sqlite');
    let f = createOrganizationFixture({ path: database });
    try {
      let app = new OrganizationDelegationApplication(f.applicationOptions);
      valid(app.prepare(f.prepareInput()));
      const snapshot = f.snapshot();
      f.close();
      f = null;
      f = createOrganizationFixture({ snapshot, path: database });
      if (field === 'issuerID') {
        f.context.issuerID = 'replacement-issuer';
        f.context.controlTrust.forEach((entry) => {
          entry.issuerID = f.context.issuerID;
        });
      } else if (field === 'controlTrust') {
        const entry = f.context.controlTrust.find(
          (value) => value.purpose === 'ORGANIZATION_DELEGATION_STATUS',
        );
        entry.objectTypes = ['GRANT', 'FINAL_AUTHORIZATION'];
      } else {
        f.context.credentialTrust.statusCertificate = f.keys.registrar.certificate;
      }
      app = new OrganizationDelegationApplication(f.applicationOptions);
      assert.throws(() => app.getOperationResult({ operationID: f.operationID }), {
        code: 'ORG_OPERATION_BINDING',
      });
      assert.equal(f.calls.sign, 0);
    } finally {
      f?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
