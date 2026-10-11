import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as immediate } from 'node:timers/promises';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, readControl } from './state.mjs';
import { createEvidencePackage, evidenceLeaf } from './evidence-plan.mjs';
import {
  OrganizationDelegationApplication,
  OrganizationDelegationVerifier,
} from './organization-delegation.mjs';
import {
  copy,
  createOrganizationFixture,
  ORGANIZATION_PLAN,
} from './organization-delegation-fixtures.mjs';

const accepted = (result, status) => {
  assert.equal(result.overall, 'VALID', JSON.stringify(result.checks));
  if (status) assert.equal(result.status, status);
  return result;
};
const rejected = (result, overall) => {
  if (overall) assert.equal(result.overall, overall, JSON.stringify(result.checks));
  else assert.notEqual(result.overall, 'VALID');
  for (const key of [
    'authorization',
    'authorizationStatus',
    'permit',
    'signature',
    'receipt',
    'cms',
    'bundle',
  ])
    assert.equal(Object.hasOwn(result, key), false, `Failure exposed ${key}`);
  return result;
};
function prepareAndApprove(f, app, input = f.prepareInput(), counter = 1) {
  const prepared = accepted(app.prepare(input), 'PREPARED');
  assert.equal(prepared.claim, 'PREPARATION_ONLY');
  for (let i = 0; i < f.persons.length; i++) {
    const approved = accepted(
      app.approve({
        operationID: input.operationID,
        personID: f.persons[i].body.personID,
        ...f.assertion(prepared.request, i, { counter }),
      }),
      'APPROVAL_RECORDED',
    );
    assert.equal(approved.acceptedCount, i + 1);
    assert.equal(approved.claim, 'APPROVAL_RECORD_ONLY');
  }
  return prepared;
}
function authorize(f, app) {
  const prepared = prepareAndApprove(f, app);
  const authorization = accepted(app.authorize({ operationID: f.operationID }), 'AUTHORIZED');
  assert.equal(f.calls.sign, 0);
  return { prepared, authorization };
}
function verifier(f, journal = new Journal()) {
  return {
    journal,
    value: new OrganizationDelegationVerifier({ journal, readContext: f.readContext }),
  };
}

test('organization application produces one real signature and independently verifies original flat evidence', async () => {
  const f = createOrganizationFixture(),
    independent = verifier(f);
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    const originalPath = f.pathBytes(),
      originalRegistrations = copy(f.registrations);
    const { prepared, authorization } = authorize(f, app);
    const result = accepted(await app.execute({ operationID: f.operationID }), 'COMPLETED');
    assert.equal(result.claim, 'CURRENT_EXECUTION');
    assert.equal(f.calls.sign, 1);
    assert(Buffer.isBuffer(result.bundle));
    const bundle = c.decodeCBOR(result.bundle),
      values = Object.fromEntries(bundle.objects.map((v) => [v.type, v.payload]));
    assert.equal(bundle.plan.profile, ORGANIZATION_PLAN);
    assert.deepEqual(values.OrganizationDelegationPath, originalPath);
    const set = c.decodeCBOR(values.OrganizationApprovalSet);
    assert.deepEqual(c.dcbor(set.request), c.dcbor(prepared.request));
    assert.equal(set.approvals.length, 2);
    set.approvals.forEach((entry, i) =>
      assert.deepEqual(entry.registrationCMS, originalRegistrations[i].cms),
    );
    const oa = readControl(
      values.OrganizationAuthorization,
      'OrganizationAuthorization',
      f.keys.terminal.certificate,
    );
    assert.deepEqual(oa.delegationPathLeafID, bundle.plan.objects.OrganizationDelegationPath);
    assert.deepEqual(oa.approvalSetLeafID, bundle.plan.objects.OrganizationApprovalSet);
    assert.deepEqual(values.OrganizationAuthorization, authorization.authorization);
    const signed = p.verifyCMS(values.CMS, {
      content: f.document,
      expectedCertificate: f.keys.seal.certificate,
    });
    assert.deepEqual(signed.signature, result.signature);
    const checked = accepted(independent.value.verify({ bundle: result.bundle }));
    assert.equal(checked.mode, 'CURRENT_STATE_ONLY');
    assert.equal(checked.pathLength, 2);
    assert.deepEqual(
      checked.admittedPersonIDs,
      f.persons.map((v) => v.body.personID),
    );
    assert(checked.limitations.includes('SIGNED_REGISTRATION_COUNTER_BASELINE_ONLY'));
  } finally {
    independent.journal.close();
    f.close();
  }
});

test('organization cached preparation preserves original nonces and times while applying current admission', () => {
  const f = createOrganizationFixture();
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions),
      input = f.prepareInput();
    const first = accepted(app.prepare(input), 'PREPARED');
    f.advance(1);
    const next = accepted(app.prepare(input), 'PREPARED');
    assert.deepEqual(next.request, first.request);
    assert.deepEqual(next.activation, first.activation);
    assert.deepEqual(next.challenges, first.challenges);
    f.context.operator.active = false;
    rejected(app.prepare(input), 'INVALID');
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

test('organization preparation rejects changing document bytes under the same operation ID', () => {
  const f = createOrganizationFixture();
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions),
      input = f.prepareInput();
    accepted(app.prepare(input));
    input.document[0] ^= 1;
    rejected(app.prepare(input), 'INVALID');
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

test('organization incomplete quorum never releases final control material', () => {
  const f = createOrganizationFixture();
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    const prepared = accepted(app.prepare(f.prepareInput()));
    accepted(
      app.approve({
        operationID: f.operationID,
        personID: f.persons[0].body.personID,
        ...f.assertion(prepared.request),
      }),
    );
    rejected(app.authorize({ operationID: f.operationID }), 'INDETERMINATE');
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

test('organization repeated approval consumes one nonce and preserves original counterBefore for authorization', () => {
  const f = createOrganizationFixture();
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    const prepared = accepted(app.prepare(f.prepareInput()));
    const first = {
      operationID: f.operationID,
      personID: f.persons[0].body.personID,
      ...f.assertion(prepared.request, 0, { counter: 7 }),
    };
    const one = accepted(app.approve(first));
    const replay = accepted(app.approve(first));
    assert.equal(one.acceptedCount, 1);
    assert.equal(replay.acceptedCount, 1);
    rejected(
      app.approve({ ...first, ...f.assertion(prepared.request, 0, { counter: 8 }) }),
      'INVALID',
    );
    accepted(
      app.approve({
        operationID: f.operationID,
        personID: f.persons[1].body.personID,
        ...f.assertion(prepared.request, 1, { counter: 7 }),
      }),
    );
    accepted(app.authorize({ operationID: f.operationID }));
    const stored = app.getOperationResult({ operationID: f.operationID });
    assert.deepEqual(
      stored.record.approvals.map((v) => [v.counterBefore, v.counterAfter]),
      [
        [0, 7],
        [0, 7],
      ],
    );
    assert.equal(stored.record.serverNonceConsumed, true);
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

test('organization cannot authorize two operation bodies with one immutable authorization ID', () => {
  const f = createOrganizationFixture();
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    authorize(f, app);
    const other = f.prepareInput();
    other.operationID = c.random();
    prepareAndApprove(f, app, other, 2);
    const denied = rejected(app.authorize({ operationID: other.operationID }), 'INVALID');
    assert.equal(denied.effectMayHaveOccurred, false);
    const record = app.getOperationResult({ operationID: other.operationID });
    assert.equal(Object.hasOwn(record.record, 'authorization'), false);
    assert.equal(Object.hasOwn(record.record, 'permit'), false);
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

test('organization accepts separate object-type mappings for the same status certificate', () => {
  const f = createOrganizationFixture();
  try {
    const entry = f.context.controlTrust.find(
      (v) => v.purpose === 'ORGANIZATION_DELEGATION_STATUS',
    );
    f.context.controlTrust = f.context.controlTrust.filter((v) => v !== entry);
    for (const objectType of ['GRANT', 'APPROVER_REGISTRATION', 'FINAL_AUTHORIZATION'])
      f.context.controlTrust.push({ ...copy(entry), objectTypes: [objectType] });
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    authorize(f, app);
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

for (const method of ['execute', 'reconcile', 'getOperationResult']) {
  test(`organization ${method} does not inspect another scope's global execution row`, async () => {
    const f = createOrganizationFixture();
    let globalQueries = 0;
    try {
      const original = f.journal.result.bind(f.journal);
      f.journal.result = (id) => {
        globalQueries++;
        if (id === c.b64u(f.operationID))
          return { status: 'COMPLETED', result: c.dcbor({ secret: true }) };
        return original(id);
      };
      const app = new OrganizationDelegationApplication(f.applicationOptions);
      const result = await app[method]({
        operationID: f.operationID,
        ...(method === 'reconcile'
          ? { signature: c.sign(f.prepared.tbs, f.keys.seal.privateKey) }
          : {}),
      });
      if (method === 'getOperationResult') assert.equal(result, null);
      else {
        rejected(result);
        assert.equal(result.effectMayHaveOccurred, false);
        assert.notEqual(result.status, 'OUTPUT_WITHHELD');
        assert.equal(Object.hasOwn(result, 'executionStatus'), false);
      }
      assert.equal(globalQueries, 0);
      assert.equal(f.calls.sign, 0);
    } finally {
      f.close();
    }
  });
}

for (const phase of ['capabilities', 'signature return']) {
  test(`organization applies current withdrawal after ${phase} without releasing a new output`, async () => {
    const f = createOrganizationFixture();
    try {
      const app = new OrganizationDelegationApplication(f.applicationOptions);
      authorize(f, app);
      const withdraw = async () => {
        await immediate();
        f.context.operator.active = false;
      };
      if (phase === 'capabilities') f.hooks.capabilities = withdraw;
      else f.hooks.afterSign = withdraw;
      rejected(await app.execute({ operationID: f.operationID }), 'INVALID');
      assert.equal(f.calls.sign, phase === 'capabilities' ? 0 : 1);
    } finally {
      f.close();
    }
  });
}

for (const method of ['execute', 'reconcile']) {
  test(`organization cached ${method} keeps COMPLETED while withholding output after withdrawal`, async () => {
    const f = createOrganizationFixture();
    try {
      const app = new OrganizationDelegationApplication(f.applicationOptions);
      authorize(f, app);
      const first = accepted(await app.execute({ operationID: f.operationID }));
      f.context.operator.active = false;
      const denied = rejected(
        await app[method]({
          operationID: f.operationID,
          ...(method === 'reconcile' ? { signature: first.signature } : {}),
        }),
        'INVALID',
      );
      assert.equal(denied.status, 'OUTPUT_WITHHELD');
      assert.equal(denied.executionStatus, 'COMPLETED');
      assert.equal(denied.effectMayHaveOccurred, true);
      assert.equal(f.calls.sign, 1);
      const record = app.getOperationResult({ operationID: f.operationID });
      assert.equal(record.originalStatus, 'COMPLETED');
      assert.equal(record.admission, 'NOT_REEVALUATED');
      assert.equal(Object.hasOwn(record, 'overall'), false);
    } finally {
      f.close();
    }
  });
}

test('organization pins the resolver identity while allowing its fixed state to revoke permission', () => {
  const f = createOrganizationFixture();
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    const input = f.prepareInput();
    accepted(app.prepare(input));
    f.context.authorityResolver = () => ({ overall: 'VALID', reason: 'REPLACEMENT' });
    rejected(app.prepare(input), 'INVALID');
    f.context.authorityResolver = f.authorityResolver;
    f.hooks.authority = () => ({ overall: 'INVALID', reason: 'AUTHORITY_REVOKED' });
    rejected(app.prepare(input), 'INVALID');
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

for (const leaf of [
  'OrganizationDelegationPath',
  'OrganizationApprovalSet',
  'OrganizationDelegationStatus',
]) {
  test(`organization retained verification requires the independent ${leaf} leaf`, async () => {
    const f = createOrganizationFixture(),
      independent = verifier(f);
    try {
      const app = new OrganizationDelegationApplication(f.applicationOptions);
      authorize(f, app);
      const result = accepted(await app.execute({ operationID: f.operationID }));
      const bundle = c.decodeCBOR(result.bundle);
      const partial = createEvidencePackage(
        ORGANIZATION_PLAN,
        bundle.objects.filter((v) => v.type !== leaf),
      );
      rejected(independent.value.verify({ bundle: c.dcbor(partial) }), 'INDETERMINATE');
      const substituted = bundle.objects.map((v) =>
        v.type === leaf ? evidenceLeaf(v.type, Buffer.from('substitution')) : v,
      );
      rejected(
        independent.value.verify({
          bundle: c.dcbor(createEvidencePackage(ORGANIZATION_PLAN, substituted)),
        }),
        'INVALID',
      );
    } finally {
      independent.journal.close();
      f.close();
    }
  });
}

test('organization retained verification rejects a legacy plan instead of bypassing new raw approvals', async () => {
  const f = createOrganizationFixture(),
    independent = verifier(f);
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    authorize(f, app);
    const result = accepted(await app.execute({ operationID: f.operationID }));
    const bundle = c.decodeCBOR(result.bundle);
    bundle.plan.profile = 'certconcord-ecp-cms-execution-v1';
    rejected(independent.value.verify({ bundle: c.dcbor(bundle) }), 'INVALID');
  } finally {
    independent.journal.close();
    f.close();
  }
});

test('organization retained bad CMS mathematics dominates unavailable current context', async () => {
  const f = createOrganizationFixture(),
    independent = verifier(f);
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    authorize(f, app);
    const result = accepted(await app.execute({ operationID: f.operationID }));
    const bundle = c.decodeCBOR(result.bundle);
    const objects = bundle.objects.map((v) => {
      if (v.type !== 'CMS') return v;
      const payload = Buffer.from(v.payload);
      payload[payload.length - 1] ^= 1;
      return evidenceLeaf(v.type, payload);
    });
    f.hooks.context = () => {
      throw new Error('offline');
    };
    rejected(
      independent.value.verify({
        bundle: c.dcbor(createEvidencePackage(ORGANIZATION_PLAN, objects)),
      }),
      'INVALID',
    );
  } finally {
    independent.journal.close();
    f.close();
  }
});

test('organization retained missing evidence and unknown version cannot conceal available bad mathematics', async () => {
  const f = createOrganizationFixture(),
    independent = verifier(f);
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    authorize(f, app);
    const completed = accepted(await app.execute({ operationID: f.operationID }));
    const original = c.decodeCBOR(completed.bundle);
    for (const leaf of original.objects) {
      const missing = createEvidencePackage(
        ORGANIZATION_PLAN,
        original.objects.filter((value) => value.type !== leaf.type),
      );
      const result = independent.value.verify({ bundle: c.dcbor(missing) });
      assert.equal(
        result.overall,
        'INDETERMINATE',
        `${leaf.type}: ${JSON.stringify(result.checks)}`,
      );
    }
    const missing = createEvidencePackage(
      ORGANIZATION_PLAN,
      original.objects.filter((value) => value.type !== 'OrganizationDelegationPath'),
    );
    for (const key of ['schemaVersion', 'plan']) {
      const unknown = copy(missing);
      if (key === 'plan') unknown.plan.schemaVersion = 3;
      else unknown.schemaVersion = 3;
      rejected(independent.value.verify({ bundle: c.dcbor(unknown) }), 'UNSUPPORTED');
    }
    const damaged = missing.objects.map((value) => {
      if (value.type !== 'CMS') return value;
      const payload = Buffer.from(value.payload);
      payload[payload.length - 1] ^= 1;
      return evidenceLeaf(value.type, payload);
    });
    const invalid = createEvidencePackage(ORGANIZATION_PLAN, damaged);
    rejected(independent.value.verify({ bundle: c.dcbor(invalid) }), 'INVALID');
    invalid.schemaVersion = 3;
    rejected(independent.value.verify({ bundle: c.dcbor(invalid) }), 'INVALID');
  } finally {
    independent.journal.close();
    f.close();
  }
});

test('organization current knowledge cannot roll back after an admitted operation observation', () => {
  const f = createOrganizationFixture();
  try {
    const app = new OrganizationDelegationApplication(f.applicationOptions);
    accepted(app.prepare(f.prepareInput()));
    f.advance(-1);
    const result = rejected(app.prepare(f.prepareInput()), 'INDETERMINATE');
    assert.equal(result.reason, 'ORG_CLOCK_ROLLBACK');
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

for (const offset of [1, 0]) {
  test(`organization historical registration authority coverage ${offset ? 'continues beyond' : 'ends at'} actual knowledge time`, () => {
    const f = createOrganizationFixture();
    let historicalQueries = 0;
    try {
      f.hooks.authority = (query) => {
        if (
          query.role !== 'REGISTRATION_AUTHORITY' ||
          query.scope.profileID !== 'ORG-SEAL' ||
          query.stateTime >= query.knowledgeTime
        )
          return undefined;
        historicalQueries++;
        return {
          overall: 'VALID',
          reason: 'AUTHORITY_VALID',
          coverageUntil: query.knowledgeTime + offset,
        };
      };
      const app = new OrganizationDelegationApplication(f.applicationOptions);
      const result = app.prepare(f.prepareInput());
      assert(historicalQueries > 0, 'The fixture must exercise the historical RAR query');
      if (offset) accepted(result, 'PREPARED');
      else rejected(result, 'INDETERMINATE');
      assert.equal(f.calls.sign, 0);
    } finally {
      f.close();
    }
  });
}
