import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as immediate } from 'node:timers/promises';
import * as c from './core.mjs';
import { readControl } from './state.mjs';
import { evidenceLeaf } from './evidence-plan.mjs';
import { issueExecutionBinding } from './execution-binding.mjs';
import {
  evaluateOrganizationRequest,
  verifyOrganizationApproval,
  verifyOrganizationApprovalSet,
  verifyOrganizationEvidence,
} from './organization-delegation-evidence.mjs';
import {
  copy,
  canonicalSet,
  createOrganizationFixture,
  emptyOrganizationState,
  signOrganizationControl,
} from './organization-delegation-fixtures.mjs';

const verdict = (result, overall) => {
  assert.equal(result.overall, overall, JSON.stringify(result.checks));
  if (overall !== 'VALID') {
    assert.equal(Object.hasOwn(result, 'facts'), false);
    assert.deepEqual(result.counterFacts, []);
  }
  return result;
};
const base = (f) => {
  const { rosterNonces, approverRegistrations, ...input } = f.pureInput();
  return input;
};
const request = (f) => verdict(evaluateOrganizationRequest(f.pureInput()), 'VALID').facts.request;
const approvalInput = (f, req = request(f), changes = {}) => ({
  ...base(f),
  approverRegistrations: copy(f.registrations),
  request: req,
  personID: f.persons[0].body.personID,
  assertion: f.assertion(req),
  counterBefore: 0,
  ...changes,
});
const setInput = (f, req = request(f)) => ({
  ...base(f),
  approvalSet: f.approvalSet(req),
  counterBaselines: { kind: 'RETAINED_REGISTRATION' },
});
const evidenceInput = (f) => {
  const input = setInput(f),
    req = c.decodeCBOR(input.approvalSet).request;
  const controls = f.finalControls(req, input.approvalSet);
  return {
    ...input,
    statusCollection: f.statusBytes([...f.context.statusMaterial, controls.authorizationStatus]),
    authorization: controls.authorization,
    permit: controls.permit,
    binding: { cms: f.binding, issuerCertificate: f.keys.binding.certificate },
    receiptCertificate: f.keys.receipt.certificate,
  };
};
const stateFrom = (result) => ({
  ...emptyOrganizationState(),
  knowledgeTime: result.knowledgeTime,
  targets: copy(result.targetObservations),
  heads: copy(result.statusObservations),
  terminalObservations: copy(result.statusObservations.filter((v) => v.status === 'REVOKED')),
  executions: copy(result.executionObservations),
  keyIncidents: result.statusObservations
    .filter((v) => v.status === 'REVOKED' && v.compromiseStart !== null)
    .map((v) => ({
      trustDomainID: v.trustDomainID,
      keyID: v.subjectKeyID,
      compromiseStart: v.compromiseStart,
      observedAt: v.observedAt,
      sourceStatusHash: v.rawHash,
      sourceObjectHash: v.objectHash,
    })),
});
const evaluate = (f, state = emptyOrganizationState()) =>
  evaluateOrganizationRequest({ ...f.pureInput(), state });
const replaceStatus = (f, changes, index = 0) => {
  f.context.statusMaterial[index] = f.status('GRANT', f.grants[index], changes);
};

test('organization evidence authenticates distinct people and three raw collection commitments', () => {
  const f = createOrganizationFixture();
  try {
    const prepared = verdict(evaluate(f), 'VALID');
    const req = prepared.facts.request;
    assert.equal(req.roster.length, 2);
    assert.deepEqual(req.pathLeafID, evidenceLeaf('OrganizationDelegationPath', f.pathBytes()).id);
    assert.deepEqual(prepared.facts.requestHash, c.H('OrganizationApprovalRequest', req));
    assert.equal(Object.hasOwn(req, 'approvalSetLeafID'), false);
    assert.equal(new Set(req.roster.map((r) => r.credentialKeyID.toString('hex'))).size, 2);
    assert.equal(new Set(req.roster.map((r) => r.personID.toString('hex'))).size, 2);
    const one = verdict(verifyOrganizationApproval(approvalInput(f, req)), 'VALID');
    assert.equal(one.counterFacts.length, 1);
    const complete = verdict(verifyOrganizationApprovalSet(setInput(f, req)), 'VALID');
    assert.equal(complete.facts.counterScope, 'SIGNED_REGISTRATION_ONLY');
    verdict(verifyOrganizationEvidence(evidenceInput(f)), 'VALID');
    assert.equal(f.calls.sign, 0);
    assert(f.queries.every((q) => q.knowledgeTime === f.at));
    assert(f.queries.some((q) => q.scope.purpose === 'ORGANIZATION_DELEGATION_ROOT'));
    assert(f.queries.some((q) => q.scope.purpose === 'ORGANIZATION_DELEGATION_ISSUE'));
    assert(f.queries.some((q) => q.scope.purpose === 'ORGANIZATION_FINAL_AUTHORIZATION'));
    assert.equal(
      f.queries.some(
        (q) =>
          c.equal(q.certificate, f.keys.terminal.certificate) &&
          q.scope.purpose === 'ORGANIZATION_DELEGATION_ISSUE',
      ),
      false,
    );
  } finally {
    f.close();
  }
});

test('organization evidence admits a new next-hop signer and strictly narrowed entitlements', () => {
  const f = createOrganizationFixture();
  try {
    f.grantRecords[0].body.entitlement.allowedOperatorIDs = canonicalSet([
      f.operatorID,
      c.random(),
    ]);
    f.grantRecords[0].body.entitlement.origins = canonicalSet([
      f.sim.origin,
      'https://unused.example',
    ]);
    f.grantRecords[1].body.validUntil -= 100;
    f.signPath();
    f.refreshStatuses();
    verdict(evaluate(f), 'VALID');
    assert.notDeepEqual(
      f.grantRecords[0].body.delegateAuthority.keyID,
      f.grantRecords[1].body.delegateAuthority.keyID,
    );
  } finally {
    f.close();
  }
});

for (const [name, mutate] of [
  [
    'operator set expansion',
    (f, child) => {
      child.entitlement.allowedOperatorIDs = canonicalSet([f.operatorID, c.random()]);
    },
  ],
  [
    'eligible person expansion',
    (_f, child) => {
      child.entitlement.eligiblePersonIDs = canonicalSet([
        ...child.entitlement.eligiblePersonIDs,
        c.random(),
      ]);
    },
  ],
  [
    'origin expansion',
    (_f, child) => {
      child.entitlement.origins = canonicalSet([
        ...child.entitlement.origins,
        'https://new.example',
      ]);
    },
  ],
  [
    'policy expansion',
    (_f, child) => {
      child.entitlement.policyHashes = canonicalSet([
        ...child.entitlement.policyHashes,
        c.random(64),
      ]);
    },
  ],
  [
    'audience expansion',
    (_f, child) => {
      child.entitlement.audiences = canonicalSet([...child.entitlement.audiences, 'new-audience']);
    },
  ],
  [
    'seal tuple expansion',
    (f, child) => {
      child.entitlement.sealKeys = canonicalSet([
        ...child.entitlement.sealKeys,
        { ...child.entitlement.sealKeys[0], keyID: c.keyID(f.keys.root.publicKey) },
      ]);
    },
  ],
  [
    'lifetime expansion',
    (f, child) => {
      child.validUntil = f.grantRecords[0].body.validUntil + 1;
    },
  ],
  [
    'delegation depth reuse',
    (f, child) => {
      child.remainingDelegations = f.grantRecords[0].body.remainingDelegations;
    },
  ],
  [
    'namespace substitution',
    (_f, child) => {
      child.identityNamespace = 'different-personnel';
    },
  ],
  [
    'organization substitution',
    (_f, child) => {
      child.organizationID = c.random();
    },
  ],
  [
    'issuer key substitution',
    (f, child) => {
      child.issuerKeyID = c.keyID(f.keys.root.publicKey);
    },
  ],
  [
    'duplicate immutable grant ID',
    (f, child) => {
      child.grantID = f.grantRecords[0].body.grantID;
    },
  ],
]) {
  test(`organization path rejects ${name} even when the selected operation itself is unchanged`, () => {
    const f = createOrganizationFixture();
    try {
      mutate(f, f.grantRecords[1].body);
      f.signPath();
      f.refreshStatuses();
      verdict(evaluate(f), 'INVALID');
    } finally {
      f.close();
    }
  });
}

test('organization path cannot reduce the inherited minimum number of people', () => {
  const f = createOrganizationFixture({ people: 3 });
  try {
    f.grantRecords[1].body.entitlement.minimumApprovers = 2;
    f.signPath();
    f.refreshStatuses();
    verdict(evaluate(f), 'INVALID');
  } finally {
    f.close();
  }
});

test('organization path cannot replace original parent CMS with a different valid parent', () => {
  const f = createOrganizationFixture();
  try {
    f.grantRecords[0].body.validUntil--;
    f.grants[0].cms = signOrganizationControl(
      'OrganizationDelegationGrant',
      f.grantRecords[0].body,
      f.keys.root,
    );
    f.refreshStatuses();
    verdict(evaluate(f), 'INVALID');
  } finally {
    f.close();
  }
});

for (const [name, mutate] of [
  [
    'same person under two registrations',
    (f) => {
      f.persons[1].body.personID = f.persons[0].body.personID;
    },
  ],
  [
    'same exact credential key under two persons',
    (f) => {
      f.persons[1].body.publicKeyDER = f.persons[0].body.publicKeyDER;
      f.persons[1].body.keyID = f.persons[0].body.keyID;
    },
  ],
  [
    'same credential ID under two persons',
    (f) => {
      f.persons[1].body.credentialID = f.persons[0].body.credentialID;
    },
  ],
  [
    'wrong explicit credential key ID',
    (f) => {
      f.persons[0].body.keyID = c.random(64);
    },
  ],
  [
    'wrong registered purpose',
    (f) => {
      f.persons[0].body.purpose = 'DOCUMENT_SIGNING';
    },
  ],
  [
    'wrong identity namespace',
    (f) => {
      f.persons[0].body.identityNamespace = 'other';
    },
  ],
  [
    'wrong registered RP',
    (f) => {
      f.persons[0].body.rpID = 'other.example';
    },
  ],
  [
    'unselected origin',
    (f) => {
      f.persons[0].body.origins = ['https://other.example'];
    },
  ],
]) {
  test(`organization roster rejects ${name}`, () => {
    const f = createOrganizationFixture();
    try {
      mutate(f);
      f.signRegistrations();
      f.refreshStatuses();
      verdict(evaluate(f), 'INVALID');
    } finally {
      f.close();
    }
  });
}

test('organization request rejects reordered registrations and duplicated challenge nonces', () => {
  const f = createOrganizationFixture();
  try {
    const input = f.pureInput();
    input.approverRegistrations.reverse();
    verdict(evaluateOrganizationRequest(input), 'INVALID');
    const duplicate = f.pureInput();
    duplicate.rosterNonces[1] = duplicate.rosterNonces[0];
    verdict(evaluateOrganizationRequest(duplicate), 'INVALID');
  } finally {
    f.close();
  }
});

for (const [name, changes] of [
  ['wrong challenge', { challenge: Buffer.alloc(64, 7) }],
  ['wrong origin', { origin: 'https://other.example' }],
  ['wrong RP', { rpID: 'other.example' }],
  ['missing UP', { flags: 4 }],
  ['missing UV', { flags: 1 }],
  ['inconsistent backup eligibility', { flags: 13 }],
  ['wrong credential ID', { credentialID: Buffer.alloc(32, 9) }],
]) {
  test(`organization approval rejects a mathematically valid assertion with ${name}`, () => {
    const f = createOrganizationFixture();
    try {
      const req = request(f);
      verdict(
        verifyOrganizationApproval(
          approvalInput(f, req, { assertion: f.assertion(req, 0, changes) }),
        ),
        'INVALID',
      );
    } finally {
      f.close();
    }
  });
}

test('organization approval preserves raw client bytes and its original explicit counter baseline', () => {
  const f = createOrganizationFixture();
  try {
    const req = request(f),
      assertion = f.assertion(req);
    const value = JSON.parse(assertion.clientDataJSON);
    const raw = Buffer.from(JSON.stringify(value, null, 2));
    const signed = f.assertion(req, 0, { clientDataJSON: raw, counter: 7 });
    const input = approvalInput(f, req, { assertion: signed, counterBefore: 6 });
    const result = verdict(verifyOrganizationApproval(input), 'VALID');
    assert.equal(result.counterFacts.length, 1);
    assert.deepEqual(input.assertion.clientDataJSON, raw);
    verdict(verifyOrganizationApproval({ ...input, counterBefore: 7 }), 'INVALID');
    const { counterBefore, ...missing } = input;
    verdict(verifyOrganizationApproval(missing), 'INVALID');
    signed.clientDataJSON = Buffer.from(JSON.stringify(value));
    verdict(verifyOrganizationApproval({ ...input, assertion: signed }), 'INVALID');
  } finally {
    f.close();
  }
});

test('organization approval permits zero counters only with the committed per-person challenge', () => {
  const f = createOrganizationFixture();
  try {
    const req = request(f);
    verdict(
      verifyOrganizationApproval(
        approvalInput(f, req, { assertion: f.assertion(req, 0, { counter: 0 }) }),
      ),
      'VALID',
    );
    const other = copy(req);
    other.roster[0].nonce = c.random();
    verdict(
      verifyOrganizationApproval(
        approvalInput(f, req, { assertion: f.assertion(other, 0, { counter: 0 }) }),
      ),
      'INVALID',
    );
  } finally {
    f.close();
  }
});

for (const [name, mutate, expected] of [
  [
    'missing selected person',
    (v) => {
      v.approvals.pop();
    },
    'INDETERMINATE',
  ],
  [
    'reordered selected people',
    (v) => {
      v.approvals.reverse();
    },
    'INVALID',
  ],
  [
    'duplicated approval',
    (v) => {
      v.approvals[1] = v.approvals[0];
    },
    'INVALID',
  ],
  [
    'extra approval',
    (v) => {
      v.approvals.push(v.approvals[0]);
    },
    'INVALID',
  ],
  [
    'substituted request nonce',
    (v) => {
      v.request.roster[0].nonce = c.random();
    },
    'INVALID',
  ],
  [
    'substituted original registration',
    (v) => {
      v.approvals[0].registrationCMS = v.approvals[1].registrationCMS;
    },
    'INVALID',
  ],
]) {
  test(`organization approval set rejects ${name}`, () => {
    const f = createOrganizationFixture();
    try {
      const input = setInput(f),
        value = copy(c.decodeCBOR(input.approvalSet));
      mutate(value);
      input.approvalSet = c.dcbor(value);
      verdict(verifyOrganizationApprovalSet(input), expected);
    } finally {
      f.close();
    }
  });
}

test('organization status retains known revocation despite a newer GOOD head', () => {
  const f = createOrganizationFixture();
  try {
    replaceStatus(f, { epoch: 2, status: 'REVOKED', effectiveTime: f.at - 1 });
    const revoked = verdict(evaluate(f), 'INVALID');
    assert(revoked.statusObservations.some((v) => v.status === 'REVOKED'));
    replaceStatus(f, { epoch: 3 });
    verdict(evaluate(f, stateFrom(revoked)), 'INVALID');
  } finally {
    f.close();
  }
});

test('organization status persists higher stale and UNKNOWN epochs without granting permission', () => {
  const f = createOrganizationFixture();
  try {
    replaceStatus(f, {
      epoch: 3,
      status: 'UNKNOWN',
      publishedAt: f.at - 10,
      nextUpdate: f.at - 1,
    });
    const newer = verdict(evaluate(f), 'INDETERMINATE');
    assert(newer.statusObservations.some((v) => v.epoch === 3));
    replaceStatus(f, { epoch: 2 });
    verdict(evaluate(f, stateFrom(newer)), 'INVALID');
  } finally {
    f.close();
  }
});

test('organization status rejects same-epoch semantic conflict independent of presentation order', () => {
  const f = createOrganizationFixture();
  try {
    const conflict = f.status('GRANT', f.grants[0], { status: 'UNKNOWN' });
    f.context.statusMaterial.push(conflict);
    verdict(evaluate(f), 'INVALID');
    f.context.statusMaterial.reverse();
    verdict(evaluate(f), 'INVALID');
  } finally {
    f.close();
  }
});

test('organization status accepts a different valid signature on the same semantic body', () => {
  const f = createOrganizationFixture();
  try {
    const original = verdict(evaluate(f), 'VALID');
    f.context.statusMaterial = f.context.statusMaterial.map((entry) => ({
      ...entry,
      cms: signOrganizationControl(
        'OrganizationDelegationStatus',
        readControl(entry.cms, 'OrganizationDelegationStatus', entry.issuerCertificate),
        f.keys.status,
      ),
    }));
    verdict(evaluate(f, stateFrom(original)), 'VALID');
  } finally {
    f.close();
  }
});

test('organization future status cannot poison epoch or key-incident knowledge', () => {
  const f = createOrganizationFixture();
  try {
    replaceStatus(f, {
      epoch: 90,
      status: 'REVOKED',
      publishedAt: f.at + 1,
      nextUpdate: f.at + 100,
      effectiveTime: f.at - 10,
      compromiseStart: f.at - 10,
    });
    const future = evaluate(f);
    assert.notEqual(future.overall, 'VALID');
    assert.equal(
      future.statusObservations.some((v) => v.epoch === 90),
      false,
    );
    replaceStatus(f, { epoch: 1 });
    verdict(evaluate(f, stateFrom(future)), 'VALID');
  } finally {
    f.close();
  }
});

test('organization unknown off-path target cannot install an incident for a selected key', () => {
  const f = createOrganizationFixture();
  try {
    const unknown = f.status('GRANT', f.grants[0], {
      objectID: c.random(),
      objectHash: c.random(64),
      subjectKeyID: f.persons[0].body.keyID,
      status: 'REVOKED',
      effectiveTime: f.at - 1,
      compromiseStart: f.at - 1,
      epoch: 50,
    });
    f.context.statusMaterial.push(unknown);
    const observed = evaluate(f);
    assert.notEqual(observed.overall, 'VALID');
    assert.equal(
      observed.statusObservations.some((v) => v.epoch === 50),
      false,
    );
    f.context.statusMaterial.pop();
    verdict(evaluate(f, stateFrom(observed)), 'VALID');
  } finally {
    f.close();
  }
});

test('organization known off-path registration compromise follows its key into a new registration', () => {
  const f = createOrganizationFixture();
  try {
    const original = verdict(evaluate(f), 'VALID');
    const incident = f.status('APPROVER_REGISTRATION', f.registrations[0], {
      epoch: 2,
      status: 'REVOKED',
      effectiveTime: f.at - 1,
      compromiseStart: f.at - 1,
    });
    f.persons[0].body.registrationID = c.random();
    f.signRegistrations();
    f.refreshStatuses();
    f.context.statusMaterial.push(incident);
    const compromised = verdict(evaluate(f, stateFrom(original)), 'INVALID');
    assert(compromised.statusObservations.some((v) => v.compromiseStart === f.at - 1));
    f.context.statusMaterial.pop();
    verdict(evaluate(f, stateFrom(compromised)), 'INVALID');
  } finally {
    f.close();
  }
});

test('organization status requires the subject key from the original signed target', () => {
  const f = createOrganizationFixture();
  try {
    replaceStatus(f, { subjectKeyID: f.sim.keyID, epoch: 10 });
    const result = verdict(evaluate(f), 'INVALID');
    assert.equal(
      result.statusObservations.some((v) => v.epoch === 10),
      false,
    );
  } finally {
    f.close();
  }
});

test('organization status mathematical failure dominates missing freshness and unavailable authority', () => {
  const f = createOrganizationFixture();
  try {
    f.context.statusMaterial[0].cms[f.context.statusMaterial[0].cms.length - 1] ^= 1;
    f.context.statusMaterial.pop();
    f.hooks.authority = () => ({ overall: 'INDETERMINATE', reason: 'UNAVAILABLE' });
    verdict(evaluate(f), 'INVALID');
  } finally {
    f.close();
  }
});

for (const name of ['original request and activation', 'final authorization and permit']) {
  test(`organization current verification refuses an expired ${name} window`, () => {
    const f = createOrganizationFixture();
    try {
      const input = evidenceInput(f);
      if (name === 'original request and activation') {
        input.context.knowledgeTime = f.sim.expiresAt;
      } else {
        input.context.knowledgeTime = readControl(
          input.authorization.cms,
          'OrganizationAuthorization',
          input.authorization.issuerCertificate,
        ).expiresAt;
      }
      input.context.executionCurrent.observedAt = input.context.knowledgeTime;
      verdict(verifyOrganizationEvidence(input), 'INVALID');
    } finally {
      f.close();
    }
  });
}

test('organization current execution rejects a different authenticated latest lease', () => {
  const f = createOrganizationFixture();
  try {
    const input = evidenceInput(f);
    input.context.executionCurrent.binding = issueExecutionBinding(
      { ...f.bindingBody, epoch: 2 },
      f.keys.binding,
    );
    verdict(verifyOrganizationEvidence(input), 'INVALID');
  } finally {
    f.close();
  }
});

test('organization future execution binding does not advance the known lease epoch', () => {
  const f = createOrganizationFixture();
  try {
    f.context.executionCurrent.binding = issueExecutionBinding(
      { ...f.bindingBody, epoch: 90, issuedAt: f.at + 1, expiresAt: f.at + 200 },
      f.keys.binding,
    );
    const future = evaluate(f);
    assert.notEqual(future.overall, 'VALID');
    assert.equal(
      future.executionObservations.some((v) => v.epoch === 90),
      false,
    );
    f.context.executionCurrent.binding = f.binding;
    verdict(evaluate(f, stateFrom(future)), 'VALID');
  } finally {
    f.close();
  }
});

test('organization pure evaluation snapshots nested bytes before authority callbacks', () => {
  const f = createOrganizationFixture();
  try {
    const input = f.pureInput(),
      original = copy(input);
    f.hooks.authority = (query) => {
      input.sim.organizationID.fill(0);
      input.delegationPath.fill(0);
      input.approverRegistrations[0].cms.fill(0);
      query.scope.trustDomainID.fill(0);
      return { overall: 'VALID', reason: 'EXPLICIT_FIXED_TEST_AUTHORITY' };
    };
    const result = verdict(evaluateOrganizationRequest(input), 'VALID');
    assert.deepEqual(result.facts.request.organizationID, original.sim.organizationID);
    assert.deepEqual(
      result.facts.pathLeafID,
      evidenceLeaf('OrganizationDelegationPath', original.delegationPath).id,
    );
  } finally {
    f.close();
  }
});

test('organization pure authority rejection stays synchronous and leaves no unhandled rejection', async () => {
  const f = createOrganizationFixture();
  try {
    f.hooks.authority = () => Promise.reject(new Error('authority offline'));
    verdict(evaluate(f), 'INDETERMINATE');
    await immediate();
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

for (const [name, mutate, expected] of [
  [
    'sparse registrations',
    (v) => {
      delete v.approverRegistrations[0];
    },
    'INVALID',
  ],
  [
    'non-Buffer path',
    (v) => {
      v.delegationPath = [];
    },
    'INVALID',
  ],
  [
    'path byte limit',
    (v) => {
      v.delegationPath = Buffer.alloc(2 * 1024 * 1024 + 1);
    },
    'UNSUPPORTED',
  ],
  [
    'registration byte limit',
    (v) => {
      v.approverRegistrations[0].cms = Buffer.alloc(65537);
    },
    'UNSUPPORTED',
  ],
  [
    'registration count limit',
    (v) => {
      v.approverRegistrations = Array(17).fill(v.approverRegistrations[0]);
    },
    'UNSUPPORTED',
  ],
  [
    'status count limit',
    (v) => {
      v.context.statusMaterial = Array(65).fill(v.context.statusMaterial[0]);
    },
    'UNSUPPORTED',
  ],
]) {
  test(`organization input rejects ${name} before it can grant facts`, () => {
    const f = createOrganizationFixture();
    try {
      const input = f.pureInput();
      mutate(input);
      verdict(evaluateOrganizationRequest(input), expected);
    } finally {
      f.close();
    }
  });
}

test('organization accepts the maximum selected path of eight valid narrowing grants', () => {
  const f = createOrganizationFixture({ pathLength: 8 });
  try {
    verdict(evaluate(f), 'VALID');
  } finally {
    f.close();
  }
});

test('organization approval cannot use authority coverage ending at the current instant', () => {
  const f = createOrganizationFixture();
  try {
    const req = request(f);
    f.hooks.authority = () => ({
      overall: 'VALID',
      reason: 'AUTHORITY_ADMITTED',
      coverageUntil: f.at + 1,
    });
    verdict(verifyOrganizationApproval(approvalInput(f, req)), 'VALID');
    f.advance(1);
    verdict(verifyOrganizationApproval(approvalInput(f, req)), 'INDETERMINATE');
  } finally {
    f.close();
  }
});

test('organization request lifetime ends before an already authenticated future revocation', () => {
  const f = createOrganizationFixture();
  try {
    replaceStatus(f, { status: 'REVOKED', effectiveTime: f.at + 10 });
    const result = verdict(evaluate(f), 'VALID');
    assert(result.facts.request.expiresAt <= f.at + 10);
    f.advance(10);
    verdict(evaluate(f), 'INVALID');
  } finally {
    f.close();
  }
});

test('organization incomplete quorum cannot conceal the final authorization binding to different raw approval bytes', () => {
  const f = createOrganizationFixture();
  try {
    const input = evidenceInput(f);
    verdict(verifyOrganizationEvidence(input), 'VALID');
    const approvals = copy(c.decodeCBOR(input.approvalSet));
    approvals.approvals.pop();
    input.approvalSet = c.dcbor(approvals);
    verdict(verifyOrganizationEvidence(input), 'INVALID');
  } finally {
    f.close();
  }
});
