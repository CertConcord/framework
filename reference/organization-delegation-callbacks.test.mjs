import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as immediate } from 'node:timers/promises';
import * as c from './core.mjs';
import { readControl } from './state.mjs';
import { verifyOrganizationExecutionEvidence } from './execution-binding.mjs';
import { copy, createOrganizationGatewayFixture } from './organization-delegation-fixtures.mjs';

const denied = { overall: 'INVALID', reason: 'ORG_REVOKED' };
const stored = (f) => f.journal.result(c.b64u(f.operationID));

test('organization gateway performs one real signature with exact DISPATCH and COMPLETE evidence', async () => {
  const f = createOrganizationGatewayFixture();
  try {
    const gateway = f.gateway();
    const result = await gateway.execute(f.input);
    assert.equal(f.calls.sign, 1);
    assert.deepEqual(
      f.views.map((view) => view.stage),
      ['DISPATCH', 'COMPLETE'],
    );
    assert.equal(f.views[0].signatureHash, null);
    assert.deepEqual(f.views[1].signatureHash, c.sha512(result.signature));
    assert(c.verify(f.prepared.tbs, result.signature, f.keys.seal.publicKey));
    const receipt = readControl(result.receipt, 'ExecutionReceipt', f.keys.receipt.certificate);
    assert.deepEqual(receipt.signatureHash, c.sha512(result.signature));
    assert.equal(receipt.executedAt, f.at);
    const facts = verifyOrganizationExecutionEvidence(
      {
        ...f.input,
        policy: f.policy,
        publicKey: f.keys.seal.publicKey,
        signature: result.signature,
        receipt: result.receipt,
        evidence: result.executionEvidence,
      },
      {
        bindingCertificate: f.keys.binding.certificate,
        permitCertificate: f.keys.permit.certificate,
        receiptCertificate: f.keys.receipt.certificate,
        trustDomainID: f.trustDomainID,
        at: f.at,
        knowledgeTime: f.at,
      },
    );
    assert.equal(facts.scope, 'MATHEMATICS_AND_BINDINGS_ONLY');
    assert.equal(Object.hasOwn(facts, 'overall'), false);
    assert.deepEqual(facts.operationID, f.operationID);
    assert.equal(stored(f).status, 'COMPLETED');
  } finally {
    f.close();
  }
});

for (const action of ['execute', 'reconcile']) {
  test(`organization gateway cached ${action} repeats COMPLETE admission and preserves completed bytes on denial`, async () => {
    const f = createOrganizationGatewayFixture();
    try {
      const gateway = f.gateway();
      const result = await gateway.execute(f.input);
      const retained = Buffer.from(stored(f).result);
      f.hooks.admission = (view, good) => (view.stage === 'COMPLETE' ? denied : good);
      await assert.rejects(
        action === 'execute'
          ? gateway.execute(f.input)
          : gateway.reconcile({ operationID: f.operationID, signature: result.signature }),
        { overall: 'INVALID', code: 'ORG_REVOKED' },
      );
      assert.equal(f.calls.sign, 1);
      assert.equal(stored(f).status, 'COMPLETED');
      assert.deepEqual(stored(f).result, retained);
      assert.equal(f.views.at(-1).stage, 'COMPLETE');
      assert.deepEqual(f.views.at(-1).signatureHash, c.sha512(result.signature));
    } finally {
      f.close();
    }
  });
}

for (const stage of [
  'capabilities',
  'dispatch authorize',
  'private signature',
  'complete authorize',
]) {
  test(`organization gateway rechecks withdrawal after ${stage} await`, async () => {
    const f = createOrganizationGatewayFixture();
    let active = true;
    const withdraw = async () => {
      await immediate();
      active = false;
    };
    try {
      f.hooks.admission = (_view, good) => (active ? good : denied);
      if (stage === 'capabilities') f.hooks.capabilities = withdraw;
      if (stage === 'private signature') f.hooks.afterSign = withdraw;
      if (stage.endsWith('authorize'))
        f.hooks.authorize = async (_view, count) => {
          if (count === (stage.startsWith('dispatch') ? 1 : 2)) await withdraw();
          return true;
        };
      await assert.rejects(f.gateway().execute(f.input), {
        overall: 'INVALID',
        code: 'ORG_REVOKED',
      });
      const dispatched = ['private signature', 'complete authorize'].includes(stage);
      assert.equal(f.calls.sign, dispatched ? 1 : 0);
      assert.equal(stored(f)?.status, dispatched ? 'UNKNOWN_EXECUTION' : undefined);
      if (dispatched) {
        assert.equal(
          f.journal.get('execution-key-lock', c.b64u(f.sim.keyID)).value.operationID,
          c.b64u(f.operationID),
        );
      }
    } finally {
      f.close();
    }
  });
}

test('organization gateway snapshots caller bytes and callback views before asynchronous use', async () => {
  const f = createOrganizationGatewayFixture();
  let entered, release;
  const ready = new Promise((resolve) => {
    entered = resolve;
  });
  const blocked = new Promise((resolve) => {
    release = resolve;
  });
  const original = copy(f.input);
  try {
    f.hooks.capabilities = async () => {
      entered();
      await blocked;
    };
    f.hooks.authorize = async (view) => {
      view.sim.subjectID.fill(0);
      view.permit.activation.tbsHash.fill(0);
      return true;
    };
    f.hooks.admission = (view, good) => {
      view.binding.keyID.fill(0);
      view.sim.organizationID.fill(0);
      queueMicrotask(() => {
        good.binding.requestHash.fill(0);
      });
      return good;
    };
    const pending = f.gateway().execute(f.input);
    await ready;
    f.input.tbs.fill(0);
    f.input.permit.fill(0);
    f.input.sim.subjectID.fill(0);
    release();
    const result = await pending;
    assert(c.verify(original.tbs, result.signature, f.keys.seal.publicKey));
    assert.equal(f.calls.sign, 1);
    assert.deepEqual(
      readControl(result.receipt, 'ExecutionReceipt', f.keys.receipt.certificate).permitHash,
      c.sha512(original.permit),
    );
  } finally {
    release?.();
    f.close();
  }
});

test('organization gateway fixes backend admission clock and Journal method references at construction', async () => {
  const f = createOrganizationGatewayFixture();
  try {
    const gateway = f.gateway();
    const forbidden = () => {
      throw Error('replaced dependency invoked');
    };
    f.backend.capabilities = forbidden;
    f.backend.sign = forbidden;
    f.gatewayOptions.currentAdmission = forbidden;
    f.gatewayOptions.authorize = forbidden;
    f.gatewayOptions.clock = forbidden;
    f.journal.get = forbidden;
    f.journal.put = forbidden;
    f.journal.transaction = forbidden;
    const result = await gateway.execute(f.input);
    assert(c.verify(f.prepared.tbs, result.signature, f.keys.seal.publicKey));
    assert.equal(f.calls.sign, 1);
  } finally {
    f.close();
  }
});

for (const field of [
  'stage',
  'operationID',
  'requestHash',
  'bindingHash',
  'permitHash',
  'keyID',
  'signatureHash',
]) {
  test(`organization gateway rejects admission tuple substitution of ${field}`, async () => {
    const f = createOrganizationGatewayFixture();
    try {
      f.hooks.admission = (_view, good) => {
        good.binding[field] =
          field === 'stage' ? 'COMPLETE' : c.random(field === 'operationID' ? 32 : 64);
        return good;
      };
      await assert.rejects(f.gateway().execute(f.input), { code: 'ORG_CURRENT_ADMISSION_BINDING' });
      assert.equal(f.calls.sign, 0);
      assert.equal(stored(f), undefined);
    } finally {
      f.close();
    }
  });
}

for (const [name, mutate] of [
  [
    'namespace',
    (guards) => {
      guards[0].namespace = 'foreign-operation';
    },
  ],
  [
    'row identity',
    (guards) => {
      guards[1].id = 'foreign-row';
    },
  ],
  [
    'missing guard',
    (guards) => {
      guards.pop();
    },
  ],
  [
    'reordered guards',
    (guards) => {
      guards.reverse();
    },
  ],
  [
    'duplicated guard',
    (guards) => {
      guards[1] = copy(guards[0]);
    },
  ],
  [
    'negative revision',
    (guards) => {
      guards[0].revision = -1;
    },
  ],
  [
    'stale revision',
    (guards) => {
      guards[0].revision++;
    },
  ],
]) {
  test(`organization gateway rejects ${name} before private dispatch`, async () => {
    const f = createOrganizationGatewayFixture();
    try {
      f.hooks.admission = (_view, good) => {
        mutate(good.journalGuards);
        return good;
      };
      await assert.rejects(f.gateway().execute(f.input), /ORG_CURRENT_ADMISSION/);
      assert.equal(f.calls.sign, 0);
      assert.equal(stored(f), undefined);
    } finally {
      f.close();
    }
  });
}

test('organization gateway does not attach a newer guard revision to an earlier admission decision', async () => {
  const f = createOrganizationGatewayFixture();
  try {
    f.hooks.admission = (_view, good) => {
      const guard = good.journalGuards[1];
      f.journal.put(guard.namespace, guard.id, { changed: true }, guard.revision);
      return good;
    };
    await assert.rejects(f.gateway().execute(f.input), { code: 'ORG_CURRENT_ADMISSION_CHANGED' });
    assert.equal(f.calls.sign, 0);
    assert.equal(stored(f), undefined);
  } finally {
    f.close();
  }
});

test('organization gateway runs external callbacks outside all SQLite transactions', async () => {
  const f = createOrganizationGatewayFixture();
  try {
    f.hooks.authorize = async () => {
      assert.equal(f.journal.db.isTransaction, false);
      return true;
    };
    f.hooks.admission = (_view, good) => {
      assert.equal(f.journal.db.isTransaction, false);
      return good;
    };
    f.hooks.beforeSign = () => {
      assert.equal(f.journal.db.isTransaction, false);
    };
    await f.gateway().execute(f.input);
    assert.equal(f.calls.sign, 1);
  } finally {
    f.close();
  }
});

for (const [name, decision] of [
  [
    'empty positive check',
    (good) => {
      good.checks = [{ overall: 'VALID' }];
      return good;
    },
  ],
  [
    'extra positive check field',
    (good) => {
      good.checks[0].installTrust = true;
      return good;
    },
  ],
  ['native rejected Promise', () => Promise.reject(Error('dependency unavailable'))],
  ['incomplete positive decision', () => ({ overall: 'VALID' })],
  ['missing decision', () => undefined],
]) {
  test(`organization gateway rejects ${name} with no private action`, async () => {
    const f = createOrganizationGatewayFixture();
    try {
      f.hooks.admission = (_view, good) => decision(good);
      await assert.rejects(f.gateway().execute(f.input), { overall: 'INDETERMINATE' });
      await immediate();
      assert.equal(f.calls.sign, 0);
      assert.equal(stored(f), undefined);
    } finally {
      f.close();
    }
  });
}

for (const overall of ['INVALID', 'UNSUPPORTED', 'INDETERMINATE']) {
  test(`organization gateway preserves typed ${overall} without requiring a positive binding`, async () => {
    const f = createOrganizationGatewayFixture();
    try {
      f.hooks.admission = () => ({ overall });
      await assert.rejects(f.gateway().execute(f.input), { overall });
      assert.equal(f.calls.sign, 0);
    } finally {
      f.close();
    }
  });
}

test('organization gateway does not invoke an accessor or arbitrary thenable admission', async () => {
  const f = createOrganizationGatewayFixture();
  let invoked = 0;
  try {
    f.hooks.admission = () =>
      Object.defineProperty({}, 'overall', {
        enumerable: true,
        get() {
          invoked++;
          return 'VALID';
        },
      });
    await assert.rejects(f.gateway().execute(f.input), { overall: 'INDETERMINATE' });
    f.hooks.admission = () => ({
      then() {
        invoked++;
      },
    });
    await assert.rejects(f.gateway().execute(f.input), { overall: 'INDETERMINATE' });
    assert.equal(invoked, 0);
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});
