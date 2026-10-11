import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { SmimeApplication } from './smime.mjs';
import { smimeMaterialFixture } from './smime-material-fixtures.mjs';
import { applicationFixture, expectOverall } from './smime-application-fixtures.mjs';

let material;
before(() => {
  material = smimeMaterialFixture();
});
after(() => material?.close());

for (const dependency of [
  'current context',
  'mailbox decision',
  'authority decision',
  'mailbox normalization',
]) {
  test(`S/MIME rejected Promise from synchronous ${dependency} stays typed without unhandled rejection`, async () => {
    const f = applicationFixture(material);
    if (dependency === 'authority decision')
      f.policy.authorityResolver = () => Promise.reject(new Error('authority unavailable'));
    if (dependency === 'mailbox normalization')
      f.backend.normalizeMailbox = () => Promise.reject(new Error('normalization unavailable'));
    const app = new SmimeApplication({ readContext: f.readContext, backend: f.backend });
    if (dependency === 'current context')
      f.state.contextOverride = () => Promise.reject(new Error('configuration unavailable'));
    else if (dependency === 'mailbox decision')
      f.state.mailboxDecision = () => Promise.reject(new Error('binding unavailable'));
    const result = expectOverall(await app.protectSmimeMessage(f.protectInput()), 'INDETERMINATE');
    assert.equal(result.effectMayHaveOccurred, false);
    assert.equal(f.count('sign'), 0);
    assert.equal(f.count('encrypt'), 0);
    assert.equal(f.count('decrypt'), 0);
    // A leaked rejected native Promise is a node:test failure at this turn.
    await setImmediate();
  });
}

test('S/MIME rejected Promise at constructor is a typed unavailable context without unhandled rejection', async () => {
  const f = applicationFixture(material);
  assert.throws(
    () =>
      new SmimeApplication({
        readContext: () => Promise.reject(new Error('initial configuration unavailable')),
        backend: f.backend,
      }),
    (error) => {
      assert.equal(error.overall, 'INDETERMINATE');
      assert.equal(typeof error.code, 'string');
      return true;
    },
  );
  assert.equal(f.count('sign'), 0);
  assert.equal(f.count('decrypt'), 0);
  await setImmediate();
});

for (const overall of ['VALID', 'INVALID']) {
  test(`S/MIME authority ${overall} without a reason produces a typed result instead of escaping recovery`, async () => {
    const f = applicationFixture(material);
    f.policy.authorityResolver = () => ({ overall });
    const app = new SmimeApplication({ readContext: f.readContext, backend: f.backend });
    let result;
    await assert.doesNotReject(async () => {
      result = await app.protectSmimeMessage(f.protectInput());
    });
    assert(['INVALID', 'UNSUPPORTED', 'INDETERMINATE'].includes(result.overall));
    assert.equal(Object.hasOwn(result, 'message'), false);
    assert.equal(Object.hasOwn(result, 'content'), false);
    assert.equal(result.effectMayHaveOccurred, false);
    assert.equal(f.count('sign'), 0);
    assert.equal(f.count('encrypt'), 0);
  });
}
