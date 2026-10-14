import test from 'node:test';
import assert from 'node:assert/strict';
import { verificationResult } from './verification-result.mjs';

test('shared verification envelope fixes revision and preserves only evaluated dimensions', () => {
  const dimensions = { status: { overall: 'INDETERMINATE', reason: 'STATUS_STALE' } };
  const value = verificationResult({
    overall: 'INDETERMINATE',
    reason: 'STATUS_STALE',
    profile: 'RFC3161',
    coreRevision: 'untrusted-revision',
    dimensions,
    knowledgeTime: 42,
  });
  assert.equal(value.coreRevision, 'draft-03');
  assert.equal(value.profile, 'RFC3161');
  assert.equal(value.knowledgeTime, 42);
  assert.deepEqual(Object.keys(value.dimensions), ['status']);
  assert.deepEqual(value.dimensions.status, { overall: 'INDETERMINATE', reason: 'STATUS_STALE' });
  dimensions.status.overall = 'VALID';
  assert.equal(value.dimensions.status.overall, 'INDETERMINATE');
  assert(
    Object.isFrozen(value) &&
      Object.isFrozen(value.dimensions) &&
      Object.isFrozen(value.dimensions.status),
  );
});

test('shared verification envelope accepts four outcomes without fabricating positive checks', () => {
  for (const overall of ['VALID', 'INVALID', 'UNSUPPORTED', 'INDETERMINATE']) {
    const result = verificationResult({ overall, reason: 'SELECTED_RESULT' });
    assert.equal(result.overall, overall);
    assert.equal(result.reason, 'SELECTED_RESULT');
    assert.equal(result.profile, null);
    assert.deepEqual(result.dimensions, {});
  }
});

test('shared verification envelope rejects absent reasons and unknown outcomes or dimensions', () => {
  for (const input of [
    { overall: 'MAYBE', reason: 'X' },
    { overall: 'VALID', reason: '' },
    { overall: 'VALID', reason: 'X', profile: '' },
    {
      overall: 'VALID',
      reason: 'X',
      dimensions: { permission: { overall: 'VALID', reason: 'X' } },
    },
    { overall: 'VALID', reason: 'X', dimensions: { integrity: { overall: 'VALID', reason: '' } } },
  ])
    assert.throws(() => verificationResult(input), /VERIFICATION_RESULT/);
});
