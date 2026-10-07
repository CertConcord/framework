import test from 'node:test';
import assert from 'node:assert/strict';

test('selected S/MIME material facade is available', async () => {
  const material = await import('./cades-validation.mjs');
  assert.equal(typeof material.validateSmimeMaterial, 'function', 'validateSmimeMaterial');
});
