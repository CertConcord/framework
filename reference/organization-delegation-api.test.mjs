import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';

async function exported(name) {
  const url = new URL(name, import.meta.url);
  return existsSync(url) ? import(url.href) : {};
}

test('organization delegation exposes the frozen application and retained verifier', async () => {
  const api = await exported('./organization-delegation.mjs');
  assert.equal(typeof api.OrganizationDelegationApplication, 'function');
  assert.equal(typeof api.OrganizationDelegationVerifier, 'function');
});

test('organization delegation exposes the four independent pure evidence APIs', async () => {
  const api = await exported('./organization-delegation-evidence.mjs');
  for (const name of [
    'evaluateOrganizationRequest',
    'verifyOrganizationApproval',
    'verifyOrganizationApprovalSet',
    'verifyOrganizationEvidence',
  ]) {
    assert.equal(typeof api[name], 'function', name);
  }
});

test('organization delegation exposes the selected retained execution mathematics seam', async () => {
  const api = await exported('./execution-binding.mjs');
  assert.equal(typeof api.verifyOrganizationExecutionEvidence, 'function');
});
