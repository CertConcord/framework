import test from 'node:test';
import assert from 'node:assert/strict';

let api;
try { api = await import('./pades.mjs'); }
catch (error) {
  if (!(error.code === 'ERR_MODULE_NOT_FOUND' && error.url === new URL('./pades.mjs', import.meta.url).href)) throw error;
}

test('selected PAdES preservation API is present (new-feature availability gate)', () => {
  assert(api, 'Selected new PAdES API is absent at the frozen CAdES base; this is not an existing semantic failure');
  for (const name of ['preparePAdESSignature', 'preparePAdESAugmentation', 'verifyPAdES'])
    assert.equal(typeof api[name], 'function', name);
});
