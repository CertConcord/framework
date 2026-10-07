import test from 'node:test';
import assert from 'node:assert/strict';

async function optionalModule(name) {
  const url = new URL(name, import.meta.url);
  try {
    return await import(url.href);
  } catch (error) {
    if (error.code === 'ERR_MODULE_NOT_FOUND' && error.url === url.href) return undefined;
    throw error;
  }
}

test('selected timestamp protocol and service public exports are available', async () => {
  const protocol = await optionalModule('./timestamp-protocol.mjs');
  const service = await optionalModule('./timestamp-service.mjs');
  assert(
    protocol && service,
    'The selected timestamp application requires both protocol and service modules',
  );
  for (const name of [
    'encodeTimestampRequest',
    'parseTimestampRequest',
    'encodeTimestampResponse',
    'parseTimestampResponse',
    'encodeTSTInfo',
  ])
    assert.equal(typeof protocol[name], 'function', name);
  for (const name of ['TimestampResponseVerifier', 'TimestampService', 'TimestampClient'])
    assert.equal(typeof service[name], 'function', name);
});
