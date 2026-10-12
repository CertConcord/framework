import { parentPort, workerData } from 'node:worker_threads';
import * as structure from './pades-structure.mjs';

try {
  const { action, input, options } = workerData;
  if (!['preparePAdESContainer', 'appendPAdESDSS', 'inspectPAdESContainer'].includes(action))
    throw Error('PADES_OPERATION');
  const value = await structure[action](Buffer.from(input), options);
  parentPort.postMessage({ ok: true, value });
} catch (error) {
  parentPort.postMessage({
    ok: false,
    code: /^[A-Z][A-Z0-9_]{1,100}$/.test(error.code ?? '')
      ? error.code
      : 'PADES_STRUCTURE_REJECTED',
    overall: ['INVALID', 'UNSUPPORTED', 'INDETERMINATE'].includes(error.overall)
      ? error.overall
      : 'INVALID',
  });
}
