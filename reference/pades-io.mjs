import { Worker } from 'node:worker_threads';
import { ProtocolError } from './core.mjs';

function failure(code, overall = 'INVALID') {
  const error = new ProtocolError(code);
  error.overall = overall;
  return error;
}
function copy(value) {
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(copy);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, copy(item)]));
  if (typeof value === 'function') throw failure('PADES_WORKER_OPTIONS');
  return value;
}
// Only public document bytes and structural parameters cross this boundary.
// Policy decisions, signing keys and authority callbacks stay with the caller.
async function structure(action, input, options = {}) {
  if (!(input instanceof Uint8Array)) throw failure('PADES_INPUT');
  if (input.length > 64 * 1024 * 1024) throw failure('PADES_SIZE_LIMIT', 'UNSUPPORTED');
  const snapshot = Buffer.from(input),
    parameters = copy(options);
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./pades-worker.mjs', import.meta.url), {
      workerData: { action, input: snapshot, options: parameters },
      resourceLimits: { maxOldGenerationSizeMb: 256, maxYoungGenerationSizeMb: 32, stackSizeMb: 4 },
      stdout: true,
      stderr: true,
      execArgv: [],
    });
    worker.stdout.resume();
    worker.stderr.resume();
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate().then(
        () => (error ? reject(error) : resolve(copy(value))),
        () => reject(failure('PADES_WORKER_TERMINATION', 'INDETERMINATE')),
      );
    };
    const timer = setTimeout(() => finish(failure('PADES_PARSE_TIMEOUT', 'INDETERMINATE')), 3000);
    worker.once('message', (message) =>
      finish(message.ok ? null : failure(message.code, message.overall), message.value),
    );
    worker.once('error', () => finish(failure('PADES_WORKER_RESOURCE_LIMIT', 'INDETERMINATE')));
    worker.once('exit', () => {
      if (!settled) finish(failure('PADES_WORKER_EXIT', 'INDETERMINATE'));
    });
  });
}

export const preparePAdESContainer = (pdf, options) =>
  structure('preparePAdESContainer', pdf, options);
export const appendPAdESDSS = (pdf, options) => structure('appendPAdESDSS', pdf, options);
export const inspectPAdESContainer = (pdf) => structure('inspectPAdESContainer', pdf);
