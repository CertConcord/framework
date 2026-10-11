import { Worker } from 'node:worker_threads';
import { createHash } from 'node:crypto';

export const LIMITS = Object.freeze({
  input: 32 * 1024 * 1024,
  content: 16 * 1024 * 1024,
  cms: 16 * 1024 * 1024,
  decoded: 16 * 1024 * 1024,
  parts: 128,
  depth: 16,
  headers: 128,
  headerBytes: 65536,
  certificates: 32,
  recipients: 32,
  timeout: 10000,
  diagnostics: 65536,
});
export function failure(code, overall = 'INVALID') {
  return Object.assign(new Error(code), { code, overall });
}
export function check(value, code, overall) {
  if (!value) throw failure(code, overall);
}
export function bytes(value, limit = LIMITS.input) {
  check(value instanceof Uint8Array, 'SMIME_BYTES_REQUIRED');
  check(value.length <= limit, 'SMIME_SIZE_LIMIT', 'UNSUPPORTED');
  return Buffer.from(value);
}
export const hash = (value) => createHash('sha256').update(value).digest();
export function copy(value) {
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(copy);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, copy(item)]));
  check(typeof value !== 'function', 'SMIME_WORKER_INPUT');
  return value;
}
export function outcome(checks, validReason = 'SMIME_CMS_VALID') {
  for (const overall of ['INVALID', 'UNSUPPORTED', 'INDETERMINATE']) {
    const item = checks.find((entry) => entry.overall === overall);
    if (item) return { overall, reason: item.reason };
  }
  return { overall: 'VALID', reason: validReason };
}
export function workerCall(url, action, input) {
  const snapshot = copy(input);
  return new Promise((resolve, reject) => {
    const worker = new Worker(url, {
      workerData: { action, input: snapshot },
      resourceLimits: { maxOldGenerationSizeMb: 128, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
      stdout: true,
      stderr: true,
      execArgv: [],
    });
    let done = false;
    const finish = (error, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      worker.terminate().then(
        () => (error ? reject(error) : resolve(copy(value))),
        () => reject(failure('SMIME_WORKER_TERMINATION', 'INDETERMINATE')),
      );
    };
    let diagnostics = 0;
    for (const stream of [worker.stdout, worker.stderr])
      stream.on('data', (chunk) => {
        diagnostics += chunk.length;
        if (diagnostics > LIMITS.diagnostics)
          finish(failure('SMIME_WORKER_OUTPUT_LIMIT', 'INDETERMINATE'));
      });
    const timer = setTimeout(
      () => finish(failure('SMIME_WORKER_TIMEOUT', 'INDETERMINATE')),
      LIMITS.timeout,
    );
    worker.once('message', (message) =>
      finish(message.ok ? null : failure(message.code, message.overall), message.value),
    );
    worker.once('error', () => finish(failure('SMIME_WORKER_UNAVAILABLE', 'INDETERMINATE')));
    worker.once('exit', () => {
      if (!done) finish(failure('SMIME_WORKER_EXIT', 'INDETERMINATE'));
    });
  });
}
