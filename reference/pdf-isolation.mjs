import { Worker } from 'node:worker_threads';
import { ProtocolError, requireThat } from './core.mjs';
import { verifyCMS } from './pki.mjs';

function buffers(value) {
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(buffers);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, buffers(v)]));
  return value;
}
// Untrusted PDF parsing never runs on the caller's event loop. A worker receives no keys.
async function structure(action, input, options) {
  if (action === 'examplePDF')
    requireThat(typeof input === 'string' && input.length <= 65536, 'PDF_TEXT_LIMIT');
  else requireThat(input instanceof Uint8Array && input.length <= 64 * 1024 * 1024, 'PDF_LIMIT');
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./pdf-worker.mjs', import.meta.url), {
      workerData: { action, input, options },
      resourceLimits: { maxOldGenerationSizeMb: 256, maxYoungGenerationSizeMb: 32, stackSizeMb: 4 },
      stdout: true,
      stderr: true,
      execArgv: [],
    });
    // Library diagnostics can contain hostile document bytes. Drain them without logging.
    worker.stdout.resume();
    worker.stderr.resume();
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate().then(
        () => (error ? reject(error) : resolve(buffers(value))),
        () => reject(new ProtocolError('PDF_WORKER_TERMINATION')),
      );
    };
    const timer = setTimeout(() => finish(new ProtocolError('PDF_PARSE_TIMEOUT')), 3000);
    worker.once('message', (r) => finish(r.ok ? null : new ProtocolError(r.code), r.value));
    worker.once('error', () => finish(new ProtocolError('PDF_WORKER_RESOURCE_LIMIT')));
    worker.once('exit', () => {
      if (!settled) finish(new ProtocolError('PDF_WORKER_EXIT'));
    });
  });
}

export const examplePDF = (text = 'CertConcord draft 02 synthetic document') =>
  structure('examplePDF', text);

export async function preparePDF(input, options = {}) {
  const { output, contentsAt, signatureBytes, ...prepared } = await structure(
    'preparePDF',
    input,
    options,
  );
  return {
    ...prepared,
    finish(cms) {
      verifyCMS(cms, { content: prepared.content });
      requireThat(cms.length <= signatureBytes, 'PDF_SIGNATURE_SPACE');
      const finished = Buffer.from(output);
      finished.write(cms.toString('hex').padEnd(signatureBytes * 2, '0'), contentsAt + 1, 'ascii');
      return finished;
    },
  };
}

export async function verifyPDF(input, options = {}) {
  requireThat(input instanceof Uint8Array && input.length <= 64 * 1024 * 1024, 'PDF_LIMIT');
  const raw = Buffer.from(input),
    parsed = await structure('verifyPDF', raw);
  return {
    ...parsed,
    signatures: parsed.signatures.map(({ cms, ...s }) => {
      const a = s.byteRange,
        content = Buffer.concat([raw.subarray(0, a[1]), raw.subarray(a[2], a[2] + a[3])]);
      return { ...verifyCMS(cms, { ...options, content }), ...s };
    }),
  };
}
