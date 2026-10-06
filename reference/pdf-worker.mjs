import { parentPort, workerData } from 'node:worker_threads';
import * as structure from './pdf-structure.mjs';
try {
  const { action, input, options } = workerData;
  if (!['examplePDF', 'preparePDF', 'verifyPDF'].includes(action)) throw Error('PDF_OPERATION');
  const value = await structure[action](
    action === 'examplePDF' ? input : Buffer.from(input),
    options,
  );
  parentPort.postMessage({ ok: true, value });
} catch (error) {
  parentPort.postMessage({
    ok: false,
    code: /^[A-Z][A-Z0-9_]{1,100}$/.test(error.code ?? '') ? error.code : 'PDF_STRUCTURE_REJECTED',
  });
}
