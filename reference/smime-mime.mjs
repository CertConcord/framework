import { bytes, copy, LIMITS, workerCall } from './smime-adapter-common.mjs';
export { normalizeMailbox } from './smime-address.mjs';

const worker = new URL('./smime-mime-worker.mjs', import.meta.url);
export const prepareMimeMessage = ({ message } = {}) =>
  workerCall(worker, 'prepare', { message: bytes(message) });
export const parseProtectedMessage = ({ message, format } = {}) =>
  workerCall(worker, 'parse', { message: bytes(message), format });
export const packageCMS = ({ cms, kind, format, outerHeaders } = {}) =>
  workerCall(worker, 'package', {
    cms: bytes(cms),
    kind,
    format,
    outerHeaders: copy(outerHeaders),
  });
export const inspectVerifiedMime = ({ mime } = {}) =>
  workerCall(worker, 'inspect', { mime: bytes(mime, LIMITS.content) });
