import { bytes, check, LIMITS, workerCall } from './smime-adapter-common.mjs';
export { normalizeMailbox } from './smime-address.mjs';

const worker = new URL('./smime-mime-worker.mjs', import.meta.url);
export const prepareMimeMessage = async ({ message } = {}) =>
  workerCall(worker, 'prepare', { message: bytes(message) });
export const parseProtectedMessage = async ({ message, format } = {}) =>
  workerCall(worker, 'parse', { message: bytes(message), format });
function headerSnapshot(value) {
  if (value === undefined) return undefined;
  check(Array.isArray(value) && value.length <= LIMITS.headers, 'SMIME_HEADER_INPUT');
  let total = 0;
  return Array.from(value, (record) => {
    check(record && typeof record === 'object', 'SMIME_HEADER_INPUT');
    const { name, value: fieldValue, raw } = record;
    check(typeof name === 'string' && typeof fieldValue === 'string', 'SMIME_HEADER_INPUT');
    const fieldRaw = bytes(raw, LIMITS.headerBytes);
    total += Buffer.byteLength(name) + Buffer.byteLength(fieldValue) + fieldRaw.length;
    check(total <= LIMITS.headerBytes * 3, 'SMIME_HEADER_LIMIT', 'UNSUPPORTED');
    return { name, value: fieldValue, raw: fieldRaw };
  });
}
export const packageCMS = async ({ cms, kind, format, outerHeaders } = {}) =>
  workerCall(worker, 'package', {
    cms: bytes(cms),
    kind,
    format,
    outerHeaders: headerSnapshot(outerHeaders),
  });
export const inspectVerifiedMime = async ({ mime } = {}) =>
  workerCall(worker, 'inspect', { mime: bytes(mime, LIMITS.content) });
