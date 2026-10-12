import { mlDsa87KeyID, subtreeInput, verifyCosignature } from './extension.mjs';

// This module selects one editor protocol. There is no legacy wire fallback.
export const SUBTREE_WIRE_PROFILE = 'C2SP-20261007-MLDSA87-v2';
const requireValue = (condition, code) => {
  if (!condition) { const error = new Error(code); error.code = code; throw error; }
};
const same = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
const nameOK = value => typeof value === 'string' && /^[\x21-\x2a\x2c-\x7e]{1,255}$/.test(value);
function unbase64(text) {
  requireValue(typeof text === 'string' && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text), 'SUBTREE_BASE64');
  const value = Buffer.from(text, 'base64');
  requireValue(value.toString('base64') === text, 'SUBTREE_BASE64');
  return value;
}
function decimal(text) {
  requireValue(typeof text === 'string' && /^(0|[1-9][0-9]*)$/.test(text), 'SUBTREE_RANGE');
  const value = BigInt(text);
  requireValue(value <= 0xffffffffffffffffn, 'SUBTREE_RANGE');
  return value;
}

export function parseCheckpointEnvelope(note) {
  requireValue(typeof note === 'string' && Buffer.byteLength(note) <= 1048576 && !note.includes('\r') && note.endsWith('\n'), 'CHECKPOINT_ENCODING');
  const cut = note.indexOf('\n\n');
  requireValue(cut > 0, 'CHECKPOINT_ENCODING');
  const body = note.slice(0, cut + 1), lines = body.slice(0, -1).split('\n');
  requireValue(lines.length === 3, 'CHECKPOINT_EXTENSIONS_UNSUPPORTED');
  requireValue(nameOK(lines[0]), 'SUBTREE_NAME');
  const size = decimal(lines[1]), root = unbase64(lines[2]);
  requireValue(root.length === 32, 'CHECKPOINT_ROOT');
  const seen = new Set();
  const signatures = note.slice(cut + 2, -1).split('\n').map(line => {
    const match = /^— ([\x21-\x2a\x2c-\x7e]{1,255}) ([A-Za-z0-9+/=]+)$/.exec(line);
    requireValue(match, 'CHECKPOINT_SIGNATURE');
    const bytes = unbase64(match[2]);
    requireValue(bytes.length > 4, 'CHECKPOINT_SIGNATURE');
    const keyID = bytes.subarray(0, 4), id = match[1] + ':' + keyID.toString('hex');
    requireValue(!seen.has(id), 'CHECKPOINT_DUPLICATE_SIGNATURE');
    seen.add(id);
    return { name: match[1], keyID, signature: bytes.subarray(4) };
  });
  return { origin: lines[0], size, root, body, signatures, note };
}

// This is a structural gate. Applications MUST also verify the log signature
// cryptographically with their externally admitted log key before accepting it.
export function assertCheckpointLogSignature(checkpoint, { name, keyID }) {
  const cp = parseCheckpointEnvelope(checkpoint);
  requireValue(nameOK(name) && Buffer.isBuffer(keyID) && keyID.length === 4, 'CHECKPOINT_LOG_KEY');
  requireValue(cp.signatures.some(signature => signature.name === name && same(signature.keyID, keyID)), 'CHECKPOINT_LOG_SIGNATURE_REQUIRED');
  return cp;
}

function requestContext(value) {
  requireValue([value.start, value.end].every(number => typeof number !== 'number' || Number.isSafeInteger(number)), 'SUBTREE_RANGE');
  const cp = parseCheckpointEnvelope(value.checkpoint);
  requireValue(cp.signatures.length === 1, 'SUBTREE_ONE_WITNESS');
  const start = decimal(String(value.start)), end = decimal(String(value.end));
  requireValue(Buffer.isBuffer(value.root) && value.root.length === 32 && Array.isArray(value.proof) && value.proof.length <= 63 && value.proof.every(hash => Buffer.isBuffer(hash) && hash.length === 32), 'SUBTREE_REQUEST');
  requireValue(end <= cp.size, 'SUBTREE_CHECKPOINT_RANGE');
  subtreeInput({ name: cp.signatures[0].name, origin: cp.origin, start, end, root: value.root, timestamp: 0 });
  return { ...value, origin: cp.origin, start, end };
}
export function encodeSubtreeRequest(value) {
  const q = requestContext(value);
  return `subtree ${q.start} ${q.end}\n${q.root.toString('base64')}\n${q.proof.map(hash => hash.toString('base64') + '\n').join('')}\n${q.checkpoint}`;
}
export function parseSubtreeRequest(text) {
  requireValue(typeof text === 'string' && Buffer.byteLength(text) <= 1048576 && !text.includes('\r'), 'SUBTREE_REQUEST');
  const cut = text.indexOf('\n\n');
  requireValue(cut > 0, 'SUBTREE_REQUEST');
  const lines = text.slice(0, cut).split('\n'), range = /^subtree (0|[1-9][0-9]*) (0|[1-9][0-9]*)$/.exec(lines.shift());
  requireValue(range, 'SUBTREE_RANGE');
  return requestContext({ start: range[1], end: range[2], root: unbase64(lines.shift()), proof: lines.map(unbase64), checkpoint: text.slice(cut + 2) });
}

// Callers verify subtree consistency separately before signing. This validates
// the request's one checkpoint signature under the same selected response key.
export function verifySubtreeCheckpoint(checkpoint, { name, publicKey, at, maxFutureSkew = 30 }) {
  requireValue(Number.isSafeInteger(at) && at >= 0 && Number.isSafeInteger(maxFutureSkew) && maxFutureSkew >= 0, 'CHECKPOINT_TIME');
  const cp = parseCheckpointEnvelope(checkpoint);
  requireValue(cp.signatures.length === 1, 'SUBTREE_ONE_WITNESS');
  const selected = cp.signatures[0];
  requireValue(selected.name === name && same(selected.keyID, mlDsa87KeyID(name, publicKey)), 'SUBTREE_WITNESS_KEY');
  requireValue(selected.signature.length === 8 + 4627, 'CHECKPOINT_SIGNATURE');
  const timestamp = selected.signature.readBigUInt64BE(0);
  requireValue(timestamp <= BigInt(at) + BigInt(maxFutureSkew), 'CHECKPOINT_FUTURE');
  requireValue(verifyCosignature({ name, origin: cp.origin, start: 0n, end: cp.size, root: cp.root, timestamp }, selected.signature.subarray(8), publicKey), 'CHECKPOINT_SIGNATURE');
  return cp;
}
export function encodeSubtreeResponse(signature) {
  requireValue(Buffer.isBuffer(signature) && signature.length === 4627, 'SUBTREE_SIGNATURE_LENGTH');
  return signature.toString('base64') + '\n';
}
export function parseSubtreeResponse(text) {
  requireValue(typeof text === 'string' && text.length <= 8192 && /^[A-Za-z0-9+/]+={0,2}\n$/.test(text), 'SUBTREE_RESPONSE_ENCODING');
  const signature = unbase64(text.slice(0, -1));
  requireValue(signature.length === 4627, 'SUBTREE_SIGNATURE_LENGTH');
  return signature;
}
