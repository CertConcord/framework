import { randomBytes } from 'node:crypto';
import { TextDecoder } from 'node:util';
import {
  ProtocolError,
  der,
  seq,
  oid,
  oidText,
  integer,
  intValue,
  octet,
  parseDER,
  equal,
} from './core.mjs';
import { OID, algID, generalizedTime } from './pki.mjs';

const HASHES = new Map([
  [OID.sha256, { name: 'sha256', length: 32 }],
  [OID.sha512, { name: 'sha512', length: 64 }],
]);
const FAILURE_BITS = Object.freeze({
  badAlg: 0,
  badRequest: 2,
  badDataFormat: 5,
  timeNotAvailable: 14,
  unacceptedPolicy: 15,
  unacceptedExtension: 16,
  addInfoNotAvailable: 17,
  systemFailure: 25,
});
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const diagnostic = (overall, reason) => Object.freeze({ overall, reason });
function error(code, overall = 'INVALID', failureInfo = 'badDataFormat', partial) {
  const value = new ProtocolError(code);
  Object.assign(value, {
    overall,
    reason: code,
    failureInfo,
    failureBit: FAILURE_BITS[failureInfo],
  });
  if (partial) value.partial = partial;
  return value;
}
function check(condition, code, overall, failureInfo) {
  if (!condition) throw error(code, overall, failureInfo);
}
function codec(operation) {
  try {
    return operation();
  } catch (caught) {
    if (caught instanceof ProtocolError && caught.overall) throw caught;
    throw error(caught.code ?? 'TSP_ENCODING');
  }
}
function bytes(value, limit, label) {
  check(Buffer.isBuffer(value) || value instanceof Uint8Array, `TSP_${label}_REQUIRED`);
  check(
    value.length > 0 && value.length <= limit,
    `TSP_${label}_LIMIT`,
    'UNSUPPORTED',
    'badRequest',
  );
  return Buffer.from(value);
}
function identifier(node) {
  check(node?.tag === 6, 'TSP_OID_ENCODING');
  check(node.value.length <= 256, 'TSP_OID_LIMIT', 'UNSUPPORTED', 'badRequest');
  return oidText(node);
}
function identifierDER(value) {
  check(typeof value === 'string' && value.length <= 256, 'TSP_OID_REQUIRED');
  const encoded = oid(value);
  check(identifier(parseDER(encoded)) === value, 'TSP_OID_ENCODING');
  return encoded;
}
function boundedInteger(value, bits, label, positive = false) {
  check(
    typeof value === 'bigint' || (typeof value === 'number' && Number.isSafeInteger(value)),
    `TSP_${label}_INTEGER`,
  );
  value = BigInt(value);
  check(
    value >= (positive ? 1n : 0n) && value < 1n << BigInt(bits),
    `TSP_${label}_RANGE`,
    'UNSUPPORTED',
    'badRequest',
  );
  return value;
}
function parsedNonce(node) {
  if (!node) return undefined;
  check(!(node.value[0] & 128), 'TSP_NONCE_RANGE', 'UNSUPPORTED', 'badRequest');
  check(node.value.length <= 33, 'TSP_NONCE_RANGE', 'UNSUPPORTED', 'badRequest');
  return boundedInteger(intValue(node), 256, 'NONCE');
}
function selectedImprint(node) {
  check(
    node?.tag === 0x30 && node.children.length === 2 && node.children[1].tag === 4,
    'TSP_IMPRINT_ENCODING',
  );
  const algorithm = node.children[0];
  check(algorithm.tag === 0x30 && [1, 2].includes(algorithm.children.length), 'TSP_HASH_ENCODING');
  const hashOID = identifier(algorithm.children[0]);
  const selected = HASHES.get(hashOID),
    imprint = Buffer.from(node.children[1].value);
  if (selected) check(imprint.length === selected.length, 'TSP_IMPRINT_LENGTH');
  return {
    hashOID,
    imprint,
    supported:
      !!selected &&
      (!algorithm.children[1] || equal(algorithm.children[1].raw, Buffer.from('0500', 'hex'))),
  };
}
function extensionFields(node) {
  if (!node) return [];
  check(node.children.length > 0, 'TSP_EXTENSIONS_EMPTY');
  const seen = new Set();
  return node.children.map((entry) => {
    const fields = entry.children;
    check(
      entry.tag === 0x30 && [2, 3].includes(fields?.length) && fields.at(-1).tag === 4,
      'TSP_EXTENSION_ENCODING',
    );
    const id = identifier(fields[0]);
    check(!seen.has(id), 'TSP_EXTENSION_DUPLICATE');
    seen.add(id);
    const critical = fields.length === 3;
    check(
      !critical || equal(fields[1].raw, Buffer.from('0101ff', 'hex')),
      'TSP_EXTENSION_CRITICAL',
    );
    return Object.freeze({ id, critical, value: Buffer.from(fields.at(-1).value) });
  });
}

/** Selected RFC 3161 request codec. This function grants no timestamp trust. */
export function parseTimestampRequest(requestDER) {
  return codec(() => {
    const raw = bytes(requestDER, 65536, 'REQUEST'),
      root = parseDER(raw),
      fields = root.children;
    check(root.tag === 0x30 && fields.length >= 2 && fields[0].tag === 2, 'TSP_REQUEST_ENCODING');
    const optional = new Map();
    let previous = -1;
    for (const field of fields.slice(2)) {
      const rank = [6, 2, 1, 0xa0].indexOf(field.tag);
      check(rank > previous, 'TSP_REQUEST_FIELD_ORDER');
      previous = rank;
      optional.set(field.tag, field);
    }
    const selected = selectedImprint(fields[1]);
    const policyOID = optional.has(6) ? identifier(optional.get(6)) : undefined;
    const certReq = optional.has(1);
    check(
      !certReq || equal(optional.get(1).raw, Buffer.from('0101ff', 'hex')),
      'TSP_CERTREQ_ENCODING',
    );
    const extensions = extensionFields(optional.get(0xa0));
    const nonce = parsedNonce(optional.get(2));
    check(equal(fields[0].raw, integer(1)), 'TSP_VERSION_UNSUPPORTED', 'UNSUPPORTED', 'badRequest');
    check(selected.supported, 'TSP_HASH_UNSUPPORTED', 'UNSUPPORTED', 'badAlg');
    check(!extensions.length, 'TSP_EXTENSIONS_UNSUPPORTED', 'UNSUPPORTED', 'unacceptedExtension');
    return Object.freeze({
      raw,
      hashOID: selected.hashOID,
      imprint: selected.imprint,
      ...(policyOID !== undefined ? { policyOID } : {}),
      ...(nonce !== undefined ? { nonce } : {}),
      certReq,
      extensions,
    });
  });
}

/** nonce:null deliberately omits the nonce; undefined generates a new positive value. */
export function encodeTimestampRequest({
  imprint,
  hashAlgorithm = 'sha256',
  policyOID,
  nonce,
  certReq = true,
} = {}) {
  return codec(() => {
    const selected = [...HASHES].find(([, entry]) => entry.name === hashAlgorithm);
    check(selected, 'TSP_HASH_UNSUPPORTED', 'UNSUPPORTED', 'badAlg');
    imprint = bytes(imprint, 64, 'IMPRINT');
    check(imprint.length === selected[1].length, 'TSP_IMPRINT_LENGTH');
    check(typeof certReq === 'boolean', 'TSP_CERTREQ_ENCODING');
    if (nonce === undefined) {
      const random = randomBytes(16);
      random[0] |= 128;
      nonce = BigInt('0x' + random.toString('hex'));
    }
    const request = seq(
      integer(1),
      seq(algID(selected[0]), octet(imprint)),
      ...(policyOID !== undefined ? [identifierDER(policyOID)] : []),
      ...(nonce !== null ? [integer(boundedInteger(nonce, 256, 'NONCE'))] : []),
      ...(certReq ? [der(1, Buffer.from([255]))] : []),
    );
    parseTimestampRequest(request);
    return request;
  });
}

function statusStrings(node) {
  if (!node) return [];
  check(node.children.length >= 1 && node.children.length <= 8, 'TSP_STATUS_TEXT_LIMIT');
  return node.children.map((entry) => {
    check(entry.tag === 12 && entry.value.length <= 1024, 'TSP_STATUS_TEXT_ENCODING');
    let text;
    try {
      text = utf8.decode(entry.value);
    } catch {
      throw error('TSP_STATUS_TEXT_UTF8');
    }
    check(equal(Buffer.from(text, 'utf8'), entry.value), 'TSP_STATUS_TEXT_UTF8');
    return text;
  });
}
function failureBits(node) {
  if (!node) return [];
  const value = node.value,
    unused = value[0];
  check(value.length >= 1 && unused <= 7, 'TSP_FAILURE_BITS_ENCODING');
  check(value.length > 1 || unused === 0, 'TSP_FAILURE_BITS_ENCODING');
  if (value.length > 1) {
    const last = value.at(-1);
    check(
      last !== 0 && (last & ((1 << unused) - 1)) === 0 && last & (1 << unused),
      'TSP_FAILURE_BITS_ENCODING',
    );
  }
  const bits = [];
  for (let index = 1; index < value.length; index++)
    for (let bit = 0; bit < 8; bit++)
      if (value[index] & (128 >> bit)) bits.push((index - 1) * 8 + bit);
  return bits;
}
function failureBitsDER(values) {
  check(Array.isArray(values) && values.length <= 8, 'TSP_FAILURE_BITS_ENCODING');
  check(new Set(values).size === values.length, 'TSP_FAILURE_BITS_DUPLICATE');
  check(
    values.every((value) => Object.values(FAILURE_BITS).includes(value)),
    'TSP_FAILURE_BITS_UNSUPPORTED',
    'UNSUPPORTED',
    'badRequest',
  );
  if (!values.length) return undefined;
  const highest = Math.max(...values),
    value = Buffer.alloc(Math.floor(highest / 8) + 2);
  value[0] = 7 - (highest % 8);
  for (const bit of values) value[1 + Math.floor(bit / 8)] |= 128 >> bit % 8;
  return der(3, value);
}

/** Preserve safely extracted token bytes for known-invalid precedence in the verifier. */
export function parseTimestampResponse(responseDER) {
  return codec(() => {
    const raw = bytes(responseDER, 1048576, 'RESPONSE'),
      root = parseDER(raw),
      fields = root.children;
    check(root.tag === 0x30 && [1, 2].includes(fields.length), 'TSP_RESPONSE_ENCODING');
    const info = fields[0];
    check(
      info.tag === 0x30 && info.children.length >= 1 && info.children[0].tag === 2,
      'TSP_STATUS_ENCODING',
    );
    if (fields[1]) check(fields[1].tag === 0x30, 'TSP_TOKEN_ENCODING');
    const optional = new Map();
    let previous = -1;
    for (const field of info.children.slice(1)) {
      const rank = [0x30, 3].indexOf(field.tag);
      check(rank > previous, 'TSP_STATUS_FIELD_ORDER');
      previous = rank;
      optional.set(field.tag, field);
    }
    const strings = statusStrings(optional.get(0x30)),
      bits = failureBits(optional.get(3));
    const statusNode = info.children[0];
    check(statusNode.value.length <= 4, 'TSP_STATUS_UNSUPPORTED', 'UNSUPPORTED', 'badRequest');
    let status = 0;
    for (const value of statusNode.value) status = status * 256 + value;
    if (statusNode.value[0] & 128) status -= 2 ** (statusNode.value.length * 8);
    const tokenDER = fields[1] && Buffer.from(fields[1].raw),
      diagnostics = [];
    if (status < 0 || status > 5)
      diagnostics.push(diagnostic('UNSUPPORTED', 'TSP_STATUS_UNSUPPORTED'));
    if (bits.some((bit) => !Object.values(FAILURE_BITS).includes(bit)))
      diagnostics.push(diagnostic('UNSUPPORTED', 'TSP_FAILURE_BITS_UNSUPPORTED'));
    const result = Object.freeze({
      raw,
      status,
      statusStrings: Object.freeze(strings),
      failureBits: Object.freeze(bits),
      ...(tokenDER ? { tokenDER } : {}),
      diagnostics: Object.freeze(diagnostics),
    });
    if (([0, 1].includes(status) && !tokenDER) || ([2, 3, 4, 5].includes(status) && tokenDER))
      throw error('TSP_STATUS_TOKEN_BINDING', 'INVALID', 'badDataFormat', result);
    if ([0, 1].includes(status) && bits.length)
      throw error('TSP_STATUS_FAILURE_CONTRADICTION', 'INVALID', 'badDataFormat', result);
    return result;
  });
}

export function encodeTimestampResponse({
  status,
  tokenDER,
  statusStrings: strings = [],
  failureBits: bits = [],
} = {}) {
  return codec(() => {
    check(
      Number.isInteger(status) && status >= 0 && status <= 5,
      'TSP_STATUS_UNSUPPORTED',
      'UNSUPPORTED',
      'badRequest',
    );
    check(Array.isArray(strings) && strings.length <= 8, 'TSP_STATUS_TEXT_LIMIT');
    const texts = strings.map((text) => {
      check(typeof text === 'string', 'TSP_STATUS_TEXT_ENCODING');
      const encoded = Buffer.from(text, 'utf8');
      check(encoded.length <= 1024 && utf8.decode(encoded) === text, 'TSP_STATUS_TEXT_ENCODING');
      return der(12, encoded);
    });
    const failInfo = failureBitsDER(bits);
    const response = seq(
      seq(
        integer(status),
        ...(texts.length ? [seq(...texts)] : []),
        ...(failInfo ? [failInfo] : []),
      ),
      ...(tokenDER !== undefined ? [bytes(tokenDER, 1048576, 'TOKEN')] : []),
    );
    parseTimestampResponse(response);
    return response;
  });
}

/** Exact integral microsecond decomposition; the caller admits clock and authority. */
export function encodeTSTInfo({
  policyOID,
  hashOID,
  imprint,
  serial,
  genTime,
  accuracyMicros,
  nonce,
} = {}) {
  return codec(() => {
    const hash = HASHES.get(hashOID);
    check(hash, 'TSP_HASH_UNSUPPORTED', 'UNSUPPORTED', 'badAlg');
    imprint = bytes(imprint, 64, 'IMPRINT');
    check(imprint.length === hash.length, 'TSP_IMPRINT_LENGTH');
    check(
      Number.isSafeInteger(genTime) && genTime >= 0 && genTime <= 253402300799,
      'TSP_TIME_RANGE',
    );
    check(
      Number.isSafeInteger(accuracyMicros) && accuracyMicros >= 0 && accuracyMicros <= 60000000,
      'TSP_ACCURACY_RANGE',
    );
    check(BigInt(genTime) * 1000000n >= BigInt(accuracyMicros), 'TSP_TIME_RANGE');
    const seconds = Math.floor(accuracyMicros / 1000000),
      millis = Math.floor(accuracyMicros / 1000) % 1000,
      micros = accuracyMicros % 1000;
    const implicit = (tag, value) => der(tag, parseDER(integer(value)).value);
    return seq(
      integer(1),
      identifierDER(policyOID),
      seq(algID(hashOID), octet(imprint)),
      integer(boundedInteger(serial, 160, 'SERIAL', true)),
      generalizedTime(genTime),
      seq(
        ...(seconds || !accuracyMicros ? [integer(seconds)] : []),
        ...(millis ? [implicit(0x80, millis)] : []),
        ...(micros ? [implicit(0x81, micros)] : []),
      ),
      ...(nonce !== undefined ? [integer(boundedInteger(nonce, 256, 'NONCE'))] : []),
    );
  });
}
