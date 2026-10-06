import assert from 'node:assert/strict';
import { Decoder } from 'cbor-x';
import { ProtocolError, decodeCBOR, dcbor, parseDER } from '../core.mjs';
import { decode as isoDecode } from '../cose.mjs';
import { decodeProof, encodeProof } from '../mtc.mjs';
import { clientData } from '../webauthn.mjs';
import { parseCheckpoint } from '../transparency.mjs';
import { parseJSON } from '../json.mjs';
// Object decoding can rename __proto__; Map preserves the original CBOR key.
const decoder = new Decoder({ mapsAsObjects: false, useRecords: false });
const normalize = (v) =>
  typeof v === 'bigint' &&
  v >= BigInt(Number.MIN_SAFE_INTEGER) &&
  v <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(v)
    : Buffer.isBuffer(v) || v instanceof Uint8Array
      ? [...v]
      : Array.isArray(v)
        ? v.map(normalize)
        : v instanceof Map
          ? Object.fromEntries([...v].map(([k, x]) => [k, normalize(x)]))
          : v && typeof v === 'object'
            ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, normalize(x)]))
            : v;
export function expectedRejection(error) {
  return (
    error instanceof ProtocolError ||
    error?.code === 'ERR_ENCODING_INVALID_ENCODED_DATA' ||
    error instanceof SyntaxError ||
    /^JSON_(SIZE|DEPTH|STRING|KEY|DUPLICATE|COLON|SEPARATOR|TRUNCATED|TRAILING|NUMBER|VALUE)$/.test(
      error?.message ?? '',
    )
  );
}
export function fuzz(data) {
  if (data.length < 1 || data.length > 65537) return;
  const bytes = data.subarray(1);
  let accepted;
  try {
    switch (data[0] % 7) {
      case 0:
        accepted = decodeCBOR(bytes, { maxBytes: 65536, maxItems: 4096 });
        break;
      case 1:
        parseDER(bytes);
        return;
      case 2:
        isoDecode(bytes, { maxBytes: 65536 });
        return;
      case 3: {
        const proof = decodeProof(bytes);
        assert.deepEqual(encodeProof(proof), bytes);
        return;
      }
      case 4:
        clientData(bytes, {
          type: 'webauthn.get',
          origin: 'https://verifier.example',
          challenge: Buffer.alloc(32),
        });
        return;
      case 5:
        parseCheckpoint(bytes.toString('utf8'));
        return;
      case 6:
        parseJSON(bytes.toString('utf8'), { maxBytes: 65536 });
        return;
    }
  } catch (error) {
    if (expectedRejection(error)) return;
    throw error;
  }
  // RRA acceptance implies identical value in an independently maintained CBOR parser.
  assert.deepEqual(normalize(decoder.decode(bytes)), normalize(accepted));
  assert(dcbor(accepted).equals(bytes));
}
