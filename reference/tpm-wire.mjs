import { requireThat } from './core.mjs';
export const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
export const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
export const tpm2b = (bytes) => {
  requireThat(Buffer.isBuffer(bytes) && bytes.length <= 65535, 'TPM2B_LENGTH');
  return Buffer.concat([u16(bytes.length), bytes]);
};
const packet = (tag, code, body) =>
  Buffer.concat([u16(tag), u32(body.length + 10), u32(code), body]);
export const readPublicCommand = (handle) => packet(0x8001, 0x173, u32(handle));
export function certifyCommand({ objectHandle, akHandle, qualifyingData, akAlgorithm = 'ec' }) {
  requireThat(
    qualifyingData.length === 32 && ['ec', 'rsa'].includes(akAlgorithm),
    'TPM_CERTIFY_PARAMETERS',
  );
  const auth = Buffer.concat([u32(0x40000009), u16(0), Buffer.from([0]), u16(0)]),
    authorizations = Buffer.concat([auth, auth]);
  return packet(
    0x8002,
    0x148,
    Buffer.concat([
      u32(objectHandle),
      u32(akHandle),
      u32(authorizations.length),
      authorizations,
      tpm2b(qualifyingData),
      u16(akAlgorithm === 'ec' ? 0x18 : 0x14),
      u16(0x0b),
    ]),
  );
}
function response(raw, expectedTag) {
  requireThat(
    Buffer.isBuffer(raw) &&
      raw.length >= 10 &&
      raw.length <= 65536 &&
      raw.readUInt32BE(2) === raw.length,
    'TPM_RESPONSE_SIZE',
  );
  requireThat(raw.readUInt32BE(6) === 0, 'TPM_RESPONSE_' + raw.readUInt32BE(6).toString(16));
  requireThat(raw.readUInt16BE(0) === expectedTag, 'TPM_RESPONSE_TAG');
}
function read2b(raw, position) {
  requireThat(position + 2 <= raw.length, 'TPM_RESPONSE_TRUNCATED');
  const stop = position + 2 + raw.readUInt16BE(position);
  requireThat(stop <= raw.length, 'TPM_RESPONSE_TRUNCATED');
  return { value: raw.subarray(position + 2, stop), next: stop };
}
export function readPublicResponse(raw) {
  response(raw, 0x8001);
  const pub = read2b(raw, 10),
    name = read2b(raw, pub.next),
    qualifiedName = read2b(raw, name.next);
  requireThat(qualifiedName.next === raw.length, 'TPM_RESPONSE_TRAILING');
  return { pubArea: pub.value, name: name.value, qualifiedName: qualifiedName.value };
}
export function certifyResponse(raw) {
  response(raw, 0x8002);
  requireThat(raw.length >= 18, 'TPM_RESPONSE_SIZE');
  const end = 14 + raw.readUInt32BE(10);
  requireThat(end + 10 === raw.length, 'TPM_RESPONSE_AUTH_SIZE');
  // Each empty TPM_RS_PW response has an empty nonce/HMAC and only continueSession may be set.
  for (const offset of [end, end + 5])
    requireThat(
      raw.readUInt16BE(offset) === 0 &&
        !(raw[offset + 2] & ~1) &&
        raw.readUInt16BE(offset + 3) === 0,
      'TPM_RESPONSE_AUTH',
    );
  const info = read2b(raw.subarray(0, end), 14);
  requireThat(info.next + 6 <= end, 'TPM_RESPONSE_SIGNATURE');
  return { certInfo: info.value, signature: raw.subarray(info.next, end) };
}
