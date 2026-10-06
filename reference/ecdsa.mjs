import { parseDER, seq, integer, requireThat } from './core.mjs';
const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
function scalar(bytes) {
  requireThat(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 33, 'ECDSA_SCALAR');
  const n = BigInt('0x' + bytes.toString('hex'));
  requireThat(n > 0n && n < order, 'ECDSA_SCALAR');
  return n;
}
export function derToP1363(signature) {
  const node = parseDER(signature);
  requireThat(node.tag === 48 && node.children?.length === 2, 'ECDSA_DER');
  return Buffer.concat(
    node.children.map((n) => {
      requireThat(n.tag === 2 && !(n.value[0] & 128), 'ECDSA_DER');
      return Buffer.from(scalar(n.value).toString(16).padStart(64, '0'), 'hex');
    }),
  );
}
export function p1363ToDER(signature) {
  requireThat(Buffer.isBuffer(signature) && signature.length === 64, 'ECDSA_P1363');
  return seq(integer(scalar(signature.subarray(0, 32))), integer(scalar(signature.subarray(32))));
}
