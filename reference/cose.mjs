import { sign, verify } from 'node:crypto';
import { requireThat } from './core.mjs';
import { Tag, encode, decode } from './vendor/mdoc-signing/cbor.mjs';
export {
  Tag,
  encode,
  decode,
  get,
  embedded,
  unembed,
  coseKey,
  coseJWK,
} from './vendor/mdoc-signing/cbor.mjs';

export function prepareSign1(payload, { certificate, detached = false } = {}) {
  const protectedBytes = encode(new Map([[1, -7]])),
    unprotected = new Map(certificate ? [[33, certificate]] : []);
  return {
    tbs: encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]),
    finish: (signature) => [
      protectedBytes,
      unprotected,
      detached ? null : payload,
      Buffer.from(signature),
    ],
  };
}
export function sign1(payload, key, options) {
  const p = prepareSign1(payload, options);
  return p.finish(sign('sha256', p.tbs, { key, dsaEncoding: 'ieee-p1363' }));
}
export function verify1(value, key, { detached } = {}) {
  const c = value instanceof Tag && value.tag === 18 ? value.value : value;
  requireThat(
    Array.isArray(c) &&
      c.length === 4 &&
      Buffer.isBuffer(c[0]) &&
      c[1] instanceof Map &&
      Buffer.isBuffer(c[3]) &&
      c[3].length === 64,
    'COSE_SIGN1',
  );
  const headers = decode(c[0]);
  requireThat(
    headers instanceof Map &&
      headers.size === 1 &&
      headers.get(1) === -7 &&
      !c[1].has(1) &&
      !c[1].has(2),
    'COSE_ALGORITHM_OR_CRITICAL',
  );
  requireThat(
    (detached !== undefined && c[2] === null) || (detached === undefined && Buffer.isBuffer(c[2])),
    'COSE_PAYLOAD_MODE',
  );
  const payload = detached ?? c[2];
  requireThat(
    key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails.namedCurve === 'prime256v1',
    'COSE_KEY_ALGORITHM',
  );
  requireThat(
    verify(
      'sha256',
      encode(['Signature1', c[0], Buffer.alloc(0), payload]),
      { key, dsaEncoding: 'ieee-p1363' },
      c[3],
    ),
    'COSE_SIGNATURE',
  );
  return { payload, certificate: c[1].get(33) };
}
