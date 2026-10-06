import { createPublicKey, hkdfSync, createHmac } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { hash_to_field } from '@noble/curves/abstract/hash-to-curve.js';
import { sha256 as nobleSHA256 } from '@noble/hashes/sha2.js';
import { requireThat, b64u } from './core.mjs';
import { encode, decode } from './cose.mjs';

export const ARKG_OPERATION = -65539;
export const ARKG_SEED_ALGORITHM = -65700;
const utf8 = (s) => Buffer.from(s, 'utf8');
const scalar = (message, dst) =>
  hash_to_field(message, 1, {
    DST: dst,
    p: p256.Point.Fn.ORDER,
    m: 1,
    k: 128,
    expand: 'xmd',
    hash: nobleSHA256,
  })[0][0];
const hkdf = (ikm, info) => Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(32), info, 32));
function point(cose) {
  requireThat(
    cose instanceof Map &&
      cose.get(1) === 2 &&
      cose.get(-1) === 1 &&
      Buffer.isBuffer(cose.get(-2)) &&
      cose.get(-2).length === 32 &&
      Buffer.isBuffer(cose.get(-3)) &&
      cose.get(-3).length === 32 &&
      !cose.has(-4),
    'ARKG_POINT',
  );
  return p256.Point.fromBytes(Buffer.concat([Buffer.from([4]), cose.get(-2), cose.get(-3)]));
}
export function arkgSeedPublicKeys(raw) {
  const seed = decode(raw);
  requireThat(
    seed instanceof Map &&
      seed.get(1) === -65537 &&
      seed.get(3) === ARKG_SEED_ALGORITHM &&
      seed.size === 4,
    'ARKG_SEED',
  );
  return { blinding: point(seed.get(-1)), kem: point(seed.get(-2)) };
}
export function p256PublicKey(bytes) {
  const p = p256.Point.fromBytes(bytes).toBytes(false);
  return createPublicKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: b64u(p.slice(1, 33)),
      y: b64u(p.slice(33)),
    },
  });
}

// Public derivation for the pinned Yubico ARKG-P256 preview. No seed private key is used here.
export function deriveARKG({ seedPublicKey, ikm, context }) {
  requireThat(
    Buffer.isBuffer(ikm) && ikm.length === 32 && Buffer.isBuffer(context) && context.length <= 64,
    'ARKG_INPUT',
  );
  const { blinding, kem } = arkgSeedPublicKeys(seedPublicKey);
  const ctxPrime = Buffer.concat([Buffer.from([context.length]), context]);
  const ctxKem = Buffer.concat([utf8('ARKG-Derive-Key-KEM.'), ctxPrime]);
  const ctxBl = Buffer.concat([utf8('ARKG-Derive-Key-BL.'), ctxPrime]);
  const kemDST = utf8('ARKG-ECDH.ARKG-P256');
  const ephemeral = scalar(ikm, Buffer.concat([utf8('ARKG-KEM-ECDH-KG.'), kemDST]));
  requireThat(ephemeral !== 0n, 'ARKG_ZERO_SCALAR');
  const cPrime = Buffer.from(p256.Point.BASE.multiply(ephemeral).toBytes(false));
  const shared = Buffer.from(kem.multiply(ephemeral).toBytes(false).slice(1, 33));
  const macKey = hkdf(shared, Buffer.concat([utf8('ARKG-KEM-HMAC-mac.'), kemDST, ctxKem]));
  const mac = createHmac('sha256', macKey).update(cPrime).digest().subarray(0, 16);
  const ikmTau = hkdf(shared, Buffer.concat([utf8('ARKG-KEM-HMAC-shared.'), kemDST, ctxKem]));
  const tau = scalar(ikmTau, Buffer.concat([utf8('ARKG-BL-EC.ARKG-P256'), ctxBl]));
  const derived = tau === 0n ? blinding : blinding.add(p256.Point.BASE.multiply(tau));
  requireThat(!derived.equals(p256.Point.ZERO), 'ARKG_IDENTITY_POINT');
  const ticket = Buffer.concat([mac, cPrime]);
  return {
    publicKey: p256PublicKey(derived.toBytes(false)),
    ticket,
    additionalArgs: arkgAdditionalArgs({ context, ticket }),
  };
}
export function arkgAdditionalArgs({ context, ticket }) {
  requireThat(
    Buffer.isBuffer(context) &&
      context.length <= 64 &&
      Buffer.isBuffer(ticket) &&
      ticket.length === 81,
    'ARKG_ARGS',
  );
  p256.Point.fromBytes(ticket.subarray(16));
  return encode(
    new Map([
      [3, ARKG_OPERATION],
      [-3, ARKG_SEED_ALGORITHM],
      [-2, context],
      [-1, ticket],
    ]),
  );
}
