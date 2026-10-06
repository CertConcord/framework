import test from 'node:test';
import assert from 'node:assert/strict';
import { compactVerify, CompactSign, compactDecrypt, CompactEncrypt, importSPKI } from 'jose';
import * as c from './core.mjs';
import { publicJWK, signJWS, verifyJWS, encryptJWE, decryptJWE } from './jose.mjs';
import { parseVPRequest, PresentationVerifier } from './openid.mjs';
import { issueCertificate, name } from './pki.mjs';
import { X509Certificate } from 'node:crypto';
import { Journal } from './state.mjs';

test('independent JOSE library verifies ES256 and ML-DSA; ECDH-ES JWE interoperates both directions', async () => {
  for (const type of ['ec', 'ml-dsa-65', 'ml-dsa-87']) {
    const k = c.generate(type),
      token = signJWS(Buffer.from('independent bytes'), k.privateKey),
      v = await compactVerify(token, k.publicKey);
    assert.equal(Buffer.from(v.payload).toString(), 'independent bytes');
    const alg = type === 'ec' ? 'ES256' : type.toUpperCase(),
      external = await new CompactSign(Buffer.from('external bytes'))
        .setProtectedHeader({ alg })
        .sign(k.privateKey);
    assert.equal(verifyJWS(external, k.publicKey).payload.toString(), 'external bytes');
  }
  const k = c.generate('ec'),
    value = { message: 'independent JWE' },
    ours = encryptJWE(value, publicJWK(k.publicKey));
  assert.deepEqual(
    JSON.parse(Buffer.from((await compactDecrypt(ours, k.privateKey)).plaintext)),
    value,
  );
  const theirs = await new CompactEncrypt(Buffer.from(JSON.stringify(value)))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
    .encrypt(k.publicKey);
  assert.equal(decryptJWE(theirs, k.privateKey).message, value.message);
});

test('DC API unsigned and multisigned requests enforce origin, authenticated client identity and signature', () => {
  const ca = c.generate('ec'),
    key = c.generate('ec'),
    root = issueCertificate(
      { publicKey: ca.publicKey, issuer: name('Root'), subject: name('Root'), serial: 1, ca: true },
      ca.privateKey,
    ),
    certificate = issueCertificate(
      { publicKey: key.publicKey, issuer: name('Root'), subject: name('Reader'), serial: 2 },
      ca.privateKey,
    ),
    roots = [new X509Certificate(root)],
    journal = new Journal(),
    origin = 'https://reader.example';
  try {
    const verifier = new PresentationVerifier({
        baseURL: origin,
        journal,
        privateKey: key.privateKey,
        certificate,
        issuerRegistry: new Map(),
        trustRoots: roots,
      }),
      request = verifier.request({ sessionID: 'synthetic', mode: 'dc_api.jwt', origin }),
      unsigned = {
        protocol: 'openid4vp-v1-unsigned',
        data: {
          ...request.request,
          client_id: 'untrusted',
          expected_origins: ['https://attacker.example'],
          state: 'ignored',
        },
      };
    const parsed = parseVPRequest(unsigned, { verifierRoots: roots, origin });
    assert.equal(parsed.client_id, undefined);
    assert.equal(parsed.state, undefined);
    assert.throws(
      () => parseVPRequest(unsigned, { verifierRoots: roots, origin: 'http://insecure.example' }),
      /ORIGIN/,
    );
    const { client_id, ...payload } = request.request,
      token = signJWS(payload, key.privateKey, {
        typ: 'oauth-authz-req+jwt',
        x5c: [certificate.toString('base64')],
        client_id,
      }),
      [protectedHeader, body, signature] = token.split('.'),
      multi = {
        protocol: 'openid4vp-v1-multisigned',
        data: {
          request: { payload: body, signatures: [{ protected: protectedHeader, signature }] },
        },
      };
    assert.equal(parseVPRequest(multi, { verifierRoots: roots, origin }).client_id, client_id);
    multi.data.request.signatures[0].signature = c.b64u(c.random(64));
    assert.throws(
      () => parseVPRequest(multi, { verifierRoots: roots, origin }),
      /NO_TRUSTED_SIGNATURE/,
    );
  } finally {
    journal.close();
  }
});
