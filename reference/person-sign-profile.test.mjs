import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';

const at = 1792771200,
  profileID = 'CERTCONCORD-PERSON-SIGN-v1',
  issuer = c.generate('ml-dsa-87');

for (const algorithm of ['ml-dsa-65', 'ml-dsa-87', 'ed25519', 'p256', 'p384'])
  test(`X509 PERSON-SIGN profile admits only the selected document suite: ${algorithm}`, () => {
    const key =
      algorithm === 'p384'
        ? generateKeyPairSync('ec', { namedCurve: 'secp384r1' })
        : c.generate(algorithm === 'p256' ? 'ec' : algorithm);
    const raw = p.issueCertificate(
      {
        publicKey: key.publicKey,
        issuer: p.name('Profile CA'),
        subject: p.name('Person signing profile'),
        serial: 1n,
        notBefore: at - 60,
        notAfter: at + 3600,
        profileID,
      },
      issuer.privateKey,
    );
    assert.deepEqual(p.validateCertificate(raw, issuer.publicKey, { at }).raw, raw);
    const selected = () => p.validateCertificate(raw, issuer.publicKey, { at, profileID });
    if (algorithm.startsWith('ml-dsa-')) assert.deepEqual(selected().raw, raw);
    else assert.throws(selected, { code: 'CERTIFICATE_DOCUMENT_KEY_ALGORITHM' });
  });
