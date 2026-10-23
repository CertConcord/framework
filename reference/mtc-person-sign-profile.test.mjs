import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as m from './mtc.mjs';

const at = 1792771200,
  profileID = 'CERTCONCORD-PERSON-SIGN-v1',
  ca = { id: '32473.201', ...c.generate('ml-dsa-87') },
  mirrors = [202, 203, 204].map((n) => ({
    id: '32473.' + n,
    operatorID: 'profile-mirror-' + n,
    ...c.generate('ml-dsa-87'),
  }));

for (const mode of ['STANDALONE', 'LANDMARK'])
  for (const algorithm of ['ml-dsa-65', 'ml-dsa-87', 'ed25519', 'p256', 'p384'])
    test(`MTC PERSON-SIGN profile admits only the selected document suite in ${mode}: ${algorithm}`, () => {
      const key =
        algorithm === 'p384'
          ? generateKeyPairSync('ec', { namedCurve: 'secp384r1' })
          : c.generate(algorithm === 'p256' ? 'ec' : algorithm);
      const tbs = m.createMTCTBS(
        {
          publicKey: key.publicKey,
          subject: p.name('Person signing profile'),
          notBefore: at - 60,
          notAfter: at + 3600,
          profileID,
        },
        { caID: ca.id, logNumber: 1, index: 0 },
      );
      const entries = [m.logEntryFromTBS(tbs)],
        raw = m.issueMTC(tbs, {
          entries,
          index: 0,
          caID: ca.id,
          logNumber: 1,
          cosigners: [ca, ...mirrors],
        }),
        options = {
          caID: ca.id,
          caPublicKey: ca.publicKey,
          members: mirrors,
          threshold: 2,
          policyHash: Buffer.alloc(64, 1),
          rtmHash: Buffer.alloc(64, 2),
          membershipEpoch: 1,
          at,
        };
      if (mode === 'LANDMARK')
        options.trustedSubtrees = [
          {
            ...options,
            logNumber: 1,
            start: 0,
            end: 1,
            root: m.treeHash(entries),
            mode: 'LIVE',
            validFrom: at - 1,
            expiresAt: at + 1,
          },
        ];
      const proof = m.verifyMTC(raw, options);
      assert.equal(proof.mode, mode);
      assert.deepEqual(proof.certificate.raw, raw);
      const selected = () => m.verifyMTC(raw, { ...options, profileID });
      if (algorithm.startsWith('ml-dsa-')) {
        const result = selected();
        assert.equal(result.mode, mode);
        assert.deepEqual(result.certificate.raw, raw);
      } else assert.throws(selected, { code: 'MTC_DOCUMENT_KEY_ALGORITHM' });
    });
