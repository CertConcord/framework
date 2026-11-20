import test from 'node:test';
import assert from 'node:assert/strict';
import { verify as verifySignature } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { issueCRL, verifyCRL } from './revocation.mjs';
import { prepareCAdESSignature, verifyCAdES } from './cades.mjs';
import { fixture, epoch, opensslAvailable } from './cades-fixtures.mjs';

const cases = JSON.parse(readFileSync(new URL('./vectors/crl-issuer-entry-admission.json', import.meta.url)));

test('complete CRL issuer rejects removeFromCRL before signing and retains certificateHold', () => {
  const key = c.generate('ec');
  const issuer = p.name('Synthetic complete CRL issuer');
  const settings = { issuer, privateKey: key.privateKey, number: 3,
    thisUpdate: epoch, nextUpdate: epoch + 100 };
  const entry = { serial: 17, revokedAt: epoch - 1 };
  assert.throws(() => issueCRL({ ...settings, entries: [{ ...entry, reason: 8 }] }),
    { code: cases.issuer.removeFromCRL });
  const hold = issueCRL({ ...settings, entries: [{ ...entry, reason: 6 }] });
  const holdNode = c.parseDER(hold);
  assert(verifySignature('sha256', holdNode.children[0].raw, key.publicKey,
    holdNode.children[2].value.subarray(1)));
  const options = { issuer, publicKey: key.publicKey, serial: 17, at: epoch,
    knowledgeTime: epoch };
  assert.equal(verifyCRL(hold, options).reason, cases.verifier.certificateHold);

  // Independently encode and sign an out-of-profile complete CRL, bypassing issueCRL.
  const fields = holdNode.children[0].children;
  const revoked = fields[5].children[0].children;
  const reason8Entry = c.seq(revoked[0].raw, revoked[1].raw,
    c.seq(p.extension('2.5.29.21', c.der(10, Buffer.from([8])))));
  const reason8TBS = c.seq(...fields.map((field, i) =>
    i === 5 ? c.seq(reason8Entry) : field.raw));
  const reason8 = c.seq(reason8TBS, holdNode.children[1].raw,
    c.bit(c.sign(reason8TBS, key.privateKey)));
  assert(verifySignature('sha256', reason8TBS, key.publicKey,
    c.parseDER(reason8).children[2].value.subarray(1)));
  assert.equal(verifyCRL(reason8, { ...options, serial: 99 }).reason,
    cases.verifier.removeFromCRL);
  reason8[reason8.length - 1] ^= 1;
  assert.equal(verifyCRL(reason8, options).reason, cases.verifier.badSignature);
});

test('CAdES complete CRL entry admits noncritical invalidity dates on either side of revocation',
  { skip: !opensslAvailable }, () => {
    const f = fixture();
    try {
      const cms = f.baseCMS({ prepareCAdESSignature }, { detached: false });
      const verify = (crl) => verifyCAdES(cms, { content: f.content,
        minimumLevel: 'B', validationTime: epoch + 40, knowledgeTime: epoch + 40,
        policy: f.policy({ currentMaterial: {
          certificates: [f.root.der, f.signer.der], crls: [crl],
        } }) });
      const entry = { serial: 77, reason: 1, revokedAt: epoch + 10 };
      const earlier = f.crl({ utcTime: true, entries: [
        { ...entry, invalidityDate: epoch + 5 },
      ] });
      const later = f.crl({ utcTime: true, entries: [
        { ...entry, invalidityDate: epoch + 20 },
      ] });
      for (const raw of [earlier, later]) {
        const node = c.parseDER(raw);
        assert(verifySignature('sha256', node.children[0].raw, f.root.publicKey,
          node.children[2].value.subarray(1)));
      }
      assert.equal(verify(earlier).reason, cases.cades.noncriticalEarlier);
      assert.equal(verify(later).reason, cases.cades.noncriticalLater);

      const original = c.parseDER(earlier);
      const tbsFields = original.children[0].children;
      const originalEntry = tbsFields[5].children[0].children;
      const criticalEntry = c.seq(originalEntry[0].raw, originalEntry[1].raw,
        c.seq(originalEntry[2].children[0].raw,
          p.extension('2.5.29.24', p.generalizedTime(epoch + 5), true)));
      const criticalTBS = c.seq(...tbsFields.map((field, i) =>
        i === 5 ? c.seq(criticalEntry) : field.raw));
      const critical = c.seq(criticalTBS, original.children[1].raw,
        c.bit(c.sign(criticalTBS, f.root.privateKey)));
      assert(verifySignature('sha256', criticalTBS, f.root.publicKey,
        c.parseDER(critical).children[2].value.subarray(1)));
      const criticalResult = verify(critical);
      assert.equal(criticalResult.overall, 'UNSUPPORTED');
      assert.equal(criticalResult.reason, cases.cades.criticalEarlier);
      assert.notEqual(criticalResult.verifiedLevel, 'B');
    } finally { f.close(); }
  });
