import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { readControl } from './state.mjs';
import { evidenceLeaf, createEvidencePackage, verifyEvidencePackage } from './evidence-plan.mjs';

test('draft 03 rejects validly signed controls from another domain revision', () => {
  const key = c.generate('ml-dsa-87');
  const certificate = p.issueCertificate(
    {
      publicKey: key.publicKey,
      issuer: p.name('Synthetic draft boundary'),
      subject: p.name('Synthetic control authority'),
      serial: 1,
      profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
    },
    key.privateKey,
  );
  const value = { schemaVersion: 1, nonce: c.random() };
  for (const label of ['RegistrationAuthorization', 'OperationPermit']) {
    const signed = (content) => p.signCMS({ content, certificate }, key.privateKey);
    assert.deepEqual(
      c.dcbor(readControl(signed(c.D(label, value)), label, certificate)),
      c.dcbor(value),
    );
    for (const revision of [1, 2, 4]) {
      const content = c.dcbor(['CertConcord', revision, label, value]);
      const envelope = signed(content);
      assert.deepEqual(
        p.verifyCMS(envelope, { expectedCertificate: certificate }).content,
        content,
      );
      assert.throws(() => readControl(envelope, label, certificate), { code: 'CONTROL_DOMAIN' });
    }
  }
});

test('flat leaf identifiers bind the draft 03 domain even when the plan matches an old identifier', () => {
  const leaf = evidenceLeaf('Document', Buffer.from('Draft boundary evidence'));
  const current = createEvidencePackage('certconcord-ecp-cms-attested-draft-03', [leaf]);
  assert.equal(verifyEvidencePackage(current).plan.profile, current.plan.profile);
  const oldID = c.sha512(
    c.dcbor([
      'CertConcord',
      2,
      'EvidenceLeaf',
      {
        type: leaf.type,
        payload: leaf.payload,
      },
    ]),
  );
  assert.notDeepEqual(oldID, leaf.id);
  const old = {
    ...current,
    plan: { ...current.plan, objects: { Document: oldID } },
    objects: [{ ...leaf, id: oldID }],
  };
  assert.throws(() => verifyEvidencePackage(old), { code: 'ECP_HASH' });
});
