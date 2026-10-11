import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { readControl } from './state.mjs';
import { verifyRegistrationBinding } from './document-evidence.mjs';
import { verifyAssertion } from './webauthn.mjs';
import {
  ORGANIZATION_PROFILE,
  SEAL_PROFILE,
  createOrganizationFixture,
} from './organization-delegation-fixtures.mjs';

test('organization fixture retains valid original grant, registration, status and credential bindings', () => {
  const f = createOrganizationFixture();
  try {
    p.validateCertificate(f.keys.seal.certificate, f.keys.issuer.publicKey, {
      at: f.at,
      profileID: SEAL_PROFILE,
    });
    const registration = verifyRegistrationBinding(
      f.registrationAuthorization,
      f.keys.seal.certificate,
      {
        raCertificate: f.keys.ra.certificate,
        subjectID: f.organizationID,
        profileID: SEAL_PROFILE,
        policyHash: f.sim.policyHash,
        issuanceScope: f.issuanceScope,
        at: f.at,
      },
    );
    assert.deepEqual(registration.spkiHash, c.sha512(c.spki(f.keys.seal.publicKey)));
    for (const [i, grant] of f.grants.entries()) {
      const body = readControl(grant.cms, 'OrganizationDelegationGrant', grant.issuerCertificate);
      assert.deepEqual(c.dcbor(body), c.dcbor(f.grantRecords[i].body));
      assert.deepEqual(body.parentGrantHash, i ? c.sha512(f.grants[i - 1].cms) : null);
      assert.deepEqual(
        body.delegateAuthority.keyID,
        c.keyID(p.parseCertificate(grant.delegateCertificate).publicKey),
      );
      if (i) assert.deepEqual(grant.issuerCertificate, f.grants[i - 1].delegateCertificate);
    }
    const objects = new Map([
      ...f.grants.map((g) => [c.sha512(g.cms).toString('hex'), g]),
      ...f.registrations.map((r) => [c.sha512(r.cms).toString('hex'), r]),
    ]);
    for (const statement of f.context.statusMaterial) {
      const body = readControl(
        statement.cms,
        'OrganizationDelegationStatus',
        statement.issuerCertificate,
      );
      assert.equal(body.status, 'GOOD');
      assert(objects.has(body.objectHash.toString('hex')));
    }
    assert.equal(f.calls.sign, 0);
  } finally {
    f.close();
  }
});

test('organization fixture uses two independent valid ES256 raw approvals and preserves client bytes', () => {
  const f = createOrganizationFixture();
  try {
    const request = {
      fixture: 'independent ordinary WebAuthn primitive control',
      roster: f.persons.map(({ body }) => ({ personID: body.personID, origin: f.sim.origin })),
    };
    const hashes = [];
    for (const [i, person] of f.persons.entries()) {
      const assertion = f.assertion(request, i);
      const challenge = c.H('OrganizationApprovalChallenge', {
        schemaVersion: 1,
        profile: ORGANIZATION_PROFILE,
        requestHash: c.H('OrganizationApprovalRequest', request),
        personID: person.body.personID,
        credentialIDHash: c.sha512(person.body.credentialID),
      });
      const result = verifyAssertion(
        {
          type: 'public-key',
          id: c.b64u(assertion.credentialID),
          rawId: c.b64u(assertion.credentialID),
          response: Object.fromEntries(
            ['clientDataJSON', 'authenticatorData', 'signature'].map((key) => [
              key,
              c.b64u(assertion[key]),
            ]),
          ),
        },
        { ...person.body, publicKey: f.keys[person.keyName].publicKey },
        { challenge, origin: f.sim.origin, rpID: f.policy.rpID },
      );
      assert.equal(result.counter, 1);
      hashes.push(result.assertionHash.toString('hex'));
      assert.equal(assertion.clientDataJSON.includes(Buffer.from(c.b64u(challenge))), true);
    }
    assert.equal(new Set(hashes).size, 2);
    assert.notDeepEqual(f.persons[0].body.keyID, f.persons[1].body.keyID);
    assert.notDeepEqual(f.persons[0].body.personID, f.persons[1].body.personID);
  } finally {
    f.close();
  }
});

test('organization fixture snapshot preserves exact signed material and real document key across restart', () => {
  const f = createOrganizationFixture();
  let restored;
  try {
    f.advance(1);
    restored = createOrganizationFixture({ snapshot: f.snapshot() });
    assert.deepEqual(restored.pathBytes(), f.pathBytes());
    assert.deepEqual(restored.statusBytes(), f.statusBytes());
    assert.deepEqual(restored.registrations, f.registrations);
    assert.deepEqual(restored.binding, f.binding);
    assert.deepEqual(restored.activation, f.activation);
    assert.equal(restored.context.knowledgeTime, f.at + 1);
    const signature = c.sign(f.prepared.tbs, restored.keys.seal.privateKey);
    const cms = f.prepared.finish(signature);
    const verified = p.verifyCMS(cms, {
      content: f.document,
      expectedCertificate: f.keys.seal.certificate,
      simHash: c.H('SIM', f.sim),
      policyHash: f.sim.policyHash,
    });
    assert.deepEqual(verified.content, f.document);
    assert.equal(f.keys.seal.publicKey.asymmetricKeyType, 'ml-dsa-65');
  } finally {
    restored?.close();
    f.close();
  }
});
