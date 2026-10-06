import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal } from './state.mjs';
import { CredentialLog, verifyCredentialLog } from './credential-log.mjs';
import { TlogMirror } from './transparency.mjs';
import { issueCRL } from './revocation.mjs';
import { identityCRLValidator, IdentityAdmission, assessIdentityStatus } from './identity.mjs';
import { createCSR } from './enrollment.mjs';

test('native credential log: growth, unavailable mirror, quorum and durable failed allocation', () => {
  const journals = Array.from({ length: 4 }, () => new Journal()),
    log = { ...c.generate('ed25519'), name: 'synthetic/log', scheme: 'ed25519-log' },
    members = Array.from({ length: 3 }, (_, i) => ({
      ...c.generate('ml-dsa-87'),
      name: 'synthetic-mirror-' + i,
      operatorID: 'operator-' + i,
      scheme: 'CERTCONCORD-MLDSA87-SUBTREE-v1',
    })),
    peers = members.map((m, i) => ({
      operatorID: m.operatorID,
      service: new TlogMirror({
        journal: journals[i + 1],
        signer: m,
        logs: new Map([[log.name, log]]),
      }),
    })),
    ledger = new CredentialLog({ journal: journals[0], log, mirrors: peers }),
    trust = { log, members, threshold: 2 },
    entry = () => ({
      schemaVersion: 1,
      trustDomainID: c.random(),
      credentialID: c.random(64),
      raAuthorizationHash: c.random(64),
      documentKeyID: c.random(64),
      policyHash: c.random(64),
    });
  try {
    const first = entry(),
      proof = ledger.append(first);
    assert.equal(verifyCredentialLog(proof, first, trust).operatorCount, 3);
    peers[2].service.addCheckpoint = () => {
      throw Error('unavailable');
    };
    const second = entry(),
      next = ledger.append(second);
    assert.equal(next.index, 1);
    assert.equal(verifyCredentialLog(next, second, trust).operatorCount, 2);
    assert.throws(
      () => verifyCredentialLog({ ...next, entry: proof.entry }, second, trust),
      /ENTRY/,
    );
    assert.throws(
      () =>
        verifyCredentialLog(
          { ...next, receipts: [next.receipts[0], next.receipts[0]] },
          second,
          trust,
        ),
      /MIRROR_PROOF/,
    );
    peers[1].service.addCheckpoint = () => {
      throw Error('unavailable');
    };
    const third = entry(),
      pending = ledger.append(third);
    assert.throws(() => verifyCredentialLog(pending, third, trust), /QUORUM/);
    assert.equal(ledger.append(third).index, 2);
    assert.equal(ledger.append(entry()).index, 3);
  } finally {
    for (const j of journals) j.close();
  }
});

test('external identity status rejects CRL rollback, equivocation, staleness and revocation', async () => {
  const journal = new Journal(),
    key = c.generate('ec'),
    name = p.name('Synthetic Identity Root'),
    issuer = p.issueCertificate(
      { publicKey: key.publicKey, subject: name, issuer: name, serial: 1, ca: true },
      key.privateKey,
    ),
    leaf = p.issueCertificate(
      {
        publicKey: c.generate('ec').publicKey,
        subject: p.name('Synthetic DS'),
        issuer: name,
        serial: 2,
      },
      key.privateKey,
    );
  const crl = (number, entries = [], thisUpdate = c.now()) =>
    issueCRL({
      issuer: name,
      privateKey: key.privateKey,
      number,
      entries,
      thisUpdate,
      nextUpdate: thisUpdate + 86400,
    });
  let raw = crl(2);
  const validate = identityCRLValidator({
    journal,
    issuerCertificate: issuer,
    fetchCRL: async () => raw,
    maxPublicationAge: 600,
  });
  try {
    assert.equal((await validate({ certificate: leaf, at: c.now() })).status, 'GOOD');
    raw = crl(1);
    await assert.rejects(validate({ certificate: leaf, at: c.now() }), /ROLLBACK|NUMBER/);
    raw = crl(2, [], c.now() - 1);
    await assert.rejects(validate({ certificate: leaf, at: c.now() }), /FORK/);
    raw = crl(3, [], c.now() - 1000);
    await assert.rejects(validate({ certificate: leaf, at: c.now() }), /FRESHNESS/);
    raw = crl(3, [{ serial: 2, revokedAt: c.now() - 10, reason: 1 }]);
    assert.equal((await validate({ certificate: leaf, at: c.now() })).status, 'REVOKED');
  } finally {
    journal.close();
  }
});

test('identity admission cannot authorize a wrong session, denied identity or replayed approval', () => {
  const journal = new Journal(),
    key = c.generate(),
    ra = c.generate('ml-dsa-87'),
    certificate = p.issueCertificate(
      { publicKey: ra.publicKey, subject: p.name('RA'), issuer: p.name('RA'), serial: 1 },
      ra.privateKey,
    ),
    csr = createCSR({
      publicKey: key.publicKey,
      privateKey: key.privateKey,
      subject: p.name('Applicant'),
    }),
    trustDomainID = c.random(),
    policyHash = c.random(64),
    subjectID = c.random();
  let allowed = false;
  const verifier = {
    journal,
    request(args) {
      this.args = args;
      return { id: 'verified-presentation' };
    },
    consumeIdentity(id, { sessionID, requestBindingHash }) {
      assert.equal(sessionID, this.args.sessionID);
      assert(c.equal(requestBindingHash, this.args.requestBindingHash));
      return {
        issuerID: 'https://identity.example',
        docType: 'issuer-specific-photoid',
        holderThumbprint: 'synthetic-holder',
        evidenceHash: c.random(64),
        statusEvidenceHash: c.random(64),
        requestBindingHash,
      };
    },
  };
  const admission = new IdentityAdmission({
    journal,
    verifier,
    trustDomainID,
    policyHash,
    certificate,
    privateKey: ra.privateKey,
    issuanceAudience: 'https://ca.example',
    decide: () => ({ approved: allowed, subjectID, assurance: 'VERIFIED_IDENTITY' }),
  });
  try {
    const request = admission.begin({
      csr,
      sessionID: 'original-session',
      issuerID: 'https://identity.example',
      claims: ['name'],
      origin: 'https://website.example',
    });
    assert.throws(() => admission.authorize(request.id, { sessionID: 'foreign-session' }), /STATE/);
    assert.throws(
      () => admission.authorize(request.id, { sessionID: 'original-session' }),
      /DENIED/,
    );
    allowed = true;
    assert(admission.authorize(request.id, { sessionID: 'original-session' }).rar.length > 0);
    assert.throws(
      () => admission.authorize(request.id, { sessionID: 'original-session' }),
      /STATE/,
    );
  } finally {
    journal.close();
  }
});

test('issuer CRL GOOD cannot satisfy per-credential status or an excessive lifetime', () => {
  const at = c.now(),
    mso = new Map([
      [
        'validityInfo',
        new Map([
          ['validFrom', { value: new Date((at - 10) * 1000).toISOString() }],
          ['validUntil', { value: new Date((at + 60) * 1000).toISOString() }],
        ]),
      ],
    ]),
    status = {
      status: 'GOOD',
      thisUpdate: at - 10,
      nextUpdate: at + 60,
      evidenceHash: c.random(64),
      coverage: 'ISSUER_CERTIFICATE',
      credentialStatus: 'NOT_PROVIDED',
    },
    profile = { statusMode: 'ISSUER_AND_VALIDITY', maxCredentialLifetime: 120 };
  assert.equal(assessIdentityStatus(status, profile, mso, at).credentialStatus, 'NOT_PROVIDED');
  assert.throws(
    () => assessIdentityStatus(status, { ...profile, statusMode: 'PER_CREDENTIAL' }, mso, at),
    /INDIVIDUAL_STATUS/,
  );
  assert.throws(
    () => assessIdentityStatus(status, { ...profile, maxCredentialLifetime: 30 }, mso, at),
    /LIFETIME/,
  );
  assert.throws(
    () => assessIdentityStatus({ ...status, credentialStatus: 'REVOKED' }, profile, mso, at),
    /REVOKED/,
  );
});
