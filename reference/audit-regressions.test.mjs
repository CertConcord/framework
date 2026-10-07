import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, SigningGateway, activationContext, readControl } from './state.mjs';
import { createCSR, issueRAR, RegistrationAuthority, AuthorizedIssuer } from './enrollment.mjs';
import { MTCIssuer } from './issuance.mjs';
import { Mirror, verifyMTC } from './mtc.mjs';
import { SoftwareProvider } from './providers.mjs';
import { createSignaturePackage } from './evidence.mjs';
import { createVerifier } from './sdk/index.mjs';
import { authorizeHumanActivation } from './webauthn.mjs';
import { exampleAssertion } from './example-authenticator.mjs';
import { exampleTimestamp } from './example-timestamp.mjs';
import { DOCUMENT_EVIDENCE_PROFILE } from './document-evidence.mjs';

const profileID = 'CERTCONCORD-PERSON-SIGN-v1';

function journalsFor(t) {
  const journals = [];
  t.after(() => journals.forEach((journal) => journal.close()));
  return () => {
    const journal = new Journal();
    journals.push(journal);
    return journal;
  };
}

async function issuanceFixture(t, representation) {
  const journal = journalsFor(t),
    root = c.generate('ml-dsa-87'),
    raKey = c.generate('ml-dsa-87'),
    documentKey = c.generate('ml-dsa-87'),
    issuerKey = c.generate('ml-dsa-87'),
    raCertificate = p.issueCertificate(
      {
        publicKey: raKey.publicKey,
        issuer: p.name('Synthetic RA root'),
        subject: p.name('Synthetic RA'),
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      root.privateKey,
    ),
    policyHash = c.random(64),
    csr = createCSR({
      subject: p.name('Synthetic approved subject'),
      publicKey: documentKey.publicKey,
      privateKey: documentKey.privateKey,
    }),
    ra = new RegistrationAuthority({
      journal: journal(),
      certificate: raCertificate,
      privateKey: raKey.privateKey,
      approve: async () => ({ approved: true }),
    }),
    issuanceScope = {
      trustDomainID: c.random(),
      issuerID: '32473.10',
      issuerKeyID: c.keyID(issuerKey.publicKey),
      representation,
    },
    originalRAR = await ra.authorize({
      csr,
      subjectID: c.random(),
      profileID,
      policyHash,
      identityEvidenceHash: c.random(64),
      issuanceScope,
    });
  // Sign the proposed scope explicitly so the baseline tests an ignored
  // authorization boundary, rather than the absence of a new constructor API.
  const rar = issueRAR(
    {
      ...readControl(originalRAR, 'RegistrationAuthorization', raCertificate),
      issuanceScope,
    },
    { certificate: raCertificate, privateKey: raKey.privateKey },
  );

  const makeIssuer = (scope = issuanceScope, key = issuerKey) => {
    const issuerJournal = journal(),
      common = {
        journal: issuerJournal,
        raCertificate,
        privateKey: key.privateKey,
        policyHash,
        allowedProfiles: [profileID],
        issuanceScope: scope,
      };
    if (scope.representation === 'X509') {
      const issuer = new AuthorizedIssuer({ ...common, issuer: p.name(scope.issuerID) });
      return {
        issue: () => issuer.issue({ csr, rar }),
        validate: (certificate) => p.validateCertificate(certificate, key.publicKey, { profileID }),
        journal: issuerJournal,
      };
    }
    const members = [0, 1, 2].map((i) => ({
        id: '32473.' + (20 + i),
        operatorID: 'synthetic-scope-mirror-' + i,
        ...c.generate('ml-dsa-87'),
      })),
      mirrors = members.map(
        (member) =>
          new Mirror({ journal: journal(), id: member.id, privateKey: member.privateKey }),
      ),
      trust = {
        caID: scope.issuerID,
        caPublicKey: key.publicKey,
        members,
        threshold: 2,
        policyHash,
        rtmHash: c.H('SyntheticRTM', { trustDomainID: scope.trustDomainID, policyHash }),
        membershipEpoch: 1,
        profileID,
      },
      issuer = new MTCIssuer({ ...common, ...trust, logNumber: 1, mirrors });
    return {
      issue: () => issuer.issue({ csr, rar }),
      validate: (certificate) => {
        assert.equal(verifyMTC(certificate, trust).mode, 'STANDALONE');
      },
      journal: issuerJournal,
    };
  };
  return { issuanceScope, issuerKey, makeIssuer };
}

for (const representation of ['X509', 'MTC']) {
  test(`${representation} issuance accepts its signed scope and reuses the same result`, async (t) => {
    const fixture = await issuanceFixture(t, representation),
      issuer = fixture.makeIssuer(),
      certificate = await issuer.issue();
    issuer.validate(certificate);
    assert.deepEqual(await issuer.issue(), certificate);
  });

  for (const boundary of ['issuer', 'domain', 'key', 'representation']) {
    test(`${representation} RAR rejects ${boundary} replay at an independent issuer`, async (t) => {
      const fixture = await issuanceFixture(t, representation),
        source = fixture.makeIssuer(),
        certificate = await source.issue(),
        key = ['issuer', 'key'].includes(boundary) ? c.generate('ml-dsa-87') : fixture.issuerKey,
        destinationScope = {
          ...fixture.issuanceScope,
          ...(boundary === 'issuer' ? { issuerID: '32473.11' } : {}),
          ...(boundary === 'domain' ? { trustDomainID: c.random() } : {}),
          issuerKeyID: c.keyID(key.publicKey),
          ...(boundary === 'representation'
            ? { representation: representation === 'X509' ? 'MTC' : 'X509' }
            : {}),
        },
        destination = fixture.makeIssuer(destinationScope, key);
      source.validate(certificate);
      assert.notEqual(source.journal, destination.journal);
      await assert.rejects(
        async () => {
          const replayed = await destination.issue();
          destination.validate(replayed);
          return replayed;
        },
        /ISSUANCE_SCOPE|ISSUANCE_AUTHORIZATION|MTC_REGISTRATION_AUTHORITY/,
        'An identical signed RAR must not authorize a different issuance scope',
      );
    });
  }
}

async function documentFixture(t, { expiredPermitAuthority = false } = {}) {
  const makeJournal = journalsFor(t),
    journal = makeJournal(),
    ca = c.generate('ml-dsa-87'),
    documentKey = c.generate('ml-dsa-87'),
    raKey = c.generate('ml-dsa-87'),
    permitKey = c.generate('ml-dsa-87'),
    receiptKey = c.generate('ml-dsa-87'),
    statusKey = c.generate('ml-dsa-87'),
    at = c.now(),
    controlCertificate = (key, serial, expired = false) =>
      p.issueCertificate(
        {
          publicKey: key.publicKey,
          serial,
          issuer: p.name('Synthetic document CA'),
          subject: p.name('Synthetic control authority ' + serial),
          profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
          ...(expired ? { notBefore: at - 3600, notAfter: at - 60 } : {}),
        },
        ca.privateKey,
      ),
    raCertificate = controlCertificate(raKey, 1),
    permitCertificate = controlCertificate(permitKey, 2, expiredPermitAuthority),
    receiptCertificate = controlCertificate(receiptKey, 3),
    statusCertificate = controlCertificate(statusKey, 4),
    trustDomainID = c.random(),
    subjectID = c.random(),
    policy = {
      schemaVersion: 1,
      activationMode: 'HUMAN_WEBAUTHN',
      allowedOrigins: ['https://document.example'],
      allowedProfiles: [profileID],
      rpID: 'document.example',
      audience: 'synthetic-document-signer',
      maxActivationLifetime: 120,
      requireTrustedTime: true,
      documentEvidence: {
        profile: DOCUMENT_EVIDENCE_PROFILE,
        organizationAuthorization: false,
      },
    },
    policyHash = c.H('SignaturePolicy', policy),
    csr = createCSR({
      subject: p.name('Synthetic document subject'),
      publicKey: documentKey.publicKey,
      privateKey: documentKey.privateKey,
    }),
    issuanceScope = {
      trustDomainID,
      issuerID: '32473.10',
      issuerKeyID: c.keyID(ca.publicKey),
      representation: 'MTC',
    },
    ra = new RegistrationAuthority({
      journal,
      certificate: raCertificate,
      privateKey: raKey.privateKey,
      approve: async () => ({ approved: true }),
    }),
    rar = await ra.authorize({
      csr,
      subjectID,
      profileID,
      policyHash,
      identityEvidenceHash: c.H('SyntheticIdentity', { subjectID }),
      issuanceScope,
    }),
    members = [0, 1, 2].map((i) => ({
      id: '32473.' + (20 + i),
      operatorID: 'synthetic-document-mirror-' + i,
      ...c.generate('ml-dsa-87'),
    })),
    mirrors = members.map(
      (member) =>
        new Mirror({ journal: makeJournal(), id: member.id, privateKey: member.privateKey }),
    ),
    mtc = {
      caID: issuanceScope.issuerID,
      caPublicKey: ca.publicKey,
      members,
      threshold: 2,
      policyHash,
      rtmHash: c.H('SyntheticRTM', { trustDomainID, policyHash }),
      membershipEpoch: 1,
    },
    issuer = new MTCIssuer({
      ...mtc,
      journal,
      raCertificate,
      privateKey: ca.privateKey,
      logNumber: 1,
      mirrors,
      allowedProfiles: [profileID],
      issuanceScope,
    }),
    certificate = await issuer.issue({ csr, rar }),
    cert = p.parseCertificate(certificate),
    document = Buffer.from('Synthetic document authority lifecycle regression'),
    sim = {
      schemaVersion: 1,
      trustDomainID,
      transactionID: c.random(),
      subjectID,
      profileID,
      keyID: c.keyID(documentKey.publicKey),
      certificateID: cert.certificateID,
      certificateRepresentationHash: cert.representationHash,
      container: 'CMS',
      adapterID: 'certconcord-cms-v1',
      documents: [
        {
          documentID: c.random(),
          mediaType: 'text/plain',
          digestAlgorithm: 'SHA-512',
          digest: c.sha512(document),
          scope: 'CMS_CONTENT',
          displayName: 'Synthetic document',
        },
      ],
      purpose: 'DOCUMENT_SIGN',
      origin: 'https://document.example',
      policyHash,
      issuedAt: c.now(),
      expiresAt: c.now() + 120,
      nonce: c.random(),
      displayText: 'Approve synthetic document',
    },
    prepared = p.prepareCMS({
      content: document,
      certificate,
      detached: true,
      context: {
        schemaVersion: 1,
        trustDomainID,
        profileID,
        container: 'CMS',
        adapterID: sim.adapterID,
      },
      simHash: c.H('SIM', sim),
      policyHash,
    }),
    activation = activationContext({
      trustDomainID,
      tbsKind: 'CMS_SIGNED_ATTRS_DER',
      tbs: prepared.tbs,
      publicKey: documentKey.publicKey,
      simHash: c.H('SIM', sim),
      certificateID: cert.certificateID,
      certificateRepresentationHash: cert.representationHash,
      transactionID: sim.transactionID,
      policyHash,
      origin: sim.origin,
      rpID: policy.rpID,
      audience: policy.audience,
      serverNonce: c.unb64u(journal.issueNonce('activation')),
    }),
    proof = exampleAssertion({
      challenge: c.H('ActivationContext', activation),
      origin: sim.origin,
      rpID: policy.rpID,
      keyID: sim.keyID,
      subjectID,
    }),
    permit = authorizeHumanActivation({
      ...proof,
      activation,
      policy,
      sim,
      journal,
      permitCertificate,
      permitKey: permitKey.privateKey,
    }),
    backend = new SoftwareProvider(new Map([['document', documentKey]])),
    gateway = new SigningGateway({
      journal,
      permitCertificate,
      receiptCertificate,
      receiptKey: receiptKey.privateKey,
      audience: policy.audience,
      backend,
      authorize: async () => true,
    });
  const pack = (executed) => {
    const status = p.signCMS(
        {
          content: c.D('CertificateStatus', {
            schemaVersion: 1,
            trustDomainID,
            certificateID: cert.certificateID,
            scope: 'CERTIFICATE',
            status: 'GOOD',
            publishedAt: c.now(),
            nextUpdate: c.now() + 3600,
          }),
          certificate: statusCertificate,
        },
        statusKey.privateKey,
      ),
      tsa = exampleTimestamp(journal),
      bundle = createSignaturePackage({
        document,
        certificate,
        sim,
        policy,
        activation,
        permit,
        receipt: executed.receipt,
        status,
        cms: prepared.finish(executed.signature),
        documentEvidence: { RegistrationAuthorization: rar, DocumentTimestamp: tsa.issue },
      }),
      trust = {
        mtc,
        permitCertificate,
        receiptCertificate,
        statusCertificate,
        expectedPolicy: policy,
        trustDomainID,
        raCertificate,
        timestamp: tsa.trust,
      };
    return { bundle, trust };
  };
  return {
    permitCertificate,
    activation,
    backend,
    execute: () => gateway.execute({ permit, tbs: prepared.tbs, keyRef: 'document' }),
    pack,
    // Construct a cryptographically authentic negative artifact independently
    // of gateway acceptance so offline verification remains a separate boundary.
    invalidAuthorityArtifact: () => {
      const signature = c.sign(prepared.tbs, documentKey.privateKey),
        receipt = p.signCMS(
          {
            content: c.D('ExecutionReceipt', {
              schemaVersion: 1,
              operationID: activation.operationID,
              activationHash: c.H('ActivationContext', activation),
              permitHash: c.sha512(permit),
              keyID: activation.keyID,
              tbsHash: activation.tbsHash,
              signatureHash: c.sha512(signature),
              executedAt: c.now(),
              provider: backend.id,
            }),
            certificate: receiptCertificate,
          },
          receiptKey.privateKey,
        );
      return pack({ signature, receipt });
    },
  };
}

test('MTC WebAuthn document accepts a current permit authority and trusted timestamp', async (t) => {
  const fixture = await documentFixture(t),
    { bundle, trust } = fixture.pack(await fixture.execute()),
    result = createVerifier({ format: 'CMS', trust }).verify(c.dcbor(bundle));
  assert.equal(result.overall, 'VALID');
  assert.equal(result.certificateTrust, 'VALID');
  assert.equal(result.activation, 'ATTESTED_VALID');
  assert.equal(result.time, 'TRUSTED_PROOF_OF_EXISTENCE');
  assert.equal(
    verifyMTC(bundle.objects.find((o) => o.type === 'Certificate').payload, trust.mtc).mode,
    'STANDALONE',
  );
});

test('gateway rejects an expired permit authority before invoking the document signer', async (t) => {
  const fixture = await documentFixture(t, { expiredPermitAuthority: true }),
    signer = t.mock.method(fixture.backend, 'sign');
  assert(p.parseCertificate(fixture.permitCertificate).notAfter < fixture.activation.issuedAt);
  await assert.rejects(fixture.execute, /AUTHORITY_(EXPIRED|VALIDITY|TIME)/);
  assert.equal(signer.mock.callCount(), 0);
});

test('offline verification rejects a document authorized by an expired permit authority', async (t) => {
  const fixture = await documentFixture(t, { expiredPermitAuthority: true }),
    { bundle, trust } = fixture.invalidAuthorityArtifact(),
    result = createVerifier({ format: 'CMS', trust }).verify(c.dcbor(bundle));
  assert(p.parseCertificate(fixture.permitCertificate).notAfter < fixture.activation.issuedAt);
  assert.equal(result.overall, 'INVALID');
  assert.match(result.reason, /^AUTHORITY_/);
});
