import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import {
  identityProfiles,
  identityClaimPaths,
  identityProfileHash,
  validateIdentityClaims,
} from './identity-profiles.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { runDemo } from './demo.mjs';
import { verifyMdocSignaturePackage } from './signer-mdoc.mjs';
import { generate, equal, random, now } from './core.mjs';
import { name } from './pki.mjs';
import { issueIACA, issueMdocCertificate, validateMdocCertificate } from './mdoc-pki.mjs';
import { PresentationVerifier } from './openid.mjs';
import { AnnexCVerifier } from './annex-verifier.mjs';
import { Journal } from './state.mjs';

test('WebAuthn activation authorizes the MTC/CMS document path', async () => {
  const { verification, summary } = await runDemo({ activationMode: 'HUMAN_WEBAUTHN' });
  assert.equal(summary.activationMode, 'HUMAN_WEBAUTHN');
  assert.equal(verification.overall, 'VALID_UNDER_POLICY');
});

for (const identityType of ['mdl', 'photoid', 'pid', 'custom'])
  for (const identityTransport of ['openid4vp', 'annex-c'])
    test(`${identityType} over ${identityTransport}: typed identity admission through document verification`, async () => {
      const { summary, verification } = await runFoundationDemo({
        identityType,
        identityTransport,
      });
      assert.equal(summary.identityDocType, identityProfiles[identityType].docType);
      assert.equal(verification.overall, 'VALID_UNDER_POLICY');
      assert.equal(verification.documentAlgorithmAssurance, 'POST_QUANTUM');
    });

for (const documentKeyMode of ['INDEPENDENT_PQ', 'DEVICE_KEY'])
  test(`${documentKeyMode}: PID direct issuance and WebAuthn activation remain distinct operations`, async () => {
    const { summary, verification, bundle, trust } = await runFoundationDemo({
      identityType: 'pid',
      issuerModel: 'direct',
      activationMode: 'HUMAN_WEBAUTHN',
      documentKeyMode,
    });
    assert.equal(summary.activationMode, 'HUMAN_WEBAUTHN');
    assert.equal(verification.overall, 'VALID_UNDER_POLICY');
    assert.equal(trust.docType, identityProfiles.pid.docType);
    assert.throws(
      () => verifyMdocSignaturePackage(bundle, { ...trust, certificateProfile: 'ISO_MDOC' }),
      /MDOC_CERTIFICATE_EKU/,
    );
    assert.throws(
      () =>
        verifyMdocSignaturePackage(bundle, {
          ...trust,
          expectedPolicy: { ...trust.expectedPolicy, activationMode: 'HUMAN_MDOC' },
        }),
      /POLICY/,
    );
  });

test('identity schemas preserve namespace, type, disclosure scope and version commitments', () => {
  const profile = identityProfiles.photoid;
  const paths = [
    ['org.iso.23220.1', 'family_name'],
    ['org.iso.23220.photoid.1', 'person_id'],
  ];
  assert.deepEqual(identityClaimPaths(profile, paths), paths);
  assert.throws(
    () => identityClaimPaths(profile, [['org.iso.18013.5.1', 'family_name']]),
    /CLAIM_POLICY/,
  );
  assert.throws(() => identityClaimPaths(profile, [paths[0], paths[0]]), /DUPLICATE/);
  assert.throws(() => identityClaimPaths(profile, []), /CLAIM_POLICY/);
  const claims = new Map([
    ['org.iso.23220.1', new Map([['family_name', 'Example']])],
    ['org.iso.23220.photoid.1', new Map([['person_id', 'sample-id']])],
  ]);
  assert.equal(
    validateIdentityClaims(profile, claims, paths)['org.iso.23220.photoid.1'].person_id,
    'sample-id',
  );
  claims.get('org.iso.23220.photoid.1').set('person_id', true);
  assert.throws(() => validateIdentityClaims(profile, claims, paths), /CLAIM_TYPE/);
  claims.get('org.iso.23220.photoid.1').set('person_id', 'sample-id');
  claims.get('org.iso.23220.1').set('unrequested', 'private');
  assert.throws(() => validateIdentityClaims(profile, claims, paths), /DISCLOSURE_SCOPE/);
  assert(
    !equal(
      identityProfileHash(profile),
      identityProfileHash({ ...profile, docType: 'org.iso.23220.photoID.1' }),
    ),
  );
});

for (const Verifier of [PresentationVerifier, AnnexCVerifier])
  test(`${Verifier.name}: changed rulebooks and expired assessments prevent identity consumption`, async () => {
    const journal = new Journal(),
      rootKey = generate('ec'),
      key = generate('ec'),
      root = issueIACA({
        ...rootKey,
        subject: name('Example IACA'),
        serial: 1,
        issuerAltName: 'https://example.test',
        crlURL: 'https://example.test/crl',
      }),
      certificate = issueMdocCertificate({
        publicKey: key.publicKey,
        subject: name('Example reader'),
        serial: 2,
        issuerCertificate: root,
        issuerKey: rootKey.privateKey,
        reader: true,
      }),
      issuerID = 'https://issuer.example',
      profile = {
        ...identityProfiles.custom,
        statusMode: 'ISSUER_AND_VALIDITY',
        maxCredentialLifetime: 86400,
      },
      issuer = {
        certificate,
        publicKey: key.publicKey,
        identityProfile: profile,
        validateIdentityStatus: async () => {
          throw Error('not reached');
        },
      },
      registry = new Map([[issuerID, issuer]]),
      verifier = new Verifier({
        baseURL: 'https://reader.example',
        journal,
        privateKey: key.privateKey,
        certificate,
        issuerRegistry: registry,
        trustRoots: [new X509Certificate(root)],
      });
    try {
      const request = verifier.request({
        sessionID: 'example-session',
        origin: 'https://reader.example',
        identityIssuerID: issuerID,
        requestBindingHash: random(64),
        claims: ['family_name'],
        mode: 'dc_api.jwt',
      });
      issuer.identityProfile = { ...profile, docType: 'org.example.changed.1' };
      if (Verifier === AnnexCVerifier)
        await assert.rejects(
          verifier.response(
            request.id,
            {},
            { sessionID: 'example-session', origin: 'https://reader.example' },
          ),
          /IDENTITY_ISSUER_POLICY/,
        );
      else {
        const record = journal.get('vp', request.id);
        assert(
          !equal(record.value.identityProfileHash, identityProfileHash(issuer.identityProfile)),
        );
        const completed = { ...record.value, status: 'COMPLETED', result: {} };
        journal.put('vp', request.id, completed, record.revision);
        assert.throws(
          () =>
            verifier.consumeIdentity(request.id, {
              sessionID: 'example-session',
              requestBindingHash: completed.requestBindingHash,
            }),
          /IDENTITY_ISSUER_POLICY/,
        );
      }
      issuer.identityProfile = profile;
      const table = Verifier === PresentationVerifier ? 'vp' : 'annex-c',
        row = journal.get(table, request.id),
        completed = {
          ...row.value,
          status: 'COMPLETED',
          result: { statusAssessment: { checkedAt: now() - 30, validUntil: now() - 1 } },
        };
      journal.put(table, request.id, completed, row.revision);
      assert.throws(
        () =>
          verifier.consumeIdentity(request.id, {
            sessionID: 'example-session',
            requestBindingHash: completed.requestBindingHash,
          }),
        /IDENTITY_ASSESSMENT_EXPIRED/,
      );
      assert.equal(journal.get(table, request.id).value.status, 'COMPLETED');
    } finally {
      journal.close();
    }
  });

test('PID and mdoc document-signer and reader EKUs are selected by trusted profile', () => {
  const rootKey = generate('ec'),
    key = generate('ec'),
    root = issueIACA({
      ...rootKey,
      subject: name('Example IACA'),
      serial: 1,
      issuerAltName: 'https://example.test',
      crlURL: 'https://example.test/crl',
    });
  for (const reader of [false, true]) {
    const certificate = issueMdocCertificate({
      publicKey: key.publicKey,
      subject: name('Example role'),
      serial: 2,
      issuerCertificate: root,
      issuerKey: rootKey.privateKey,
      reader,
      certificateProfile: 'EUDI_PID_ARF_1_4',
    });
    validateMdocCertificate(certificate, { reader, certificateProfile: 'EUDI_PID_ARF_1_4' });
    assert.throws(() => validateMdocCertificate(certificate, { reader }), /MDOC_CERTIFICATE_EKU/);
    assert.throws(
      () =>
        validateMdocCertificate(certificate, {
          reader: !reader,
          certificateProfile: 'EUDI_PID_ARF_1_4',
        }),
      /MDOC_CERTIFICATE_EKU/,
    );
  }
});
