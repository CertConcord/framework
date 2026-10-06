import { H, sha512, equal, random, now, b64u, requireThat } from './core.mjs';
import { verifyCSR, issueRAR } from './enrollment.mjs';
import { verifyCRL } from './revocation.mjs';
import { parseCertificate } from './pki.mjs';

// External identity credentials use the issuer's own schema and status mechanism.
export function identityCRLValidator({
  issuerCertificate,
  fetchCRL,
  journal,
  minNumber = 0n,
  maxPublicationAge = 86400,
}) {
  const issuer = parseCertificate(issuerCertificate);
  requireThat(journal, 'IDENTITY_STATUS_JOURNAL_REQUIRED');
  const watermarkID = b64u(sha512(issuerCertificate));
  return async ({ certificate, at }) => {
    const leaf = parseCertificate(certificate),
      raw = await fetchCRL();
    requireThat(equal(leaf.issuer, issuer.subject), 'IDENTITY_CRL_ISSUER');
    return journal.transaction(() => {
      const row = journal.get('identity-crl-watermark', watermarkID),
        watermark = row?.value.number ?? BigInt(minNumber);
      const status = verifyCRL(raw, {
        issuer: issuer.subject,
        publicKey: issuer.publicKey,
        serial: leaf.serial,
        at,
        minNumber: watermark,
      });
      requireThat(at - status.thisUpdate <= maxPublicationAge, 'IDENTITY_CRL_FRESHNESS');
      requireThat(
        !row ||
          BigInt(status.number) !== BigInt(row.value.number) ||
          equal(sha512(raw), row.value.digest),
        'IDENTITY_CRL_FORK',
      );
      journal.put(
        'identity-crl-watermark',
        watermarkID,
        { number: status.number, digest: sha512(raw) },
        row?.revision ?? -1,
      );
      return {
        ...status,
        validUntil: Math.min(
          status.nextUpdate,
          status.thisUpdate + maxPublicationAge,
          leaf.notAfter,
          issuer.notAfter,
        ),
        coverage: 'ISSUER_CERTIFICATE',
        credentialStatus: 'NOT_PROVIDED',
        evidenceHash: H('IdentityCRLEvidence', {
          certificateHash: sha512(certificate),
          crlHash: sha512(raw),
        }),
      };
    });
  };
}

export function assessIdentityStatus(status, profile, mso, at = now()) {
  requireThat(
    status?.status === 'GOOD' &&
      status.thisUpdate <= at &&
      status.nextUpdate > at &&
      status.evidenceHash?.length === 64,
    'IDENTITY_STATUS',
  );
  requireThat(
    ['ISSUER_AND_VALIDITY', 'PER_CREDENTIAL'].includes(profile.statusMode) &&
      Number.isSafeInteger(profile.maxCredentialLifetime) &&
      profile.maxCredentialLifetime > 0,
    'IDENTITY_STATUS_POLICY',
  );
  const validity = mso.get('validityInfo'),
    start = Date.parse(validity.get('validFrom').value) / 1000,
    end = Date.parse(validity.get('validUntil').value) / 1000;
  requireThat(
    start <= at && end > at && end - start <= profile.maxCredentialLifetime,
    'IDENTITY_CREDENTIAL_LIFETIME',
  );
  requireThat(
    ['ISSUER_CERTIFICATE', 'ISSUER_AND_CREDENTIAL'].includes(status.coverage),
    'IDENTITY_STATUS_COVERAGE',
  );
  if (profile.statusMode === 'PER_CREDENTIAL')
    requireThat(
      status.coverage === 'ISSUER_AND_CREDENTIAL' && status.credentialStatus === 'GOOD',
      'IDENTITY_INDIVIDUAL_STATUS_REQUIRED',
    );
  else
    requireThat(
      ['NOT_PROVIDED', 'GOOD'].includes(status.credentialStatus),
      'IDENTITY_CREDENTIAL_REVOKED',
    );
  return {
    mode: profile.statusMode,
    coverage: status.coverage,
    credentialStatus: status.credentialStatus,
    checkedAt: at,
    validUntil: Math.min(status.nextUpdate, status.validUntil ?? status.nextUpdate, end),
    evidenceHash: status.evidenceHash,
  };
}

export function requireFreshIdentityAssessment(assessment, at = now()) {
  requireThat(
    assessment &&
      Number.isFinite(assessment.checkedAt) &&
      Number.isFinite(assessment.validUntil) &&
      assessment.checkedAt <= at &&
      assessment.validUntil > at,
    'IDENTITY_ASSESSMENT_EXPIRED',
  );
}

export class IdentityAdmission {
  constructor({
    journal,
    verifier,
    trustDomainID,
    policyHash,
    certificate,
    privateKey,
    decide,
    issuanceAudience,
    keyBindings,
  }) {
    requireThat(
      typeof decide === 'function' &&
        verifier.journal === journal &&
        typeof issuanceAudience === 'string',
      'IDENTITY_POLICY_BOUNDARY',
    );
    Object.assign(this, {
      journal,
      verifier,
      trustDomainID,
      policyHash,
      certificate,
      privateKey,
      decide,
      issuanceAudience,
      keyBindings,
    });
  }
  begin({
    csr,
    sessionID,
    issuerID,
    claims,
    origin,
    profileID = 'CERTCONCORD-PERSON-SIGN-v1',
    mode = 'dc_api.jwt',
    keyBindingID,
  }) {
    const parsed = verifyCSR(csr);
    requireThat(
      ['CERTCONCORD-PERSON-DEVICE-SIGN-v1', 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1'].includes(profileID)
        ? parsed.publicKey.asymmetricKeyType === 'ec' &&
            parsed.publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1'
        : profileID === 'CERTCONCORD-PERSON-SIGN-v1' &&
            ['ml-dsa-65', 'ml-dsa-87'].includes(parsed.publicKey.asymmetricKeyType),
      'IDENTITY_DOCUMENT_KEY_SUITE',
    );
    requireThat(
      profileID !== 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1' || (this.keyBindings && keyBindingID),
      'PASSKEY_ADMISSION_REQUIRED',
    );
    const request = {
        schemaVersion: 1,
        trustDomainID: this.trustDomainID,
        policyHash: this.policyHash,
        csrHash: sha512(csr),
        profileID,
        sessionIDHash: H('BrowserSession', sessionID),
        nonce: random(),
        ...(keyBindingID ? { keyBindingID } : {}),
      },
      requestBindingHash = H('IdentityEnrollment', request);
    const presentation = this.verifier.request({
      sessionID,
      identityIssuerID: issuerID,
      requestBindingHash,
      claims,
      origin,
      mode,
    });
    this.journal.put('identity-enrollment', presentation.id, {
      request,
      csr,
      sessionID,
      expiresAt: now() + 120,
    });
    return presentation;
  }
  authorize(presentationID, { sessionID }) {
    return this.journal.transaction(() => {
      const row = this.journal.get('identity-enrollment', presentationID),
        enrollment = row?.value;
      requireThat(
        enrollment &&
          enrollment.sessionID === sessionID &&
          enrollment.expiresAt > now() &&
          !enrollment.used,
        'IDENTITY_ENROLLMENT_STATE',
      );
      const evidence = this.verifier.consumeIdentity(presentationID, {
          sessionID,
          requestBindingHash: H('IdentityEnrollment', enrollment.request),
        }),
        csr = verifyCSR(enrollment.csr),
        decision = this.decide({ evidence, csr, profileID: enrollment.request.profileID });
      requireThat(
        decision?.approved === true &&
          decision.subjectID?.length === 32 &&
          typeof decision.assurance === 'string',
        'IDENTITY_POLICY_DENIED',
      );
      const identityEvidenceHash = H('VerifiedIdentityPresentation', {
          trustDomainID: this.trustDomainID,
          issuerID: evidence.issuerID,
          docType: evidence.docType,
          holderThumbprint: evidence.holderThumbprint,
          presentationHash: evidence.evidenceHash,
          statusEvidenceHash: evidence.statusEvidenceHash,
          requestBindingHash: evidence.requestBindingHash,
          ...(evidence.identityProfileHash
            ? { identityProfileHash: evidence.identityProfileHash }
            : {}),
          assurance: decision.assurance,
        }),
        keyAdmission =
          enrollment.request.profileID === 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1'
            ? this.keyBindings.forIssuance(enrollment.request.keyBindingID, {
                csr: enrollment.csr,
                subjectID: decision.subjectID,
                profileID: enrollment.request.profileID,
                policyHash: this.policyHash,
                identityEvidenceHash,
              })
            : null,
        request = {
          schemaVersion: 1,
          requestID: random(),
          trustDomainID: this.trustDomainID,
          audience: this.issuanceAudience,
          credentialFormat: 'mso_mdoc',
          identityAssurance: decision.assurance,
          subjectID: decision.subjectID,
          profileID: enrollment.request.profileID,
          policyHash: this.policyHash,
          identityEvidenceHash,
          spkiHash: sha512(csr.spki),
          csrHash: sha512(enrollment.csr),
          possessionMode: csr.possessionMode,
          issuedAt: now(),
          expiresAt: now() + 120,
          ...(keyAdmission
            ? { keyBindingID: keyAdmission.binding.bindingID, keyBindingHash: keyAdmission.hash }
            : {}),
        },
        rar = issueRAR(request, this);
      this.journal.put(
        'identity-enrollment',
        presentationID,
        { ...enrollment, used: true, rarHash: sha512(rar) },
        row.revision,
      );
      this.journal.put('identity-evidence', b64u(identityEvidenceHash), {
        issuerID: evidence.issuerID,
        docType: evidence.docType,
        evidenceHash: evidence.evidenceHash,
        statusEvidenceHash: evidence.statusEvidenceHash,
        ...(evidence.identityProfileHash
          ? { identityProfileHash: evidence.identityProfileHash }
          : {}),
        assurance: decision.assurance,
        verifiedAt: now(),
      });
      return { rar, subjectID: decision.subjectID, identityEvidenceHash };
    });
  }
}
