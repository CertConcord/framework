import { decodeCBOR, requireThat, H, publicFromDER, equal, now, sha512, keyID } from '../core.mjs';
import { verifySignaturePackage } from '../evidence.mjs';
import {
  verifyMdocSignaturePackage,
  verifyMdocDocument,
  SIGNER_DOCTYPE,
  SIGNER_NAMESPACE,
} from '../signer-mdoc.mjs';
import { executionRequirement } from '../execution-binding.mjs';
import { inspectEvidencePackage } from '../evidence-plan.mjs';
import {
  documentPlans,
  documentEvidenceTypes,
  documentTimestampImprint,
  verifyOrganizationAuthorizationBinding,
} from '../document-evidence.mjs';
import { readControl, evaluateStatus, validateActivation } from '../state.mjs';
import { verifyCMS, parseCertificate, OID } from '../pki.mjs';
import { inspectIssuerSigned, verifyIssuerSigned } from '../mdoc.mjs';
import { verifyExternalCMS } from '../external-cms.mjs';
import { verifyTimestampToken } from '../timestamp.mjs';
import { requireAuthority, AuthorityError } from '../authority-history.mjs';
import { snapshotIssuanceScope } from '../enrollment-scope.mjs';
import {
  VerificationEvaluation,
  verificationOutcome,
  verificationResult,
  evaluatedCheck,
} from '../verification-result.mjs';

export const profiles = Object.freeze(['CMS', 'MDOC']);
export { createOrganizationHistoryVerifier } from '../organization-history.mjs';
export { createOrganizationHistorySource } from '../organization-history-source.mjs';
const plans = Object.freeze({
  CMS: [
    'certconcord-ecp-cms-attested-draft-03',
    'certconcord-ecp-cms-passkey-draft-03',
    'certconcord-ecp-cms-execution-draft-03',
    ...Object.keys(documentPlans).filter((p) => p.includes('-cms-')),
  ],
  MDOC: [
    'certconcord-ecp-mdoc-attested-draft-03',
    'certconcord-ecp-mdoc-passkey-draft-03',
    'certconcord-ecp-mdoc-execution-draft-03',
    ...Object.keys(documentPlans).filter((p) => p.includes('-mdoc-')),
  ],
});

// This bounded scan is used only after a selected flat plan cannot complete.
// It reuses the selected primitives and status-authority checks, returns no
// permission or credential facts, and never invents missing content or trust.
function availableChecks(format, values, trust, evaluation, imprintComplete) {
  const failures = [],
    controls = {};
  const check = (dimension, callback) => {
    try {
      return evaluatedCheck(evaluation, dimension, callback);
    } catch (error) {
      failures.push(error);
      return undefined;
    }
  };
  for (const [type, certificate, dimension] of [
    ['RegistrationAuthorization', trust.raCertificate, 'integrity'],
    ['OperationPermit', trust.permitCertificate, 'integrity'],
    ['ExecutionReceipt', trust.receiptCertificate, 'integrity'],
    ['CertificateStatus', trust.statusCertificate, 'status'],
    ['CredentialSeal', trust.sealCertificate, 'integrity'],
  ])
    if (values[type] && certificate)
      controls[type] = check(dimension, () =>
        readControl(
          values[type],
          type === 'CredentialSeal' ? 'MdocCredentialSeal' : type,
          certificate,
        ),
      );
  const sim = values.SIM && check('integrity', () => decodeCBOR(values.SIM));
  const policy =
    values.SignaturePolicy && check('integrity', () => decodeCBOR(values.SignaturePolicy));
  let organizationAuthority;
  if (sim && values.OrganizationAuthorization) {
    organizationAuthority = trust.organizationAuthorities?.find((entry) =>
      equal(entry.organizationID, sim.subjectID),
    );
    if (organizationAuthority?.certificate)
      controls.OrganizationAuthorization = check('integrity', () =>
        readControl(
          values.OrganizationAuthorization,
          'OrganizationAuthorization',
          organizationAuthority.certificate,
        ),
      );
    if (values.OrganizationAuthorizationStatus && organizationAuthority?.statusCertificate)
      controls.OrganizationAuthorizationStatus = check('status', () =>
        readControl(
          values.OrganizationAuthorizationStatus,
          'OrganizationAuthorizationStatus',
          organizationAuthority.statusCertificate,
        ),
      );
  }
  let signedDocument, credentialBinding;
  if (format === 'CMS' && values.CMS && values.Certificate && values.Document) {
    signedDocument = check('integrity', () =>
      verifyCMS(values.CMS, {
        content: values.Document,
        expectedCertificate: values.Certificate,
        ...(sim && policy
          ? {
              context: {
                schemaVersion: 1,
                trustDomainID: trust.trustDomainID,
                profileID: sim.profileID,
                container: sim.container,
                adapterID: sim.adapterID,
              },
              simHash: H('SIM', sim),
              policyHash: H('SignaturePolicy', policy),
            }
          : {}),
      }),
    );
    if (signedDocument) credentialBinding = signedDocument.cert;
  }
  if (format === 'MDOC' && values.PersonalMdoc) {
    // Receipt time is unavailable until its operation tuple has been bound.
    // Reuse the component's no-time facts without granting credential acceptance.
    const credential = check('integrity', () =>
      inspectIssuerSigned(values.PersonalMdoc, {
        issuerKey: trust.issuerPublicKey,
        certificate: trust.issuerCertificate,
        docType: trust.docType ?? SIGNER_DOCTYPE,
        allowPartial: false,
      }),
    );
    if (credential && values.COSE && values.Document && sim && policy) {
      credentialBinding = check('integrity', () => ({
        publicKey: publicFromDER(credential.claims.get(SIGNER_NAMESPACE).get('signing_key')),
        certificateID: H('MdocIssuerAuth', credential.issuerAuthBytes),
        representationHash: sha512(values.PersonalMdoc),
      }));
      if (credentialBinding)
        signedDocument = check('integrity', () =>
          verifyMdocDocument(values.COSE, values.Document, {
            credential: values.PersonalMdoc,
            publicKey: credentialBinding.publicKey,
            context: {
              schemaVersion: 1,
              trustDomainID: trust.trustDomainID,
              profileID: sim.profileID,
              container: 'COSE',
              adapterID: sim.adapterID,
              credentialType: 'MDOC',
            },
            simHash: H('SIM', sim),
            policyHash: H('SignaturePolicy', policy),
          }),
        );
    }
  }
  if (values.DocumentTimestamp && trust.timestamp?.certificate) {
    // A timestamp's embedded CMS mathematics can be assessed without inventing
    // a missing covered leaf. Its request imprint is checked only with closure.
    const math = check('time', () => {
      const profile = trust.timestamp.signatureProfile ?? 'CERTCONCORD-PQ';
      requireThat(
        ['CERTCONCORD-PQ', 'EXTERNAL-RFC3161'].includes(profile),
        'TSA_SIGNATURE_PROFILE',
      );
      return profile === 'EXTERNAL-RFC3161'
        ? verifyExternalCMS(values.DocumentTimestamp, {
            certificate: trust.timestamp.certificate,
            expectedContentType: OID.tstInfo,
          })
        : verifyCMS(values.DocumentTimestamp, {
            expectedCertificate: trust.timestamp.certificate,
            expectedContentType: OID.tstInfo,
          });
    });
    if (math && imprintComplete)
      check('time', () =>
        verifyTimestampToken(values.DocumentTimestamp, {
          ...trust.timestamp,
          imprint: documentTimestampImprint(
            format,
            Object.entries(values).map(([type, payload]) => ({ type, payload })),
          ),
          at: trust.knowledgeTime ?? now(),
          maxFutureSkew: 0,
        }),
      );
  }
  const receipt = controls.ExecutionReceipt;
  const permit = controls.OperationPermit;
  // A valid receipt signature alone supplies no operation time for this document.
  // Require the original signed message and the complete selected binding tuple.
  const boundReceipt =
    sim &&
    policy &&
    receipt &&
    permit &&
    signedDocument &&
    credentialBinding &&
    check('authorization', () => {
      const activation = permit.activation,
        prefix = format === 'CMS' ? 'ECP_' : 'MDOC_ECP_',
        at = receipt.executedAt;
      requireThat(
        equal(credentialBinding.certificateID, sim.certificateID) &&
          equal(credentialBinding.representationHash, sim.certificateRepresentationHash) &&
          equal(keyID(credentialBinding.publicKey), sim.keyID),
        prefix + 'CERTIFICATE_BINDING',
      );
      for (const field of [
        'trustDomainID',
        'transactionID',
        'keyID',
        'certificateID',
        'certificateRepresentationHash',
        'policyHash',
      ])
        requireThat(equal(sim[field], activation[field]), prefix + 'SIM_ACTIVATION');
      requireThat(
        Number.isSafeInteger(at) &&
          at >= 0 &&
          at <= (trust.knowledgeTime ?? now()) &&
          sim.issuedAt <= at &&
          sim.expiresAt > at &&
          sim.origin === activation.origin &&
          activation.tbsKind === (format === 'CMS' ? 'CMS_SIGNED_ATTRS_DER' : 'ADAPTER_MESSAGE') &&
          equal(activation.simHash, H('SIM', sim)),
        prefix + 'ACTIVATION_CONTEXT',
      );
      const activationHash = validateActivation(activation, {
        tbs: signedDocument.tbs,
        publicKey: credentialBinding.publicKey,
        audience: policy.audience,
        at,
        maxLifetime: policy.maxActivationLifetime,
      });
      requireThat(
        permit.proofMode === policy.activationMode &&
          permit.issuedAt <= at &&
          permit.expiresAt > at &&
          permit.expiresAt <= activation.expiresAt &&
          Buffer.isBuffer(permit.activationEvidenceHash) &&
          permit.activationEvidenceHash.length === 64,
        prefix + 'PERMIT',
      );
      requireThat(
        equal(receipt.operationID, activation.operationID) &&
          equal(receipt.activationHash, activationHash) &&
          equal(receipt.permitHash, sha512(values.OperationPermit)) &&
          equal(receipt.keyID, sim.keyID) &&
          equal(receipt.tbsHash, sha512(signedDocument.tbs)) &&
          equal(receipt.signatureHash, sha512(signedDocument.signature)) &&
          typeof receipt.provider === 'string',
        format === 'CMS' ? 'ECP_EXECUTION_RECEIPT' : 'MDOC_ECP_RECEIPT',
      );
      return true;
    });
  if (boundReceipt && format === 'MDOC')
    check('integrity', () =>
      verifyIssuerSigned(values.PersonalMdoc, {
        issuerKey: trust.issuerPublicKey,
        certificate: trust.issuerCertificate,
        docType: trust.docType ?? SIGNER_DOCTYPE,
        certificateProfile: trust.certificateProfile ?? 'ISO_MDOC',
        at: receipt.executedAt,
        allowPartial: false,
      }),
    );
  if (boundReceipt && (controls.CertificateStatus || controls.OrganizationAuthorizationStatus)) {
    const knowledgeTime = trust.knowledgeTime ?? now();
    const scope = check('authorization', () => {
      const selected = snapshotIssuanceScope(trust.issuanceScope);
      requireThat(
        equal(selected.trustDomainID, trust.trustDomainID) &&
          equal(sim.trustDomainID, trust.trustDomainID) &&
          equal(H('SignaturePolicy', policy), H('SignaturePolicy', trust.expectedPolicy)) &&
          equal(sim.policyHash, H('SignaturePolicy', policy)) &&
          policy.allowedProfiles.includes(sim.profileID),
        'ECP_POLICY_AUTHORITY',
      );
      requireThat(
        Number.isSafeInteger(knowledgeTime) &&
          knowledgeTime >= 0 &&
          Number.isSafeInteger(receipt.executedAt) &&
          receipt.executedAt >= 0 &&
          receipt.executedAt <= knowledgeTime,
        'ECP_ACTIVATION_CONTEXT',
      );
      const scope = {
        trustDomainID: trust.trustDomainID,
        profileID: sim.profileID,
        issuerID: selected.issuerID,
        representation: selected.representation,
      };
      requireAuthority(evaluation.authority(trust.authorityResolver), {
        certificate: trust.receiptCertificate,
        role: 'RECEIPT_AUTHORITY',
        scope,
        stateTime: receipt.executedAt,
        knowledgeTime,
      });
      return scope;
    });
    const statusCheck = (statement, certificate, kind, prefix, binding) =>
      check('status', () => {
        binding();
        // Only authenticated, presently known authority statements may establish
        // revocation. A pin or self-declared status signer is not admission.
        if (statement.publishedAt <= knowledgeTime)
          requireAuthority(evaluation.authority(trust.authorityResolver), {
            certificate,
            role: 'STATUS_AUTHORITY',
            scope,
            stateTime: statement.publishedAt,
            knowledgeTime,
          });
        const result = evaluateStatus(statement, {
          stateTime: receipt.executedAt,
          knowledgeTime,
          scope: kind,
        });
        if (result.overall !== 'VALID')
          throw new AuthorityError({ ...result, reason: prefix + result.reason });
      });
    if (scope && controls.CertificateStatus && values.Certificate)
      statusCheck(
        controls.CertificateStatus,
        trust.statusCertificate,
        'CERTIFICATE',
        'ECP_',
        () => {
          const cert = parseCertificate(values.Certificate);
          requireThat(
            equal(controls.CertificateStatus.certificateID, cert.certificateID) &&
              equal(controls.CertificateStatus.trustDomainID, trust.trustDomainID),
            'ECP_STATUS_BINDING',
          );
        },
      );
    const boundOrganization =
      scope &&
      controls.OrganizationAuthorization &&
      check('authorization', () => {
        requireThat(
          policy.documentEvidence?.organizationAuthorization === true,
          'DOCUMENT_ORGANIZATION_PURPOSE',
        );
        verifyOrganizationAuthorizationBinding(controls.OrganizationAuthorization, {
          raw: values.OrganizationAuthorization,
          sim,
          activation: permit.activation,
          permit,
          receipt,
        });
        return true;
      });
    if (boundOrganization && controls.OrganizationAuthorizationStatus)
      statusCheck(
        controls.OrganizationAuthorizationStatus,
        organizationAuthority.statusCertificate,
        'ORGANIZATION_AUTHORIZATION',
        'DOCUMENT_ORGANIZATION_',
        () => {
          const statement = controls.OrganizationAuthorizationStatus;
          requireThat(
            equal(statement.authorizationID, controls.OrganizationAuthorization.authorizationID) &&
              equal(statement.authorizationHash, sha512(values.OrganizationAuthorization)) &&
              equal(statement.trustDomainID, trust.trustDomainID),
            'DOCUMENT_ORGANIZATION_STATUS_BINDING',
          );
        },
      );
  }
  return failures;
}

const completedReasons = Object.freeze({
  integrity: 'SELECTED_SIGNATURES_AND_BINDINGS_VALID',
  issuerTrust: 'SELECTED_ISSUER_AUTHORITIES_VALID',
  qualification: 'REGISTRATION_AUTHORIZATION_VALID',
  keyBinding: 'DOCUMENT_KEY_BINDING_VALID',
  authorization: 'SELECTED_OPERATION_AUTHORIZATION_VALID',
  status: 'SELECTED_STATUS_VALID',
});

/** Construct a verifier from relying-party authority and policy. Evidence cannot supply these inputs. */
export function createVerifier({ format, trust, maxBytes = 16 * 1024 * 1024 }) {
  requireThat(profiles.includes(format), 'SDK_FORMAT');
  requireThat(
    trust &&
      Buffer.isBuffer(trust.trustDomainID) &&
      trust.trustDomainID.length === 32 &&
      trust.expectedPolicy &&
      Buffer.isBuffer(trust.permitCertificate) &&
      Buffer.isBuffer(trust.receiptCertificate) &&
      Buffer.isBuffer(trust.raCertificate),
    'SDK_TRUST_REQUIRED',
  );
  requireThat(
    format === 'CMS'
      ? (trust.mtc || trust.issuerPublicKey) && trust.statusCertificate
      : trust.issuerRoots?.length &&
          trust.issuerCertificate &&
          trust.issuerPublicKey &&
          trust.sealCertificate &&
          trust.credentialLogTrust &&
          trust.statusURI,
    'SDK_AUTHORITY_REQUIRED',
  );
  requireThat(
    Number.isInteger(maxBytes) && maxBytes > 0 && maxBytes <= 64 * 1024 * 1024,
    'SDK_LIMIT',
  );
  if (executionRequirement(trust.expectedPolicy))
    requireThat(
      Buffer.isBuffer(trust.executionBindingCertificate) &&
        typeof trust.executionStatus === 'function',
      'SDK_EXECUTION_TRUST_REQUIRED',
    );
  if (trust.expectedPolicy.documentEvidence) {
    documentEvidenceTypes(trust.expectedPolicy, format);
    if (trust.expectedPolicy.requireTrustedTime)
      requireThat(
        trust.timestamp?.certificate &&
          trust.timestamp.issuerKey &&
          typeof trust.timestamp.policy === 'string' &&
          typeof trust.timestamp.status === 'function',
        'SDK_TIMESTAMP_TRUST_REQUIRED',
      );
  }
  const verify = format === 'CMS' ? verifySignaturePackage : verifyMdocSignaturePackage;
  return Object.freeze({
    verify(bytes) {
      const evaluation = new VerificationEvaluation();
      let inspected,
        profile = null;
      try {
        evaluation.phase('integrity');
        requireThat(Buffer.isBuffer(bytes) || bytes instanceof Uint8Array, 'SDK_BINARY_INPUT');
        const bundle = decodeCBOR(bytes, { maxBytes, maxItems: 100000 });
        if (
          typeof bundle?.plan?.profile === 'string' &&
          bundle.plan.profile.length > 0 &&
          bundle.plan.profile.length <= 256
        )
          profile = bundle.plan.profile;
        // Check available commitments before reporting missing or unsupported semantics.
        inspected = inspectEvidencePackage(bundle, { maxBytes });
        evaluation.phase(undefined);
        requireThat(inspected.supportedSchema, 'ECP_UNSUPPORTED_SCHEMA');
        if (inspected.plan)
          requireThat(plans[format].includes(inspected.plan.profile), 'SDK_UNSUPPORTED_PROFILE');
        evaluation.missing(inspected.missingTypes);
        requireThat(inspected.missingTypes.length === 0, 'ECP_MISSING_OBJECT');
        const result = verify(
          bundle,
          { ...trust, authorityResolver: evaluation.authority(trust.authorityResolver) },
          evaluation,
        );
        for (const [dimension, reason] of Object.entries(completedReasons))
          evaluation.observe(dimension, 'VALID', reason);
        evaluation.observe(
          'time',
          result.reason === 'TRUSTED_TIME_EVIDENCE_REQUIRED' ? 'INDETERMINATE' : 'VALID',
          result.reason === 'TRUSTED_TIME_EVIDENCE_REQUIRED' ? result.reason : result.time,
        );
        return verificationResult({
          ...result,
          overall: result.overall === 'VALID_UNDER_POLICY' ? 'VALID' : result.overall,
          profile,
          dimensions: evaluation.result(),
        });
      } catch (error) {
        evaluation.failure(error);
        let failure = error;
        if (
          verificationOutcome(error).overall !== 'INVALID' &&
          inspected?.supportedSchema &&
          plans[format].includes(profile)
        ) {
          const failures = availableChecks(
            format,
            inspected.values,
            trust,
            evaluation,
            error?.code !== 'ECP_MISSING_OBJECT' && inspected.missingTypes.length === 0,
          );
          failure =
            failures.find((value) => verificationOutcome(value).overall === 'INVALID') ??
            (verificationOutcome(error).overall === 'UNSUPPORTED'
              ? error
              : failures.find((value) => verificationOutcome(value).overall === 'UNSUPPORTED')) ??
            error;
        }
        const { overall, reason } = verificationOutcome(failure);
        return verificationResult({
          overall,
          reason,
          profile,
          dimensions: evaluation.result(),
        });
      }
    },
  });
}
