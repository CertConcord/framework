import { decodeCBOR, requireThat, ProtocolError } from '../core.mjs';
import { verifySignaturePackage } from '../evidence.mjs';
import { verifyMdocSignaturePackage } from '../signer-mdoc.mjs';
import { executionRequirement } from '../execution-binding.mjs';
import { verifyEvidencePackage } from '../evidence-plan.mjs';
import { documentPlans, documentEvidenceTypes } from '../document-evidence.mjs';
import { AuthorityError } from '../authority-history.mjs';

export const profiles = Object.freeze(['CMS', 'MDOC']);
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
      try {
        requireThat(Buffer.isBuffer(bytes) || bytes instanceof Uint8Array, 'SDK_BINARY_INPUT');
        const bundle = decodeCBOR(bytes, { maxBytes, maxItems: 100000 });
        // Check available commitments before reporting missing or unsupported semantics.
        const { plan } = verifyEvidencePackage(bundle, { maxBytes });
        requireThat(plans[format].includes(plan.profile), 'SDK_UNSUPPORTED_PROFILE');
        const result = verify(bundle, trust);
        return Object.freeze({
          ...result,
          overall: result.overall === 'VALID_UNDER_POLICY' ? 'VALID' : result.overall,
          coreRevision: 'draft-03',
          profile: plan.profile,
        });
      } catch (error) {
        const reason = error instanceof ProtocolError ? error.code : 'MALFORMED_EVIDENCE';
        return Object.freeze({
          overall:
            error instanceof AuthorityError
              ? error.overall
              : [
                    'ECP_MISSING_OBJECT',
                    'ECP_STATUS_STALE',
                    'ECP_STATUS_UNKNOWN',
                    'STATUS_LIST_STALE',
                    'STATUS_LIST_MISSING',
                    'STATUS_LIST_NOT_YET_KNOWN',
                    'DOCUMENT_ORGANIZATION_STATUS_STALE',
                    'DOCUMENT_ORGANIZATION_STATUS_UNKNOWN',
                    'DOCUMENT_TIMESTAMP_ACCURACY_REQUIRED',
                  ].includes(reason)
                ? 'INDETERMINATE'
                : ['SDK_UNSUPPORTED_PROFILE', 'ECP_UNSUPPORTED_SCHEMA'].includes(reason)
                  ? 'UNSUPPORTED'
                  : 'INVALID',
          reason,
          coreRevision: 'draft-03',
        });
      }
    },
  });
}
