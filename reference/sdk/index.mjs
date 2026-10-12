import { decodeCBOR, requireThat, fields, ProtocolError } from '../core.mjs';
import { verifySignaturePackage } from '../evidence.mjs';
import { verifyMdocSignaturePackage } from '../signer-mdoc.mjs';
import { executionRequirement } from '../execution-binding.mjs';
import { verifyEvidenceClosure } from '../state.mjs';
import { documentPlans, documentEvidenceTypes } from '../document-evidence.mjs';

export const profiles = Object.freeze(['CMS', 'MDOC']);
const plans = Object.freeze({
  CMS: [
    'certconcord-ecp-cms-attested-v1',
    'certconcord-ecp-cms-passkey-v1',
    'certconcord-ecp-cms-execution-draft-02',
    ...Object.keys(documentPlans).filter((p) => p.includes('-cms-')),
  ],
  MDOC: [
    'certconcord-ecp-mdoc-attested-v1',
    'certconcord-ecp-mdoc-passkey-v1',
    'certconcord-ecp-mdoc-execution-draft-02',
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
      Buffer.isBuffer(trust.receiptCertificate),
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
    requireThat(format !== 'CMS' || Buffer.isBuffer(trust.raCertificate), 'SDK_RA_TRUST_REQUIRED');
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
        fields(bundle, ['schemaVersion', 'root', 'objects']);
        requireThat(
          Buffer.isBuffer(bundle.root) &&
            bundle.root.length === 64 &&
            Array.isArray(bundle.objects) &&
            bundle.objects.length <= 128,
          'SDK_EVIDENCE_SHAPE',
        );
        for (const o of bundle.objects) {
          fields(o, ['id', 'type', 'version', 'payload', 'dependencies']);
          requireThat(
            Buffer.isBuffer(o.id) &&
              o.id.length === 64 &&
              typeof o.type === 'string' &&
              Buffer.isBuffer(o.payload) &&
              Array.isArray(o.dependencies) &&
              o.dependencies.length <= 128 &&
              o.dependencies.every((x) => Buffer.isBuffer(x) && x.length === 64),
            'SDK_EVIDENCE_SHAPE',
          );
        }
        // Check available commitments before reporting missing or unsupported semantics.
        verifyEvidenceClosure(bundle.objects, [bundle.root]);
        requireThat(
          Number.isSafeInteger(bundle.schemaVersion) && bundle.schemaVersion > 0,
          'SDK_EVIDENCE_SHAPE',
        );
        requireThat(bundle.schemaVersion === 1, 'SDK_UNSUPPORTED_SCHEMA');
        const roots = bundle.objects.filter((o) => o.type === 'VerificationPlan');
        requireThat(roots.length === 1 && roots[0].id.equals(bundle.root), 'SDK_PLAN_SHAPE');
        const plan = decodeCBOR(roots[0].payload);
        fields(plan, ['schemaVersion', 'profile', 'objects']);
        requireThat(
          Number.isSafeInteger(plan.schemaVersion) &&
            plan.schemaVersion > 0 &&
            typeof plan.profile === 'string' &&
            plan.profile.length > 0 &&
            plan.objects &&
            typeof plan.objects === 'object' &&
            !Array.isArray(plan.objects) &&
            Object.values(plan.objects).every((id) => Buffer.isBuffer(id) && id.length === 64),
          'SDK_PLAN_SHAPE',
        );
        requireThat(plan.schemaVersion === 1, 'SDK_UNSUPPORTED_SCHEMA');
        requireThat(plans[format].includes(plan.profile), 'SDK_UNSUPPORTED_PROFILE');
        const result = verify(bundle, trust);
        return Object.freeze({
          ...result,
          overall: result.overall === 'VALID_UNDER_POLICY' ? 'VALID' : result.overall,
          coreRevision: 'draft-02',
          profile: plan.profile,
        });
      } catch (error) {
        const reason = error instanceof ProtocolError ? error.code : 'MALFORMED_EVIDENCE';
        return Object.freeze({
          overall: [
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
            : ['SDK_UNSUPPORTED_PROFILE', 'SDK_UNSUPPORTED_SCHEMA'].includes(reason)
              ? 'UNSUPPORTED'
              : 'INVALID',
          reason,
          coreRevision: 'draft-02',
        });
      }
    },
  });
}
