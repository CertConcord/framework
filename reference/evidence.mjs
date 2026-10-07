import {
  dcbor,
  decodeCBOR,
  H,
  sha512,
  equal,
  requireThat,
  keyID,
  now,
  fields,
  publicFromDER,
  spki,
} from './core.mjs';
import { verifyCMS, parseCertificate, validateCertificate, OID, RRA } from './pki.mjs';
import { PASSKEY_SIGN_PROFILE } from './raw-signing.mjs';
import { verifyPasskeyOperation } from './passkey-credentials.mjs';
import { readControl, validateActivation, evaluateStatus } from './state.mjs';
import { evidenceLeaf, createEvidencePackage, verifyEvidencePackage } from './evidence-plan.mjs';
import { verifyMTC } from './mtc.mjs';
import { snapshotIssuanceScope } from './enrollment-scope.mjs';
import { AuthorityError } from './authority-history.mjs';
import {
  operationAuthorityQueries,
  requireAuthorities,
  collectAuthorityFailure,
} from './control-authority.mjs';
import { executionRequirement, verifyExecutionEvidence } from './execution-binding.mjs';
import {
  appendDocumentEvidence,
  selectDocumentPlan,
  documentPlans,
  documentEvidenceTypes,
  verifyDocumentEvidence,
} from './document-evidence.mjs';

const types = [
  'Document',
  'Certificate',
  'RegistrationAuthorization',
  'SIM',
  'SignaturePolicy',
  'OperationPermit',
  'ExecutionReceipt',
  'CertificateStatus',
  'CMS',
];
export function createSignaturePackage({
  document,
  certificate,
  registrationAuthorization,
  sim,
  policy,
  permit,
  receipt,
  status,
  cms,
  passkeyEvidence,
  executionEvidence,
  documentEvidence,
  ...unknown
}) {
  requireThat(!Object.hasOwn(unknown, 'activation'), 'ECP_DUPLICATE_ACTIVATION');
  fields(unknown, []);
  requireThat(
    !!executionRequirement(policy) === !!executionEvidence &&
      !(passkeyEvidence && executionEvidence),
    'ECP_EXECUTION_PROFILE',
  );
  const payloads = [
      document,
      certificate,
      registrationAuthorization,
      dcbor(sim),
      dcbor(policy),
      permit,
      receipt,
      status,
      cms,
    ],
    objects = types.map((type, i) => evidenceLeaf(type, payloads[i]));
  if (passkeyEvidence) {
    const { binding, ...raw } = passkeyEvidence;
    objects.push(
      evidenceLeaf('PasskeySigningBinding', dcbor(binding)),
      evidenceLeaf('PasskeyRawEvidence', dcbor(raw)),
    );
  }
  if (executionEvidence)
    objects.push(evidenceLeaf('ExecutionBindingEvidence', dcbor(executionEvidence)));
  appendDocumentEvidence(objects, { policy, format: 'CMS', evidence: documentEvidence });
  return createEvidencePackage(
    selectDocumentPlan(
      executionEvidence
        ? 'certconcord-ecp-cms-execution-draft-03'
        : passkeyEvidence
          ? 'certconcord-ecp-cms-passkey-draft-03'
          : 'certconcord-ecp-cms-attested-draft-03',
      policy,
    ),
    objects,
  );
}

// Trust inputs are provided by the relying party, never taken as authority from the package itself.
export function verifySignaturePackage(
  bundle,
  {
    issuerPublicKey,
    issuerCertificate,
    issuanceScope,
    authorityResolver,
    mtc,
    permitCertificate,
    receiptCertificate,
    statusCertificate,
    expectedPolicy,
    trustDomainID,
    knowledgeTime = now(),
    passkeyStatus,
    executionBindingCertificate,
    executionStatus,
    ...documentTrust
  },
) {
  const { plan } = verifyEvidencePackage(bundle);
  const document = Object.hasOwn(documentPlans, plan.profile);
  const passkey = plan.profile === 'certconcord-ecp-cms-passkey-draft-03';
  const execution = plan.profile === 'certconcord-ecp-cms-execution-draft-03';
  const selectedTypes = [
    ...(execution
      ? [...types, 'ExecutionBindingEvidence']
      : passkey
        ? [...types, 'PasskeySigningBinding', 'PasskeyRawEvidence']
        : types),
    ...(document ? documentEvidenceTypes(expectedPolicy, 'CMS') : []),
  ];
  const { values } = verifyEvidencePackage(bundle, { requiredTypes: selectedTypes });
  requireThat(
    execution ||
      passkey ||
      plan.profile === 'certconcord-ecp-cms-attested-draft-03' ||
      documentPlans[plan.profile] === 'certconcord-ecp-cms-attested-draft-03',
    'ECP_PLAN_PROFILE',
  );
  const sim = decodeCBOR(values.SIM),
    policy = decodeCBOR(values.SignaturePolicy),
    cert = parseCertificate(values.Certificate),
    permit = readControl(values.OperationPermit, 'OperationPermit', permitCertificate),
    activation = permit.activation,
    receipt = readControl(values.ExecutionReceipt, 'ExecutionReceipt', receiptCertificate),
    status = readControl(values.CertificateStatus, 'CertificateStatus', statusCertificate);
  requireThat(!!executionRequirement(policy) === execution, 'ECP_EXECUTION_DOWNGRADE');
  requireThat(!!policy.documentEvidence === document, 'DOCUMENT_EVIDENCE_DOWNGRADE');
  requireThat(
    passkey === (sim.profileID === PASSKEY_SIGN_PROFILE) &&
      passkey === cert.extensions.has(RRA['id-pe-certconcordPasskeyBinding']),
    'ECP_PASSKEY_PROFILE',
  );
  requireThat(
    expectedPolicy &&
      equal(H('SignaturePolicy', policy), H('SignaturePolicy', expectedPolicy)) &&
      equal(sim.policyHash, H('SignaturePolicy', policy)) &&
      equal(activation.trustDomainID, trustDomainID) &&
      equal(sim.trustDomainID, trustDomainID),
    'ECP_POLICY_AUTHORITY',
  );
  requireThat(
    policy.allowedProfiles.includes(sim.profileID) &&
      policy.allowedOrigins.includes(sim.origin) &&
      sim.container === 'CMS' &&
      sim.adapterID === (passkey ? 'certconcord-cms-passkey-v1' : 'certconcord-cms-v1') &&
      sim.documents?.length === 1,
    'ECP_SIGNATURE_PROFILE',
  );
  const context = {
      schemaVersion: 1,
      trustDomainID,
      profileID: sim.profileID,
      container: sim.container,
      adapterID: sim.adapterID,
    },
    v = verifyCMS(values.CMS, {
      content: values.Document,
      expectedCertificate: values.Certificate,
      context,
      simHash: H('SIM', sim),
      policyHash: H('SignaturePolicy', policy),
    });
  const doc = sim.documents[0];
  requireThat(
    doc.scope === 'CMS_CONTENT' &&
      doc.digestAlgorithm === 'SHA-512' &&
      equal(doc.digest, sha512(values.Document)),
    'ECP_DOCUMENT_SCOPE',
  );
  requireThat(
    equal(cert.certificateID, sim.certificateID) &&
      equal(cert.representationHash, sim.certificateRepresentationHash) &&
      equal(keyID(cert.publicKey), sim.keyID),
    'ECP_CERTIFICATE_BINDING',
  );
  for (const field of [
    'trustDomainID',
    'transactionID',
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'policyHash',
  ])
    requireThat(equal(sim[field], activation[field]), 'ECP_SIM_ACTIVATION');
  const at = receipt.executedAt;
  requireThat(
    Number.isSafeInteger(at) &&
      at <= knowledgeTime &&
      sim.issuedAt <= at &&
      sim.expiresAt > at &&
      sim.origin === activation.origin &&
      activation.tbsKind === 'CMS_SIGNED_ATTRS_DER' &&
      equal(activation.simHash, H('SIM', sim)),
    'ECP_ACTIVATION_CONTEXT',
  );
  const activationHash = validateActivation(activation, {
    tbs: v.tbs,
    publicKey: cert.publicKey,
    audience: policy.audience,
    at,
    maxLifetime: policy.maxActivationLifetime,
  });
  requireThat(
    permit.proofMode === policy.activationMode &&
      permit.issuedAt <= at &&
      permit.expiresAt > at &&
      permit.expiresAt <= activation.expiresAt &&
      permit.activationEvidenceHash.length === 64,
    'ECP_PERMIT',
  );
  requireThat(
    equal(receipt.operationID, activation.operationID) &&
      equal(receipt.activationHash, activationHash) &&
      equal(receipt.permitHash, sha512(values.OperationPermit)) &&
      equal(receipt.keyID, sim.keyID) &&
      equal(receipt.tbsHash, sha512(v.tbs)) &&
      equal(receipt.signatureHash, sha512(v.signature)) &&
      typeof receipt.provider === 'string',
    'ECP_EXECUTION_RECEIPT',
  );
  const selectedScope = snapshotIssuanceScope(issuanceScope),
    scope = {
      trustDomainID,
      issuerID: selectedScope.issuerID,
      representation: cert.algorithm === OID.mtc ? 'MTC' : 'X509',
      profileID: sim.profileID,
    },
    issuerKey = cert.algorithm === OID.mtc ? mtc?.caPublicKey : issuerPublicKey,
    issuedAt = readControl(
      values.RegistrationAuthorization,
      'RegistrationAuthorization',
      documentTrust.raCertificate,
    ).issuedAt,
    authorityQueries = [],
    authorityQuorums = [],
    unavailable = [],
    authorityFailures = [];
  requireThat(
    equal(selectedScope.trustDomainID, trustDomainID) &&
      selectedScope.representation === scope.representation &&
      issuerKey &&
      equal(selectedScope.issuerKeyID, keyID(issuerKey)),
    'ISSUANCE_SCOPE',
  );
  if (issuerCertificate)
    requireThat(
      equal(keyID(parseCertificate(issuerCertificate).publicKey), keyID(issuerKey)),
      'ISSUER_KEY_BINDING',
    );
  const verifyState = (stateTime, { proofOfExistenceUpperBound } = {}) => {
    if (cert.algorithm === OID.mtc) {
      requireThat(mtc, 'ECP_MTC_TRUST_REQUIRED');
      const proof = verifyMTC(values.Certificate, {
        ...mtc,
        at: stateTime,
        profileID: sim.profileID,
        trustedSubtrees: [],
      });
      authorityQuorums.push({
        members: proof.verifiedCosigners,
        threshold: mtc.threshold,
        role: 'COSIGNER',
        scope,
        stateTimes:
          proofOfExistenceUpperBound === undefined
            ? [issuedAt]
            : [issuedAt, proofOfExistenceUpperBound],
        knowledgeTime,
      });
    } else {
      requireThat(issuerPublicKey, 'ECP_ISSUER_REQUIRED');
      validateCertificate(values.Certificate, issuerPublicKey, {
        at: stateTime,
        profileID: sim.profileID,
      });
    }
    requireThat(
      equal(status.certificateID, cert.certificateID) && equal(status.trustDomainID, trustDomainID),
      'ECP_STATUS_BINDING',
    );
    const statusResult = evaluateStatus(status, {
      stateTime,
      knowledgeTime,
      scope: 'CERTIFICATE',
    });
    if (statusResult.overall === 'INDETERMINATE') unavailable.push('ECP_' + statusResult.reason);
    else if (statusResult.overall !== 'VALID')
      authorityFailures.push(
        new AuthorityError({ ...statusResult, reason: 'ECP_' + statusResult.reason }),
      );
    authorityQueries.push(
      ...operationAuthorityQueries(
        { permitCertificate, receiptCertificate },
        scope,
        stateTime,
        knowledgeTime,
      ),
      {
        ...(issuerCertificate
          ? { certificate: issuerCertificate }
          : { publicKeyDER: spki(issuerKey) }),
        role: 'ISSUER',
        scope,
        stateTime: issuedAt,
        knowledgeTime,
      },
      ...(status.publishedAt <= knowledgeTime
        ? [
            {
              certificate: statusCertificate,
              role: 'STATUS_AUTHORITY',
              scope,
              stateTime: status.publishedAt,
              knowledgeTime,
            },
          ]
        : []),
    );
  };
  verifyState(at);
  if (passkey) {
    const binding = decodeCBOR(values.PasskeySigningBinding),
      raw = decodeCBOR(values.PasskeyRawEvidence);
    requireThat(equal(sim.subjectID, binding.subjectID), 'ECP_PASSKEY_SUBJECT');
    collectAuthorityFailure(
      () =>
        verifyPasskeyOperation(
          {
            permit: values.OperationPermit,
            tbs: v.tbs,
            signature: v.signature,
            assertion: raw.assertion,
            receipt: values.ExecutionReceipt,
            binding,
            registration: {
              ...raw.registration,
              publicKey: publicFromDER(raw.registration.publicKeyDER),
            },
            certificate: values.Certificate,
          },
          {
            authorityResolver,
            knowledgeTime,
            permitCertificate,
            receiptCertificate,
            certificateVerifier: () => true,
            audience: policy.audience,
            at,
            status: ({ binding: b }) =>
              typeof passkeyStatus === 'function' &&
              passkeyStatus(b, { at, knowledgeTime }) === true,
          },
        ),
      authorityFailures,
    );
  }
  const executionResult = execution
    ? collectAuthorityFailure(
        () =>
          verifyExecutionEvidence(
            {
              policy,
              sim,
              permit: values.OperationPermit,
              tbs: v.tbs,
              signature: v.signature,
              publicKey: cert.publicKey,
              receipt: values.ExecutionReceipt,
              evidence: decodeCBOR(values.ExecutionBindingEvidence),
            },
            {
              authorityResolver,
              bindingCertificate: executionBindingCertificate,
              permitCertificate,
              receiptCertificate,
              trustDomainID,
              at,
              knowledgeTime,
              status: executionStatus,
            },
          ),
        authorityFailures,
      )
    : undefined;
  const documentResult = collectAuthorityFailure(
    () =>
      verifyDocumentEvidence(
        {
          format: 'CMS',
          values,
          sim,
          policy,
          activation,
          permit,
          receipt,
          knowledgeTime,
          verifyState,
        },
        { ...documentTrust, issuanceScope, authorityResolver },
      ),
    authorityFailures,
  );
  requireAuthorities(
    authorityResolver,
    authorityQueries,
    unavailable,
    authorityFailures,
    authorityQuorums,
  );
  const missingTime = policy.requireTrustedTime && !policy.documentEvidence;
  return {
    ...(executionResult ? { execution: executionResult } : {}),
    profile: plan.profile,
    closure: 'COMPLETE',
    semanticValidation: 'PLAN_VALIDATED',
    cryptographicValidity: 'VALID',
    certificateTrust: 'VALID',
    activation: 'ATTESTED_VALID',
    status: 'GOOD',
    time: 'DECLARED_EXECUTION_TIME',
    coverage: 'CMS_CONTENT',
    ...(passkey
      ? {
          documentAlgorithm: 'ES256',
          documentKeyMode: 'PASSKEY_KEY',
          documentAlgorithmAssurance: 'CLASSICAL',
        }
      : {}),
    overall: missingTime ? 'INDETERMINATE' : 'VALID_UNDER_POLICY',
    reason: missingTime
      ? 'TRUSTED_TIME_EVIDENCE_REQUIRED'
      : 'ALL_SELECTED_POLICY_REQUIREMENTS_SATISFIED',
    stateTime: at,
    knowledgeTime,
    ...documentResult,
  };
}
