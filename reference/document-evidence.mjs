import { H, sha512, spki, parseDER, equal, requireThat, fields } from './core.mjs';
import { parseCertificate, RRA } from './pki.mjs';
import { evidenceObject, readControl, evaluateStatus } from './state.mjs';
import { verifyTimestampToken } from './timestamp.mjs';

export const DOCUMENT_EVIDENCE_PROFILE = 'certconcord-document-evidence-draft-02';
export const documentPlans = Object.freeze({
  'certconcord-ecp-cms-attested-draft-02': 'certconcord-ecp-cms-attested-v1',
  'certconcord-ecp-mdoc-attested-draft-02': 'certconcord-ecp-mdoc-attested-v1',
});

export function documentEvidenceTypes(policy, format) {
  if (!policy.documentEvidence) return [];
  fields(policy.documentEvidence, ['profile', 'organizationAuthorization']);
  requireThat(
    policy.documentEvidence.profile === DOCUMENT_EVIDENCE_PROFILE &&
      typeof policy.documentEvidence.organizationAuthorization === 'boolean' &&
      typeof policy.requireTrustedTime === 'boolean' &&
      ['CMS', 'MDOC'].includes(format),
    'DOCUMENT_EVIDENCE_POLICY',
  );
  requireThat(
    !policy.documentEvidence.organizationAuthorization || format === 'CMS',
    'DOCUMENT_ORGANIZATION_REPRESENTATION',
  );
  return [
    ...(format === 'CMS' ? ['RegistrationAuthorization'] : []),
    ...(policy.documentEvidence.organizationAuthorization
      ? ['OrganizationAuthorization', 'OrganizationAuthorizationStatus']
      : []),
    ...(policy.requireTrustedTime ? ['DocumentTimestamp'] : []),
  ];
}

// Status can be refreshed without changing the proof of existence of the signed operation.
const mutableTypes = new Set([
  'CertificateStatus',
  'CredentialStatusList',
  'OrganizationAuthorizationStatus',
  'DocumentTimestamp',
  'VerificationPlan',
]);
export function documentTimestampImprint(format, objects) {
  const selected = objects.filter((o) => !mutableTypes.has(o.type));
  requireThat(
    new Set(selected.map((o) => o.type)).size === selected.length,
    'DOCUMENT_TIMESTAMP_DUPLICATE',
  );
  return H('DocumentTimeProof', {
    schemaVersion: 1,
    format,
    objects: selected
      .map((o) => ({ type: o.type, payloadHash: sha512(o.payload) }))
      .sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0)),
  });
}

export function appendDocumentEvidence(objects, { policy, format, evidence }) {
  requireThat(!!policy.documentEvidence === !!evidence, 'DOCUMENT_EVIDENCE_REQUIRED');
  if (!evidence) return;
  const types = documentEvidenceTypes(policy, format);
  fields(evidence, types);
  for (const type of types.filter((t) => t !== 'DocumentTimestamp')) {
    requireThat(Buffer.isBuffer(evidence[type]), 'DOCUMENT_EVIDENCE_BINARY');
    objects.push(evidenceObject(type, evidence[type]));
  }
  if (types.includes('DocumentTimestamp')) {
    const source = evidence.DocumentTimestamp;
    const token =
      typeof source === 'function' ? source(documentTimestampImprint(format, objects)) : source;
    requireThat(Buffer.isBuffer(token), 'DOCUMENT_EVIDENCE_BINARY');
    objects.push(evidenceObject('DocumentTimestamp', token));
  }
}

export function selectDocumentPlan(base, policy) {
  if (!policy.documentEvidence) return base;
  const selected = Object.entries(documentPlans).find(([, value]) => value === base);
  requireThat(selected, 'DOCUMENT_EVIDENCE_PLAN');
  return selected[0];
}

export function verifyRegistrationBinding(
  raw,
  certificate,
  { raCertificate, subjectID, profileID, policyHash, at },
) {
  requireThat(Buffer.isBuffer(raCertificate), 'DOCUMENT_RA_TRUST_REQUIRED');
  const r = readControl(raw, 'RegistrationAuthorization', raCertificate);
  const cert = parseCertificate(certificate);
  const extension = cert.extensions.get(RRA['id-pe-certconcordAuthorizationID']);
  const commitment = extension && parseDER(extension.value);
  requireThat(
    r.schemaVersion === 1 &&
      commitment?.tag === 4 &&
      equal(commitment.value, H('RegistrationAuthorization', r)) &&
      Buffer.isBuffer(r.subjectID) &&
      r.subjectID.length === 32 &&
      equal(r.subjectID, subjectID) &&
      r.profileID === profileID &&
      equal(r.policyHash, policyHash) &&
      equal(r.spkiHash, sha512(spki(cert.publicKey))) &&
      Number.isSafeInteger(r.issuedAt) &&
      Number.isSafeInteger(r.expiresAt) &&
      r.issuedAt <= at &&
      r.expiresAt > r.issuedAt &&
      r.expiresAt - r.issuedAt <= 300,
    'DOCUMENT_REGISTRATION_BINDING',
  );
  return r;
}

export function verifyDocumentEvidence(
  { format, values, sim, policy, activation, permit, receipt, knowledgeTime, verifyState },
  trust,
) {
  if (!policy.documentEvidence) return undefined;
  documentEvidenceTypes(policy, format);
  if (format === 'CMS')
    verifyRegistrationBinding(values.RegistrationAuthorization, values.Certificate, {
      raCertificate: trust.raCertificate,
      subjectID: sim.subjectID,
      profileID: sim.profileID,
      policyHash: sim.policyHash,
      at: receipt.executedAt,
    });
  const org = policy.documentEvidence.organizationAuthorization;
  requireThat(org === (sim.profileID === 'CERTCONCORD-ORG-SEAL-v1'), 'DOCUMENT_ORGANIZATION_PURPOSE');
  let authorization, authority;
  if (org) {
    authority = trust.organizationAuthorities?.find((a) => equal(a.organizationID, sim.subjectID));
    requireThat(
      authority?.certificate && authority.statusCertificate,
      'DOCUMENT_ORGANIZATION_TRUST_REQUIRED',
    );
    authorization = readControl(
      values.OrganizationAuthorization,
      'OrganizationAuthorization',
      authority.certificate,
    );
    fields(authorization, [
      'schemaVersion',
      'authorizationID',
      'trustDomainID',
      'organizationID',
      'actorID',
      'actorType',
      'keyID',
      'certificateID',
      'purpose',
      'activationHash',
      'policyHash',
      'issuedAt',
      'expiresAt',
    ]);
    requireThat(
      authorization.schemaVersion === 1 &&
        Buffer.isBuffer(authorization.authorizationID) &&
        authorization.authorizationID.length === 32 &&
        equal(authorization.authorizationID, sim.organizationAuthorizationID) &&
        equal(authorization.trustDomainID, sim.trustDomainID) &&
        equal(authorization.organizationID, sim.subjectID) &&
        Buffer.isBuffer(authorization.actorID) &&
        authorization.actorID.length === 32 &&
        ['PERSON', 'WORKLOAD'].includes(authorization.actorType) &&
        (authorization.actorType === 'WORKLOAD'
          ? permit.proofMode === 'WORKLOAD'
          : ['HUMAN_WEBAUTHN', 'HUMAN_MDOC', 'HUMAN_SESSION'].includes(permit.proofMode)) &&
        authorization.purpose === 'ORGANIZATION_SEAL' &&
        sim.purpose === 'ORGANIZATION_SEAL' &&
        equal(authorization.keyID, sim.keyID) &&
        equal(authorization.certificateID, sim.certificateID) &&
        equal(authorization.policyHash, sim.policyHash) &&
        equal(authorization.activationHash, H('ActivationContext', activation)) &&
        equal(permit.activationEvidenceHash, sha512(values.OrganizationAuthorization)) &&
        Number.isSafeInteger(authorization.issuedAt) &&
        Number.isSafeInteger(authorization.expiresAt) &&
        authorization.issuedAt >= activation.issuedAt &&
        authorization.expiresAt <= activation.expiresAt &&
        authorization.issuedAt <= receipt.executedAt &&
        authorization.expiresAt > receipt.executedAt,
      'DOCUMENT_ORGANIZATION_BINDING',
    );
  }
  let stateTime = receipt.executedAt,
    time = 'DECLARED_EXECUTION_TIME',
    timeResult;
  if (policy.requireTrustedTime) {
    requireThat(
      trust.timestamp?.certificate &&
        trust.timestamp.issuerKey &&
        typeof trust.timestamp.policy === 'string' &&
        typeof trust.timestamp.status === 'function',
      'DOCUMENT_TIMESTAMP_TRUST_REQUIRED',
    );
    const objects = Object.entries(values).map(([type, payload]) => ({ type, payload }));
    timeResult = verifyTimestampToken(values.DocumentTimestamp, {
      ...trust.timestamp,
      imprint: documentTimestampImprint(format, objects),
      at: knowledgeTime,
      maxFutureSkew: 0,
    });
    const tsa = parseCertificate(trust.timestamp.certificate);
    requireThat(timeResult.accuracy !== undefined, 'DOCUMENT_TIMESTAMP_ACCURACY_REQUIRED');
    requireThat(
      Number.isFinite(timeResult.poeUpperBound) &&
        timeResult.poeUpperBound <= knowledgeTime &&
        tsa.notBefore <= timeResult.genTime - timeResult.accuracy &&
        tsa.notAfter > timeResult.poeUpperBound &&
        trust.timestamp.status({
          certificate: trust.timestamp.certificate,
          genTime: timeResult.genTime,
          stateTime: timeResult.poeUpperBound,
          knowledgeTime,
        }) === true,
      'DOCUMENT_TIMESTAMP_STATUS_OR_ACCURACY',
    );
    stateTime = timeResult.poeUpperBound;
    requireThat(
      receipt.executedAt <= stateTime &&
        sim.issuedAt <= stateTime &&
        sim.expiresAt > stateTime &&
        activation.issuedAt <= stateTime &&
        activation.expiresAt > stateTime &&
        permit.issuedAt <= stateTime &&
        permit.expiresAt > stateTime,
      'DOCUMENT_TIMESTAMP_OPERATION_WINDOW',
    );
    verifyState(stateTime);
    time = 'TRUSTED_PROOF_OF_EXISTENCE';
  }
  if (org) {
    requireThat(
      authorization.issuedAt <= stateTime && authorization.expiresAt > stateTime,
      'DOCUMENT_ORGANIZATION_WINDOW',
    );
    const status = readControl(
      values.OrganizationAuthorizationStatus,
      'OrganizationAuthorizationStatus',
      authority.statusCertificate,
    );
    requireThat(
      equal(status.authorizationID, authorization.authorizationID) &&
        equal(status.authorizationHash, sha512(values.OrganizationAuthorization)) &&
        equal(status.trustDomainID, sim.trustDomainID),
      'DOCUMENT_ORGANIZATION_STATUS_BINDING',
    );
    const result = evaluateStatus(status, {
      stateTime,
      knowledgeTime,
      scope: 'ORGANIZATION_AUTHORIZATION',
    });
    requireThat(result === 'GOOD', 'DOCUMENT_ORGANIZATION_STATUS_' + result);
  }
  return {
    time,
    stateTime,
    ...(timeResult
      ? {
          proofOfExistenceUpperBound: stateTime,
          timestampGenerationTime: timeResult.genTime,
          timestampAccuracy: timeResult.accuracy,
        }
      : {}),
    subjectBinding: format === 'CMS' ? 'REGISTRATION_AUTHORIZATION' : 'NATIVE_MDOC',
    ...(org
      ? {
          organizationAuthorization: 'AUTHORITY_ATTESTED_OPERATION',
          actorType: authorization.actorType,
        }
      : {}),
  };
}
