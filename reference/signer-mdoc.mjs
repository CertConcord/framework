import { documentKeyRelation } from './vendor/mdoc-signing/key-relation.mjs';
import {
  D,
  spki,
  H,
  b64u,
  unb64u,
  random,
  now,
  equal,
  requireThat,
  sha512,
  keyID,
  publicFromDER,
  sign,
  verify,
  dcbor,
  decodeCBOR,
  fields,
} from './core.mjs';
import { encode, decode, get, coseJWK } from './cose.mjs';
import { importPublicJWK } from './jose.mjs';
import { derToP1363, p1363ToDER } from './ecdsa.mjs';
import { validateAdmissionAssessment } from './key-attestation.mjs';
import { issueMdoc, verifyIssuerSigned, MDOC_CONFIG } from './mdoc.mjs';
import { CredentialIssuer, verifyX5C, verifyStatusList } from './openid.mjs';
import { verifyCSR } from './enrollment.mjs';
import { snapshotIssuanceScope, issuanceRequestID, requireIssuanceAuthority } from './enrollment-scope.mjs';
import { requireAuthority } from './authority-history.mjs';
import { signCMS, parseCertificate } from './pki.mjs';
import {
  readControl,
  validateActivation,
  evidenceObject,
  verifyEvidenceClosure,
} from './state.mjs';
import { verifyCredentialLog } from './credential-log.mjs';
import { PASSKEY_SIGN_PROFILE } from './raw-signing.mjs';
import { verifyPasskeyOperation } from './passkey-credentials.mjs';
import { executionRequirement, verifyExecutionEvidence } from './execution-binding.mjs';

export const SIGNER_DOCTYPE = 'org.certconcord.signer.1';
export const SIGNER_NAMESPACE = SIGNER_DOCTYPE;
export const DEVICE_SIGN_PROFILE = 'CERTCONCORD-PERSON-DEVICE-SIGN-v1';
export function documentKeyMode(profileID, publicKey, holderPublicKey) {
  const mode = profileID === PASSKEY_SIGN_PROFILE ? 'PASSKEY_KEY'
    : profileID === DEVICE_SIGN_PROFILE ? 'DEVICE_KEY' : 'INDEPENDENT_PQ';
  requireThat(mode !== 'INDEPENDENT_PQ' || profileID === 'CERTCONCORD-PERSON-SIGN-v1', 'DOCUMENT_INDEPENDENT_PQ_KEY');
  return documentKeyRelation(mode, spki(publicKey), spki(holderPublicKey));
}

const plain = (v) =>
  v instanceof Map
    ? Object.fromEntries([...v].map(([k, x]) => [k, plain(x)]))
    : Array.isArray(v)
      ? v.map(plain)
      : v;
const authBytes = (credential) => encode(get(decode(credential), 'issuerAuth'));

export class PersonalMdocCA extends CredentialIssuer {
  constructor({
    bindings,
    raCertificate,
    sealCertificate,
    sealKey,
    credentialLog,
    credentialLogTrust,
    allowedProfiles = ['CERTCONCORD-PERSON-SIGN-v1'],
    validity = 86400,
    docType = SIGNER_DOCTYPE,
    certificateProfile = 'ISO_MDOC',
    additionalNamespaces = () => ({}),
    keyBindings,
    issuanceScope,
    authorityResolver,
    ...options
  }) {
    super({
      ...options,
      mdocDocType: docType,
      mdocNamespace: SIGNER_NAMESPACE,
      authorizeCredential: ({ offer, holderJWK }) => {
        bindings.authorizeCredential({ offer, holderJWK });
        requireThat(offer.expiresAt > now(), 'PERSONAL_MDOC_GRANT_EXPIRED');
        return true;
      },
      mintCredential: (request) => this.mint(request),
    });
    requireThat(
      credentialLog?.journal !== options.journal && credentialLog && credentialLogTrust,
      'CREDENTIAL_LOG_BOUNDARY',
    );
    requireThat(
      parseCertificate(sealCertificate).publicKey.asymmetricKeyType === 'ml-dsa-87' &&
        typeof additionalNamespaces === 'function',
      'PERSONAL_MDOC_SEAL_AUTHORITY',
    );
    Object.assign(this, {
      bindings,
      raCertificate,
      sealCertificate,
      sealKey,
      credentialLog,
      credentialLogTrust,
      allowedProfiles,
      validity,
      certificateProfile,
      additionalNamespaces,
      keyBindings,
      issuanceScope: snapshotIssuanceScope(issuanceScope),
      authorityResolver,
    });
    requireThat(this.issuanceScope.representation === 'MDOC' && this.issuanceScope.issuerID === this.issuer, 'ISSUANCE_SCOPE');
  }
  metadata() {
    const m = super.metadata();
    m.credential_configurations_supported = {
      [MDOC_CONFIG]: m.credential_configurations_supported[MDOC_CONFIG],
    };
    m.batch_credential_issuance = { batch_size: 1 };
    return m;
  }
  offer({ csr, rar, bindingID, preAuthorized = false, txCode }) {
    ({ csr, rar, bindingID } = decodeCBOR(dcbor({ csr, rar, bindingID })));
    const r = readControl(rar, 'RegistrationAuthorization', this.raCertificate),
      q = verifyCSR(csr),
      b = this.bindings.active(bindingID);
    requireIssuanceAuthority(r, { ...this, issuerCertificate: this.certificate });
    requireThat(
      !equal(keyID(q.publicKey), keyID(parseCertificate(this.sealCertificate).publicKey)) &&
        !equal(keyID(q.publicKey), keyID(parseCertificate(this.raCertificate).publicKey)),
      'PERSONAL_MDOC_KEY_ROLE_COLLISION',
    );
    requireThat(
      r.schemaVersion === 1 &&
        r.audience === this.issuer &&
        r.credentialFormat === 'mso_mdoc' &&
        equal(r.issuanceScope.trustDomainID, b.trustDomainID) &&
        equal(r.trustDomainID, b.trustDomainID) &&
        equal(r.subjectID, b.subjectID) &&
        equal(r.policyHash, b.policyHash) &&
        equal(r.csrHash, sha512(csr)) &&
        equal(r.spkiHash, sha512(q.spki)) &&
        r.possessionMode === q.possessionMode &&
        equal(keyID(q.publicKey), b.documentKeyID) &&
        this.allowedProfiles.includes(r.profileID) &&
        (!b.profileID || r.profileID === b.profileID) &&
        r.issuedAt <= now() &&
        r.expiresAt > now(),
      'PERSONAL_MDOC_RA_AUTHORITY',
    );
    const mode = documentKeyMode(r.profileID, q.publicKey, publicFromDER(b.holderSPKI));
    requireThat(
      mode !== 'PASSKEY_KEY' || (this.keyBindings && r.keyBindingID),
      'PASSKEY_ADMISSION_REQUIRED',
    );
    const keyAdmission =
      mode === 'PASSKEY_KEY' ? this.keyBindings.forIssuance(r.keyBindingID, { ...r, csr }) : null;
    if (keyAdmission) requireThat(equal(keyAdmission.hash, r.keyBindingHash), 'PASSKEY_RA_BINDING');
    return this.journal.transaction(() => {
      const id = issuanceRequestID(r),
        inputHash = H('MdocIssuanceOffer', { rarHash: sha512(rar), csrHash: sha512(csr), bindingID, preAuthorized, txCode: txCode ?? null }),
        old = this.journal.get('personal-mdoc-approval', id);
      if (old) {
        requireThat(equal(old.value.inputHash, inputHash), 'ISSUANCE_CONFLICT');
        return old.value.offer;
      }
      const offer = super.offer({
        configurationID: MDOC_CONFIG,
        subjectID: b64u(b.subjectID),
        preAuthorized,
        txCode,
        expiresIn: Math.min(300, r.expiresAt - now()),
        claims: {
          ...this.bindings.qualificationClaims(bindingID, { qualification: r.identityAssurance }),
          trust_domain_id: b.trustDomainID,
          subject_id: b.subjectID,
          signing_key: q.spki,
          signing_key_id: b.documentKeyID,
          profile_id: r.profileID,
          document_key_mode: mode,
          key_admission: b.keyAdmission,
          allowed_purposes: ['DOCUMENT_SIGN'],
          policy_hash: b.policyHash,
          ra_authorization_hash: sha512(rar),
          issuance_scope: r.issuanceScope,
          ...(keyAdmission
            ? { passkey_binding: keyAdmission.binding, passkey_binding_hash: keyAdmission.hash }
            : {}),
        },
      });
      this.journal.put('personal-mdoc-approval', id, { inputHash, offer });
      this.journal.put('personal-mdoc-rar', b64u(sha512(rar)), { request: r });
      return offer;
    });
  }
  credential(params, ...rest) {
    requireThat(
      params.credential_configuration_id === MDOC_CONFIG && params.proofs?.jwt?.length === 1,
      'PERSONAL_MDOC_CREDENTIAL_PROFILE',
    );
    return super.credential(params, ...rest);
  }
  mint({ offer, holderJWK, status, configurationID }) {
    requireThat(configurationID === MDOC_CONFIG, 'PERSONAL_MDOC_FORMAT');
    const authorization = this.journal.get('personal-mdoc-rar', b64u(offer.claims.ra_authorization_hash));
    requireThat(authorization, 'PERSONAL_MDOC_RA_AUTHORITY');
    requireIssuanceAuthority(authorization.value.request, { ...this, issuerCertificate: this.certificate });
    requireAuthority(this.authorityResolver, { certificate: this.sealCertificate, role: 'DOCUMENT_SEAL',
      scope: { trustDomainID: this.issuanceScope.trustDomainID, issuerID: this.issuer, representation: 'MDOC', profileID: offer.claims.profile_id },
      stateTime: now(), knowledgeTime: now() });
    const binding = this.bindings.active(offer.claims.device_binding_id),
      validUntil = Math.min(
        binding.expiresAt,
        now() + this.validity,
        offer.claims.passkey_binding?.expiresAt ?? Infinity,
      ),
      credential = issueMdoc({
        claims: { ...offer.claims, credential_id: random(), issuer: this.issuer, status },
        holderJWK,
        certificate: this.certificate,
        privateKey: this.privateKey,
        docType: this.mdocDocType,
        namespace: SIGNER_NAMESPACE,
        certificateProfile: this.certificateProfile,
        additionalNamespaces: this.additionalNamespaces({ offer, binding }),
        validUntil,
      }),
      credentialID = H('MdocIssuerAuth', authBytes(credential)),
      entry = {
        schemaVersion: 1,
        trustDomainID: binding.trustDomainID,
        credentialID,
        raAuthorizationHash: offer.claims.ra_authorization_hash,
        documentKeyID: binding.documentKeyID,
        policyHash: binding.policyHash,
      },
      logProof = this.credentialLog.append(entry);
    verifyCredentialLog(logProof, entry, this.credentialLogTrust);
    const seal = signCMS(
      {
        certificate: this.sealCertificate,
        content: D('MdocCredentialSeal', {
          schemaVersion: 1,
          trustDomainID: binding.trustDomainID,
          credentialID,
          issuerAuthHash: sha512(authBytes(credential)),
          policyHash: binding.policyHash,
          documentKeyID: binding.documentKeyID,
          logProof,
          issuedAt: now(),
          expiresAt: validUntil,
        }),
      },
      this.sealKey,
    );
    this.journal.put('personal-mdoc', b64u(credentialID), {
      credential,
      seal,
      bindingID: binding.bindingID,
      status,
      issuedAt: now(),
      expiresAt: validUntil,
      ...(binding.profileID === PASSKEY_SIGN_PROFILE
        ? { passkeyBindingID: offer.claims.passkey_binding.bindingID }
        : {}),
    });
    return { credential: b64u(credential), certconcord_credential_seal: b64u(seal) };
  }
  publishPasskeyStatus() {
    requireThat(this.keyBindings, 'PASSKEY_ADMISSION_REQUIRED');
    for (const row of this.journal.list('personal-mdoc')) {
      const issued = this.journal.get('personal-mdoc', row.id).value;
      if (!issued.passkeyBindingID) continue;
      const binding = this.keyBindings.journal.get(
        'passkey-enrollment',
        b64u(issued.passkeyBindingID),
      )?.value;
      requireThat(binding, 'PASSKEY_STATUS_INVENTORY');
      const parent = this.keyBindings.journal.get(
        'passkey-parent-status',
        b64u(binding.parent.credentialID),
      );
      if (['SUSPENDED', 'REVOKED'].includes(binding.state) || parent)
        this.status.revoke(issued.status.status_list.idx);
    }
    return this.status.token();
  }
}

function inspectPersonalMdoc(
  credential,
  {
    issuerCertificate,
    issuerPublicKey,
    issuerRoots,
    sealCertificate,
    seal,
    trustDomainID,
    policyHash,
    statusToken,
    statusURI,
    credentialLogTrust,
    docType = SIGNER_DOCTYPE,
    certificateProfile = 'ISO_MDOC',
    at = now(),
    knowledgeTime = at,
  },
) {
  requireThat(
    parseCertificate(sealCertificate).publicKey.asymmetricKeyType === 'ml-dsa-87',
    'PERSONAL_MDOC_SEAL_AUTHORITY',
  );
  verifyX5C({ x5c: [issuerCertificate.toString('base64')] }, issuerRoots, {
    at,
    expectedLeaf: issuerCertificate,
  });
  const v = verifyIssuerSigned(credential, {
      issuerKey: issuerPublicKey,
      certificate: issuerCertificate,
      docType,
      at,
      allowPartial: false,
      certificateProfile,
    }),
    claims = plain(v.claims.get(SIGNER_NAMESPACE)),
    publicKey = publicFromDER(claims.signing_key),
    credentialID = H('MdocIssuerAuth', authBytes(credential)),
    s = readControl(seal, 'MdocCredentialSeal', sealCertificate);
  requireThat(
    !equal(keyID(publicKey), keyID(parseCertificate(sealCertificate).publicKey)),
    'PERSONAL_MDOC_KEY_ROLE_COLLISION',
  );
  requireThat(
    equal(claims.trust_domain_id, trustDomainID) &&
      equal(claims.policy_hash, policyHash) &&
      equal(claims.signing_key_id, keyID(publicKey)) &&
      typeof claims.document_key_mode === 'string' &&
      claims.allowed_purposes?.includes('DOCUMENT_SIGN'),
    'PERSONAL_MDOC_PURPOSE',
  );
  requireThat(
    s.schemaVersion === 1 &&
      equal(s.credentialID, credentialID) &&
      equal(s.issuerAuthHash, sha512(authBytes(credential))) &&
      equal(s.documentKeyID, keyID(publicKey)) &&
      equal(s.policyHash, policyHash) &&
      equal(s.trustDomainID, trustDomainID) &&
      s.issuedAt <= at &&
      s.expiresAt > at,
    'PERSONAL_MDOC_PQ_SEAL',
  );
  const holderPublicKey = importPublicJWK(coseJWK(get(get(v.mso, 'deviceKeyInfo'), 'deviceKey'))),
    mode = documentKeyMode(claims.profile_id, publicKey, holderPublicKey);
  requireThat(mode === claims.document_key_mode, 'PERSONAL_MDOC_KEY_ADMISSION');
  if (mode === 'PASSKEY_KEY') {
    const binding = claims.passkey_binding;
    requireThat(
      binding?.schemaVersion === 1 &&
        binding.profileID === PASSKEY_SIGN_PROFILE &&
        equal(H('PasskeySigningBinding', binding), claims.passkey_binding_hash) &&
        equal(binding.documentSPKI, claims.signing_key) &&
        equal(binding.subjectID, claims.subject_id) &&
        equal(binding.trustDomainID, trustDomainID) &&
        equal(binding.policyHash, policyHash) &&
        binding.issuedAt <= at &&
        binding.expiresAt > at &&
        binding.keyAssurance?.level === 'KAL2' &&
        binding.keyAssurance.fixedFlags === 5,
      'PERSONAL_MDOC_PASSKEY_BINDING',
    );
  }
  validateAdmissionAssessment(claims.key_admission, holderPublicKey, at);
  verifyCredentialLog(
    s.logProof,
    {
      schemaVersion: 1,
      trustDomainID,
      credentialID,
      raAuthorizationHash: claims.ra_authorization_hash,
      documentKeyID: claims.signing_key_id,
      policyHash,
    },
    credentialLogTrust,
  );
  const status = claims.status?.status_list;
  requireThat(status?.uri === statusURI, 'PERSONAL_MDOC_STATUS');
  const assessment = verifyStatusList(statusToken, {
    publicKey: issuerPublicKey,
    uri: statusURI,
    index: status.idx,
    at: knowledgeTime,
  });
  requireThat(assessment.overall !== 'INVALID', assessment.reason);
  return {
    ...v,
    statusAssessment: assessment,
    claims,
    publicKey,
    holderPublicKey,
    documentKeyMode: mode,
    credentialID,
    representationHash: sha512(credential),
  };
}

export function verifyPersonalMdoc(credential, trust) {
  const result = inspectPersonalMdoc(credential, trust);
  requireThat(result.statusAssessment.overall === 'VALID', result.statusAssessment.reason);
  return result;
}

const headers = ['urn:certconcord:context:1', 'urn:certconcord:sim:1', 'urn:certconcord:policy:1', 'urn:certconcord:credential:1'];
const coseAlgorithm = (key) =>
  ({ 'ml-dsa-65': -49, 'ml-dsa-87': -50, ec: -7 })[key.asymmetricKeyType];
export function prepareMdocDocument(
  document,
  { credential, publicKey, context, simHash, policyHash },
) {
  const algorithm = coseAlgorithm(publicKey);
  requireThat(
    algorithm &&
      (algorithm === -7
        ? [DEVICE_SIGN_PROFILE, PASSKEY_SIGN_PROFILE].includes(context.profileID) &&
          publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1'
        : ![DEVICE_SIGN_PROFILE, PASSKEY_SIGN_PROFILE].includes(context.profileID)),
    'MDOC_DOCUMENT_ALGORITHM',
  );
  const protectedBytes = encode(
      new Map([
        [1, algorithm],
        [2, headers],
        [3, 'application/certconcord-mdoc-document'],
        [headers[0], D('SignatureContext', context)],
        [headers[1], simHash],
        [headers[2], policyHash],
        [headers[3], sha512(credential)],
      ]),
    ),
    tbs = encode(['Signature1', protectedBytes, Buffer.alloc(0), document]);
  return {
    tbs,
    finish(signature) {
      requireThat(verify(tbs, signature, publicKey), 'MDOC_DOCUMENT_SIGNATURE');
      return encode([
        protectedBytes,
        new Map(),
        null,
        algorithm === -7 ? derToP1363(signature) : signature,
      ]);
    },
  };
}
export function verifyMdocDocument(
  signature,
  document,
  { credential, publicKey, context, simHash, policyHash },
) {
  const a = decode(signature);
  requireThat(
    Array.isArray(a) &&
      a.length === 4 &&
      Buffer.isBuffer(a[0]) &&
      a[1] instanceof Map &&
      a[1].size === 0 &&
      a[2] === null &&
      Buffer.isBuffer(a[3]),
    'MDOC_DOCUMENT_COSE',
  );
  const expected = prepareMdocDocument(document, {
      credential,
      publicKey,
      context,
      simHash,
      policyHash,
    }),
    providerSignature = publicKey.asymmetricKeyType === 'ec' ? p1363ToDER(a[3]) : a[3],
    canonical = decode(expected.finish(providerSignature));
  requireThat(equal(a[0], canonical[0]), 'MDOC_DOCUMENT_PROTECTED_HEADERS');
  return { tbs: expected.tbs, signature: providerSignature };
}

import {
  appendDocumentEvidence,
  selectDocumentPlan,
  documentPlans,
  documentEvidenceTypes,
  verifyDocumentEvidence,
} from './document-evidence.mjs';

const types = [
  'Document',
  'PersonalMdoc',
  'CredentialSeal',
  'CredentialStatusList',
  'SIM',
  'SignaturePolicy',
  'ActivationContext',
  'OperationPermit',
  'ExecutionReceipt',
  'COSE',
];
export function createMdocSignaturePackage({
  document,
  credential,
  seal,
  statusToken,
  sim,
  policy,
  activation,
  permit,
  receipt,
  signature,
  passkeyEvidence,
  executionEvidence,
  documentEvidence,
}) {
  requireThat(
    !!executionRequirement(policy) === !!executionEvidence &&
      !(executionEvidence && passkeyEvidence),
    'MDOC_ECP_EXECUTION_PROFILE',
  );
  const payloads = [
      document,
      credential,
      seal,
      Buffer.from(statusToken),
      dcbor(sim),
      dcbor(policy),
      dcbor(activation),
      permit,
      receipt,
      signature,
    ],
    objects = [
      ...types.map((type, i) => evidenceObject(type, payloads[i])),
      ...(passkeyEvidence ? [evidenceObject('PasskeyRawEvidence', dcbor(passkeyEvidence))] : []),
      ...(executionEvidence
        ? [evidenceObject('ExecutionBindingEvidence', dcbor(executionEvidence))]
        : []),
    ];
  appendDocumentEvidence(objects, { policy, format: 'MDOC', evidence: documentEvidence });
  const plan = evidenceObject(
    'VerificationPlan',
    dcbor({
      schemaVersion: 1,
      profile: selectDocumentPlan(
        executionEvidence
          ? 'certconcord-ecp-mdoc-execution-draft-02'
          : passkeyEvidence
            ? 'certconcord-ecp-mdoc-passkey-v1'
            : 'certconcord-ecp-mdoc-attested-v1',
        policy,
      ),
      objects: Object.fromEntries(objects.map((o) => [o.type, o.id])),
    }),
    objects.map((o) => o.id),
  );
  return { schemaVersion: 1, root: plan.id, objects: [...objects, plan] };
}
export function verifyMdocSignaturePackage(bundle, trust) {
  fields(bundle, ['schemaVersion', 'root', 'objects']);
  verifyEvidenceClosure(bundle.objects, [bundle.root], {
    requiredTypes: [...types, 'VerificationPlan'],
  });
  const root = bundle.objects.find(
      (o) => o.type === 'VerificationPlan' && equal(o.id, bundle.root),
    ),
    plan = root && decodeCBOR(root.payload);
  const document = Object.hasOwn(documentPlans, plan?.profile);
  const passkey = plan?.profile === 'certconcord-ecp-mdoc-passkey-v1',
    execution = plan?.profile === 'certconcord-ecp-mdoc-execution-draft-02',
    selectedTypes = [
      ...(execution
        ? [...types, 'ExecutionBindingEvidence']
        : passkey
          ? [...types, 'PasskeyRawEvidence']
          : types),
      ...(document ? documentEvidenceTypes(trust.expectedPolicy, 'MDOC') : []),
    ];
  requireThat(
    bundle.schemaVersion === 1 &&
      plan?.schemaVersion === 1 &&
      (execution ||
        passkey ||
        plan.profile === 'certconcord-ecp-mdoc-attested-v1' ||
        documentPlans[plan.profile] === 'certconcord-ecp-mdoc-attested-v1') &&
      bundle.objects.length === selectedTypes.length + 1,
    'MDOC_ECP_PLAN',
  );
  fields(plan, ['schemaVersion', 'profile', 'objects']);
  fields(plan.objects, selectedTypes);
  const value = {};
  for (const type of selectedTypes) {
    const o = bundle.objects.find((o) => o.type === type && equal(o.id, plan.objects[type]));
    requireThat(o, 'MDOC_ECP_OBJECT');
    value[type] = o.payload;
  }
  const sim = decodeCBOR(value.SIM),
    policy = decodeCBOR(value.SignaturePolicy),
    activation = decodeCBOR(value.ActivationContext),
    permit = readControl(value.OperationPermit, 'OperationPermit', trust.permitCertificate),
    receipt = readControl(value.ExecutionReceipt, 'ExecutionReceipt', trust.receiptCertificate),
    at = receipt.executedAt,
    knowledgeTime = trust.knowledgeTime ?? now();
  requireThat(!!executionRequirement(policy) === execution, 'MDOC_ECP_EXECUTION_DOWNGRADE');
  requireThat(!!policy.documentEvidence === document, 'DOCUMENT_EVIDENCE_DOWNGRADE');
  requireThat(
    equal(H('SignaturePolicy', policy), H('SignaturePolicy', trust.expectedPolicy)) &&
      at <= knowledgeTime,
    'MDOC_ECP_POLICY',
  );
  const verifyState = (stateTime) =>
    inspectPersonalMdoc(value.PersonalMdoc, {
      ...trust,
      seal: value.CredentialSeal,
      statusToken: value.CredentialStatusList.toString('utf8'),
      policyHash: H('SignaturePolicy', policy),
      at: stateTime,
      knowledgeTime,
    });
  const v = verifyState(at);
  requireThat(
    sim.container === 'COSE' &&
      sim.adapterID === 'certconcord-mdoc-document-v1' &&
      sim.credentialType === 'MDOC' &&
      sim.documents.length === 1 &&
      sim.documents[0].scope === 'COSE_PAYLOAD' &&
      sim.documents[0].digestAlgorithm === 'SHA-512' &&
      equal(sim.documents[0].digest, sha512(value.Document)) &&
      equal(sim.subjectID, v.claims.subject_id) &&
      sim.profileID === v.claims.profile_id &&
      policy.allowedProfiles.includes(sim.profileID) &&
      policy.allowedOrigins.includes(sim.origin) &&
      equal(sim.certificateID, v.credentialID) &&
      equal(sim.certificateRepresentationHash, v.representationHash),
    'MDOC_ECP_CREDENTIAL_BINDING',
  );
  requireThat(
    policy.holderKeyAdmission === v.claims.key_admission.assurance &&
      (!policy.requirePostQuantumDocument || v.documentKeyMode === 'INDEPENDENT_PQ'),
    'MDOC_ECP_ASSURANCE',
  );
  const context = {
      schemaVersion: 1,
      trustDomainID: trust.trustDomainID,
      profileID: sim.profileID,
      container: 'COSE',
      adapterID: sim.adapterID,
      credentialType: 'MDOC',
    },
    signed = verifyMdocDocument(value.COSE, value.Document, {
      credential: value.PersonalMdoc,
      publicKey: v.publicKey,
      context,
      simHash: H('SIM', sim),
      policyHash: H('SignaturePolicy', policy),
    });
  for (const field of [
    'trustDomainID',
    'transactionID',
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'policyHash',
  ])
    requireThat(equal(sim[field], activation[field]), 'MDOC_ECP_ACTIVATION');
  const activationHash = validateActivation(activation, {
    tbs: signed.tbs,
    publicKey: v.publicKey,
    audience: policy.audience,
    at,
    maxLifetime: policy.maxActivationLifetime,
  });
  requireThat(
    equal(sim.trustDomainID, trust.trustDomainID) &&
      equal(activation.simHash, H('SIM', sim)) &&
      activation.tbsKind === 'ADAPTER_MESSAGE' &&
      sim.origin === activation.origin &&
      sim.issuedAt <= at &&
      sim.expiresAt > at &&
      equal(D('ActivationContext', permit.activation), D('ActivationContext', activation)) &&
      permit.proofMode === policy.activationMode &&
      permit.issuedAt <= at &&
      permit.expiresAt > at &&
      permit.expiresAt <= activation.expiresAt,
    'MDOC_ECP_PERMIT',
  );
  requireThat(
    equal(receipt.operationID, activation.operationID) &&
      equal(receipt.activationHash, activationHash) &&
      equal(receipt.permitHash, sha512(value.OperationPermit)) &&
      equal(receipt.keyID, keyID(v.publicKey)) &&
      equal(receipt.tbsHash, sha512(signed.tbs)) &&
      equal(receipt.signatureHash, sha512(signed.signature)),
    'MDOC_ECP_RECEIPT',
  );
  requireThat(passkey === (v.documentKeyMode === 'PASSKEY_KEY'), 'MDOC_ECP_PASSKEY_PROFILE');
  if (passkey) {
    const evidence = decodeCBOR(value.PasskeyRawEvidence);
    verifyPasskeyOperation(
      {
        permit: value.OperationPermit,
        tbs: signed.tbs,
        signature: signed.signature,
        assertion: evidence.assertion,
        receipt: value.ExecutionReceipt,
        binding: v.claims.passkey_binding,
        registration: {
          ...evidence.registration,
          publicKey: publicFromDER(evidence.registration.publicKeyDER),
        },
        credential: value.PersonalMdoc,
        seal: value.CredentialSeal,
      },
      {
        permitCertificate: trust.permitCertificate,
        receiptCertificate: trust.receiptCertificate,
        mdocVerifier: () => v,
        audience: policy.audience,
        at,
        status: ({ binding }) =>
          typeof trust.passkeyStatus === 'function' &&
          trust.passkeyStatus(binding, { at, knowledgeTime }) === true,
      },
    );
  }
  const executionResult = execution
    ? verifyExecutionEvidence(
        {
          policy,
          sim,
          permit: value.OperationPermit,
          tbs: signed.tbs,
          signature: signed.signature,
          publicKey: v.publicKey,
          receipt: value.ExecutionReceipt,
          evidence: decodeCBOR(value.ExecutionBindingEvidence),
        },
        {
          bindingCertificate: trust.executionBindingCertificate,
          permitCertificate: trust.permitCertificate,
          receiptCertificate: trust.receiptCertificate,
          trustDomainID: trust.trustDomainID,
          at,
          knowledgeTime,
          status: trust.executionStatus,
        },
      )
    : undefined;
  const documentResult = verifyDocumentEvidence(
    {
      format: 'MDOC',
      values: value,
      sim,
      policy,
      activation,
      permit,
      receipt,
      knowledgeTime,
      verifyState,
    },
    trust,
  );
  const missingTime = policy.requireTrustedTime && !documentResult;
  requireThat(v.statusAssessment.overall === 'VALID', v.statusAssessment.reason);
  return {
    ...(executionResult ? { execution: executionResult } : {}),
    profile: plan.profile,
    signerCredential: 'MDOC',
    documentAlgorithm:
      v.publicKey.asymmetricKeyType === 'ec' ? 'ES256' : v.publicKey.asymmetricKeyType,
    documentKeyMode: v.documentKeyMode,
    documentAlgorithmAssurance:
      v.documentKeyMode === 'INDEPENDENT_PQ' ? 'POST_QUANTUM' : 'CLASSICAL',
    holderKeyAssurance: v.claims.key_admission.assurance,
    documentKeyAssurance:
      v.documentKeyMode === 'DEVICE_KEY'
        ? v.claims.key_admission.keyAssurance
        : passkey
          ? v.claims.passkey_binding.keyAssurance.level
          : 'KAL1',
    cryptographicValidity: 'VALID',
    credentialTrust: 'VALID',
    activation: 'ATTESTED_VALID',
    status: 'GOOD',
    time: 'DECLARED_EXECUTION_TIME',
    coverage: 'COSE_PAYLOAD',
    closure: 'COMPLETE',
    overall: missingTime ? 'INDETERMINATE' : 'VALID_UNDER_POLICY',
    reason: missingTime
      ? 'TRUSTED_TIME_EVIDENCE_REQUIRED'
      : 'ALL_SELECTED_POLICY_REQUIREMENTS_SATISFIED',
    stateTime: at,
    knowledgeTime,
    ...documentResult,
  };
}
