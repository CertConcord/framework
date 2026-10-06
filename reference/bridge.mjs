import { createPublicKey } from 'node:crypto';
import {
  D,
  H,
  sha512,
  keyID,
  spki,
  random,
  b64u,
  unb64u,
  equal,
  requireThat,
  now,
  verify,
} from './core.mjs';
import { readControl, issuePermit, validateActivation } from './state.mjs';
import { publicJWK, thumbprint } from './jose.mjs';
import { CredentialIssuer } from './openid.mjs';
import { assessKeyAttestation } from './key-attestation.mjs';

// Registration authority, credential issuer, verifier and signing gateway share these bindings.
export class DeviceBindingRegistry {
  constructor({
    journal,
    registrationAuthorityCertificate,
    trustDomainID,
    audience = 'certconcord-device-registry',
    policyHash,
    maxBindingLifetime = 90 * 86400,
    attestationPolicy,
    allowUnattested = false,
  }) {
    Object.assign(this, {
      journal,
      registrationAuthorityCertificate,
      trustDomainID,
      audience,
      policyHash,
      maxBindingLifetime,
      attestationPolicy,
      allowUnattested,
    });
  }
  challenge(context) {
    requireThat(
      this.allowUnattested ||
        (context?.subjectID?.length === 32 &&
          (context?.profileID === 'CERTCONCORD-PERSON-DEVICE-SIGN-v1'
            ? context.documentKeyID === undefined
            : context?.documentKeyID?.length === 64) &&
          typeof context?.profileID === 'string' &&
          typeof context?.sessionID === 'string' &&
          context.sessionID.length >= 16),
      'KEY_ADMISSION_CONTEXT',
    );
    requireThat(
      !context ||
        Object.keys(context).every((k) =>
          ['subjectID', 'documentKeyID', 'profileID', 'sessionID'].includes(k),
        ),
      'KEY_ADMISSION_CONTEXT_FIELDS',
    );
    const nonce = this.journal.issueNonce('device-registration', 120);
    this.journal.put('key-admission-challenge', nonce, {
      schemaVersion: 1,
      trustDomainID: this.trustDomainID,
      policyHash: this.policyHash,
      audience: this.audience,
      ...(context ?? {}),
      issuedAt: now(),
      expiresAt: now() + 120,
    });
    return nonce;
  }
  assess({ holderPublicKey, nonce, evidence, sessionID }) {
    const request = this.journal.get('key-admission-challenge', nonce)?.value;
    requireThat(
      request &&
        request.expiresAt > now() &&
        (!request.sessionID || request.sessionID === sessionID),
      'KEY_ADMISSION_SESSION',
    );
    return assessKeyAttestation(evidence, {
      holderPublicKey,
      challenge: nonce,
      policy: this.attestationPolicy,
      allowUnattested: this.allowUnattested,
    });
  }
  enroll({ authorization, holderPublicKey, nonce, proof, attestation, sessionID }) {
    const a = readControl(
      authorization,
      'DeviceRegistrationAuthorization',
      this.registrationAuthorityCertificate,
    );
    requireThat(
      a.schemaVersion === 1 &&
        equal(a.trustDomainID, this.trustDomainID) &&
        a.audience === this.audience &&
        equal(a.policyHash, this.policyHash) &&
        equal(a.holderKeyID, keyID(holderPublicKey)) &&
        holderPublicKey.asymmetricKeyType === 'ec' &&
        holderPublicKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
        a.subjectID.length === 32 &&
        a.documentKeyID.length === 64 &&
        a.expiresAt > now() &&
        a.issuedAt <= now(),
      'DEVICE_REGISTRATION_AUTHORITY',
    );
    const request = this.journal.get('key-admission-challenge', nonce)?.value,
      assessment = this.assess({ holderPublicKey, nonce, evidence: attestation, sessionID });
    if (!this.allowUnattested || request.subjectID)
      requireThat(
        equal(request.subjectID, a.subjectID) &&
          (request.profileID === 'CERTCONCORD-PERSON-DEVICE-SIGN-v1'
            ? equal(a.documentKeyID, a.holderKeyID)
            : equal(request.documentKeyID, a.documentKeyID)) &&
          request.profileID === a.profileID,
        'KEY_ADMISSION_AUTHORITY',
      );
    requireThat(
      a.keyAssurance === assessment.keyAssurance &&
        a.localUVPolicy === assessment.localUVPolicy &&
        (assessment.assurance === 'UNATTESTED' ||
          equal(a.attestationEvidenceHash, assessment.evidenceHash)),
      'KEY_ADMISSION_CLAIMS',
    );
    const tbs = D('DeviceRegistrationProof', {
      schemaVersion: 1,
      authorizationHash: sha512(authorization),
      nonce,
      audience: a.audience,
    });
    requireThat(verify(tbs, proof, holderPublicKey), 'DEVICE_REGISTRATION_PROOF');
    const bindingExpiresAt = a.bindingExpiresAt ?? a.expiresAt;
    requireThat(
      bindingExpiresAt > now() && bindingExpiresAt - now() <= this.maxBindingLifetime,
      'DEVICE_BINDING_LIFETIME',
    );
    return this.journal.transaction(() => {
      this.journal.consumeNonce('device-registration', nonce);
      this.journal.put('device-registration-authorization', b64u(sha512(authorization)), {
        usedAt: now(),
      });
      const binding = {
        schemaVersion: 1,
        trustDomainID: this.trustDomainID,
        bindingID: random(),
        subjectID: a.subjectID,
        holderKeyID: a.holderKeyID,
        holderThumbprint: thumbprint(publicJWK(holderPublicKey)),
        holderSPKI: spki(holderPublicKey),
        documentKeyID: a.documentKeyID,
        policyHash: this.policyHash,
        authorizationHash: sha512(authorization),
        attestationEvidenceHash: assessment.evidenceHash,
        keyAssurance: assessment.keyAssurance,
        keyAdmission: assessment,
        localUVPolicy: assessment.localUVPolicy,
        ...(a.profileID ? { profileID: a.profileID } : {}),
        epoch: 0,
        status: 'ACTIVE',
        createdAt: now(),
        expiresAt: Math.min(bindingExpiresAt, assessment.expiresAt),
      };
      this.journal.put('key-admission-evidence', b64u(binding.bindingID), {
        evidence: attestation ?? { format: 'none' },
        nonce,
      });
      this.journal.put('device-binding', b64u(binding.bindingID), binding);
      return binding;
    });
  }
  qualificationClaims(bindingID, { qualification }) {
    const binding = this.active(bindingID);
    return {
      qualification,
      device_binding_id: b64u(binding.bindingID),
      binding_epoch: binding.epoch,
    };
  }
  authorizeCredential({ offer, holderJWK }) {
    const binding = this.active(offer.claims.device_binding_id);
    requireThat(
      offer.subjectID === b64u(binding.subjectID) &&
        offer.claims.binding_epoch === binding.epoch &&
        thumbprint(holderJWK) === binding.holderThumbprint &&
        equal(binding.policyHash, this.policyHash) &&
        equal(binding.trustDomainID, this.trustDomainID),
      'CREDENTIAL_DEVICE_BINDING',
    );
    return true;
  }
  active(bindingID) {
    const row = this.journal.get(
      'device-binding',
      typeof bindingID === 'string' ? bindingID : b64u(bindingID),
    );
    requireThat(
      row && row.value.status === 'ACTIVE' && row.value.expiresAt > now(),
      'DEVICE_BINDING_INACTIVE',
    );
    const evidence = this.journal.get('key-admission-evidence', b64u(row.value.bindingID))?.value;
    requireThat(evidence, 'KEY_ADMISSION_RECORD');
    const current = assessKeyAttestation(evidence.evidence, {
      holderPublicKey: createPublicKey({ key: row.value.holderSPKI, format: 'der', type: 'spki' }),
      challenge: evidence.nonce,
      policy: this.attestationPolicy,
      allowUnattested: this.allowUnattested,
    });
    requireThat(
      equal(current.evidenceHash, row.value.attestationEvidenceHash) &&
        current.assurance === row.value.keyAdmission.assurance,
      'KEY_ADMISSION_CHANGED',
    );
    return row.value;
  }
  revoke(bindingID, { authorization }) {
    const id = typeof bindingID === 'string' ? bindingID : b64u(bindingID),
      row = this.journal.get('device-binding', id),
      a = readControl(
        authorization,
        'DeviceBindingRevocation',
        this.registrationAuthorityCertificate,
      );
    requireThat(
      row &&
        equal(a.trustDomainID, this.trustDomainID) &&
        equal(a.bindingID, row.value.bindingID) &&
        a.epoch === row.value.epoch &&
        a.expiresAt > now() &&
        a.reason,
      'DEVICE_REVOCATION_AUTHORITY',
    );
    this.journal.put(
      'device-binding',
      id,
      {
        ...row.value,
        status: 'REVOKED',
        epoch: row.value.epoch + 1,
        revokedAt: now(),
        revocationHash: sha512(authorization),
      },
      row.revision,
    );
  }
}

// The RRA issuer boundary only creates offers from an approved live binding.
export class RRACredentialIssuer extends CredentialIssuer {
  constructor({ bindings, qualificationAllowed, ...options }) {
    requireThat(typeof qualificationAllowed === 'function', 'QUALIFICATION_POLICY_REQUIRED');
    super({
      ...options,
      authorizeCredential: (request) => {
        bindings.authorizeCredential(request);
        requireThat(
          qualificationAllowed(
            bindings.active(request.offer.claims.device_binding_id),
            request.offer.claims.qualification,
          ) === true,
          'QUALIFICATION_AUTHORITY',
        );
        return true;
      },
    });
    Object.assign(this, { bindings, qualificationAllowed });
  }
  offer({ bindingID, qualification, ...options }) {
    requireThat(
      !Object.hasOwn(options, 'claims') && !Object.hasOwn(options, 'subjectID'),
      'CERTCONCORD_OFFER_INPUT',
    );
    const binding = this.bindings.active(bindingID);
    requireThat(
      this.qualificationAllowed(binding, qualification) === true,
      'QUALIFICATION_AUTHORITY',
    );
    return super.offer({
      ...options,
      claims: this.bindings.qualificationClaims(bindingID, { qualification }),
      subjectID: b64u(binding.subjectID),
    });
  }
}
export function authorizeMdocActivation({
  verifier,
  presentationID,
  sessionID,
  activation,
  tbs,
  documentPublicKey,
  sim,
  policy,
  bindings,
  journal,
  permitCertificate,
  permitKey,
}) {
  const activationHash = validateActivation(activation, {
    tbs,
    publicKey: documentPublicKey,
    audience: policy.audience,
    maxLifetime: policy.maxActivationLifetime,
  });
  requireThat(
    policy.activationMode === 'HUMAN_MDOC' &&
      policy.maxSAL === 1 &&
      equal(activation.simHash, H('SIM', sim)) &&
      equal(activation.policyHash, H('SignaturePolicy', policy)),
    'MDOC_ACTIVATION_POLICY',
  );
  for (const field of [
    'trustDomainID',
    'transactionID',
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'policyHash',
  ])
    requireThat(equal(activation[field], sim[field]), 'SIM_ACTIVATION_BINDING');
  requireThat(
    sim.expiresAt >= activation.expiresAt &&
      sim.issuedAt <= now() &&
      policy.allowedProfiles.includes(sim.profileID) &&
      activation.rpID === policy.rpID &&
      sim.origin === activation.origin &&
      policy.allowedOrigins.includes(activation.origin),
    'SIM_TIME_OR_ORIGIN',
  );
  return journal.transaction(() => {
    const result = verifier.consumeQualification(presentationID, { sessionID, activationHash }),
      binding = bindings.active(result.claims.device_binding_id);
    requireThat(
      result.format === 'mso_mdoc' &&
        result.claims.binding_epoch === binding.epoch &&
        binding.holderThumbprint === result.holderThumbprint &&
        equal(binding.documentKeyID, activation.keyID) &&
        equal(binding.policyHash, activation.policyHash) &&
        equal(binding.trustDomainID, activation.trustDomainID) &&
        equal(binding.subjectID, sim.subjectID) &&
        policy.acceptedQualifications.includes(result.claims.qualification),
      'QUALIFICATION_DEVICE_BINDING',
    );
    journal.consumeNonce('activation', b64u(activation.serverNonce));
    return issuePermit(activation, {
      certificate: permitCertificate,
      privateKey: permitKey,
      activationEvidenceHash: H('MdocActivationEvidence', {
        presentationHash: result.evidenceHash,
        bindingID: binding.bindingID,
        bindingEpoch: binding.epoch,
        activationHash,
      }),
      proofMode: 'HUMAN_MDOC',
    });
  });
}
