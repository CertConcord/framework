import { createPublicKey, X509Certificate } from 'node:crypto';
import { decode as decodeISO } from './cose.mjs';
import { parseJSON } from './json.mjs';
import {
  requireThat,
  unb64u,
  b64u,
  sha256,
  equal,
  verify,
  spki,
  H,
  D,
  now,
  keyID,
} from './core.mjs';
import { issuePermit, readControl } from './state.mjs';
const decoder = {
  decode: decodeISO,
  decodeMultiple(input) {
    const values = [];
    let offset = 0;
    while (offset < input.length) {
      const result = decodeISO(input.subarray(offset), { allowTrailing: true });
      values.push(result.value);
      offset += result.bytesRead;
    }
    return values;
  },
};
export function cosePublicKey(cose) {
  requireThat(cose instanceof Map, 'COSE_KEY');
  const get = (n) => cose.get(n),
    algorithm = get(3);
  let jwk;
  if (algorithm === -7) {
    requireThat(
      get(1) === 2 && get(-1) === 1 && get(-2)?.length === 32 && get(-3)?.length === 32,
      'COSE_EC',
    );
    jwk = { kty: 'EC', crv: 'P-256', x: b64u(get(-2)), y: b64u(get(-3)) };
  } else if (algorithm === -8) {
    requireThat(get(1) === 1 && get(-1) === 6 && get(-2)?.length === 32, 'COSE_OKP');
    jwk = { kty: 'OKP', crv: 'Ed25519', x: b64u(get(-2)) };
  } else throw Error('UNSUPPORTED_CREDENTIAL_ALGORITHM');
  return createPublicKey({ key: jwk, format: 'jwk' });
}
export function clientData(raw, { type, challenge, origin }) {
  const json = parseJSON(new TextDecoder('utf-8', { fatal: true }).decode(raw), { maxBytes: 8192 });
  requireThat(
    json !== null &&
      typeof json === 'object' &&
      !Array.isArray(json) &&
      json.type === type &&
      json.challenge === b64u(challenge) &&
      json.origin === origin &&
      (!Object.hasOwn(json, 'crossOrigin') || json.crossOrigin === false) &&
      !Object.hasOwn(json, 'topOrigin'),
    'WEBAUTHN_CLIENT_DATA',
  );
  return json;
}
export function authenticatorData(raw, { rpID, uv = true }) {
  requireThat(raw.length >= 37 && raw.length <= 65536, 'AUTHENTICATOR_DATA');
  requireThat(equal(raw.subarray(0, 32), sha256(Buffer.from(rpID))), 'RP_ID_HASH');
  const flags = raw[32];
  requireThat(flags & 1, 'USER_PRESENCE_REQUIRED');
  if (uv) requireThat(flags & 4, 'USER_VERIFICATION_REQUIRED');
  requireThat(!(flags & 16) || flags & 8, 'BACKUP_FLAGS');
  requireThat(!(flags & 0x22), 'RESERVED_AUTH_FLAGS');
  return {
    flags,
    counter: raw.readUInt32BE(33),
    backupEligible: !!(flags & 8),
    backedUp: !!(flags & 16),
  };
}
export function verifyRegistration(
  response,
  { challenge, origin, rpID, uv = true, attestationRoots = [] },
) {
  requireThat(response.type === 'public-key' && response.id === response.rawId, 'CREDENTIAL_ID');
  const rawId = unb64u(response.rawId),
    client = unb64u(response.response.clientDataJSON);
  clientData(client, { type: 'webauthn.create', challenge, origin });
  const attestation = decoder.decode(unb64u(response.response.attestationObject));
  requireThat(attestation instanceof Map, 'ATTESTATION_OBJECT');
  const auth = Buffer.from(attestation.get('authData')),
    data = authenticatorData(auth, { rpID, uv });
  requireThat(data.flags & 64, 'ATTESTED_DATA_REQUIRED');
  requireThat(auth.length >= 55, 'ATTESTED_DATA');
  const len = auth.readUInt16BE(53);
  requireThat(
    len > 0 && 55 + len < auth.length && equal(auth.subarray(55, 55 + len), rawId),
    'ATTESTED_CREDENTIAL_ID',
  );
  const encodedKeys = decoder.decodeMultiple(auth.subarray(55 + len));
  requireThat(encodedKeys.length === (data.flags & 128 ? 2 : 1), 'ATTESTATION_TRAILING');
  const publicKey = cosePublicKey(encodedKeys[0]),
    fmt = attestation.get('fmt'),
    statement = attestation.get('attStmt');
  let attestationVerified = false;
  if (fmt === 'none')
    requireThat(statement instanceof Map && statement.size === 0, 'NONE_ATTESTATION');
  else if (fmt === 'packed') {
    const chain = statement.get('x5c'),
      sig = statement.get('sig');
    let verifier = publicKey;
    if (chain) {
      requireThat(
        Array.isArray(chain) && chain.length > 0 && chain.length <= 8,
        'ATTESTATION_CHAIN',
      );
      const certs = chain.map((c) => new X509Certificate(c));
      for (let i = 0; i < certs.length; i++) {
        const cert = certs[i];
        requireThat(
          Date.now() >= Date.parse(cert.validFrom) && Date.now() < Date.parse(cert.validTo),
          'ATTESTATION_CERT_TIME',
        );
        const issuer = certs[i + 1] ?? attestationRoots.find((r) => cert.verify(r.publicKey));
        requireThat(issuer && cert.verify(issuer.publicKey), 'ATTESTATION_CHAIN_TRUST');
      }
      verifier = certs[0].publicKey;
      attestationVerified = true;
    }
    requireThat(
      statement.get('alg') === (verifier.asymmetricKeyType === 'ec' ? -7 : -8) &&
        verify(Buffer.concat([auth, sha256(client)]), sig, verifier),
      'ATTESTATION_SIGNATURE',
    );
  } else throw Error('UNSUPPORTED_ATTESTATION_FORMAT');
  return {
    credentialID: rawId,
    publicKey,
    publicKeyDER: spki(publicKey),
    aaguid: auth.subarray(37, 53),
    ...data,
    attestationVerified,
    assurance: 'UNASSESSED',
    rpID,
    origin,
  };
}
export function verifyAssertion(
  response,
  registration,
  { challenge, origin = registration.origin, rpID = registration.rpID, uv = true },
) {
  requireThat(
    response.type === 'public-key' &&
      response.id === response.rawId &&
      equal(unb64u(response.rawId), registration.credentialID),
    'CREDENTIAL_BINDING',
  );
  const client = unb64u(response.response.clientDataJSON),
    auth = unb64u(response.response.authenticatorData);
  clientData(client, { type: 'webauthn.get', challenge, origin });
  const data = authenticatorData(auth, { rpID, uv });
  requireThat(
    !(data.flags & 64) && (data.flags & 128 || auth.length === 37),
    'ASSERTION_AUTH_DATA',
  );
  if (data.flags & 128)
    requireThat(decoder.decode(auth.subarray(37)) instanceof Map, 'AUTHENTICATOR_EXTENSIONS');
  requireThat(
    verify(
      Buffer.concat([auth, sha256(client)]),
      unb64u(response.response.signature),
      registration.publicKey,
    ),
    'ASSERTION_SIGNATURE',
  );
  requireThat(data.backupEligible === registration.backupEligible, 'BACKUP_ELIGIBILITY_CHANGED');
  if (data.counter !== 0 || registration.counter !== 0)
    requireThat(data.counter > registration.counter, 'SIGN_COUNT_ROLLBACK');
  return {
    ...data,
    assertionHash: H('WebAuthnAssertion', {
      credentialID: registration.credentialID,
      clientDataJSON: client,
      authenticatorData: auth,
      signature: unb64u(response.response.signature),
    }),
  };
}
export function authorizeHumanActivation({
  activation,
  assertion,
  registration,
  policy,
  sim,
  orp,
  orpCertificate,
  journal,
  permitCertificate,
  permitKey,
  capability,
  capabilityRegistry,
}) {
  requireThat(
    activation.expiresAt > now() &&
      activation.issuedAt <= now() &&
      activation.expiresAt - activation.issuedAt <= policy.maxActivationLifetime,
    'ACTIVATION_TIME',
  );
  requireThat(
    equal(activation.simHash, H('SIM', sim)) &&
      equal(activation.policyHash, H('SignaturePolicy', policy)) &&
      equal(sim.policyHash, activation.policyHash),
    'AUTHORIZATION_POLICY_BINDING',
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
    sim.origin === activation.origin &&
      sim.issuedAt <= now() &&
      sim.expiresAt >= activation.expiresAt &&
      policy.allowedProfiles.includes(sim.profileID),
    'SIM_PROFILE_OR_TIME',
  );
  requireThat(
    registration.active &&
      equal(registration.keyID, activation.keyID) &&
      equal(registration.subjectID, sim.subjectID) &&
      sim.expiresAt > now(),
    'CREDENTIAL_AUTHORIZATION',
  );
  requireThat(
    policy.allowedOrigins.includes(activation.origin) &&
      policy.rpID === activation.rpID &&
      policy.activationMode === 'HUMAN_WEBAUTHN',
    'ACTIVATION_POLICY',
  );
  const hash = H('ActivationContext', activation),
    proof = verifyAssertion(assertion, registration, {
      challenge: hash,
      origin: activation.origin,
      rpID: activation.rpID,
      uv: true,
    });
  if (policy.orpRequired) {
    const o = readControl(orp, 'OrganizationalEndorsement', orpCertificate);
    requireThat(
      equal(o.simHash, activation.simHash) &&
        equal(o.organizationID, sim.organizationID) &&
        o.expiresAt > now() &&
        o.issuedAt <= now() &&
        o.profileID === sim.profileID,
      'ORGANIZATIONAL_AUTHORITY',
    );
  }
  if (policy.capabilityRequired) {
    requireThat(capability && capabilityRegistry, 'CAPABILITY_REQUIRED');
    const registered = capabilityRegistry.active(registration),
      x = capability.context;
    requireThat(
      equal(x.activationHash, hash) &&
        equal(x.operationID, activation.operationID) &&
        x.audience === activation.audience &&
        x.expiresAt > now() &&
        x.expiresAt <= activation.expiresAt &&
        verify(D('CapabilityActivation', x), capability.signature, registered.publicKey),
      'CAPABILITY_ACTIVATION',
    );
  }
  return journal.transaction(() => {
    journal.consumeNonce('activation', b64u(activation.serverNonce));
    const id = b64u(registration.credentialID),
      old = journal.get('credential-counter', id);
    requireThat(
      !old || (proof.counter === 0 && old.value.counter === 0) || proof.counter > old.value.counter,
      'SIGN_COUNT_CONCURRENT_REPLAY',
    );
    journal.put('credential-counter', id, { counter: proof.counter }, old?.revision ?? -1);
    return issuePermit(activation, {
      certificate: permitCertificate,
      privateKey: permitKey,
      activationEvidenceHash: proof.assertionHash,
      proofMode: 'HUMAN_WEBAUTHN',
    });
  });
}
