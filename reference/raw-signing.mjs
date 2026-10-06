import { createPublicKey, X509Certificate } from 'node:crypto';
import { decode } from './cose.mjs';
import {
  H,
  sha256,
  sha512,
  spki,
  keyID,
  equal,
  requireThat,
  unb64u,
  b64u,
  now,
  verify,
  parseDER,
} from './core.mjs';
import { authenticatorData, verifyRegistration, verifyAssertion } from './webauthn.mjs';
import { verifiedChain } from './key-attestation.mjs';
import { arkgSeedPublicKeys, ARKG_OPERATION } from './arkg.mjs';

export const PASSKEY_SIGN_PROFILE = 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1';
export const RAW_VERSIONS = Object.freeze({
  'previewSign-4': 'previewSign',
  'previewSign5-2026-09-09': 'previewSign5',
});
export function rawExtension(version) {
  const id = RAW_VERSIONS[version];
  requireThat(id, 'RAW_SIGNING_VERSION');
  return id;
}
export function rawInput(tbs, algorithm) {
  requireThat(
    Buffer.isBuffer(tbs) && tbs.length > 0 && tbs.length <= 1024 * 1024,
    'RAW_SIGNING_INPUT',
  );
  requireThat([-9, -300, ARKG_OPERATION].includes(algorithm), 'RAW_SIGNING_ALGORITHM');
  return algorithm === -9 ? tbs : sha256(tbs);
}
function extensionOutputs(auth, version, attested = false) {
  requireThat(
    Buffer.isBuffer(auth) && auth.length >= 37 && auth.length <= 65536 && auth[32] & 128,
    'RAW_SIGNING_ED_REQUIRED',
  );
  let start = 37;
  if (attested) {
    requireThat(auth.length >= 55 && auth[32] & 64, 'RAW_SIGNING_AT_REQUIRED');
    start = 55 + auth.readUInt16BE(53);
    requireThat(start < auth.length, 'RAW_SIGNING_AUTH_DATA');
    const key = decode(auth.subarray(start), { allowTrailing: true });
    start += key.bytesRead;
  }
  const outputs = decode(auth.subarray(start));
  requireThat(
    outputs instanceof Map &&
      !outputs.has(version === 'previewSign-4' ? 'previewSign5' : 'previewSign'),
    'RAW_SIGNING_VERSION_CONFUSION',
  );
  const output = outputs.get(rawExtension(version));
  requireThat(output instanceof Map && !output.has(-1), 'RAW_SIGNING_EXTENSION_ERROR');
  return output;
}
function signingPublicKey(raw, algorithm) {
  const key = decode(raw);
  if (algorithm === ARKG_OPERATION) {
    arkgSeedPublicKeys(raw);
    return null;
  }
  requireThat(
    [-9, -300].includes(algorithm) &&
      key instanceof Map &&
      key.get(1) === 2 &&
      [-7, -9].includes(key.get(3)) &&
      key.get(-1) === 1 &&
      !key.has(-4) &&
      Buffer.isBuffer(key.get(-2)) &&
      key.get(-2).length === 32 &&
      Buffer.isBuffer(key.get(-3)) &&
      key.get(-3).length === 32,
    'RAW_SIGNING_PUBLIC_KEY',
  );
  return createPublicKey({
    format: 'jwk',
    key: { kty: 'EC', crv: 'P-256', x: b64u(key.get(-2)), y: b64u(key.get(-3)) },
  });
}

// The model policy is installed by the trust operator; it is not supplied by the enrolling client.
export function verifySigningKeyGeneration(
  { ceremony, generatedKey, registration },
  { challenge, origin, rpID, version, algorithms, attestationPolicy, at = now() },
) {
  rawExtension(version);
  const isCreate = Boolean(ceremony.response?.attestationObject);
  requireThat(isCreate || version === 'previewSign5-2026-09-09', 'RAW_GENERATION_CEREMONY');
  const parentObject = isCreate ? decode(unb64u(ceremony.response.attestationObject)) : null;
  const parentAuth = isCreate
    ? parentObject.get('authData')
    : unb64u(ceremony.response.authenticatorData);
  const parent = isCreate
    ? verifyRegistration(ceremony, {
        challenge,
        origin,
        rpID,
        uv: true,
        attestationRoots: attestationPolicy.roots.map((r) => new X509Certificate(r)),
      })
    : registration;
  requireThat(
    parent &&
      parent.attestationVerified === true &&
      parent.origin === origin &&
      parent.rpID === rpID,
    'RAW_PARENT_REGISTRATION',
  );
  const parentProof = isCreate
    ? null
    : verifyAssertion(ceremony, parent, { challenge, origin, rpID, uv: true });
  requireThat(!parent.backupEligible && !parent.backedUp, 'RAW_PARENT_DEVICE_BOUND_REQUIRED');
  const output = extensionOutputs(parentAuth, version, isCreate);
  requireThat(
    output.size === 1 &&
      output.has(3) &&
      algorithms.includes(output.get(3)) &&
      generatedKey?.algorithm === output.get(3),
    'RAW_SIGNING_ALGORITHM_BINDING',
  );
  const algorithm = output.get(3),
    objectBytes = generatedKey.attestationObject;
  requireThat(Buffer.isBuffer(objectBytes) && objectBytes.length <= 65536, 'RAW_ATTESTATION_SIZE');
  const object = decode(objectBytes),
    auth = object.get('authData'),
    statement = object.get('attStmt');
  requireThat(
    object.get('fmt') === 'packed' && statement instanceof Map && statement.has('x5c'),
    'RAW_ATTESTATION_FORMAT',
  );
  const flags = authenticatorData(auth, { rpID, uv: true });
  requireThat(
    auth.length >= 55 && flags.flags === (parentAuth[32] | 192) && flags.counter === 0,
    'RAW_ATTESTATION_FLAGS',
  );
  const len = auth.readUInt16BE(53),
    handle = auth.subarray(55, 55 + len);
  requireThat(len <= 1024 && 55 + len < auth.length, 'RAW_KEY_HANDLE');
  const parsed = decode(auth.subarray(55 + len), { allowTrailing: true });
  const publicKeyBytes = auth.subarray(55 + len, 55 + len + parsed.bytesRead);
  const outputs = extensionOutputs(auth, version, true);
  requireThat(outputs.size === 1 && outputs.get(4) === 5, 'RAW_SIGNING_FIXED_UV');
  requireThat(
    equal(handle, generatedKey.keyHandle) && equal(publicKeyBytes, generatedKey.publicKey),
    'RAW_ATTESTATION_CLIENT_MISMATCH',
  );
  const aaguid = auth.subarray(37, 53);
  requireThat(equal(aaguid, parent.aaguid), 'RAW_ATTESTATION_AAGUID');
  const trust = verifiedChain(statement.get('x5c'), attestationPolicy, at);
  const attestationKey = trust.leaf.publicKey;
  if (isCreate) {
    requireThat(parentObject.get('fmt') === 'packed', 'RAW_PARENT_ATTESTATION');
    const parentTrust = verifiedChain(
      parentObject.get('attStmt').get('x5c'),
      attestationPolicy,
      at,
    );
    requireThat(
      equal(parentTrust.rootHash, trust.rootHash) && equal(parentTrust.leaf.spki, trust.leaf.spki),
      'RAW_PARENT_ATTESTATION_BINDING',
    );
  }
  requireThat(
    attestationKey.asymmetricKeyType === 'ec' &&
      attestationKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
      statement.get('alg') === -7,
    'RAW_ATTESTATION_ALGORITHM',
  );
  requireThat(
    verify(
      Buffer.concat([auth, sha256(unb64u(ceremony.response.clientDataJSON))]),
      statement.get('sig'),
      attestationKey,
    ),
    'RAW_ATTESTATION_SIGNATURE',
  );
  const aaguidExtension = trust.leaf.extensions.get('1.3.6.1.4.1.45724.1.1.4');
  if (aaguidExtension) {
    const n = parseDER(aaguidExtension.value);
    requireThat(
      !aaguidExtension.critical && n.tag === 4 && equal(n.value, aaguid),
      'RAW_CERTIFICATE_AAGUID',
    );
  }
  const model = attestationPolicy.models?.find(
    (m) =>
      equal(m.aaguid, aaguid) &&
      equal(m.rootHash, trust.rootHash) &&
      m.versions.includes(version) &&
      m.algorithms.includes(algorithm),
  );
  requireThat(
    model &&
      ['SECURE_ELEMENT', 'TEE', 'TPM', 'SECURE_ENCLAVE'].includes(model.custody) &&
      model.nonExportable === true &&
      model.status === 'APPROVED' &&
      model.expiresAt > at,
    'RAW_AUTHENTICATOR_MODEL_POLICY',
  );
  const publicKey = signingPublicKey(publicKeyBytes, algorithm);
  requireThat(
    !publicKey ||
      (!equal(spki(publicKey), spki(parent.publicKey)) &&
        !equal(spki(publicKey), spki(attestationKey))),
    'RAW_KEY_ROLE_COLLISION',
  );
  return {
    registration: parent,
    publicKey,
    publicKeyBytes,
    keyHandle: handle,
    algorithm,
    version,
    aaguid,
    fixedFlags: 5,
    custody: model.custody,
    level: 'KAL2',
    attestationHash: sha512(objectBytes),
    generationProofHash: H('PasskeyKeyGeneration', {
      ceremony,
      attestationHash: sha512(objectBytes),
    }),
    parentCounter: parentProof?.counter ?? parent.counter,
    modelPolicyHash: H('PasskeyAuthenticatorModel', model),
    statusEvidenceHash: trust.statusEvidenceHash,
    expiresAt: Math.min(trust.expiresAt, model.expiresAt),
  };
}

export function verifyRawSigningAssertion(
  { assertion, signature },
  registration,
  {
    challenge,
    origin = registration.origin,
    rpID = registration.rpID,
    version,
    algorithm,
    publicKey,
    tbs,
  },
) {
  rawInput(tbs, algorithm);
  const proof = verifyAssertion(assertion, registration, { challenge, origin, rpID, uv: true });
  const output = extensionOutputs(unb64u(assertion.response.authenticatorData), version);
  requireThat(
    output.size === 1 && Buffer.isBuffer(output.get(6)) && equal(output.get(6), signature),
    'RAW_SIGNATURE_DUAL_BINDING',
  );
  requireThat(
    Buffer.isBuffer(signature) &&
      signature.length <= 80 &&
      publicKey.asymmetricKeyType === 'ec' &&
      publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1',
    'RAW_SIGNATURE_FORMAT',
  );
  const parsed = parseDER(signature);
  requireThat(
    parsed.tag === 48 &&
      parsed.children?.length === 2 &&
      parsed.children.every((n) => n.tag === 2) &&
      verify(tbs, signature, publicKey),
    'RAW_DOCUMENT_SIGNATURE',
  );
  return {
    ...proof,
    documentKeyID: keyID(publicKey),
    signatureHash: sha512(signature),
    evidenceHash: H('PasskeyRawProof', {
      assertionHash: proof.assertionHash,
      signatureHash: sha512(signature),
      tbsHash: sha512(tbs),
      version,
      algorithm,
    }),
  };
}

export function storeParentCounter(journal, registration, proof) {
  const id = b64u(registration.credentialID),
    row = journal.get('credential-counter', id);
  requireThat(
    !row || (proof.counter === 0 && row.value.counter === 0) || proof.counter > row.value.counter,
    'SIGN_COUNT_CONCURRENT_REPLAY',
  );
  journal.put('credential-counter', id, { counter: proof.counter }, row?.revision ?? -1);
}
