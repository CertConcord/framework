import { verify } from 'node:crypto';
import { Tag, decode, embedded, encode, get } from './cbor.mjs';
import { BASE_PROFILE, SIGNING_DOCTYPE, SIGNING_NAMESPACE, isLegacyClassicalProfile,
  verifyIssuerSigned } from './base.mjs';
import { requireThat } from './errors.mjs';

const same = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
const emptyNameSpaces = () => embedded(new Map());
const holderAlgorithm = key => ({ ec: key?.asymmetricKeyDetails?.namedCurve === 'prime256v1' ? -7 : undefined,
  'ml-dsa-65': -49, 'ml-dsa-87': -50 })[key?.asymmetricKeyType];
const signatureLength = algorithm => ({ '-7': 64, '-49': 3309, '-50': 4627 })[algorithm];
const protectedBytes = algorithm => encode(new Map([[1, algorithm]]));

function transcript(bytes) {
  requireThat(Buffer.isBuffer(bytes), 'MDOC_SESSION_TRANSCRIPT');
  const retained = Buffer.from(bytes), value = decode(retained);
  requireThat(Array.isArray(value) && value.length === 3 && value[2] !== null && same(encode(value), retained), 'MDOC_SESSION_TRANSCRIPT');
  return value;
}

function deviceAuthentication(sessionTranscript, docType, nameSpaces) {
  requireThat(typeof docType === 'string' && docType.length > 0, 'MDOC_HOLDER_DOCTYPE');
  return encode(embedded(['DeviceAuthentication', transcript(sessionTranscript), docType, nameSpaces]));
}

function signatureInput(sessionTranscript, docType, nameSpaces, receivedProtected) {
  const payload = deviceAuthentication(sessionTranscript, docType, nameSpaces);
  return encode(['Signature1', receivedProtected, Buffer.alloc(0), payload]);
}

// This selected proof carries no device namespace claims. The caller supplies the
// exact session transcript and is responsible for its challenge and freshness.
export function prepareHolderAuthentication(sessionTranscript, { holderPublicKey, docType = SIGNING_DOCTYPE,
  profileID = BASE_PROFILE, allowLegacyClassical = false } = {}) {
  const algorithm = holderAlgorithm(holderPublicKey);
  requireThat(algorithm, 'MDOC_HOLDER_KEY');
  requireThat(profileID === BASE_PROFILE || (allowLegacyClassical && isLegacyClassicalProfile(profileID)),
    'MDOC_HOLDER_PROFILE_UNSUPPORTED', 'UNSUPPORTED');
  requireThat(profileID === BASE_PROFILE ? algorithm === -49 : algorithm === -7,
    profileID === BASE_PROFILE ? 'MDOC_HOLDER_PQC_REQUIRED' : 'MDOC_LEGACY_AUTHENTICATION_REQUIRED');
  const nameSpaces = emptyNameSpaces(), headers = protectedBytes(algorithm);
  const tbs = signatureInput(sessionTranscript, docType, nameSpaces, headers);
  return { tbs: Buffer.from(tbs), finish(signature) {
    requireThat(Buffer.isBuffer(signature) && signature.length === signatureLength(algorithm) &&
      verify(algorithm === -7 ? 'sha256' : null, tbs,
        algorithm === -7 ? { key: holderPublicKey, dsaEncoding: 'ieee-p1363' } : holderPublicKey, signature), 'MDOC_HOLDER_SIGNATURE');
    return encode({ nameSpaces, deviceAuth: { deviceSignature: [headers, new Map(), null, Buffer.from(signature)] } });
  } };
}

// Holder control at one session transcript is separate from issuer authorization,
// credential status and the document-signing key's detached COSE signature.
export function verifyHolderAuthentication(deviceSigned, credential, {
  issuerKey, certificate, at, sessionTranscript, docType = SIGNING_DOCTYPE,
  profileID = BASE_PROFILE, allowLegacyClassical = false,
} = {}) {
  requireThat(Buffer.isBuffer(deviceSigned) && Buffer.isBuffer(credential), 'MDOC_HOLDER_BYTES');
  const facts = verifyIssuerSigned(Buffer.from(credential), { issuerKey, certificate, at, docType });
  requireThat(facts.claims.get(SIGNING_NAMESPACE)?.get('profile_id') === profileID, 'MDOC_HOLDER_PROFILE');
  requireThat(profileID === BASE_PROFILE || (allowLegacyClassical && isLegacyClassicalProfile(profileID)),
    'MDOC_HOLDER_PROFILE_UNSUPPORTED', 'UNSUPPORTED');
  if (profileID === BASE_PROFILE) requireThat(issuerKey?.asymmetricKeyType === 'ml-dsa-65' &&
    facts.holderPublicKey.asymmetricKeyType === 'ml-dsa-65', 'MDOC_HOLDER_PQC_REQUIRED');
  else requireThat(issuerKey?.asymmetricKeyType === 'ec' &&
    issuerKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
    facts.holderPublicKey.asymmetricKeyType === 'ec' &&
    facts.holderPublicKey.asymmetricKeyDetails.namedCurve === 'prime256v1',
    'MDOC_LEGACY_AUTHENTICATION_REQUIRED');
  const value = decode(Buffer.from(deviceSigned));
  requireThat(value instanceof Map && value.size === 2 && value.has('nameSpaces') && value.has('deviceAuth'), 'MDOC_DEVICE_SIGNED');
  const nameSpaces = get(value, 'nameSpaces'), auth = get(value, 'deviceAuth');
  requireThat(nameSpaces instanceof Tag && nameSpaces.tag === 24 && Buffer.isBuffer(nameSpaces.value), 'MDOC_DEVICE_NAMESPACES');
  const deviceNameSpaces = decode(nameSpaces.value);
  requireThat(deviceNameSpaces instanceof Map && same(nameSpaces.value, encode(deviceNameSpaces)), 'MDOC_DEVICE_NAMESPACES');
  requireThat(deviceNameSpaces.size === 0, 'MDOC_DEVICE_NAMESPACES_UNSUPPORTED', 'UNSUPPORTED');
  requireThat(auth instanceof Map, 'MDOC_HOLDER_AUTH');
  requireThat(auth.size === 1, 'MDOC_HOLDER_AUTH');
  requireThat(!auth.has('deviceMac'), 'MDOC_HOLDER_MAC_UNSUPPORTED', 'UNSUPPORTED');
  requireThat(auth.has('deviceSignature'), 'MDOC_HOLDER_AUTH');
  const cose = auth.get('deviceSignature');
  requireThat(Array.isArray(cose) && cose.length === 4 && Buffer.isBuffer(cose[0]) && cose[1] instanceof Map && cose[1].size === 0 && cose[2] === null && Buffer.isBuffer(cose[3]), 'MDOC_HOLDER_COSE');
  const headers = decode(cose[0]);
  const algorithm = holderAlgorithm(facts.holderPublicKey);
  requireThat(headers instanceof Map && headers.get(1) === algorithm, 'MDOC_HOLDER_ALGORITHM');
  const tbs = signatureInput(sessionTranscript, docType, nameSpaces, cose[0]);
  requireThat(cose[3].length === signatureLength(algorithm) &&
    verify(algorithm === -7 ? 'sha256' : null, tbs,
      algorithm === -7 ? { key: facts.holderPublicKey, dsaEncoding: 'ieee-p1363' } : facts.holderPublicKey, cose[3]), 'MDOC_HOLDER_SIGNATURE');
  requireThat(same(cose[0], protectedBytes(algorithm)), 'MDOC_HOLDER_HEADERS');
  return { issuerFacts: facts, holderProof: { tbs, signature: Buffer.from(cose[3]) } };
}
