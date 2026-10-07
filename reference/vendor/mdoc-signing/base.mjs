import { createHash, createPublicKey, randomBytes, sign, verify, X509Certificate } from 'node:crypto';
import { Tag, encode, decode, get, embedded, unembed, coseKey, coseJWK } from './cbor.mjs';
import { documentKeyRelation } from './key-relation.mjs';
import { MdocValidationError, requireThat } from './errors.mjs';

export const SIGNING_DOCTYPE = 'org.certconcord.signer.1';
export const SIGNING_NAMESPACE = SIGNING_DOCTYPE;
export const BASE_PROFILE = 'MDOC-SIGNING-PERSON-PQ-v2';
export const CREDENTIAL_HEADER = 'urn:certconcord:credential:1';
const hash = (algorithm, bytes) => createHash(algorithm).update(bytes).digest();
const same = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
const spki = key => key.export({ format: 'der', type: 'spki' });
const copy = value => decode(encode(value));
const text = value => typeof value === 'string' && value.length > 0;
const integer = value => Number.isSafeInteger(value) && value >= 0;
const stamp = value => new Tag(0, new Date(value * 1000).toISOString().replace('.000Z', 'Z'));
function time(value) {
  requireThat(value instanceof Tag && value.tag === 0 && typeof value.value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value.value), 'MDOC_TIME');
  const seconds = Date.parse(value.value) / 1000;
  requireThat(integer(seconds) && stamp(seconds).value === value.value, 'MDOC_TIME');
  return seconds;
}
function fields(value, required, optional = []) {
  requireThat(value instanceof Map && required.every(key => value.has(key)) && [...value.keys()].every(key => [...required, ...optional].includes(key)), 'MDOC_FIELDS');
}
function p256(key) {
  return key?.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails.namedCurve === 'prime256v1';
}
function certificateDetails(bytes) {
  requireThat(Buffer.isBuffer(bytes) && bytes.length > 0, 'MDOC_CERTIFICATE');
  let certificate;
  try { certificate = new X509Certificate(bytes); }
  catch { throw new MdocValidationError('MDOC_CERTIFICATE'); }
  requireThat(same(certificate.raw, bytes), 'MDOC_CERTIFICATE_ENCODING');
  return { certificate, publicKey: certificate.publicKey, notBefore: certificate.validFromDate.getTime() / 1000, notAfter: certificate.validToDate.getTime() / 1000 };
}
function issuerAuth(value) {
  requireThat(Array.isArray(value) && value.length === 4 && Buffer.isBuffer(value[0]) && value[1] instanceof Map && Buffer.isBuffer(value[2]) && Buffer.isBuffer(value[3]), 'MDOC_ISSUER_AUTH');
  const headers = decode(value[0]), unprotected = value[1];
  requireThat(headers instanceof Map, 'COSE_HEADERS');
  requireThat(headers.get(1) === -7, 'COSE_ALGORITHM_UNSUPPORTED', 'UNSUPPORTED');
  requireThat(!headers.has(2) && !unprotected.has(2), 'COSE_CRITICAL_UNSUPPORTED', 'UNSUPPORTED');
  requireThat([...headers.keys()].every(key => [1, 33, 34].includes(key)) && [...unprotected.keys()].every(key => key === 33), 'COSE_HEADERS');
  requireThat(!(headers.has(33) && unprotected.has(33)), 'MDOC_CERTIFICATE_LOCATION');
  const chain = headers.get(33) ?? unprotected.get(33);
  const certificates = Array.isArray(chain) ? chain : [chain];
  requireThat(certificates.length >= 1 && certificates.length <= 8 && certificates.every(item => Buffer.isBuffer(item) && item.length > 0), 'MDOC_CERTIFICATE_CHAIN');
  if (headers.has(34)) {
    const thumbprint = headers.get(34);
    requireThat(Array.isArray(thumbprint) && thumbprint.length === 2 && thumbprint[0] === -16 && same(thumbprint[1], hash('sha256', certificates[0])), 'MDOC_CERTIFICATE_THUMBPRINT');
  }
  requireThat(value[3].length === 64, 'COSE_SIGNATURE');
  return { value, headers, certificates, certificateBound: headers.has(34) };
}

// Cryptographic issuer-authentication primitive. This does not admit an issuer.
export function verifyIssuerSigned(credential, { issuerKey, certificate, docType = SIGNING_DOCTYPE, at, allowPartial = false } = {}) {
  requireThat(integer(at), 'MDOC_STATE_TIME');
  const bytes = Buffer.isBuffer(credential) ? Buffer.from(credential) : encode(credential);
  const is = decode(bytes);
  fields(is, ['nameSpaces', 'issuerAuth']);
  const ds = certificateDetails(Buffer.from(certificate ?? []));
  requireThat(p256(ds.publicKey) && p256(issuerKey) && same(spki(ds.publicKey), spki(issuerKey)), 'MDOC_ISSUER_KEY');
  requireThat(ds.notBefore <= at && at < ds.notAfter, 'MDOC_CERTIFICATE_VALIDITY');
  const auth = issuerAuth(get(is, 'issuerAuth'));
  requireThat(same(auth.certificates[0], ds.certificate.raw), 'MDOC_ISSUER_PIN');
  requireThat(verify('sha256', encode(['Signature1', auth.value[0], Buffer.alloc(0), auth.value[2]]), { key: issuerKey, dsaEncoding: 'ieee-p1363' }, auth.value[3]), 'COSE_SIGNATURE');
  const mso = unembed(decode(auth.value[2]));
  fields(mso, ['version', 'digestAlgorithm', 'valueDigests', 'deviceKeyInfo', 'docType', 'validityInfo'], ['status']);
  requireThat(mso.get('version') === '1.0', 'MDOC_VERSION_UNSUPPORTED', 'UNSUPPORTED');
  requireThat(mso.get('digestAlgorithm') === 'SHA-256', 'MDOC_DIGEST_UNSUPPORTED', 'UNSUPPORTED');
  requireThat(text(docType) && mso.get('docType') === docType, 'MDOC_DOCTYPE');
  const validityInfo = get(mso, 'validityInfo');
  fields(validityInfo, ['signed', 'validFrom', 'validUntil'], ['expectedUpdate']);
  const validity = Object.fromEntries([...validityInfo].map(([name, value]) => [name, time(value)]));
  requireThat(ds.notBefore <= validity.signed && validity.signed <= validity.validFrom && validity.validFrom < validity.validUntil && validity.validUntil <= ds.notAfter && validity.validFrom <= at && at < validity.validUntil, 'MDOC_EXPIRED');
  if (Object.hasOwn(validity, 'expectedUpdate')) requireThat(validity.signed <= validity.expectedUpdate && validity.expectedUpdate <= validity.validUntil, 'MDOC_UPDATE_TIME');
  const digests = get(mso, 'valueDigests'), namespaces = get(is, 'nameSpaces');
  requireThat(digests instanceof Map && digests.size > 0 && namespaces instanceof Map && namespaces.size > 0, 'MDOC_NAMESPACES');
  for (const [namespace, values] of digests) {
    requireThat(text(namespace) && values instanceof Map && values.size > 0 && [...values].every(([id, digest]) => integer(id) && Buffer.isBuffer(digest) && digest.length === 32), 'MDOC_DIGEST_TABLE');
  }
  const claims = new Map(), salts = new Set();
  for (const [namespace, items] of namespaces) {
    requireThat(text(namespace) && Array.isArray(items) && items.length > 0 && digests.has(namespace), 'MDOC_NAMESPACE');
    const values = new Map(), ids = new Set();
    for (const item of items) {
      const data = unembed(item);
      fields(data, ['digestID', 'random', 'elementIdentifier', 'elementValue']);
      const id = data.get('digestID'), name = data.get('elementIdentifier'), salt = data.get('random');
      requireThat(integer(id) && text(name) && !ids.has(id) && !values.has(name) && Buffer.isBuffer(salt) && salt.length >= 16 && !salts.has(salt.toString('hex')), 'MDOC_ITEM');
      requireThat(same(digests.get(namespace).get(id), hash('sha256', encode(item))), 'MDOC_DIGEST');
      ids.add(id); salts.add(salt.toString('hex')); values.set(name, data.get('elementValue'));
    }
    if (!allowPartial) requireThat(ids.size === digests.get(namespace).size, 'MDOC_INCOMPLETE_ISSUANCE');
    claims.set(namespace, values);
  }
  if (!allowPartial) requireThat(claims.size === digests.size, 'MDOC_INCOMPLETE_ISSUANCE');
  const keyInfo = get(mso, 'deviceKeyInfo');
  fields(keyInfo, ['deviceKey']);
  const holderJWK = coseJWK(get(keyInfo, 'deviceKey'));
  requireThat(get(keyInfo, 'deviceKey').size === 4, 'MDOC_DEVICE_KEY_FIELDS');
  const holderPublicKey = createPublicKey({ key: holderJWK, format: 'jwk' });
  requireThat(!same(spki(issuerKey), spki(holderPublicKey)), 'MDOC_KEY_ROLE_COLLISION');
  return { mso, claims, holderJWK, holderPublicKey, issuerSigned: is, credential: bytes, issuerAuthBytes: encode(auth.value), certificateBytes: Buffer.from(certificate), certificateChain: auth.certificates.map(value => Buffer.from(value)), certificateBound: auth.certificateBound, validity };
}

export function issueIssuerSigned({ namespaces, holderJWK, certificate, privateKey, docType = SIGNING_DOCTYPE, signed, validFrom, validUntil }) {
  requireThat(integer(signed) && integer(validFrom) && integer(validUntil) && signed <= validFrom && validFrom < validUntil && text(docType), 'MDOC_VALIDITY');
  const ds = certificateDetails(certificate), issuerKey = createPublicKey(privateKey), deviceKey = coseKey(holderJWK);
  requireThat(p256(issuerKey) && same(spki(ds.publicKey), spki(issuerKey)), 'MDOC_ISSUER_KEY');
  const nameSpaces = new Map(), valueDigests = new Map();
  for (const [namespace, data] of namespaces instanceof Map ? namespaces : Object.entries(namespaces)) {
    const values = data instanceof Map ? data : new Map(Object.entries(data));
    const items = [], digests = new Map(); let id = 0;
    for (const [elementIdentifier, elementValue] of values) {
      const item = embedded({ digestID: id, random: randomBytes(32), elementIdentifier, elementValue });
      items.push(item); digests.set(id++, hash('sha256', encode(item)));
    }
    nameSpaces.set(namespace, items); valueDigests.set(namespace, digests);
  }
  const mso = { version: '1.0', digestAlgorithm: 'SHA-256', valueDigests, deviceKeyInfo: { deviceKey }, docType, validityInfo: { signed: stamp(signed), validFrom: stamp(validFrom), validUntil: stamp(validUntil) } };
  const protectedBytes = encode(new Map([[1, -7], [34, [-16, hash('sha256', certificate)]]])), payload = encode(embedded(mso));
  const signature = sign('sha256', encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const credential = encode({ nameSpaces, issuerAuth: [protectedBytes, new Map([[33, certificate]]), payload, signature] });
  verifyIssuerSigned(credential, { issuerKey, certificate, docType, at: validFrom, allowPartial: false });
  return credential;
}

function externalDecision(callback, input, code) {
  requireThat(typeof callback === 'function', code + '_MISSING', 'INDETERMINATE');
  let value;
  try { value = callback(input); } catch { throw new MdocValidationError(code + '_UNAVAILABLE', 'INDETERMINATE'); }
  requireThat(value && typeof value.then !== 'function' && ['VALID', 'INVALID', 'INDETERMINATE', 'UNSUPPORTED'].includes(value.overall), code + '_RESULT');
  return { ...value };
}
export function verifySigningCredential(credential, {
  issuerKey, certificate, docType = SIGNING_DOCTYPE, namespace = SIGNING_NAMESPACE,
  profileID = BASE_PROFILE, documentKeyMode = 'INDEPENDENT_PQ', authorizeIssuer, resolveStatus,
  stateTime, knowledgeTime = stateTime, statusEvidence,
} = {}) {
  requireThat(integer(stateTime) && integer(knowledgeTime) && stateTime <= knowledgeTime, 'MDOC_VALIDATION_TIME');
  const retainedStatusEvidence = statusEvidence === undefined ? undefined : copy(statusEvidence);
  const validated = verifyIssuerSigned(credential, { issuerKey, certificate, docType, at: stateTime, allowPartial: false });
  requireThat(validated.certificateBound, 'MDOC_CERTIFICATE_BINDING_REQUIRED');
  requireThat(!validated.mso.has('status'), 'MDOC_MSO_STATUS_UNSUPPORTED', 'UNSUPPORTED');
  const claims = validated.claims.get(namespace);
  requireThat(claims instanceof Map, 'MDOC_SIGNING_NAMESPACE');
  for (const name of ['subject_id', 'credential_id']) requireThat(Buffer.isBuffer(claims.get(name)) && claims.get(name).length === 32, 'MDOC_IDENTIFIER');
  requireThat(text(claims.get('issuer')) && text(profileID) && claims.get('profile_id') === profileID, 'MDOC_PROFILE');
  requireThat(Array.isArray(claims.get('allowed_purposes')) && claims.get('allowed_purposes').length === 1 && claims.get('allowed_purposes')[0] === 'DOCUMENT_SIGN', 'MDOC_PURPOSE');
  requireThat(['INDEPENDENT_PQ', 'DEVICE_KEY', 'PASSKEY_KEY'].includes(documentKeyMode) && claims.get('document_key_mode') === documentKeyMode, 'MDOC_KEY_MODE');
  const keyBytes = claims.get('signing_key');
  requireThat(Buffer.isBuffer(keyBytes), 'MDOC_DOCUMENT_KEY');
  let publicKey;
  try { publicKey = createPublicKey({ key: keyBytes, type: 'spki', format: 'der' }); }
  catch { throw new MdocValidationError('MDOC_DOCUMENT_KEY'); }
  requireThat(same(spki(publicKey), keyBytes) && same(claims.get('signing_key_id'), hash('sha512', keyBytes)), 'MDOC_DOCUMENT_KEY_ID');
  documentKeyRelation(documentKeyMode, keyBytes, spki(validated.holderPublicKey));
  requireThat(!same(keyBytes, spki(issuerKey)), 'MDOC_KEY_ROLE_COLLISION');
  const status = claims.get('status');
  fields(status, ['status_list']);
  const reference = status.get('status_list');
  fields(reference, ['uri', 'idx']);
  let uri;
  try { uri = new URL(reference.get('uri')); } catch { throw new MdocValidationError('MDOC_STATUS_REFERENCE'); }
  requireThat(uri.protocol === 'https:' && !uri.username && !uri.password && !uri.hash && uri.href === reference.get('uri') && integer(reference.get('idx')), 'MDOC_STATUS_REFERENCE');
  const common = { issuer: claims.get('issuer'), docType, namespace, profileID, documentKeyMode, purpose: 'DOCUMENT_SIGN', stateTime, knowledgeTime };
  const authorization = externalDecision(authorizeIssuer, { ...common, certificate: Buffer.from(validated.certificateBytes), certificateChain: validated.certificateChain.map(value => Buffer.from(value)), credentialID: Buffer.from(claims.get('credential_id')) }, 'MDOC_ISSUER_AUTHORIZATION');
  requireThat(authorization.overall === 'VALID', 'MDOC_ISSUER_AUTHORIZATION', authorization.overall);
  const decision = externalDecision(resolveStatus, { ...common, reference: { uri: reference.get('uri'), idx: reference.get('idx') }, credentialID: Buffer.from(claims.get('credential_id')), certificate: Buffer.from(validated.certificateBytes), evidence: retainedStatusEvidence }, 'MDOC_STATUS');
  const outcomes = { GOOD: 'VALID', REVOKED: 'INVALID', INVALID: 'INVALID', STALE: 'INDETERMINATE', MISSING: 'INDETERMINATE', UNKNOWN: 'INDETERMINATE', CONFLICTING: 'INDETERMINATE', UNSUPPORTED: 'UNSUPPORTED' };
  requireThat(outcomes[decision.status] === decision.overall, 'MDOC_STATUS_RESULT');
  requireThat(decision.overall === 'VALID', 'MDOC_STATUS_' + decision.status, decision.overall);
  return { ...validated, overall: 'VALID', signingClaims: claims, publicKey, documentKeyMode, status: decision, authorization, representationHash: hash('sha512', validated.credential) };
}

function signatureParameters(document, { credential, publicKey, requiredProtectedHeaders = new Map() }) {
  requireThat(Buffer.isBuffer(document) && Buffer.isBuffer(credential), 'MDOC_DOCUMENT_BYTES');
  const algorithm = { 'ml-dsa-65': -49, 'ml-dsa-87': -50, ec: -7 }[publicKey?.asymmetricKeyType];
  requireThat(algorithm && (algorithm !== -7 || p256(publicKey)), 'MDOC_DOCUMENT_ALGORITHM', 'UNSUPPORTED');
  requireThat(requiredProtectedHeaders instanceof Map && [...requiredProtectedHeaders.keys()].every(key => (text(key) || Number.isSafeInteger(key)) && ![1, 2, 3, CREDENTIAL_HEADER].includes(key)), 'MDOC_REQUIRED_HEADERS');
  const extensions = copy(requiredProtectedHeaders);
  const headers = new Map([[1, algorithm], [2, [CREDENTIAL_HEADER, ...extensions.keys()]], [3, 'application/certconcord-mdoc-document'], [CREDENTIAL_HEADER, hash('sha512', credential)], ...extensions]);
  const protectedBytes = encode(headers), payload = Buffer.from(document);
  return { algorithm, protectedBytes, tbs: encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]), publicKey };
}
function verifyDocumentValue(parameters, signature) {
  return Buffer.isBuffer(signature) && (parameters.algorithm === -7 ? signature.length === 64 : signature.length === (parameters.algorithm === -49 ? 3309 : 4627)) && verify(parameters.algorithm === -7 ? 'sha256' : null, parameters.tbs, parameters.algorithm === -7 ? { key: parameters.publicKey, dsaEncoding: 'ieee-p1363' } : parameters.publicKey, signature);
}
export function prepareDocumentSignature(document, options) {
  const parameters = signatureParameters(document, options);
  return { tbs: Buffer.from(parameters.tbs), algorithm: parameters.algorithm, finish(signature) {
    requireThat(verifyDocumentValue(parameters, signature), 'MDOC_DOCUMENT_SIGNATURE');
    return encode([parameters.protectedBytes, new Map(), null, Buffer.from(signature)]);
  } };
}
export function verifyDocumentSignature(signature, document, options) {
  const value = decode(signature);
  requireThat(Array.isArray(value) && value.length === 4 && Buffer.isBuffer(value[0]) && value[1] instanceof Map && value[1].size === 0 && value[2] === null && Buffer.isBuffer(value[3]), 'MDOC_DOCUMENT_COSE');
  const headers = decode(value[0]);
  requireThat(headers instanceof Map && [-49, -50, -7].includes(headers.get(1)), 'MDOC_DOCUMENT_ALGORITHM', 'UNSUPPORTED');
  const parameters = signatureParameters(document, options);
  requireThat(same(value[0], parameters.protectedBytes), 'MDOC_DOCUMENT_PROTECTED_HEADERS');
  requireThat(verifyDocumentValue(parameters, value[3]), 'MDOC_DOCUMENT_SIGNATURE');
  return { tbs: parameters.tbs, signature: Buffer.from(value[3]) };
}
export function verifySignedDocument(document, signature, credential, options) {
  requireThat(Buffer.isBuffer(document) && Buffer.isBuffer(signature) && Buffer.isBuffer(credential), 'MDOC_DOCUMENT_BYTES');
  const retainedDocument = Buffer.from(document), retainedSignature = Buffer.from(signature), retainedCredential = Buffer.from(credential);
  const retainedOptions = { ...options, certificate: Buffer.from(options.certificate), requiredProtectedHeaders: copy(options.requiredProtectedHeaders ?? new Map()) };
  const validated = verifySigningCredential(retainedCredential, retainedOptions);
  const documentSignature = verifyDocumentSignature(retainedSignature, retainedDocument, { credential: validated.credential, publicKey: validated.publicKey, requiredProtectedHeaders: retainedOptions.requiredProtectedHeaders });
  return { ...validated, documentSignature };
}
export function evaluateSignedDocument(...arguments_) {
  try { return verifySignedDocument(...arguments_); }
  catch (error) { return { overall: error.overall ?? 'INVALID', reason: error.code ?? 'MDOC_MALFORMED' }; }
}
