import { X509Certificate } from 'node:crypto';
import { evaluateSignedDocument, BASE_PROFILE } from './vendor/mdoc-signing/base.mjs';
import { verifyHolderAuthentication } from './vendor/mdoc-signing/holder-auth.mjs';
import { verifyStatusList } from './openid.mjs';
import { decodeJWS } from './jose.mjs';
import { parseJSON } from './json.mjs';

const statusResult = (status, reason, algorithm) => ({
  status,
  overall: {
    GOOD: 'VALID',
    REVOKED: 'INVALID',
    INVALID: 'INVALID',
    STALE: 'INDETERMINATE',
    MISSING: 'INDETERMINATE',
    UNKNOWN: 'INDETERMINATE',
  }[status],
  ...(reason ? { reason } : {}),
  ...(algorithm ? { algorithm } : {}),
});

// The experimental v3 profile selects an ML-DSA-65 JWT status token under the
// admitted document signer. Its current-list evidence does not prove historical
// status coverage or replace the caller's issuer lifecycle decision.
export function verifyPqMdocStatusList(token, { publicKey, uri, index, at } = {}) {
  if (!Number.isSafeInteger(at) || at < 0) return statusResult('INVALID', 'MDOC_STATUS_TIME');
  if (publicKey?.asymmetricKeyType !== 'ml-dsa-65')
    return statusResult('INVALID', 'MDOC_PQC_STATUS_KEY');
  if (token === undefined || token === null) return statusResult('MISSING', 'MDOC_STATUS_MISSING');
  const assessed = verifyStatusList(token, { publicKey, uri, index, at });
  if (assessed.status === 'INVALID') return statusResult('INVALID', assessed.reason);
  try {
    const { header, payload } = decodeJWS(token);
    const claims = parseJSON(payload.toString('utf8'));
    if (
      header.alg !== 'ML-DSA-65' ||
      header.typ !== 'statuslist+jwt' ||
      !Number.isSafeInteger(claims.ttl) ||
      claims.ttl <= 0 ||
      claims.ttl > 300 ||
      !Number.isSafeInteger(claims.iat + claims.ttl)
    )
      return statusResult('INVALID', 'MDOC_STATUS_TTL');
    if (assessed.status === 'GOOD' && claims.iat + claims.ttl <= at)
      return statusResult('STALE', 'MDOC_STATUS_TTL_EXPIRED');
    return statusResult(
      assessed.status,
      assessed.reason,
      assessed.status === 'GOOD' ? 'ML-DSA-65' : undefined,
    );
  } catch {
    return statusResult('INVALID', 'MDOC_STATUS_INVALID');
  }
}

const failure = (error) => ({
  overall: error.overall ?? 'INVALID',
  reason: error.code ?? 'MDOC_PQC_INVALID',
});

// This entry is separate from ISO_MDOC P-256 presentation and certificate
// admission. The caller must pin a document-signing trust anchor, authorization
// policy, status URI and real session transcript for this experimental suite.
export function evaluateExperimentalPqDocumentBundle({
  document,
  signature,
  credential,
  deviceSigned,
  sessionTranscript,
  certificate,
  trustAnchorCertificate,
  stateTime,
  knowledgeTime = stateTime,
  statusEvidence,
  statusURI,
  authorizeIssuer,
  profileID = BASE_PROFILE,
}) {
  try {
    if (profileID !== BASE_PROFILE)
      return { overall: 'UNSUPPORTED', reason: 'MDOC_PQC_PROFILE_UNSUPPORTED' };
    if (typeof authorizeIssuer !== 'function')
      return { overall: 'INDETERMINATE', reason: 'MDOC_ISSUER_AUTHORIZATION_MISSING' };
    const retained = {
      document: Buffer.from(document),
      signature: Buffer.from(signature),
      credential: Buffer.from(credential),
      deviceSigned: Buffer.from(deviceSigned),
      sessionTranscript: Buffer.from(sessionTranscript),
      certificate: Buffer.from(certificate),
      trustAnchorCertificate:
        trustAnchorCertificate === undefined ? undefined : Buffer.from(trustAnchorCertificate),
    };
    const issuerKey = new X509Certificate(retained.certificate).publicKey;
    const signed = evaluateSignedDocument(
      retained.document,
      retained.signature,
      retained.credential,
      {
        certificate: retained.certificate,
        issuerKey,
        trustAnchorCertificate: retained.trustAnchorCertificate,
        profileID: BASE_PROFILE,
        documentKeyMode: 'INDEPENDENT_PQ',
        stateTime,
        knowledgeTime,
        statusEvidence,
        authorizeIssuer,
        resolveStatus: ({ reference, evidence, knowledgeTime: time, statusAlgorithm }) => {
          if (statusAlgorithm !== 'ML-DSA-65' || reference.uri !== statusURI)
            return statusResult('INVALID', 'MDOC_STATUS_REFERENCE');
          return verifyPqMdocStatusList(evidence, {
            publicKey: issuerKey,
            uri: statusURI,
            index: reference.idx,
            at: time,
          });
        },
      },
    );
    if (signed.overall !== 'VALID') return signed;
    const holder = verifyHolderAuthentication(retained.deviceSigned, retained.credential, {
      issuerKey,
      certificate: retained.certificate,
      at: stateTime,
      sessionTranscript: retained.sessionTranscript,
      profileID: BASE_PROFILE,
    });
    return {
      overall: 'VALID',
      profileID: BASE_PROFILE,
      documentKeyType: signed.publicKey.asymmetricKeyType,
      holderKeyType: holder.issuerFacts.holderPublicKey.asymmetricKeyType,
      issuer: signed.signingClaims.get('issuer'),
      representationHash: signed.representationHash,
      status: signed.status,
      holderProof: holder.holderProof,
    };
  } catch (error) {
    return failure(error);
  }
}
