import { createPrivateKey } from 'node:crypto';
import { assessIdentityStatus, requireFreshIdentityAssessment } from './identity.mjs';
import {
  identityClaimPaths,
  identityProfileHash,
  requestedNamespaces,
  validateIdentityClaims,
} from './identity-profiles.mjs';
import { b64u, random, now, unb64u, equal, H, requireThat } from './core.mjs';
import { annexCRequest, annexCVerify, NAMESPACE } from './mdoc.mjs';
import { thumbprint } from './jose.mjs';
import { verifyX5C, verifyStatusList } from './openid.mjs';

function plain(v) {
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, plain(x)]));
  if (Array.isArray(v)) return v.map(plain);
  return v;
}

// Platform origin and authenticated browser session are supplied by the host boundary.
export class AnnexCVerifier {
  constructor({ journal, privateKey, certificate, issuerRegistry, trustRoots }) {
    Object.assign(this, { journal, privateKey, certificate, issuerRegistry, trustRoots });
  }
  request({
    sessionID,
    origin,
    issuerID,
    identityIssuerID,
    requestBindingHash,
    activationHash,
    displayText,
    claims,
    docType,
    namespace = NAMESPACE,
  }) {
    issuerID = identityIssuerID ?? issuerID;
    const issuer = this.issuerRegistry.get(issuerID),
      identity = identityIssuerID && issuer?.identityProfile;
    let claimPaths;
    requireThat(
      issuer &&
        typeof sessionID === 'string' &&
        (identity ? requestBindingHash?.length === 64 : activationHash?.length === 64),
      'ANNEX_C_REQUEST_POLICY',
    );
    if (identity) {
      requireThat(typeof issuer.validateIdentityStatus === 'function', 'IDENTITY_ISSUER_POLICY');
      docType = identity.docType;
      namespace = identity.namespace;
      claimPaths = identityClaimPaths(identity, claims);
    }
    const session = annexCRequest({
      origin,
      readerKey: this.privateKey,
      readerCertificate: this.certificate,
      requested: claimPaths
        ? requestedNamespaces(claimPaths)
        : new Map([[namespace, [...new Set(identity ? claims : [...claims, 'issuer', 'status'])]]]),
      activationHash,
      displayText,
      ...(docType ? { docType } : {}),
    });
    const id = b64u(random());
    this.journal.put('annex-c', id, {
      ...session,
      requested: claims,
      namespace,
      privateKey: session.privateKey.export({ type: 'pkcs8', format: 'der' }),
      issuerID,
      sessionID,
      expiresAt: now() + 120,
      status: 'REQUESTED',
      ...(identity
        ? {
            identityIssuerID,
            requestBindingHash,
            claimPaths,
            identityProfileHash: identityProfileHash(identity),
          }
        : {}),
    });
    return { id, request: session.request };
  }
  async response(id, response, { sessionID, origin }) {
    const row = this.journal.get('annex-c', id),
      r = row?.value;
    requireThat(
      r &&
        r.status === 'REQUESTED' &&
        r.sessionID === sessionID &&
        r.origin === origin &&
        r.expiresAt > now(),
      'ANNEX_C_SESSION',
    );
    const issuer = this.issuerRegistry.get(r.issuerID);
    requireThat(issuer, 'ANNEX_C_ISSUER');
    if (r.identityIssuerID)
      requireThat(
        equal(r.identityProfileHash, identityProfileHash(issuer.identityProfile)),
        'IDENTITY_ISSUER_POLICY',
      );
    verifyX5C({ x5c: [issuer.certificate.toString('base64')] }, this.trustRoots, {
      expectedLeaf: issuer.certificate,
    });
    const result = await annexCVerify(
      response,
      {
        ...r,
        requested: r.claimPaths
          ? requestedNamespaces(r.claimPaths)
          : new Map([
              [
                r.namespace,
                [
                  ...new Set(
                    r.identityIssuerID ? r.requested : [...r.requested, 'issuer', 'status'],
                  ),
                ],
              ],
            ]),
        privateKey: createPrivateKey({ key: r.privateKey, format: 'der', type: 'pkcs8' }),
      },
      {
        issuerKey: issuer.publicKey,
        certificate: issuer.certificate,
        certificateProfile: r.identityIssuerID
          ? issuer.identityProfile.certificateProfile
          : issuer.certificateProfile,
      },
    );
    const claims = plain(result.claims.get(r.namespace) ?? new Map());
    const namespaces = r.identityIssuerID
      ? plain(validateIdentityClaims(issuer.identityProfile, result.claims, r.claimPaths))
      : undefined;
    let statusEvidenceHash, statusAssessment;
    if (r.identityIssuerID) {
      const status = await issuer.validateIdentityStatus({
        claims,
        namespaces,
        at: now(),
        certificate: issuer.certificate,
      });
      statusAssessment = assessIdentityStatus(status, issuer.identityProfile, result.mso);
      statusEvidenceHash = H('IdentityStatusAssessment', statusAssessment);
    } else {
      const status = claims.status?.status_list;
      requireThat(
        claims.issuer === r.issuerID && status?.uri === issuer.statusURI,
        'ANNEX_C_ISSUER_STATUS',
      );
      const assessment = verifyStatusList(await issuer.fetchStatus(), {
        publicKey: issuer.publicKey,
        uri: issuer.statusURI,
        index: status.idx,
      });
      requireThat(assessment.overall === 'VALID', assessment.reason);
    }
    const qualification = {
      format: 'mso_mdoc',
      claims,
      holderThumbprint: thumbprint(result.holderJWK),
      activationHash: r.activationHash ?? Buffer.alloc(0),
      evidenceHash: H('AnnexCPresentation', { request: r.request, response, origin }),
      state: 'PRESENTED',
      ...(r.identityIssuerID
        ? {
            issuerID: r.issuerID,
            docType: r.docType,
            namespace: r.namespace,
            namespaces,
            identityProfileHash: r.identityProfileHash,
            requestBindingHash: r.requestBindingHash,
            statusEvidenceHash,
            statusAssessment,
          }
        : {}),
    };
    this.journal.put(
      'annex-c',
      id,
      { ...r, status: 'COMPLETED', result: qualification },
      row.revision,
    );
    return qualification;
  }
  consumeQualification(id, { sessionID, activationHash }) {
    const row = this.journal.get('annex-c', id),
      r = row?.value;
    requireThat(
      r &&
        r.status === 'COMPLETED' &&
        r.sessionID === sessionID &&
        r.expiresAt > now() &&
        equal(r.activationHash, activationHash),
      'QUALIFICATION_BINDING',
    );
    this.journal.put('annex-c', id, { ...r, status: 'CONSUMED' }, row.revision);
    return r.result;
  }
  consumeIdentity(id, { sessionID, requestBindingHash }) {
    const row = this.journal.get('annex-c', id),
      r = row?.value;
    requireThat(
      r?.identityIssuerID &&
        r.status === 'COMPLETED' &&
        r.sessionID === sessionID &&
        r.expiresAt > now() &&
        equal(r.requestBindingHash, requestBindingHash),
      'IDENTITY_PRESENTATION_BINDING',
    );
    requireThat(
      equal(
        r.identityProfileHash,
        identityProfileHash(this.issuerRegistry.get(r.issuerID)?.identityProfile),
      ),
      'IDENTITY_ISSUER_POLICY',
    );
    requireFreshIdentityAssessment(r.result.statusAssessment);
    this.journal.put('annex-c', id, { ...r, status: 'CONSUMED' }, row.revision);
    return r.result;
  }
}
