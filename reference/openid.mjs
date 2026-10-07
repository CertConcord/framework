import { createPublicKey, createPrivateKey, X509Certificate, randomInt } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { parseJSON } from './json.mjs';
import { assessIdentityStatus, requireFreshIdentityAssessment } from './identity.mjs';
import {
  identityClaimPaths,
  identityProfileHash,
  requestedNamespaces,
  validateIdentityClaims,
} from './identity-profiles.mjs';
import {
  requireThat,
  random,
  b64u,
  unb64u,
  sha256,
  sha512,
  now,
  generate,
  equal,
  D,
  H,
  dcbor,
  parseDER,
  intValue,
} from './core.mjs';
import {
  signJWS,
  verifyJWT,
  verifyJWS,
  decodeJWS,
  publicJWK,
  importPublicJWK,
  thumbprint,
  issueSDJWT,
  verifySDJWT,
  presentSDJWT,
  verifyDPoP,
  encryptJWE,
  decryptJWE,
} from './jose.mjs';
import { parseCertificate } from './pki.mjs';
import {
  MDOC_CONFIG,
  DOCTYPE,
  NAMESPACE,
  issueMdoc,
  issuerCertificate,
  verifyMdoc,
  presentMdoc,
  openidTranscript,
} from './mdoc.mjs';
import { decode as decodeISO, get as isoGet } from './cose.mjs';

export const VC_TYPE = 'https://github.com/CertConcord/framework/credentials/trust-qualification/v1';
export const CONFIG_ID = 'certconcord_trust_qualification';
const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
export function verifyX5C(header, roots, { at = now(), expectedLeaf } = {}) {
  requireThat(
    Array.isArray(header.x5c) && header.x5c.length > 0 && header.x5c.length <= 8,
    'X5C_REQUIRED',
  );
  const chain = header.x5c.map((s) => {
    requireThat(typeof s === 'string' && s.length <= 65536, 'X5C_SIZE');
    return new X509Certificate(Buffer.from(s, 'base64'));
  });
  const constraints = (cert, isCA, caBelow) => {
    const parsed = parseCertificate(cert.raw),
      basic = parsed.extensions.get('2.5.29.19'),
      usage = parsed.extensions.get('2.5.29.15');
    requireThat(basic?.critical && usage?.critical, 'X5C_CONSTRAINTS_REQUIRED');
    const bc = parseDER(basic.value),
      ku = parseDER(usage.value);
    requireThat(
      bc.tag === 0x30 &&
        ku.tag === 3 &&
        ku.value.length >= 2 &&
        (ku.value[1] & (isCA ? 4 : 128)) !== 0 &&
        cert.ca === isCA,
      'X5C_KEY_USAGE',
    );
    if (isCA && bc.children.length === 2)
      requireThat(intValue(bc.children[1]) >= BigInt(caBelow), 'X5C_PATH_LENGTH');
    for (const [id, e] of parsed.extensions)
      requireThat(
        !e.critical || ['2.5.29.19', '2.5.29.15', '2.5.29.37'].includes(id),
        'X5C_UNSUPPORTED_CRITICAL_CONSTRAINT',
      );
    requireThat(at >= parsed.notBefore && at < parsed.notAfter, 'X5C_TIME');
  };
  if (expectedLeaf) requireThat(equal(chain[0].raw, expectedLeaf), 'X5C_PIN');
  requireThat(!chain[0].verify(chain[0].publicKey), 'X5C_SELF_SIGNED_LEAF');
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    constraints(cert, i > 0, Math.max(0, i - 1));
    requireThat(
      at * 1000 >= Date.parse(cert.validFrom) && at * 1000 < Date.parse(cert.validTo),
      'X5C_TIME',
    );
    if (i > 0) requireThat(cert.ca, 'X5C_NOT_CA');
    const issuer =
      chain[i + 1] ?? roots.find((r) => cert.issuer === r.subject && cert.verify(r.publicKey));
    requireThat(
      issuer && cert.issuer === issuer.subject && cert.verify(issuer.publicKey),
      'X5C_TRUST',
    );
    if (i === chain.length - 1) constraints(issuer, true, i);
    if (i === chain.length - 1)
      requireThat(!roots.some((r) => equal(r.raw, cert.raw)), 'X5C_ROOT_INCLUDED');
  }
  return chain[0];
}
export function verifyWalletAttestation(attestation, pop, { roots, clientID, issuer, journal }) {
  const leaf = verifyX5C(decodeJWS(attestation).header, roots),
    a = verifyJWT(attestation, leaf.publicKey, { typ: 'oauth-client-attestation+jwt' }).claims;
  requireThat(
    a.sub === clientID && typeof a.iss === 'string' && a.exp > now() && a.cnf?.jwk,
    'WALLET_ATTESTATION',
  );
  const k = importPublicJWK(a.cnf.jwk),
    p = verifyJWT(pop, k, {
      typ: 'oauth-client-attestation-pop+jwt',
      audience: issuer,
      maxAge: 120,
    }).claims;
  requireThat(
    p.iss === clientID && typeof p.jti === 'string' && !journal.get('wallet-pop', p.jti),
    'WALLET_POP',
  );
  journal.put('wallet-pop', p.jti, { expiresAt: now() + 120 });
  return a;
}
export function verifyKeyAttestation(attestation, { roots, nonce, holderJWK }) {
  const leaf = verifyX5C(decodeJWS(attestation).header, roots),
    a = verifyJWT(attestation, leaf.publicKey, { typ: 'key-attestation+jwt', maxAge: 300 }).claims;
  requireThat(
    a.exp > now() &&
      a.nonce === nonce &&
      Array.isArray(a.attested_keys) &&
      a.attested_keys.length > 0 &&
      a.attested_keys.some((k) => thumbprint(k) === thumbprint(holderJWK)),
    'KEY_ATTESTATION',
  );
  return a;
}

export class StatusList {
  constructor({ journal, uri, privateKey, certificate, size = 16384 }) {
    requireThat(Number.isInteger(size) && size >= 1024 && size <= 1048576, 'STATUS_LIST_SIZE');
    Object.assign(this, { journal, uri, privateKey, certificate, size });
  }
  allocate() {
    return this.journal.transaction(() => {
      const row = this.journal.get('status-list', this.uri),
        state = row?.value ?? { bytes: Buffer.alloc(this.size), used: [] };
      requireThat(state.used.length < this.size * 8, 'STATUS_LIST_FULL');
      // Uniform rank among the remaining indices avoids modulo bias and retry exhaustion.
      let idx = randomInt(this.size * 8 - state.used.length);
      for (const used of [...state.used].sort((a, b) => a - b)) {
        if (used > idx) break;
        idx++;
      }
      state.used.push(idx);
      this.save(state, (row?.revision ?? -1) + 1);
      return { status_list: { idx, uri: this.uri } };
    });
  }
  save(state, revision) {
    this.journal.put('status-list', this.uri, state, revision - 1);
  }
  revoke(idx) {
    this.journal.transaction(() => {
      const r = this.journal.get('status-list', this.uri);
      requireThat(r && r.value.used.includes(idx), 'STATUS_INDEX');
      r.value.bytes[idx >> 3] |= 1 << (idx & 7);
      this.save(r.value, r.revision + 1);
    });
  }
  token() {
    const s = this.journal.get('status-list', this.uri)?.value ?? {
      bytes: Buffer.alloc(this.size),
    };
    return signJWS(
      {
        iss: this.uri,
        sub: this.uri,
        iat: now(),
        exp: now() + 300,
        ttl: 300,
        status_list: { bits: 1, lst: b64u(deflateSync(s.bytes)) },
      },
      this.privateKey,
      { typ: 'statuslist+jwt', x5c: [this.certificate.toString('base64')] },
    );
  }
}
/**
 * @returns {Readonly<{status: 'GOOD'|'REVOKED'|'STALE'|'UNKNOWN',
 * overall: 'VALID'|'INVALID'|'INDETERMINATE', reason?: string}>}
 */
export function verifyStatusList(token, { publicKey, uri, index, at = now() }) {
  requireThat(Number.isSafeInteger(at) && at >= 0, 'STATUS_LIST_TIME');
  if (token === undefined || token === null)
    return Object.freeze({
      status: 'UNKNOWN',
      overall: 'INDETERMINATE',
      reason: 'STATUS_LIST_MISSING',
    });
  // Status freshness is evidence availability, not authorization-token expiry.
  // Authenticate and validate the complete status value before classifying it.
  const c = parseJSON(
    verifyJWS(token, publicKey, { typ: 'statuslist+jwt' }).payload.toString('utf8'),
  );
  requireThat(
    c.iss === uri &&
      c.sub === uri &&
      Number.isSafeInteger(c.iat) &&
      c.iat >= 0 &&
      Number.isSafeInteger(c.exp) &&
      c.exp > c.iat &&
      c.exp - c.iat <= 300 &&
      (c.nbf === undefined || (Number.isSafeInteger(c.nbf) && c.nbf >= 0 && c.nbf < c.exp)) &&
      c.status_list?.bits === 1 &&
      Number.isSafeInteger(index) &&
      index >= 0,
    'STATUS_LIST_CONTEXT',
  );
  const b = inflateSync(unb64u(c.status_list.lst), { maxOutputLength: 1048576 });
  requireThat(index < b.length * 8, 'STATUS_INDEX');
  if (c.iat > at || (c.nbf !== undefined && c.nbf > at))
    return Object.freeze({
      status: 'UNKNOWN',
      overall: 'INDETERMINATE',
      reason: 'STATUS_LIST_NOT_YET_KNOWN',
    });
  if (b[index >> 3] & (1 << (index & 7)))
    return Object.freeze({ status: 'REVOKED', overall: 'INVALID', reason: 'STATUS_LIST_REVOKED' });
  if (c.exp <= at)
    return Object.freeze({
      status: 'STALE',
      overall: 'INDETERMINATE',
      reason: 'STATUS_LIST_STALE',
    });
  return Object.freeze({ status: 'GOOD', overall: 'VALID' });
}

export class CredentialIssuer {
  constructor({
    issuer,
    journal,
    privateKey,
    certificate,
    clients,
    walletRoots = [],
    keyAttestationRoots = [],
    requireKeyAttestation = false,
    enforceDPoPNonce = false,
    authorizeCredential = () => true,
    mintCredential,
    mdocDocType = DOCTYPE,
    mdocNamespace = NAMESPACE,
  }) {
    Object.assign(this, {
      issuer,
      journal,
      privateKey,
      certificate,
      clients,
      walletRoots,
      keyAttestationRoots,
      requireKeyAttestation,
      enforceDPoPNonce,
      authorizeCredential,
      mintCredential,
      mdocDocType,
      mdocNamespace,
    });
    this.status = new StatusList({ journal, uri: issuer + '/status/1', privateKey, certificate });
    for (const name of ['par', 'authorize', 'token', 'credential', 'deferred', 'notification']) {
      const method = this[name].bind(this);
      this[name] = (...args) => journal.transaction(() => method(...args));
    }
  }
  metadata() {
    return {
      credential_issuer: this.issuer,
      authorization_servers: [this.issuer],
      credential_endpoint: this.issuer + '/credential',
      nonce_endpoint: this.issuer + '/nonce',
      deferred_credential_endpoint: this.issuer + '/deferred',
      notification_endpoint: this.issuer + '/notification',
      batch_credential_issuance: { batch_size: 10 },
      credential_response_encryption: {
        alg_values_supported: ['ECDH-ES'],
        enc_values_supported: ['A128GCM', 'A256GCM'],
        encryption_required: false,
      },
      credential_configurations_supported: {
        [MDOC_CONFIG]: {
          format: 'mso_mdoc',
          scope: MDOC_CONFIG,
          doctype: this.mdocDocType,
          cryptographic_binding_methods_supported: ['cose_key'],
          credential_signing_alg_values_supported: [-7],
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ['ES256'],
              ...(this.requireKeyAttestation ? { key_attestations_required: {} } : {}),
            },
          },
        },
        [CONFIG_ID]: {
          format: 'dc+sd-jwt',
          scope: CONFIG_ID,
          vct: VC_TYPE,
          cryptographic_binding_methods_supported: ['jwk'],
          credential_signing_alg_values_supported: ['ES256', 'ML-DSA-65', 'ML-DSA-87'],
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ['ES256', 'Ed25519', 'ML-DSA-65', 'ML-DSA-87'],
              ...(this.requireKeyAttestation ? { key_attestations_required: {} } : {}),
            },
          },
        },
      },
    };
  }
  signedMetadata() {
    return signJWS(
      { ...this.metadata(), iss: this.issuer, sub: this.issuer, iat: now(), exp: now() + 300 },
      this.privateKey,
      { typ: 'openidvci-issuer-metadata+jwt', x5c: [this.certificate.toString('base64')] },
    );
  }
  dpopNonce() {
    const r = this.journal.get('dpop-nonce', this.issuer);
    if (r && r.value.expiresAt > now()) return r.value.nonce;
    const nonce = b64u(random());
    this.journal.put(
      'dpop-nonce',
      this.issuer,
      { nonce, expiresAt: now() + 300 },
      r?.revision ?? -1,
    );
    return nonce;
  }
  requireDPoP(headers) {
    if (this.enforceDPoPNonce) {
      const nonce = this.dpopNonce();
      requireThat(
        headers.dpop && parseJSON(decodeJWS(headers.dpop).payload.toString('utf8')).nonce === nonce,
        'use_dpop_nonce',
      );
    }
  }
  authorizationMetadata() {
    return {
      issuer: this.issuer,
      authorization_endpoint: this.issuer + '/authorize',
      token_endpoint: this.issuer + '/token',
      pushed_authorization_request_endpoint: this.issuer + '/par',
      require_pushed_authorization_requests: true,
      grant_types_supported: ['authorization_code', PRE_AUTH, 'refresh_token'],
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['private_key_jwt', 'attest_jwt_client_auth'],
      dpop_signing_alg_values_supported: ['ES256'],
      authorization_response_iss_parameter_supported: true,
    };
  }
  authenticate(params, headers, url) {
    const client = this.clients.get(params.client_id);
    requireThat(client, 'invalid_client');
    if (headers['oauth-client-attestation']) {
      verifyWalletAttestation(
        headers['oauth-client-attestation'],
        headers['oauth-client-attestation-pop'],
        {
          roots: this.walletRoots,
          clientID: params.client_id,
          issuer: this.issuer,
          journal: this.journal,
        },
      );
    } else {
      requireThat(
        params.client_assertion_type === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'invalid_client',
      );
      const a = verifyJWT(params.client_assertion, client.publicKey, {
        typ: 'JWT',
        audience: this.issuer,
        maxAge: 60,
      }).claims;
      requireThat(
        a.iss === params.client_id &&
          a.sub === params.client_id &&
          a.exp > now() &&
          a.exp <= now() + 120 &&
          typeof a.jti === 'string' &&
          !this.journal.get('client-assertion', a.jti),
        'invalid_client',
      );
      this.journal.put('client-assertion', a.jti, { expiresAt: a.exp });
    }
    return client;
  }
  offer({
    claims,
    subjectID,
    configurationID = MDOC_CONFIG,
    preAuthorized = false,
    txCode,
    expiresIn = 300,
  }) {
    requireThat(
      [CONFIG_ID, MDOC_CONFIG].includes(configurationID),
      'unknown_credential_configuration',
    );
    const id = b64u(random()),
      grant = {
        claims,
        subjectID,
        configurationID,
        grantType: preAuthorized ? PRE_AUTH : 'authorization_code',
        issued: false,
        expiresAt: now() + expiresIn,
        used: false,
        txCodeHash: txCode ? sha256(Buffer.from(txCode)) : Buffer.alloc(0),
      };
    this.journal.put('offers', id, grant);
    return {
      credential_issuer: this.issuer,
      credential_configuration_ids: [configurationID],
      grants: preAuthorized
        ? {
            [PRE_AUTH]: {
              'pre-authorized_code': id,
              ...(txCode ? { tx_code: { input_mode: 'numeric', length: txCode.length } } : {}),
            },
          }
        : { authorization_code: { issuer_state: id, scope: configurationID } },
    };
  }
  par(params, headers = {}) {
    const client = this.authenticate(params, headers, this.issuer + '/par');
    requireThat(
      params.response_type === 'code' &&
        [CONFIG_ID, MDOC_CONFIG].includes(params.scope) &&
        params.code_challenge_method === 'S256' &&
        /^[A-Za-z0-9_-]{43}$/.test(params.code_challenge) &&
        client.redirectURIs.includes(params.redirect_uri) &&
        typeof params.state === 'string' &&
        params.state.length >= 16,
      'invalid_request',
    );
    const requestURI = 'urn:ietf:params:oauth:request_uri:' + b64u(random());
    this.journal.put('par', requestURI, { params, expiresAt: now() + 90, used: false });
    return { request_uri: requestURI, expires_in: 90 };
  }
  authorize({ request_uri, client_id }, { approved, subjectID }) {
    requireThat(approved === true, 'access_denied');
    const row = this.journal.get('par', request_uri),
      p = row?.value.params;
    requireThat(
      row && !row.value.used && row.value.expiresAt > now() && p.client_id === client_id,
      'invalid_request_uri',
    );
    const offer = this.journal.get('offers', p.issuer_state);
    requireThat(
      offer &&
        !offer.value.used &&
        offer.value.expiresAt > now() &&
        offer.value.subjectID === subjectID &&
        offer.value.grantType === 'authorization_code' &&
        offer.value.configurationID === p.scope,
      'invalid_grant',
    );
    this.journal.put('offers', p.issuer_state, { ...offer.value, used: true }, offer.revision);
    this.journal.put('par', request_uri, { ...row.value, used: true }, row.revision);
    const code = b64u(random());
    this.journal.put('codes', code, {
      params: p,
      offerID: p.issuer_state,
      expiresAt: now() + 60,
      used: false,
    });
    return { redirect_uri: p.redirect_uri, code, state: p.state, iss: this.issuer };
  }
  token(params, headers = {}) {
    this.requireDPoP(headers);
    this.authenticate(params, headers, this.issuer + '/token');
    const jkt = verifyDPoP(headers.dpop, {
      method: 'POST',
      url: this.issuer + '/token',
      journal: this.journal,
    });
    let offerID, grantRow, namespace, id;
    if (params.grant_type === 'authorization_code') {
      namespace = 'codes';
      id = params.code;
      grantRow = this.journal.get(namespace, id);
      const p = grantRow?.value.params;
      requireThat(
        p &&
          p.client_id === params.client_id &&
          p.redirect_uri === params.redirect_uri &&
          /^[A-Za-z0-9._~-]{43,128}$/.test(params.code_verifier) &&
          p.code_challenge === b64u(sha256(Buffer.from(params.code_verifier))),
        'invalid_grant',
      );
      offerID = grantRow.value.offerID;
    } else if (params.grant_type === PRE_AUTH) {
      namespace = 'offers';
      id = params['pre-authorized_code'];
      grantRow = this.journal.get(namespace, id);
      requireThat(
        grantRow &&
          grantRow.value.grantType === PRE_AUTH &&
          (!grantRow.value.txCodeHash.length ||
            equal(grantRow.value.txCodeHash, sha256(Buffer.from(params.tx_code ?? '')))),
        'invalid_grant',
      );
      offerID = id;
    } else if (params.grant_type === 'refresh_token') {
      namespace = 'refresh';
      id = b64u(sha256(Buffer.from(params.refresh_token ?? '')));
      grantRow = this.journal.get(namespace, id);
      requireThat(
        grantRow && grantRow.value.clientID === params.client_id && grantRow.value.jkt === jkt,
        'invalid_grant',
      );
      offerID = grantRow.value.offerID;
    } else throw Error('unsupported_grant_type');
    requireThat(
      grantRow && !grantRow.value.used && grantRow.value.expiresAt > now(),
      'invalid_grant',
    );
    this.journal.put(namespace, id, { ...grantRow.value, used: true }, grantRow.revision);
    const accessToken = b64u(random()),
      refreshToken = b64u(random());
    this.journal.put('access', b64u(sha256(Buffer.from(accessToken))), {
      offerID,
      clientID: params.client_id,
      jkt,
      expiresAt: now() + 300,
    });
    this.journal.put('refresh', b64u(sha256(Buffer.from(refreshToken))), {
      offerID,
      clientID: params.client_id,
      jkt,
      expiresAt: now() + 86400,
      used: false,
    });
    return {
      access_token: accessToken,
      token_type: 'DPoP',
      expires_in: 300,
      refresh_token: refreshToken,
      scope: this.journal.get('offers', offerID).value.configurationID,
    };
  }
  nonce() {
    return { c_nonce: this.journal.issueNonce('oid4vci', 120) };
  }
  access(headers, url) {
    this.requireDPoP(headers);
    const a = headers.authorization?.match(/^DPoP ([A-Za-z0-9_-]+)$/);
    requireThat(a, 'invalid_token');
    const r = this.journal.get('access', b64u(sha256(Buffer.from(a[1]))));
    requireThat(r && r.value.expiresAt > now(), 'invalid_token');
    verifyDPoP(headers.dpop, {
      method: 'POST',
      url,
      accessToken: a[1],
      expectedThumbprint: r.value.jkt,
      journal: this.journal,
    });
    return r.value;
  }
  credential(params, headers = {}, { defer = false } = {}) {
    const access = this.access(headers, this.issuer + '/credential');
    requireThat(
      [CONFIG_ID, MDOC_CONFIG].includes(params.credential_configuration_id) &&
        !params.credential_identifier,
      'unknown_credential_configuration',
    );
    const proofs = params.proofs;
    requireThat(
      proofs &&
        Object.keys(proofs).length === 1 &&
        Array.isArray(proofs.jwt) &&
        proofs.jwt.length >= 1 &&
        proofs.jwt.length <= 10,
      'invalid_proof',
    );
    const holderKeys = proofs.jwt.map((token) => {
      const h = decodeJWS(token).header,
        k = importPublicJWK(h.jwk),
        p = verifyJWT(token, k, {
          typ: 'openid4vci-proof+jwt',
          audience: this.issuer,
          maxAge: 120,
        }).claims;
      requireThat(!p.iss || p.iss === access.clientID, 'invalid_proof');
      requireThat(typeof p.nonce === 'string', 'invalid_nonce');
      if (this.requireKeyAttestation || h.key_attestation)
        verifyKeyAttestation(h.key_attestation, {
          roots: this.keyAttestationRoots,
          nonce: p.nonce,
          holderJWK: h.jwk,
        });
      if (params.credential_configuration_id === MDOC_CONFIG)
        requireThat(
          h.jwk.kty === 'EC' && h.jwk.crv === 'P-256' && h.alg === 'ES256',
          'invalid_proof',
        );
      return { jwk: h.jwk, nonce: p.nonce };
    });
    for (const nonce of new Set(holderKeys.map((k) => k.nonce)))
      this.journal.consumeNonce('oid4vci', nonce);
    const offer = this.journal.get('offers', access.offerID);
    requireThat(
      offer &&
        !offer.value.issued &&
        offer.value.configurationID === params.credential_configuration_id,
      'invalid_credential_request',
    );
    this.journal.put('offers', access.offerID, { ...offer.value, issued: true }, offer.revision);
    const credentials = holderKeys.map((k) => {
      requireThat(
        this.authorizeCredential({ offer: offer.value, holderJWK: k.jwk, access }) === true,
        'credential_request_denied',
      );
      const status = this.status.allocate();
      if (this.mintCredential)
        return this.mintCredential({
          offer: offer.value,
          holderJWK: k.jwk,
          status,
          configurationID: params.credential_configuration_id,
        });
      return {
        credential:
          params.credential_configuration_id === MDOC_CONFIG
            ? b64u(
                issueMdoc({
                  claims: { ...offer.value.claims, issuer: this.issuer, status },
                  holderJWK: k.jwk,
                  privateKey: this.privateKey,
                  certificate: this.certificate,
                  docType: this.mdocDocType,
                  namespace: this.mdocNamespace,
                }),
              )
            : issueSDJWT(
                {
                  claims: offer.value.claims,
                  issuer: this.issuer,
                  holderJWK: k.jwk,
                  vct: VC_TYPE,
                  status,
                },
                this.privateKey,
                { x5c: [this.certificate.toString('base64')] },
              ).credential,
      };
    });
    if (params.credential_response_encryption) {
      const e = params.credential_response_encryption;
      requireThat(
        e.alg === 'ECDH-ES' &&
          ['A128GCM', 'A256GCM'].includes(e.enc) &&
          !e.zip &&
          e.jwk?.kty === 'EC' &&
          e.jwk.crv === 'P-256' &&
          !e.jwk.d,
        'encryption_parameters_not_supported',
      );
    }
    const notification_id = b64u(random());
    this.journal.put('notifications', notification_id, {
      clientID: access.clientID,
      offerID: access.offerID,
      received: false,
    });
    const response = { credentials, notification_id };
    if (defer) {
      const transaction_id = b64u(random());
      this.journal.put('deferred', transaction_id, {
        response,
        clientID: access.clientID,
        offerID: access.offerID,
        encryption: params.credential_response_encryption ?? null,
        expiresAt: now() + 300,
        used: false,
      });
      return { transaction_id, interval: 1 };
    }
    if (params.credential_response_encryption) {
      const e = params.credential_response_encryption;
      requireThat(!e.zip, 'encryption_parameters_not_supported');
      return encryptJWE(response, e.jwk, { enc: e.enc, kid: e.jwk.kid });
    }
    return response;
  }
  deferred(params, headers) {
    const a = this.access(headers, this.issuer + '/deferred'),
      row = this.journal.get('deferred', params.transaction_id);
    requireThat(
      row &&
        !row.value.used &&
        row.value.expiresAt > now() &&
        row.value.clientID === a.clientID &&
        row.value.offerID === a.offerID,
      'invalid_transaction_id',
    );
    this.journal.put('deferred', params.transaction_id, { ...row.value, used: true }, row.revision);
    return row.value.encryption
      ? encryptJWE(row.value.response, row.value.encryption.jwk, {
          enc: row.value.encryption.enc,
          kid: row.value.encryption.jwk.kid,
        })
      : row.value.response;
  }
  notification(params, headers) {
    const a = this.access(headers, this.issuer + '/notification'),
      r = this.journal.get('notifications', params.notification_id);
    requireThat(
      r &&
        r.value.clientID === a.clientID &&
        r.value.offerID === a.offerID &&
        (!r.value.received || r.value.event === params.event) &&
        ['credential_accepted', 'credential_failure', 'credential_deleted'].includes(params.event),
      'invalid_notification_id',
    );
    this.journal.put(
      'notifications',
      params.notification_id,
      { ...r.value, received: true, event: params.event },
      r.revision,
    );
    return {};
  }
}

export class PresentationVerifier {
  constructor({ baseURL, journal, privateKey, certificate, issuerRegistry, trustRoots }) {
    Object.assign(this, { baseURL, journal, privateKey, certificate, issuerRegistry, trustRoots });
    this.clientID = 'x509_hash:' + b64u(sha256(certificate));
  }
  signedRequest(id) {
    const r = this.journal.get('vp', id);
    requireThat(r?.value.status === 'REQUESTED' && r.value.request.exp > now(), 'VP_STATE');
    return signJWS(r.value.request, this.privateKey, {
      typ: 'oauth-authz-req+jwt',
      x5c: [this.certificate.toString('base64')],
    });
  }
  request({
    sessionID,
    claims = ['qualification'],
    activationHash,
    format = 'mso_mdoc',
    displayText = '',
    mode = 'direct_post.jwt',
    origin,
    aki = [],
    identityIssuerID,
    requestBindingHash,
    docType = DOCTYPE,
    namespace = NAMESPACE,
  }) {
    const identityIssuer = identityIssuerID && this.issuerRegistry.get(identityIssuerID);
    let claimPaths;
    if (identityIssuerID) {
      requireThat(
        format === 'mso_mdoc' &&
          identityIssuer?.identityProfile &&
          typeof identityIssuer.validateIdentityStatus === 'function' &&
          requestBindingHash?.length === 64,
        'IDENTITY_ISSUER_POLICY',
      );
      docType = identityIssuer.identityProfile.docType;
      namespace = identityIssuer.identityProfile.namespace;
      claimPaths = identityClaimPaths(identityIssuer.identityProfile, claims);
    }
    requireThat(
      sessionID && ['direct_post.jwt', 'dc_api.jwt'].includes(mode),
      'VP_SESSION_OR_MODE',
    );
    const id = b64u(random()),
      nonce = b64u(random()),
      state = b64u(random()),
      encryption = generate('ec'),
      kid = b64u(random(16));
    const request = {
      client_id: this.clientID,
      response_type: 'vp_token',
      response_mode: mode,
      nonce,
      state,
      dcql_query: {
        credentials: [
          {
            id: 'qualification',
            format,
            meta: format === 'mso_mdoc' ? { doctype_value: docType } : { vct_values: [VC_TYPE] },
            claims: claimPaths
              ? claimPaths.map((path, i) => ({ id: 'c' + i, path }))
              : [
                  ...new Set(
                    format === 'mso_mdoc' && !identityIssuerID
                      ? [...claims, 'issuer', 'status']
                      : claims,
                  ),
                ].map((name, i) => ({
                  id: 'c' + i,
                  path: format === 'mso_mdoc' ? [namespace, name] : [name],
                })),
            ...(aki.length ? { trusted_authorities: [{ type: 'aki', values: aki }] } : {}),
          },
        ],
      },
      client_metadata: {
        jwks: { keys: [{ ...publicJWK(encryption.publicKey), kid, alg: 'ECDH-ES', use: 'enc' }] },
        encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
        vp_formats_supported: {
          mso_mdoc: { issuerauth_alg_values: [-7], deviceauth_alg_values: [-7] },
          'dc+sd-jwt': {
            'sd-jwt_alg_values': ['ES256', 'ML-DSA-65', 'ML-DSA-87'],
            'kb-jwt_alg_values': ['ES256', 'Ed25519', 'ML-DSA-65', 'ML-DSA-87'],
          },
        },
      },
      ...(mode === 'direct_post.jwt'
        ? { response_uri: this.baseURL + '/response/' + id }
        : { expected_origins: [origin] }),
      iat: now(),
      exp: now() + 120,
    };
    if (mode === 'dc_api.jwt') delete request.state;
    requireThat(['mso_mdoc', 'dc+sd-jwt'].includes(format), 'VP_FORMAT');
    if (activationHash) {
      requireThat(activationHash.length === 64, 'ACTIVATION_HASH');
      request.transaction_data = [
        b64u(
          Buffer.from(
            JSON.stringify({
              type: 'urn:certconcord:activation:1',
              credential_ids: ['qualification'],
              activation_hash: b64u(activationHash),
              display_text: displayText,
            }),
          ),
        ),
      ];
    }
    const signed = signJWS(request, this.privateKey, {
      typ: 'oauth-authz-req+jwt',
      x5c: [this.certificate.toString('base64')],
    });
    this.journal.put('vp', id, {
      request,
      sessionID,
      activationHash: activationHash ?? Buffer.alloc(0),
      privateKey: encryption.privateKey.export({ format: 'der', type: 'pkcs8' }),
      kid,
      status: 'REQUESTED',
      origin: origin ?? '',
      ...(identityIssuerID
        ? {
            identityIssuerID,
            requestBindingHash,
            identityProfileHash: identityProfileHash(identityIssuer.identityProfile),
          }
        : {}),
    });
    return {
      id,
      request,
      signed,
      uri:
        'haip-vp://?' +
        new URLSearchParams({
          client_id: this.clientID,
          request_uri: this.baseURL + '/request/' + id,
        }),
      request_uri: this.baseURL + '/request/' + id,
    };
  }
  async response(id, jwe, { sessionID, mode = 'direct_post.jwt' } = {}) {
    const row = this.journal.get('vp', id),
      r = row?.value;
    requireThat(
      r && r.status === 'REQUESTED' && r.request.exp > now() && r.request.response_mode === mode,
      'VP_STATE',
    );
    if (mode === 'dc_api.jwt') requireThat(r.sessionID === sessionID, 'VP_SESSION');
    const decoded = decryptJWE(
      jwe,
      createPrivateKey({ key: r.privateKey, type: 'pkcs8', format: 'der' }),
      { kid: r.kid },
    );
    requireThat(
      decoded.state === r.request.state &&
        decoded.vp_token &&
        Object.keys(decoded.vp_token).length === 1 &&
        decoded.vp_token.qualification?.length === 1,
      'VP_RESPONSE',
    );
    const token = decoded.vp_token.qualification[0],
      query = r.request.dcql_query.credentials[0];
    let credential, issuer, statusEvidenceHash, statusAssessment;
    if (query.format === 'mso_mdoc') {
      const bytes = unb64u(token),
        doc = isoGet(decodeISO(bytes), 'documents')[0],
        certificate = issuerCertificate(isoGet(doc, 'issuerSigned'));
      issuer = r.identityIssuerID
        ? this.issuerRegistry.get(r.identityIssuerID)
        : [...this.issuerRegistry.values()].find((i) => equal(i.certificate, certificate));
      requireThat(issuer && equal(issuer.certificate, certificate), 'UNTRUSTED_ISSUER');
      if (r.identityIssuerID)
        requireThat(
          this.issuerRegistry.get(r.identityIssuerID) === issuer &&
            query.meta.doctype_value === issuer.identityProfile.docType &&
            equal(r.identityProfileHash, identityProfileHash(issuer.identityProfile)),
          'IDENTITY_ISSUER_POLICY',
        );
      verifyX5C({ x5c: [certificate.toString('base64')] }, this.trustRoots, {
        expectedLeaf: issuer.certificate,
      });
      const recipient = r.request.client_metadata.jwks.keys[0],
        sessionTranscript = openidTranscript({
          clientID: this.clientID,
          nonce: r.request.nonce,
          responseURI: r.request.response_uri,
          origin: mode === 'dc_api.jwt' ? r.origin : undefined,
          encryptionJWK: recipient,
        });
      const expectedDeviceClaims = r.activationHash.length
        ? new Map([[NAMESPACE, new Map([['activation_hash', r.activationHash]])]])
        : new Map();
      const v = verifyMdoc(bytes, {
        issuerKey: issuer.publicKey,
        certificate,
        sessionTranscript,
        requested: requestedNamespaces(query.claims.map((c) => c.path)),
        docType: query.meta.doctype_value,
        certificateProfile: r.identityIssuerID
          ? issuer.identityProfile.certificateProfile
          : issuer.certificateProfile,
        expectedDeviceClaims,
      });
      credential = {
        mso: v.mso,
        claims: isoPlain(
          v.claims.get(
            r.identityIssuerID ? issuer.identityProfile.namespace : query.claims[0].path[0],
          ) ?? new Map(),
        ),
        namespaces: r.identityIssuerID
          ? isoPlain(
              validateIdentityClaims(
                issuer.identityProfile,
                v.claims,
                query.claims.map((c) => c.path),
              ),
            )
          : undefined,
        holderJWK: v.holderJWK,
      };
      if (!r.identityIssuerID)
        requireThat(this.issuerRegistry.get(credential.claims.issuer) === issuer, 'MDOC_ISSUER_ID');
    } else {
      const issuerJWT = token.split('~')[0],
        untrusted = parseJSON(decodeJWS(issuerJWT).payload.toString('utf8'));
      issuer = this.issuerRegistry.get(untrusted.iss);
      requireThat(issuer, 'UNTRUSTED_ISSUER');
      verifyX5C(decodeJWS(issuerJWT).header, this.trustRoots, { expectedLeaf: issuer.certificate });
      credential = verifySDJWT(token, issuer.publicKey, {
        issuer: untrusted.iss,
        vct: VC_TYPE,
        requireKeyBinding: true,
        audience: mode === 'dc_api.jwt' ? 'origin:' + r.origin : this.clientID,
        nonce: r.request.nonce,
        transactionData: r.request.transaction_data,
      });
      for (const c of query.claims)
        requireThat(Object.hasOwn(credential.claims, c.path[0]), 'DCQL_CLAIM_MISSING');
    }
    if (query.trusted_authorities)
      requireThat(
        query.trusted_authorities.some(
          (a) =>
            a.type === 'aki' && a.values.some((v) => issuer.authorityKeyIdentifiers?.includes(v)),
        ),
        'DCQL_TRUSTED_AUTHORITY',
      );
    if (r.identityIssuerID) {
      const status = await issuer.validateIdentityStatus({
        claims: credential.claims,
        namespaces: credential.namespaces,
        at: now(),
        certificate: issuer.certificate,
      });
      statusAssessment = assessIdentityStatus(status, issuer.identityProfile, credential.mso);
      statusEvidenceHash = H('IdentityStatusAssessment', statusAssessment);
    } else {
      const status = credential.claims.status?.status_list;
      requireThat(status && status.uri === issuer.statusURI, 'CREDENTIAL_STATUS');
      const statusToken = await issuer.fetchStatus();
      verifyX5C(decodeJWS(statusToken).header, this.trustRoots, {
        expectedLeaf: issuer.certificate,
      });
      const assessment = verifyStatusList(statusToken, {
        publicKey: issuer.publicKey,
        uri: status.uri,
        index: status.idx,
      });
      requireThat(assessment.overall === 'VALID', assessment.reason);
    }
    const responseCode = b64u(random()),
      result = {
        format: query.format,
        claims: credential.claims,
        holderThumbprint: thumbprint(credential.holderJWK),
        activationHash: r.activationHash,
        evidenceHash: sha512(Buffer.from(token)),
        state: 'PRESENTED',
        ...(r.identityIssuerID
          ? {
              issuerID: r.identityIssuerID,
              docType: query.meta.doctype_value,
              namespace: issuer.identityProfile.namespace,
              namespaces: credential.namespaces,
              identityProfileHash: r.identityProfileHash,
              statusEvidenceHash,
              statusAssessment,
              requestBindingHash: r.requestBindingHash,
            }
          : {}),
      };
    this.journal.put(
      'vp',
      id,
      {
        ...r,
        status: mode === 'dc_api.jwt' ? 'COMPLETED' : 'AWAITING_REDIRECT',
        responseCode,
        result,
      },
      row.revision,
    );
    return { redirect_uri: this.baseURL + '/complete/' + id + '?response_code=' + responseCode };
  }
  complete(id, { sessionID, responseCode }) {
    const row = this.journal.get('vp', id),
      r = row?.value;
    requireThat(
      r &&
        r.status === 'AWAITING_REDIRECT' &&
        r.sessionID === sessionID &&
        r.responseCode === responseCode &&
        r.request.exp > now(),
      'VP_SESSION_BINDING',
    );
    this.journal.put('vp', id, { ...r, status: 'COMPLETED' }, row.revision);
    return r.result;
  }
  consumeQualification(id, { sessionID, activationHash }) {
    const row = this.journal.get('vp', id),
      r = row?.value;
    requireThat(
      r &&
        r.status === 'COMPLETED' &&
        r.sessionID === sessionID &&
        r.request.exp > now() &&
        equal(r.activationHash, activationHash),
      'QUALIFICATION_BINDING',
    );
    this.journal.put('vp', id, { ...r, status: 'CONSUMED' }, row.revision);
    return r.result;
  }
  consumeIdentity(id, { sessionID, requestBindingHash }) {
    const row = this.journal.get('vp', id),
      r = row?.value;
    requireThat(
      r?.identityIssuerID &&
        r.status === 'COMPLETED' &&
        r.sessionID === sessionID &&
        r.request.exp > now() &&
        equal(r.requestBindingHash, requestBindingHash),
      'IDENTITY_PRESENTATION_BINDING',
    );
    requireThat(
      equal(
        r.identityProfileHash,
        identityProfileHash(this.issuerRegistry.get(r.identityIssuerID)?.identityProfile),
      ),
      'IDENTITY_ISSUER_POLICY',
    );
    requireFreshIdentityAssessment(r.result.statusAssessment);
    this.journal.put('vp', id, { ...r, status: 'CONSUMED' }, row.revision);
    return r.result;
  }
}
export function walletPresentation(
  signedRequest,
  { credential, holderKey, verifierRoots, expectedResponseOrigin, origin, approveTransaction },
) {
  const r = parseVPRequest(signedRequest, { verifierRoots, expectedResponseOrigin, origin });
  const queries = r.dcql_query?.credentials;
  requireThat(
    queries?.length === 1 &&
      queries[0].format === 'dc+sd-jwt' &&
      Array.isArray(queries[0].meta?.vct_values) &&
      queries[0].meta.vct_values.some((value) => value === VC_TYPE),
    'DCQL_QUERY',
  );
  const q = queries[0];
  requireThat(
    q.claims?.every((c) => c.path.length === 1 && typeof c.path[0] === 'string'),
    'DCQL_CLAIM_PATH',
  );
  const keys = r.client_metadata?.jwks?.keys,
    recipient = keys?.find((k) => k.alg === 'ECDH-ES' && k.use === 'enc' && k.crv === 'P-256');
  requireThat(recipient && recipient.kid, 'VP_ENCRYPTION_KEY');
  if (r.transaction_data) {
    requireThat(typeof approveTransaction === 'function', 'TRANSACTION_CONSENT_REQUIRED');
    for (const encoded of r.transaction_data) {
      const t = parseJSON(unb64u(encoded).toString('utf8'));
      requireThat(
        t.type === 'urn:certconcord:activation:1' &&
          t.credential_ids?.includes(q.id) &&
          (!t.transaction_data_hashes_alg || t.transaction_data_hashes_alg.includes('sha-256')) &&
          approveTransaction(t) === true,
        'TRANSACTION_DECLINED',
      );
    }
  }
  const vp = presentSDJWT(credential, holderKey, {
    audience: r.response_mode === 'dc_api.jwt' ? 'origin:' + origin : r.client_id,
    nonce: r.nonce,
    claimNames: q.claims.map((c) => c.path[0]),
    transactionData: r.transaction_data,
  });
  const enc = r.client_metadata.encrypted_response_enc_values_supported.includes('A256GCM')
    ? 'A256GCM'
    : 'A128GCM';
  return {
    response: encryptJWE({ state: r.state, vp_token: { [q.id]: [vp] } }, recipient, {
      enc,
      kid: recipient.kid,
    }),
    responseURI: r.response_uri,
  };
}

function isoPlain(v) {
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, isoPlain(x)]));
  if (Array.isArray(v)) return v.map(isoPlain);
  return v;
}

export async function walletMdocPresentation(
  signedRequest,
  {
    credential,
    holderKey,
    signer,
    verifierRoots,
    expectedResponseOrigin,
    origin,
    approveTransaction,
    docType = DOCTYPE,
    namespace = NAMESPACE,
    namespaces = [namespace],
  },
) {
  const r = parseVPRequest(signedRequest, { verifierRoots, expectedResponseOrigin, origin });
  const q = r.dcql_query?.credentials?.[0];
  requireThat(
    r.dcql_query.credentials.length === 1 &&
      q.format === 'mso_mdoc' &&
      q.meta.doctype_value === docType &&
      q.claims.every((c) => c.path.length === 2 && namespaces.includes(c.path[0])),
    'DCQL_QUERY',
  );
  const recipient = r.client_metadata.jwks.keys.find(
    (k) => k.alg === 'ECDH-ES' && k.use === 'enc' && k.crv === 'P-256',
  );
  requireThat(recipient?.kid, 'VP_ENCRYPTION_KEY');
  if (q.trusted_authorities) {
    const cert = parseCertificate(issuerCertificate(unb64u(credential))),
      ext = cert.extensions.get('2.5.29.35'),
      aki = ext && parseDER(ext.value).children.find((n) => n.tag === 0x80)?.value;
    requireThat(
      aki && q.trusted_authorities.some((a) => a.type === 'aki' && a.values.includes(b64u(aki))),
      'DCQL_TRUSTED_AUTHORITY',
    );
  }
  const deviceClaims = new Map();
  if (r.transaction_data) {
    requireThat(
      r.transaction_data.length === 1 && typeof approveTransaction === 'function',
      'TRANSACTION_CONSENT_REQUIRED',
    );
    const t = parseJSON(unb64u(r.transaction_data[0]).toString('utf8'));
    requireThat(
      t.type === 'urn:certconcord:activation:1' &&
        t.credential_ids?.length === 1 &&
        t.credential_ids[0] === q.id &&
        unb64u(t.activation_hash).length === 64,
      'TRANSACTION_DATA',
    );
    requireThat(await approveTransaction(t), 'TRANSACTION_DECLINED');
    deviceClaims.set(NAMESPACE, new Map([['activation_hash', unb64u(t.activation_hash)]]));
  }
  const sessionTranscript = openidTranscript({
    clientID: r.client_id,
    nonce: r.nonce,
    responseURI: r.response_uri,
    origin: r.response_mode === 'dc_api.jwt' ? origin : undefined,
    encryptionJWK: recipient,
  });
  const vp = await presentMdoc(unb64u(credential), {
    holderKey,
    signer,
    sessionTranscript,
    requested: requestedNamespaces(q.claims.map((c) => c.path)),
    docType,
    deviceClaims,
  });
  return {
    response: encryptJWE({ state: r.state, vp_token: { [q.id]: [b64u(vp)] } }, recipient, {
      enc: r.client_metadata.encrypted_response_enc_values_supported.includes('A256GCM')
        ? 'A256GCM'
        : 'A128GCM',
      kid: recipient.kid,
    }),
    responseURI: r.response_uri,
  };
}

export function parseVPRequest(input, { verifierRoots, expectedResponseOrigin, origin }) {
  let r,
    signed = true;
  if (typeof input === 'string') {
    const leaf = verifyX5C(decodeJWS(input).header, verifierRoots);
    r = verifyJWT(input, leaf.publicKey, { typ: 'oauth-authz-req+jwt', maxAge: 120 }).claims;
    requireThat(r.client_id === 'x509_hash:' + b64u(sha256(leaf.raw)), 'VP_CLIENT_ID');
  } else if (input?.protocol === 'openid4vp-v1-signed')
    return parseVPRequest(input.data.request, { verifierRoots, expectedResponseOrigin, origin });
  else if (input?.protocol === 'openid4vp-v1-unsigned') {
    signed = false;
    requireThat(
      origin && new URL(origin).origin === origin && origin.startsWith('https://'),
      'VP_DC_ORIGIN',
    );
    const allowed = [
      'response_type',
      'response_mode',
      'nonce',
      'client_metadata',
      'dcql_query',
      'transaction_data',
    ];
    r = Object.fromEntries(
      allowed.filter((k) => Object.hasOwn(input.data, k)).map((k) => [k, input.data[k]]),
    );
    r.exp = now() + 120;
  } else if (input?.protocol === 'openid4vp-v1-multisigned') {
    const jws = input.data.request;
    requireThat(
      jws &&
        Array.isArray(jws.signatures) &&
        jws.signatures.length >= 1 &&
        jws.signatures.length <= 8,
      'VP_MULTISIGNATURE',
    );
    const payload = parseJSON(unb64u(jws.payload).toString('utf8'));
    requireThat(
      !Object.hasOwn(payload, 'client_id') && !Object.hasOwn(payload, 'verifier_info'),
      'VP_MULTISIGNATURE_PARAMETERS',
    );
    for (const sig of jws.signatures) {
      try {
        requireThat(!sig.header, 'VP_UNPROTECTED_HEADER');
        const token = sig.protected + '.' + jws.payload + '.' + sig.signature,
          header = decodeJWS(token).header,
          leaf = verifyX5C(header, verifierRoots);
        requireThat(header.client_id === 'x509_hash:' + b64u(sha256(leaf.raw)), 'VP_CLIENT_ID');
        r = {
          ...verifyJWT(token, leaf.publicKey, { typ: 'oauth-authz-req+jwt', maxAge: 120 }).claims,
          client_id: header.client_id,
        };
        break;
      } catch {}
    }
    requireThat(r, 'VP_NO_TRUSTED_SIGNATURE');
  } else throw Error('VP_REQUEST_PROTOCOL');
  requireThat(
    r.exp > now() &&
      r.response_type === 'vp_token' &&
      typeof r.nonce === 'string' &&
      r.nonce.length >= 16 &&
      ['direct_post.jwt', 'dc_api.jwt'].includes(r.response_mode),
    'VP_REQUEST',
  );
  if (r.response_mode === 'direct_post.jwt')
    requireThat(
      typeof input === 'string' && new URL(r.response_uri).origin === expectedResponseOrigin,
      'VP_RESPONSE_ORIGIN',
    );
  else requireThat(origin && (!signed || r.expected_origins?.includes(origin)), 'VP_DC_ORIGIN');
  return r;
}
