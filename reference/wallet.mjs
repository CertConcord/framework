import { createPublicKey } from 'node:crypto';
import { b64u, unb64u, random, sha256, now, requireThat, equal } from './core.mjs';
import { requestBytes, endpoint } from './transport.mjs';
import { parseJSON } from './json.mjs';
import {
  publicJWK,
  signJWS,
  verifyJWT,
  verifyJWS,
  dpopProof,
  thumbprint,
  decryptJWE,
} from './jose.mjs';
import { verifyX5C, verifyStatusList, CONFIG_ID, VC_TYPE } from './openid.mjs';
import { verifySDJWT } from './jose.mjs';
import { MDOC_CONFIG, verifyIssuerSigned, NAMESPACE } from './mdoc.mjs';

export class OpenIDWallet {
  constructor({
    issuer,
    clientID,
    clientKey,
    clientAuthentication,
    dpopKey,
    holderKey,
    holderPublicKey,
    holderSigner,
    keyAttestation,
    issuerCertificate,
    issuerRoots,
    mdocDocType,
    mdocNamespace = NAMESPACE,
    mdocCertificateProfile = 'ISO_MDOC',
    verifyCredentialExtension,
    allowLoopback = false,
  }) {
    endpoint(issuer, { allowLoopback });
    requireThat(
      clientKey || typeof clientAuthentication === 'function',
      'WALLET_CLIENT_AUTH_REQUIRED',
    );
    Object.assign(this, {
      issuer,
      clientID,
      clientKey,
      clientAuthentication,
      dpopKey,
      holderKey,
      holderPublicKey: holderPublicKey ?? createPublicKey(holderKey),
      holderSigner,
      keyAttestation,
      issuerCertificate,
      issuerRoots,
      mdocDocType,
      mdocNamespace,
      mdocCertificateProfile,
      verifyCredentialExtension,
      allowLoopback,
    });
  }
  async discover() {
    const u = new URL(this.issuer),
      url = u.origin + '/.well-known/openid-credential-issuer' + u.pathname.replace(/\/$/, '');
    const r = await requestBytes(url, { allowLoopback: this.allowLoopback });
    requireThat(r.status === 200, 'ISSUER_DISCOVERY');
    const metadata = parseJSON(r.body.toString('utf8'));
    requireThat(typeof metadata.signed_metadata === 'string', 'SIGNED_METADATA_REQUIRED');
    const leaf = verifyX5C(
        (await import('./jose.mjs')).decodeJWS(metadata.signed_metadata).header,
        this.issuerRoots,
        { expectedLeaf: this.issuerCertificate },
      ),
      signed = verifyJWT(metadata.signed_metadata, leaf.publicKey, {
        typ: 'openidvci-issuer-metadata+jwt',
        issuer: this.issuer,
        maxAge: 300,
      }).claims;
    requireThat(
      signed.sub === this.issuer && signed.credential_issuer === this.issuer,
      'ISSUER_METADATA_BINDING',
    );
    for (const field of [
      'credential_endpoint',
      'nonce_endpoint',
      'deferred_credential_endpoint',
      'notification_endpoint',
    ]) {
      endpoint(signed[field], { allowLoopback: this.allowLoopback });
      requireThat(new URL(signed[field]).origin === u.origin, 'ISSUER_ENDPOINT_ORIGIN');
    }
    this.metadata = signed;
    this.issuerPublicKey = leaf.publicKey;
    return signed;
  }
  async auth() {
    if (this.clientAuthentication)
      return this.clientAuthentication({ clientID: this.clientID, issuer: this.issuer });
    return {
      parameters: {
        client_id: this.clientID,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: signJWS(
          {
            iss: this.clientID,
            sub: this.clientID,
            aud: this.issuer,
            iat: now(),
            exp: now() + 60,
            jti: b64u(random()),
          },
          this.clientKey,
          { typ: 'JWT' },
        ),
      },
      headers: {},
    };
  }
  async post(path, parameters, { accessToken, authenticate = false, form = false } = {}) {
    const url = this.issuer + path;
    for (let attempt = 0; attempt < 2; attempt++) {
      const auth = authenticate ? await this.auth() : { parameters: {}, headers: {} },
        value = { ...parameters, ...auth.parameters },
        headers = {
          ...auth.headers,
          'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json',
          dpop: dpopProof(this.dpopKey, {
            method: 'POST',
            url,
            accessToken,
            nonce: this.dpopNonce,
          }),
          ...(accessToken ? { authorization: 'DPoP ' + accessToken } : {}),
        };
      const response = await requestBytes(url, {
        method: 'POST',
        headers,
        body: form ? new URLSearchParams(value).toString() : JSON.stringify(value),
        allowLoopback: this.allowLoopback,
      });
      this.dpopNonce = response.headers.get('dpop-nonce') ?? this.dpopNonce;
      const jwt = response.headers.get('content-type')?.split(';')[0] === 'application/jwt',
        body = jwt ? response.body.toString('utf8') : parseJSON(response.body.toString('utf8'));
      if (response.status >= 400) {
        if (body.error === 'use_dpop_nonce' && attempt === 0 && this.dpopNonce) continue;
        throw Error(body.error ?? 'WALLET_HTTP');
      }
      return body;
    }
    throw Error('DPOP_NONCE_RETRY');
  }
  async proof(nonce) {
    const header = {
        alg: 'ES256',
        typ: 'openid4vci-proof+jwt',
        jwk: publicJWK(this.holderPublicKey),
      },
      payload = { iss: this.clientID, aud: this.issuer, iat: now(), nonce };
    if (this.keyAttestation)
      header.key_attestation = await this.keyAttestation({
        nonce,
        holderPublicKey: this.holderPublicKey,
      });
    if (!this.holderSigner) return signJWS(payload, this.holderKey, header);
    const base =
        b64u(Buffer.from(JSON.stringify(header))) +
        '.' +
        b64u(Buffer.from(JSON.stringify(payload))),
      signature = await this.holderSigner(Buffer.from(base)),
      token = base + '.' + b64u(signature);
    verifyJWS(token, this.holderPublicKey, { typ: header.typ });
    return token;
  }
  async receive({ accessToken, configurationID = MDOC_CONFIG, encryptionKey, transactionID }) {
    if (!this.metadata) await this.discover();
    let response;
    if (transactionID)
      response = await this.post('/deferred', { transaction_id: transactionID }, { accessToken });
    else {
      const nonce = await this.post('/nonce', {}),
        params = {
          credential_configuration_id: configurationID,
          proofs: { jwt: [await this.proof(nonce.c_nonce)] },
        };
      if (encryptionKey)
        params.credential_response_encryption = {
          alg: 'ECDH-ES',
          enc: 'A256GCM',
          jwk: publicJWK(createPublicKey(encryptionKey)),
        };
      response = await this.post('/credential', params, { accessToken });
    }
    if (response.transaction_id) return { deferred: true, ...response };
    if (typeof response === 'string') {
      requireThat(encryptionKey, 'CREDENTIAL_DECRYPTION_KEY');
      response = decryptJWE(response, encryptionKey);
    }
    requireThat(response.credentials?.length === 1, 'CREDENTIAL_COUNT');
    const credential = response.credentials[0].credential;
    let claims, holderJWK;
    if (configurationID === MDOC_CONFIG) {
      const verified = verifyIssuerSigned(unb64u(credential), {
        issuerKey: this.issuerPublicKey,
        certificate: this.issuerCertificate,
        allowPartial: false,
        certificateProfile: this.mdocCertificateProfile,
        ...(this.mdocDocType ? { docType: this.mdocDocType } : {}),
      });
      claims = Object.fromEntries(verified.claims.get(this.mdocNamespace));
      holderJWK = verified.holderJWK;
      requireThat(claims.issuer === this.issuer, 'CREDENTIAL_ISSUER');
    } else {
      requireThat(configurationID === CONFIG_ID, 'CREDENTIAL_FORMAT');
      const verified = verifySDJWT(credential, this.issuerPublicKey, {
        issuer: this.issuer,
        vct: VC_TYPE,
      });
      claims = verified.claims;
      holderJWK = verified.holderJWK;
    }
    requireThat(
      thumbprint(holderJWK) === thumbprint(publicJWK(this.holderPublicKey)),
      'CREDENTIAL_HOLDER',
    );
    const rawStatus =
        claims.status instanceof Map ? Object.fromEntries(claims.status) : claims.status,
      status =
        rawStatus?.status_list instanceof Map
          ? Object.fromEntries(rawStatus.status_list)
          : rawStatus?.status_list;
    requireThat(status?.uri === this.issuer + '/status/1', 'CREDENTIAL_STATUS_URI');
    const r = await requestBytes(status.uri, { allowLoopback: this.allowLoopback });
    requireThat(r.status === 200, 'STATUS_LIST_MISSING');
    const assessment = verifyStatusList(r.body.toString('utf8'), {
      publicKey: this.issuerPublicKey,
      uri: status.uri,
      index: status.idx,
    });
    requireThat(assessment.overall === 'VALID', assessment.reason);
    if (this.verifyCredentialExtension)
      await this.verifyCredentialExtension(response.credentials[0]);
    await this.post(
      '/notification',
      { notification_id: response.notification_id, event: 'credential_accepted' },
      { accessToken },
    );
    return {
      credential,
      configurationID,
      issuer: this.issuer,
      holderThumbprint: thumbprint(holderJWK),
      ...(response.credentials[0].certconcord_credential_seal
        ? { certconcordCredentialSeal: response.credentials[0].certconcord_credential_seal }
        : {}),
    };
  }
  async preAuthorized(offer, { txCode, configurationID = MDOC_CONFIG, encryptionKey } = {}) {
    if (!this.metadata) await this.discover();
    requireThat(
      offer.credential_issuer === this.issuer &&
        offer.credential_configuration_ids?.includes(configurationID),
      'CREDENTIAL_OFFER',
    );
    const grant = 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      code = offer.grants?.[grant]?.['pre-authorized_code'];
    requireThat(typeof code === 'string', 'CREDENTIAL_GRANT');
    const token = await this.post(
      '/token',
      { grant_type: grant, 'pre-authorized_code': code, ...(txCode ? { tx_code: txCode } : {}) },
      { authenticate: true, form: true },
    );
    return this.receive({ accessToken: token.access_token, configurationID, encryptionKey });
  }
  async startAuthorization(offer, { redirectURI, configurationID = MDOC_CONFIG }) {
    if (!this.metadata) await this.discover();
    requireThat(
      offer.credential_issuer === this.issuer &&
        offer.credential_configuration_ids?.includes(configurationID) &&
        typeof offer.grants?.authorization_code?.issuer_state === 'string',
      'CREDENTIAL_OFFER',
    );
    const state = b64u(random()),
      codeVerifier = b64u(random()),
      params = {
        client_id: this.clientID,
        response_type: 'code',
        redirect_uri: redirectURI,
        scope: configurationID,
        issuer_state: offer.grants.authorization_code.issuer_state,
        state,
        code_challenge: b64u(sha256(Buffer.from(codeVerifier))),
        code_challenge_method: 'S256',
      };
    const par = await this.post('/par', params, { authenticate: true, form: true });
    return {
      authorizationURL:
        this.issuer +
        '/authorize?' +
        new URLSearchParams({ client_id: this.clientID, request_uri: par.request_uri }),
      state,
      codeVerifier,
      redirectURI,
      configurationID,
      expiresAt: now() + par.expires_in,
    };
  }
  async finishAuthorization(redirect, session, { encryptionKey } = {}) {
    const url = new URL(redirect),
      expected = new URL(session.redirectURI),
      params = url.searchParams;
    requireThat(
      url.origin === expected.origin &&
        url.pathname === expected.pathname &&
        [...params.keys()].length === new Set(params.keys()).size &&
        params.get('state') === session.state &&
        params.get('iss') === this.issuer &&
        params.get('code') &&
        session.expiresAt > now() &&
        !session.consumed,
      'AUTHORIZATION_RESPONSE_BINDING',
    );
    for (const [k, v] of expected.searchParams)
      requireThat(params.get(k) === v, 'AUTHORIZATION_REDIRECT');
    session.consumed = true;
    const token = await this.post(
      '/token',
      {
        grant_type: 'authorization_code',
        code: params.get('code'),
        redirect_uri: session.redirectURI,
        code_verifier: session.codeVerifier,
      },
      { authenticate: true, form: true },
    );
    return this.receive({
      accessToken: token.access_token,
      configurationID: session.configurationID,
      encryptionKey,
    });
  }
}
