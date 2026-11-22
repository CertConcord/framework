import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { Readable } from 'node:stream';
import { now } from './core.mjs';
import { createProtocolHandler } from './http.mjs';
import { signJWS } from './jose.mjs';
import { CredentialIssuer } from './openid.mjs';

const issuerURL = 'https://issuer.example';
const clientID = 'https://wallet.example';
const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

function makeRequest(handler, endpoint, assertion) {
  const body = Buffer.from(
    new URLSearchParams({
      client_id: clientID,
      client_assertion_type: assertionType,
      client_assertion: assertion,
    }).toString(),
  );
  const req = Readable.from([body]);
  req.method = 'POST';
  req.url = '/' + endpoint;
  req.headers = { 'content-type': 'application/x-www-form-urlencoded' };
  const res = {
    writeHead(status) { this.status = status; },
    end(bytes) { this.body = JSON.parse(Buffer.from(bytes).toString('utf8')); },
  };
  return handler(req, res).then(() => res);
}

for (const endpoint of ['token', 'par']) {
  test('RFC 10070 issuer-only client assertion at /' + endpoint, async () => {
    const clientKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const issuer = {
      issuer: issuerURL,
      clients: new Map([[clientID, { publicKey: clientKey.publicKey }]]),
      journal: { get: () => undefined, put: () => undefined },
      token(params, headers) {
        CredentialIssuer.prototype.authenticate.call(this, params, headers, issuerURL + '/token');
        return { access_token: 'synthetic' };
      },
      par(params, headers) {
        CredentialIssuer.prototype.authenticate.call(this, params, headers, issuerURL + '/par');
        return { request_uri: 'urn:synthetic' };
      },
    };
    const handler = createProtocolHandler({ issuer });
    const assertion = (aud, typ, jti) => signJWS(
      { iss: clientID, sub: clientID, aud, iat: now(), exp: now() + 60, jti },
      clientKey.privateKey,
      typ === undefined ? {} : { typ },
    );

    for (const [name, typ] of [
      ['recommended', 'client-authentication+jwt'],
      ['legacy', 'JWT'],
      ['absent', undefined],
    ]) {
      const response = await makeRequest(handler, endpoint, assertion(issuerURL, typ, name));
      assert.equal(response.status, endpoint === 'par' ? 201 : 200, name);
    }

    for (const [name, aud, typ, causeCode] of [
      ['issuer-plus-other', [issuerURL, 'https://other.example'], 'client-authentication+jwt', 'JWT_AUDIENCE'],
      ['issuer-array', [issuerURL], 'client-authentication+jwt', 'JWT_AUDIENCE'],
      ['endpoint-audience', issuerURL + '/' + endpoint, 'client-authentication+jwt', 'JWT_AUDIENCE'],
      ['unrelated-type', issuerURL, 'at+jwt', 'JWS_TYPE'],
    ]) {
      const token = assertion(aud, typ, name);
      assert.throws(
        () => CredentialIssuer.prototype.authenticate.call(
          issuer,
          { client_id: clientID, client_assertion_type: assertionType, client_assertion: token },
          {},
          issuerURL + '/' + endpoint,
        ),
        (error) => error.code === 'invalid_client' && error.cause?.code === causeCode,
        name,
      );
      const response = await makeRequest(handler, endpoint, token);
      assert.equal(response.status, 400, name);
      assert.equal(response.body.error, 'invalid_client', name);
    }
  });
}

for (const endpoint of ['token', 'par']) {
  test(`private_key_jwt ${endpoint} maps invalid assertions to invalid_client`, async () => {
    const clientKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const otherKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const issuer = {
      issuer: issuerURL,
      clients: new Map([[clientID, { publicKey: clientKey.publicKey }]]),
      journal: { get: () => undefined, put: () => undefined },
      token(params, headers) {
        CredentialIssuer.prototype.authenticate.call(this, params, headers, issuerURL + '/token');
        return { access_token: 'synthetic' };
      },
      par(params, headers) {
        CredentialIssuer.prototype.authenticate.call(this, params, headers, issuerURL + '/par');
        return { request_uri: 'urn:synthetic' };
      },
    };
    const handler = createProtocolHandler({ issuer });
    const assertion = (key, exp, jti) =>
      signJWS(
        { iss: clientID, sub: clientID, aud: issuerURL, iat: now(), exp, jti },
        key,
        { typ: 'JWT' },
      );

    const valid = await makeRequest(handler, endpoint, assertion(clientKey.privateKey, now() + 60, 'valid'));
    assert.equal(valid.status, endpoint === 'par' ? 201 : 200);

    for (const { token, causeCode } of [
      { token: assertion(otherKey.privateKey, now() + 60, 'bad-signature'), causeCode: 'JWS_SIGNATURE' },
      { token: assertion(clientKey.privateKey, now() - 10, 'expired'), causeCode: 'JWT_EXPIRED' },
    ]) {
      assert.throws(
        () => CredentialIssuer.prototype.authenticate.call(
          issuer,
          { client_id: clientID, client_assertion_type: assertionType, client_assertion: token },
          {},
          issuerURL + '/' + endpoint,
        ),
        (error) => error.code === 'invalid_client' && error.cause?.code === causeCode,
      );
      const response = await makeRequest(handler, endpoint, token);
      assert.equal(response.status, 400);
      assert.equal(response.body.error, 'invalid_client');
    }
  });
}
