import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { issueCRL, verifyCRL, ocspRequest, issueOCSP, verifyOCSP } from './revocation.mjs';
import { evaluateStatus } from './state.mjs';
import { signJWS } from './jose.mjs';
import { verifyStatusList } from './openid.mjs';

test('CRL, OCSP, Status List and experimental status share authenticated result semantics', () => {
  const at = c.now(), key = c.generate('ec'), issuer = p.name('Synthetic status issuer'), serial = 7n,
    uri = 'https://status.example/list';
  const variants = {
    CRL: (kind, knowledgeTime, bad = false) => {
      const raw = issueCRL({ issuer, privateKey: key.privateKey, number: 1n, thisUpdate: at,
        nextUpdate: at + 100, entries: kind === 'REVOKED' ? [{ serial, revokedAt: at, reason: 1 }] : [] });
      if (bad) raw[raw.length - 1] ^= 1;
      return verifyCRL(raw, { issuer, publicKey: key.publicKey, serial, at, knowledgeTime });
    },
    OCSP: (kind, knowledgeTime, bad = false) => {
      const request = ocspRequest({ issuer, issuerPublicKey: key.publicKey, serial });
      const raw = issueOCSP(request.raw, { issuer, issuerPublicKey: key.publicKey, privateKey: key.privateKey,
        thisUpdate: at, nextUpdate: at + 100,
        records: new Map([[String(serial), { status: kind, revokedAt: at, reason: 1 }]]) });
      if (bad) raw[raw.length - 1] ^= 1;
      return verifyOCSP(raw, { request: request.raw, issuerPublicKey: key.publicKey, at, knowledgeTime });
    },
    STATUS_LIST: (kind, knowledgeTime, bad = false) => {
      const bytes = Buffer.alloc(1024); if (kind === 'REVOKED') bytes[0] = 1;
      const token = signJWS({ iss: uri, sub: uri, iat: at, exp: at + 100,
        status_list: { bits: 1, lst: c.b64u(deflateSync(bytes)) } },
      bad ? c.generate('ec').privateKey : key.privateKey, { typ: 'statuslist+jwt' });
      return verifyStatusList(token, { publicKey: key.publicKey, uri, index: 0, at: knowledgeTime });
    },
    EXPERIMENTAL: (kind, knowledgeTime, bad = false) => evaluateStatus({
      scope: bad ? 'OTHER' : 'CERTIFICATE', status: kind, publishedAt: at, nextUpdate: at + 100,
      ...(kind === 'REVOKED' ? { effectiveTime: at } : {}),
    }, { stateTime: at, knowledgeTime, scope: 'CERTIFICATE' }),
  };
  for (const [name, evaluate] of Object.entries(variants)) {
    assert.equal(evaluate('GOOD', at).overall, 'VALID', name);
    assert.equal(evaluate('REVOKED', at).overall, 'INVALID', name);
    assert.equal(evaluate('GOOD', at + 100).overall, 'INDETERMINATE', name);
    assert.equal(evaluate('REVOKED', at + 100).overall, 'INVALID', name);
    assert.equal(evaluate('GOOD', at + 100, true).overall, 'INVALID', name);
    assert(Object.isFrozen(evaluate('GOOD', at)), name);
  }
});

test('missing, future and unknown critical status cannot authorize acceptance', () => {
  const at = c.now(), key = c.generate('ec'), issuer = p.name('Synthetic status issuer'), serial = 9n;
  for (const missing of [verifyCRL(undefined, {}), verifyOCSP(undefined, {}),
    verifyStatusList(undefined, { at }), evaluateStatus(undefined, {})])
    assert.equal(missing.overall, 'INDETERMINATE');
  const statement = { scope: 'CERTIFICATE', status: 'GOOD', publishedAt: at + 1, nextUpdate: at + 100 };
  const future = evaluateStatus(statement, { stateTime: at, knowledgeTime: at, scope: 'CERTIFICATE' });
  assert.equal(future.overall, 'INDETERMINATE');
  assert.equal(future.reason, 'STATUS_NOT_YET_KNOWN');
  assert.equal(evaluateStatus({ ...statement, publishedAt: at, critical: ['future-rule'] },
    { stateTime: at, knowledgeTime: at, scope: 'CERTIFICATE' }).overall, 'UNSUPPORTED');
  const raw = issueCRL({ issuer, privateKey: key.privateKey, number: 1n, thisUpdate: at + 1, nextUpdate: at + 100 });
  assert.equal(verifyCRL(raw, { issuer, publicKey: key.publicKey, serial, at }).overall, 'INDETERMINATE');
  const q = ocspRequest({ issuer, issuerPublicKey: key.publicKey, serial });
  const ocsp = issueOCSP(q.raw, { issuer, issuerPublicKey: key.publicKey, privateKey: key.privateKey,
    records: new Map(), thisUpdate: at + 1, nextUpdate: at + 100 });
  assert.equal(verifyOCSP(ocsp, { request: q.raw, issuerPublicKey: key.publicKey, at }).overall, 'INDETERMINATE');
});
