import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ACMEService } from './acme.mjs';
import { Journal } from './state.mjs';

const frozen = JSON.parse(
  readFileSync(new URL('./vectors/acme-revocation-reason.json', import.meta.url), 'utf8'),
);

test('original signed ACME revocation requests retain optional reason and ownership gates', async () => {
  assert.equal(frozen.profile, 'RFC8555_ACME_REVOCATION_OPTIONAL_REASON_ADMISSION');
  assert.equal(frozen.vectors.length, 3);
  const originalNow = Date.now;
  Date.now = () => frozen.capturedAt * 1000;
  try {
    for (const vector of frozen.vectors) {
      const journal = new Journal(),
        calls = [];
      try {
        for (const name of ['owner', 'other'])
          journal.put('acme-account', frozen.kids[name], {
            status: 'valid',
            contact: [],
            jwk: frozen.publicJWKs[name],
          });
        journal.put('acme-order', frozen.ownedOrder.id, {
          status: 'valid',
          account: frozen.ownedOrder.owner,
          certificateHash: Buffer.from(frozen.ownedOrder.certificateHash, 'hex'),
        });
        journal.db
          .prepare('INSERT INTO nonce(scope,value,expires,consumed) VALUES(?,?,?,?)')
          .run(vector.nonce.scope, vector.nonce.value, vector.nonce.expires, vector.nonce.consumed);

        const jws = vector.jws,
          key = createPublicKey({ key: frozen.publicJWKs[vector.key], format: 'jwk' }),
          signed = Buffer.from(jws.protected + '.' + jws.payload),
          signature = Buffer.from(jws.signature, 'base64url');
        assert(verify('sha256', signed, { key, dsaEncoding: 'ieee-p1363' }, signature));
        const header = JSON.parse(Buffer.from(jws.protected, 'base64url')),
          payload = JSON.parse(Buffer.from(jws.payload, 'base64url'));
        assert.equal(header.kid, vector.kid);
        assert.equal(header.nonce, vector.nonce.value);
        assert.equal(header.url, frozen.baseURL + '/revoke-cert');
        assert.equal(Object.hasOwn(payload, 'reason'), vector.expected.reasonPresent);
        assert.equal(payload.reason, vector.expected.reason ?? undefined);
        assert.equal(
          createHash('sha512').update(Buffer.from(payload.certificate, 'base64url')).digest('hex'),
          frozen.ownedOrder.certificateHash,
        );

        const service = new ACMEService({
          baseURL: frozen.baseURL,
          journal,
          profiles: ['synthetic-document'],
          authorizeFinalize: () => assert.fail('unexpected finalize'),
          issue: () => assert.fail('unexpected issuance'),
          revoke: async (request) => calls.push(request),
        });
        if (vector.expected.accepted) {
          const response = await service.handle('/revoke-cert', jws);
          assert.equal(response.status, 200, vector.id);
          assert.equal(calls.length, 1, vector.id);
          assert.equal(Object.hasOwn(calls[0], 'reason'), vector.expected.reasonPresent);
          assert.equal(calls[0].reason, vector.expected.reason ?? undefined);
          assert.equal(calls[0].accountID, frozen.kids.owner);
        } else {
          await assert.rejects(
            service.handle('/revoke-cert', jws),
            { code: vector.expected.error },
            vector.id,
          );
          assert.equal(calls.length, 0, vector.id);
        }
        assert.equal(
          journal.get('acme-order', frozen.ownedOrder.id).value.account,
          frozen.kids.owner,
        );
      } finally {
        journal.close();
      }
    }
  } finally {
    Date.now = originalNow;
  }
});
