import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { decode, encode } from './cose.mjs';
import { verifyRegistration, verifyAssertion } from './webauthn.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/webauthn-authenticator-extensions.json', import.meta.url)),
);
const bytes = (value) => Buffer.from(value, 'base64url');
const hash = (value) => createHash('sha256').update(value).digest();
const publicKeyDER = bytes(vectors.publicKeySPKI);
const publicKey = createPublicKey({ key: publicKeyDER, format: 'der', type: 'spki' });
const registration = {
  publicKey,
  credentialID: bytes(vectors.credentialID),
  rpID: vectors.rpID,
  origin: vectors.origin,
  counter: 0,
  backupEligible: false,
};
const options = { challenge: bytes(vectors.challenge), origin: vectors.origin, rpID: vectors.rpID };
const call = (v, opts = options, stored = registration) =>
  v.kind === 'registration'
    ? verifyRegistration(v.credential, opts)
    : verifyAssertion(v.credential, stored, opts);
const find = (id) => vectors.cases.find((v) => v.id === id);

for (const v of vectors.cases) {
  test('WebAuthn extension raw input: ' + v.id, () => {
    const auth = bytes(v.authenticatorData),
      client = bytes(v.credential.response.clientDataJSON);
    assert.deepEqual(auth.subarray(0, 32), hash(Buffer.from(vectors.rpID)));
    assert.equal(v.credential.id, vectors.credentialID);
    assert.equal(v.credential.rawId, vectors.credentialID);
    const expectedClient = {
      type: v.kind === 'registration' ? 'webauthn.create' : 'webauthn.get',
      challenge: vectors.challenge,
      origin: vectors.origin,
      crossOrigin: false,
    };
    assert.deepEqual(JSON.parse(client), expectedClient);
    let signature;
    if (v.kind === 'registration') {
      const attestation = decode(bytes(v.credential.response.attestationObject));
      assert.equal(attestation.get('fmt'), v.fmt);
      assert.deepEqual(attestation.get('authData'), auth);
      const len = auth.readUInt16BE(53);
      assert.equal(len, registration.credentialID.length);
      assert.deepEqual(auth.subarray(55, 55 + len), registration.credentialID);
      const encodedKey = Buffer.from(vectors.cosePublicKeyHex, 'hex');
      assert.deepEqual(auth.subarray(55 + len, 55 + len + encodedKey.length), encodedKey);
      assert.equal(auth.subarray(55 + len + encodedKey.length).toString('hex'), v.extensionHex);
      if (v.fmt === 'packed') {
        const statement = attestation.get('attStmt');
        assert.equal(statement.get('alg'), -7);
        assert.equal(statement.has('x5c'), false);
        signature = statement.get('sig');
      } else assert.equal(attestation.get('attStmt').size, 0);
    } else {
      assert.deepEqual(bytes(v.credential.response.authenticatorData), auth);
      assert.equal(auth.subarray(37).toString('hex'), v.extensionHex);
      signature = bytes(v.credential.response.signature);
    }
    if (signature)
      assert.equal(
        verify('sha256', Buffer.concat([auth, hash(client)]), publicKey, signature),
        v.signatureValid,
      );
    else assert.equal(v.signatureValid, null);
    if (!v.expected.accepted) {
      assert.throws(() => call(v), { code: v.expected.error });
      return;
    }
    const result = call(v);
    assert.equal(result.flags, auth[32]);
    assert.equal(result.counter, auth.readUInt32BE(33));
    assert.equal(result.backupEligible, false);
    assert.equal(result.backedUp, false);
    if (v.kind === 'registration') {
      assert.deepEqual(result.credentialID, registration.credentialID);
      assert.deepEqual(result.publicKeyDER, publicKeyDER);
      assert.deepEqual(result.publicKey.export({ format: 'der', type: 'spki' }), publicKeyDER);
      assert.deepEqual(result.aaguid, Buffer.alloc(16));
      assert.equal(result.attestationVerified, false);
      assert.equal(result.assurance, 'UNASSESSED');
      assert.equal(result.rpID, vectors.rpID);
      assert.equal(result.origin, vectors.origin);
    } else assert.equal(result.assertionHash.length, 64);
  });
}

for (const kind of ['registration', 'assertion']) {
  const v = find(kind + '-unknown-text');
  test('WebAuthn extensions preserve ceremony and credential binding: ' + kind, () => {
    assert.throws(() => call(v, { ...options, challenge: Buffer.alloc(32) }), {
      code: 'WEBAUTHN_CLIENT_DATA',
    });
    assert.throws(() => call(v, { ...options, origin: 'https://other.example.invalid' }), {
      code: 'WEBAUTHN_CLIENT_DATA',
    });
    assert.throws(() => call(v, { ...options, rpID: 'other.example.invalid' }), {
      code: 'RP_ID_HASH',
    });
    const changed = structuredClone(v);
    changed.credential.id = changed.credential.rawId =
      Buffer.from('other credential').toString('base64url');
    assert.throws(() => call(changed), {
      code: kind === 'registration' ? 'ATTESTED_CREDENTIAL_ID' : 'CREDENTIAL_BINDING',
    });
  });
  test('WebAuthn extensions retain optional UV policy: ' + kind, () => {
    const result = call(find(kind + '-missing-uv'), { ...options, uv: false });
    assert.equal(result.flags & 4, 0);
    assert.equal(result.counter, 1);
  });
}
test('WebAuthn extension acceptance does not bypass the sign counter', () => {
  assert.throws(
    () => call(find('assertion-unknown-text'), options, { ...registration, counter: 1 }),
    { code: 'SIGN_COUNT_ROLLBACK' },
  );
});

// Derived controls retain each frozen signature and change only the stated raw field.
for (const id of ['assertion-unknown-text', 'registration-packed-text'])
  test('WebAuthn extensions bind the exact output bytes: ' + id, () => {
    const original = find(id),
      changed = structuredClone(original);
    const auth = bytes(original.authenticatorData);
    assert.equal(auth.at(-1), 0xf5);
    auth[auth.length - 1] = 0xf4; // CBOR true -> false; text identifier and map remain valid.
    let signature;
    if (original.kind === 'assertion') {
      changed.credential.response.authenticatorData = auth.toString('base64url');
      signature = bytes(original.credential.response.signature);
    } else {
      const attestation = decode(bytes(original.credential.response.attestationObject));
      signature = attestation.get('attStmt').get('sig');
      attestation.set('authData', auth);
      changed.credential.response.attestationObject = encode(attestation).toString('base64url');
    }
    const client = bytes(original.credential.response.clientDataJSON);
    assert.equal(
      verify('sha256', Buffer.concat([auth, hash(client)]), publicKey, signature),
      false,
    );
    const before = structuredClone(changed.credential);
    assert.throws(() => call(changed), {
      code: original.kind === 'assertion' ? 'ASSERTION_SIGNATURE' : 'ATTESTATION_SIGNATURE',
    });
    assert.deepEqual(changed.credential, before);
  });

test('WebAuthn extensions preserve credential-key error precedence', () => {
  const changed = structuredClone(find('registration-integer-key'));
  const attestation = decode(bytes(changed.credential.response.attestationObject));
  const auth = attestation.get('authData');
  const offset = 55 + auth.readUInt16BE(53);
  const keyBytes = Buffer.from(vectors.cosePublicKeyHex, 'hex');
  const key = decode(keyBytes);
  key.set(-1, 2); // Unsupported curve with an otherwise valid integer-key extension map.
  attestation.set(
    'authData',
    Buffer.concat([auth.subarray(0, offset), encode(key), auth.subarray(offset + keyBytes.length)]),
  );
  changed.credential.response.attestationObject = encode(attestation).toString('base64url');
  const before = structuredClone(changed.credential);
  assert.throws(() => call(changed), { code: 'COSE_EC' });
  assert.deepEqual(changed.credential, before);
});
