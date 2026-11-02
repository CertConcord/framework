import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { decode } from './cose.mjs';
import {
  verifiedChain,
  verifyAndroidKeyAttestation,
  verifyAppleManagedAttestation,
} from './key-attestation.mjs';
import { verifySigningKeyGeneration } from './raw-signing.mjs';

const corpus = JSON.parse(
  readFileSync(new URL('./vectors/attestation-pathlen.json', import.meta.url)),
);
const bytes = (id) => Buffer.from(corpus.certificates[id].der, 'base64');
const holderPublicKey = c.publicFromDER(Buffer.from(corpus.holderSPKI, 'base64'));
const statusEvidence = c.H('SyntheticAttestationStatus', {});
function policy(root, mode = 'good', target) {
  const calls = [];
  return {
    calls,
    roots: [bytes(root)],
    status(cert, context) {
      calls.push({
        certificate: Buffer.from(cert.raw),
        issuer: Buffer.from(context.issuer.raw),
        at: context.at,
      });
      assert.equal(context.at, corpus.at);
      const selected = target && !cert.raw.equals(bytes(target)) ? 'good' : mode;
      if (selected === 'missing') return null;
      return {
        status: selected === 'revoked' ? 'REVOKED' : 'GOOD',
        checkedAt: corpus.at - (selected === 'stale' ? 86401 : 0),
        nextUpdate: corpus.at + 60,
        evidenceHash: statusEvidence,
      };
    },
  };
}
function rejection(action, expected) {
  assert.throws(action, (error) => {
    assert(
      expected.includes(error.message),
      'Expected ' + expected.join('/') + ', got ' + error.message,
    );
    return true;
  });
}
function originalBytes(buffers, copies) {
  assert.equal(buffers.length, copies.length);
  for (let i = 0; i < buffers.length; i++) assert.deepEqual(buffers[i], copies[i]);
}
function acceptedStatus(calls, chain, root) {
  const complete = chain.at(-1).equals(root) ? chain : [...chain, root];
  assert.equal(calls.length, complete.length - 1);
  for (let i = 0; i < calls.length; i++) {
    assert.deepEqual(calls[i].certificate, complete[i]);
    assert.deepEqual(calls[i].issuer, complete[i + 1]);
    assert.equal(calls[i].at, corpus.at);
  }
}

test('Attestation path count corpus pins public raw certificates and independent signature controls', () => {
  assert.equal(corpus.format, 'certconcord-identical-name-attestation-path-v1');
  assert.equal(corpus.qualification, 'SYNTHETIC_CONTROLLED_ROOTS_ONLY');
  assert.equal(new Set(corpus.cases.map((row) => row.id)).size, corpus.cases.length);
  assert.equal(corpus.android.cases.length, 3);
  assert.equal(corpus.pscp.length, 3);
  for (const [id, record] of Object.entries(corpus.certificates)) {
    const raw = bytes(id);
    assert.equal(c.sha256(raw).toString('hex'), record.sha256, id);
    const issuer = c.publicFromDER(Buffer.from(record.expectedSignerSPKI, 'base64'));
    assert.equal(new X509Certificate(raw).verify(issuer), record.signatureValid, id);
  }
  const ordinary = p.parseCertificate(bytes('ordinary0')),
    rollover = p.parseCertificate(bytes('roll0'));
  assert(!ordinary.issuer.equals(ordinary.subject));
  assert(rollover.issuer.equals(rollover.subject));
  const native = new X509Certificate(bytes('roll-aki'));
  assert.equal(native.verify(native.publicKey), false);
  assert.equal(native.verify(new X509Certificate(bytes('parent0')).publicKey), true);
  assert.equal(
    native.checkIssued(native),
    false,
    'old-key AKI/new-key SKI must not decide the counting exemption',
  );
  const zero = p.parseCertificate(bytes('parent0')),
    one = p.parseCertificate(bytes('parent1'));
  assert.equal(zero.serial, one.serial);
  assert.deepEqual(zero.issuer, one.issuer);
  assert.deepEqual(zero.subject, one.subject);
  assert.deepEqual(zero.spki, one.spki);
  assert.equal(zero.notBefore, one.notBefore);
  assert.equal(zero.notAfter, one.notAfter);
  for (const [oid, value] of zero.extensions)
    if (oid !== '2.5.29.19') assert.deepEqual(value, one.extensions.get(oid));
});

for (const row of corpus.cases)
  test('Attestation path count: ' + row.id, () => {
    for (const api of ['chain', 'apple']) {
      const chain = row.chain.map(bytes),
        copies = chain.map((value) => Buffer.from(value)),
        trusted = policy(row.root, row.statusMode);
      const action = () =>
        api === 'chain'
          ? verifiedChain(chain, trusted, corpus.at)
          : verifyAppleManagedAttestation(
              { x5c: chain },
              {
                holderPublicKey,
                challenge: corpus.challenge,
                at: corpus.at,
                policy: {
                  ...trusted,
                  flow: 'ACME_HARDWARE_BOUND',
                  requiredProperties: [
                    {
                      oid: corpus.apple.osOID,
                      acceptedValues: [Buffer.from(corpus.apple.os, 'base64')],
                    },
                  ],
                },
              },
            );
      if (!row.expected.accepted) rejection(action, row.expected.error);
      else {
        const result = action();
        acceptedStatus(trusted.calls, chain, bytes(row.root));
        assert.equal(result.expiresAt, corpus.at + 3600);
        const expectedEvidence = c.H(
          'AttestationStatus',
          trusted.calls.map(() => statusEvidence),
        );
        assert.deepEqual(result.statusEvidenceHash, expectedEvidence);
        if (api === 'chain') {
          assert.deepEqual(result.rootHash, c.sha256(bytes(row.root)));
          assert.deepEqual(result.leaf.spki, c.spki(holderPublicKey));
          const complete = chain.at(-1).equals(bytes(row.root))
            ? chain
            : [...chain, bytes(row.root)];
          assert.deepEqual(
            result.chain.map((cert) => cert.raw),
            complete,
          );
        } else {
          assert.equal(result.boundary, 'APPLE_SECURE_ENCLAVE');
          assert.equal(result.localUVPolicy, 'UNASSESSED');
          assert.deepEqual(result.trustAnchorHash, c.sha256(bytes(row.root)));
        }
      }
      originalBytes(chain, copies);
    }
  });

test('Attestation path count Apple admission keeps exact holder and challenge bindings', () => {
  const chain = ['leaf-roll', 'roll-aki', 'parent0', 'root3'].map(bytes);
  const trusted = policy('root3'),
    base = {
      holderPublicKey,
      challenge: corpus.challenge,
      at: corpus.at,
      policy: {
        ...trusted,
        flow: 'ACME_HARDWARE_BOUND',
        requiredProperties: [
          { oid: corpus.apple.osOID, acceptedValues: [Buffer.from(corpus.apple.os, 'base64')] },
        ],
      },
    };
  rejection(
    () => verifyAppleManagedAttestation({ x5c: chain }, { ...base, challenge: 'different' }),
    ['KEY_ATTESTATION_CHALLENGE'],
  );
  rejection(
    () =>
      verifyAppleManagedAttestation(
        { x5c: chain },
        { ...base, holderPublicKey: new X509Certificate(bytes('roll0')).publicKey },
      ),
    ['KEY_ATTESTATION_SUBJECT_KEY'],
  );
});

for (const row of corpus.android.cases)
  test('Attestation path count shared consumer: ' + row.id, () => {
    const chain = row.chain.map(bytes),
      copies = chain.map((value) => Buffer.from(value)),
      trusted = policy('root3');
    const action = () =>
      verifyAndroidKeyAttestation(
        { x5c: chain },
        {
          holderPublicKey,
          challenge: row.challenge ?? corpus.challenge,
          at: corpus.at,
          policy: { ...corpus.android.policy, ...trusted },
        },
      );
    if (row.accepted) {
      const result = action();
      assert.equal(result.boundary, 'ANDROID_STRONGBOX');
      assert.equal(result.localUVPolicy, 'PER_USE_AUTH_REQUIRED');
      assert.deepEqual(result.trustAnchorHash, c.sha256(bytes('root3')));
      acceptedStatus(trusted.calls, chain, bytes('root3'));
    } else rejection(action, [row.error]);
    originalBytes(chain, copies);
  });

test('Attestation path count exempt rollover still requires current trusted status', () => {
  const chain = ['leaf-roll', 'roll0', 'parent0', 'root3'].map(bytes);
  const copies = chain.map((value) => Buffer.from(value));
  for (const mode of ['revoked', 'stale', 'missing']) {
    for (const api of ['chain', 'apple']) {
      const trusted = policy('root3', mode, 'roll0');
      const action = () =>
        api === 'chain'
          ? verifiedChain(chain, trusted, corpus.at)
          : verifyAppleManagedAttestation(
              { x5c: chain },
              {
                holderPublicKey,
                challenge: corpus.challenge,
                at: corpus.at,
                policy: {
                  ...trusted,
                  flow: 'ACME_HARDWARE_BOUND',
                  requiredProperties: [
                    {
                      oid: corpus.apple.osOID,
                      acceptedValues: [Buffer.from(corpus.apple.os, 'base64')],
                    },
                  ],
                },
              },
            );
      rejection(action, ['KEY_ATTESTATION_STATUS']);
      assert.equal(trusted.calls.length, 2);
      for (let i = 0; i < 2; i++) {
        assert.deepEqual(trusted.calls[i].certificate, chain[i]);
        assert.deepEqual(trusted.calls[i].issuer, chain[i + 1]);
      }
      originalBytes(chain, copies);
    }
  }
});

for (const row of corpus.pscp)
  test('Attestation path count shared consumer: ' + row.id, (t) => {
    // The WebAuthn registration verifier reads the clock directly; use the corpus time for this complete public flow.
    t.mock.method(Date, 'now', () => corpus.at * 1000);
    const trusted = policy(row.root),
      input = {
        ceremony: structuredClone(row.ceremony),
        generatedKey: Object.fromEntries(
          Object.entries(row.generatedKey).map(([key, value]) => [
            key,
            key === 'algorithm' ? value : Buffer.from(value, 'base64'),
          ]),
        ),
      };
    const original = JSON.stringify(input);
    const childChain = decode(input.generatedKey.attestationObject).get('attStmt').get('x5c');
    const parentChain = decode(c.unb64u(input.ceremony.response.attestationObject))
      .get('attStmt')
      .get('x5c');
    const model = {
      ...row.model,
      aaguid: Buffer.from(row.model.aaguid, 'base64'),
      rootHash: Buffer.from(row.model.rootHash, 'base64'),
    };
    const action = () =>
      verifySigningKeyGeneration(input, {
        challenge: Buffer.from(row.challenge, 'base64'),
        origin: row.origin,
        rpID: row.rpID,
        version: row.version,
        algorithms: row.algorithms,
        at: corpus.at,
        attestationPolicy: { ...trusted, models: [model] },
      });
    if (row.accepted) {
      const result = action();
      assert.deepEqual(result.publicKeyBytes, input.generatedKey.publicKey);
      assert.deepEqual(result.keyHandle, input.generatedKey.keyHandle);
      assert.equal(result.algorithm, -9);
      assert.equal(result.version, row.version);
      assert.equal(result.fixedFlags, 5);
      assert.equal(result.expiresAt, corpus.at + 3600);
      assert.deepEqual(result.attestationHash, c.sha512(input.generatedKey.attestationObject));
      assert.deepEqual(
        result.generationProofHash,
        c.H('PasskeyKeyGeneration', {
          ceremony: input.ceremony,
          attestationHash: c.sha512(input.generatedKey.attestationObject),
        }),
      );
      assert.equal(
        trusted.calls.length,
        6,
        'Both three-link child and parent chains must reach trusted status',
      );
      acceptedStatus(trusted.calls.slice(0, 3), childChain, bytes(row.root));
      acceptedStatus(trusted.calls.slice(3), parentChain, bytes(row.root));
    } else {
      rejection(action, [row.error]);
      const parentFailure = row.id === 'pscp-parent-path-enforced';
      assert.equal(trusted.calls.length, parentFailure ? 5 : 2);
      if (parentFailure) acceptedStatus(trusted.calls.slice(0, 3), childChain, bytes(row.root));
      const partial = trusted.calls.slice(parentFailure ? 3 : 0),
        failedChain = parentFailure ? parentChain : childChain;
      for (let i = 0; i < 2; i++) {
        assert.deepEqual(partial[i].certificate, failedChain[i]);
        assert.deepEqual(partial[i].issuer, failedChain[i + 1]);
      }
    }
    assert.equal(JSON.stringify(input), original);
  });
