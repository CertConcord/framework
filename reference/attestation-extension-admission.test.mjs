import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate, verify as verifySignature } from 'node:crypto';
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
  readFileSync(new URL('./vectors/attestation-extension-admission.json', import.meta.url)),
);
const bytes = (id) => Buffer.from(corpus.certificates[id].der, 'base64');
const holderPublicKey = c.publicFromDER(Buffer.from(corpus.holderSPKI, 'base64'));
const statusEvidence = c.H('SyntheticAttestationStatus', {});
function policy(root, target, mode = 'good') {
  const calls = [];
  return {
    calls,
    roots: [bytes(root)],
    status(cert, input) {
      calls.push({
        certificate: Buffer.from(cert.raw),
        issuer: Buffer.from(input.issuer.raw),
        at: input.at,
      });
      assert.equal(input.at, corpus.at);
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
function applePolicy(trusted) {
  return {
    ...trusted,
    flow: 'ACME_HARDWARE_BOUND',
    requiredProperties: [
      {
        oid: corpus.apple.osOID,
        acceptedValues: [Buffer.from(corpus.apple.os, 'base64')],
      },
    ],
  };
}
function rejection(action, code) {
  assert.throws(action, (error) => {
    assert.equal(error.message, code);
    return true;
  });
}
function prefix(calls, chain, count) {
  assert.equal(calls.length, count);
  for (let i = 0; i < count; i++) {
    assert.deepEqual(calls[i].certificate, chain[i]);
    assert.deepEqual(calls[i].issuer, chain[i + 1]);
    assert.equal(calls[i].at, corpus.at);
  }
}
function unchanged(chain, copies) {
  assert.deepEqual(chain, copies);
}

test('Attestation extension corpus pins signed bytes and distinguishes profile limits', () => {
  assert.equal(corpus.format, 'certconcord-attestation-extension-admission-v1');
  assert.equal(corpus.qualification, 'SYNTHETIC_CONTROLLED_ROOTS_ONLY');
  assert.equal(corpus.cases.length, 76);
  assert.equal(new Set(corpus.cases.map((row) => row.id)).size, 76);
  assert.equal(corpus.android.cases.length, 6);
  assert.equal(corpus.pscp.length, 5);
  for (const row of corpus.cases)
    for (const expected of Object.values(row.expected))
      if (expected.accepted) assert.equal(Object.hasOwn(expected, 'error'), false);
      else assert.equal(typeof expected.error, 'string');
  for (const [id, record] of Object.entries(corpus.certificates)) {
    const raw = bytes(id),
      issuer = c.publicFromDER(Buffer.from(record.expectedSignerSPKI, 'base64'));
    const parsed = p.parseCertificate(raw);
    assert.equal(c.sha256(raw).toString('hex'), record.sha256, id);
    assert.equal(new X509Certificate(raw).verify(issuer), record.signatureValid, id);
    assert.equal(
      verifySignature('sha256', parsed.tbs, issuer, parsed.signature),
      record.signatureValid,
      id,
    );
  }
  for (const row of corpus.cases.filter((row) => row.id.includes('unsupported-bit-')))
    assert.equal(row.classification, 'PROFILE_LIMIT');
  assert.equal(
    corpus.cases.find((row) => row.id === 'leaf-bc-path-without-ca').classification,
    'PROFILE_SHAPE',
  );
  assert.deepEqual(
    p.parseCertificate(bytes('leaf-ku-multiple-known-bits')).extensions.get('2.5.29.15').value,
    Buffer.from('030206c0', 'hex'),
  );
  for (const critical of [true, false]) {
    const raw = bytes('leaf-bc-role-255-' + critical + '-false');
    assert.equal(new X509Certificate(raw).ca, false);
    assert.deepEqual(
      p.parseCertificate(raw).extensions.get('2.5.29.19').value,
      Buffer.from('30030101ff', 'hex'),
    );
  }
});

for (const row of corpus.cases)
  test('Attestation extension admission: ' + row.id, () => {
    const complete = row.chain.map(bytes);
    for (const mode of ['included', 'appended'])
      for (const api of ['chain', 'apple']) {
        const input = (mode === 'included' ? complete : complete.slice(0, -1)).map((value) =>
          Buffer.from(value),
        );
        const copies = input.map((value) => Buffer.from(value)),
          trusted = policy(row.root),
          wanted = row.expected[mode];
        const action = () =>
          api === 'chain'
            ? verifiedChain(input, trusted, corpus.at)
            : verifyAppleManagedAttestation(
                { x5c: input },
                {
                  holderPublicKey,
                  challenge: corpus.challenge,
                  at: corpus.at,
                  policy: applePolicy(trusted),
                },
              );
        if (wanted.accepted) {
          const result = action();
          assert.equal(result.expiresAt, corpus.at + 3600);
          assert.deepEqual(
            result.statusEvidenceHash,
            c.H('AttestationStatus', [statusEvidence, statusEvidence]),
          );
          if (api === 'chain') {
            assert.deepEqual(
              result.chain.map((cert) => cert.raw),
              complete,
            );
            assert.deepEqual(result.leaf.raw, complete[0]);
            assert.deepEqual(result.rootHash, c.sha256(bytes(row.root)));
          } else {
            assert.equal(result.boundary, 'APPLE_SECURE_ENCLAVE');
            assert.deepEqual(result.trustAnchorHash, c.sha256(bytes(row.root)));
          }
        } else rejection(action, wanted.error);
        prefix(trusted.calls, complete, wanted.statusCalls);
        unchanged(input, copies);
      }
  });

test('Attestation extension admission preserves Apple holder and challenge binding', () => {
  const chain = ['leaf', 'ca', 'root'].map(bytes),
    original = chain.map((value) => Buffer.from(value));
  for (const [change, error] of [
    [{ challenge: 'different' }, 'KEY_ATTESTATION_CHALLENGE'],
    [
      { holderPublicKey: new X509Certificate(bytes('ca')).publicKey },
      'KEY_ATTESTATION_SUBJECT_KEY',
    ],
  ]) {
    const trusted = policy('root');
    rejection(
      () =>
        verifyAppleManagedAttestation(
          { x5c: chain },
          {
            holderPublicKey,
            challenge: corpus.challenge,
            at: corpus.at,
            policy: applePolicy(trusted),
            ...change,
          },
        ),
      error,
    );
    prefix(trusted.calls, chain, 2);
    unchanged(chain, original);
  }
});

test('Attestation extension admission preserves issuer identity and current status', () => {
  const chain = ['leaf', 'ca', 'root'].map(bytes),
    original = chain.map((value) => Buffer.from(value));
  for (const target of ['leaf', 'ca'])
    for (const mode of ['revoked', 'stale', 'missing'])
      for (const api of ['chain', 'apple']) {
        const trusted = policy('root', target, mode);
        const action = () =>
          api === 'chain'
            ? verifiedChain(chain, trusted, corpus.at)
            : verifyAppleManagedAttestation(
                { x5c: chain },
                {
                  holderPublicKey,
                  challenge: corpus.challenge,
                  at: corpus.at,
                  policy: applePolicy(trusted),
                },
              );
        rejection(action, 'KEY_ATTESTATION_STATUS');
        prefix(trusted.calls, chain, target === 'leaf' ? 1 : 2);
        unchanged(chain, original);
      }
});

for (const row of corpus.android.cases)
  test('Attestation extension shared consumer: ' + row.id, () => {
    const chain = row.chain.map(bytes),
      original = chain.map((value) => Buffer.from(value)),
      trusted = policy(row.root);
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
    if (row.expected.accepted) {
      const result = action();
      assert.equal(result.boundary, 'ANDROID_STRONGBOX');
      assert.equal(result.localUVPolicy, 'PER_USE_AUTH_REQUIRED');
      assert.equal(result.expiresAt, corpus.at + 3600);
      assert.deepEqual(result.trustAnchorHash, c.sha256(bytes(row.root)));
      assert.deepEqual(
        result.statusEvidenceHash,
        c.H('AttestationStatus', [statusEvidence, statusEvidence]),
      );
    } else rejection(action, row.expected.error);
    prefix(trusted.calls, chain, row.expected.statusCalls);
    unchanged(chain, original);
  });

for (const row of corpus.pscp)
  test('Attestation extension shared consumer: ' + row.id, (t) => {
    t.mock.method(Date, 'now', () => corpus.at * 1000);
    const trusted = policy(row.root),
      input = {
        ceremony: structuredClone(row.ceremony),
        generatedKey: Object.fromEntries(
          Object.entries(row.generatedKey).map(([name, value]) => [
            name,
            name === 'algorithm' ? value : Buffer.from(value, 'base64'),
          ]),
        ),
      };
    const original = JSON.stringify(input),
      child = decode(input.generatedKey.attestationObject).get('attStmt').get('x5c');
    const parent = decode(c.unb64u(input.ceremony.response.attestationObject))
      .get('attStmt')
      .get('x5c');
    assert.deepEqual(child, row.childChain.map(bytes));
    assert.deepEqual(parent, row.parentChain.map(bytes));
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
    if (row.expected.accepted) {
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
    } else rejection(action, row.expected.error);
    assert.equal(trusted.calls.length, row.expected.childCalls + row.expected.parentCalls);
    prefix(trusted.calls.slice(0, row.expected.childCalls), child, row.expected.childCalls);
    prefix(trusted.calls.slice(row.expected.childCalls), parent, row.expected.parentCalls);
    assert.equal(JSON.stringify(input), original);
  });
