import test from 'node:test';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
test('MTC draft06 independent C.1.4 covering-subtree aggregate vector', () => {
  const h = createHash('sha256');
  for (let end = 0; end <= 130; end++)
    for (let start = 0; start <= end; start++) {
      const [[a, b], [x, y]] = m.coverInterval(start, end);
      h.update(`[${a}, ${b}) [${x}, ${y})\n`);
    }
  assert.equal(h.digest('hex'), '7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0');
});

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as m from './mtc.mjs';
import * as v from './protection.mjs';
import * as s from './state.mjs';

export function fixture(profileID = 'CERTCONCORD-PERSON-SIGN-v1') {
  const root = c.generate('ml-dsa-87'),
    key = c.generate('ml-dsa-65'),
    issuer = p.name('Public test issuer'),
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        issuer,
        subject: p.name('Public test subject'),
        serial: 1,
        profileID,
      },
      root.privateKey,
    );
  return { root, key, issuer, certificate };
}
test('RFC9881 X.509 and RFC9882 CMS encode/verify with OpenSSL certificate parser', () => {
  const f = fixture(),
    content = Buffer.from('A document requiring consent');
  assert(p.nativeCertificate(f.certificate).verify(f.root.publicKey));
  p.validateCertificate(f.certificate, f.root.publicKey);
  const cms = p.signCMS({ content, certificate: f.certificate }, f.key.privateKey);
  const r = p.verifyCMS(cms, { issuerKey: f.root.publicKey, profileID: 'CERTCONCORD-PERSON-SIGN-v1' });
  assert(c.equal(r.content, content));
  cms[cms.length - 2] ^= 1;
  assert.throws(() => p.verifyCMS(cms), /CMS_SIGNATURE/);
});
test('CMS detached content, ESS representation, signed SIM and policy substitution', () => {
  const f = fixture(),
    content = c.random(40),
    simHash = c.random(64),
    policyHash = c.random(64),
    context = { adapterID: 'cms-rfc9882-v1' };
  const cms = p.signCMS(
    { content, certificate: f.certificate, detached: true, context, simHash, policyHash },
    f.key.privateKey,
  );
  p.verifyCMS(cms, { content, context, simHash, policyHash });
  assert.throws(() => p.verifyCMS(cms, { content: c.random(40) }), /DIGEST/);
  assert.throws(() => p.verifyCMS(cms, { content, simHash: c.random(64) }), /BINDING/);
  assert.throws(
    () => p.verifyCMS(cms, { content, expectedCertificate: fixture().certificate }),
    /REPRESENTATION/,
  );
});
test('MTC draft06 Appendix C.1.1 independent rolling hash vector', () => {
  const data = Array.from({ length: 130 }, (_, i) => Buffer.from([i])),
    h = createHash('sha256');
  for (let end = 0; end <= 130; end++)
    for (let start = 0; start <= end; start++)
      if (m.validSubtree(start, end))
        h.update(`[${start}, ${end}) ${m.treeHash(data.slice(start, end)).toString('hex')}\n`);
  assert.equal(h.digest('hex'), 'b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81');
});
test('MTC subtree inclusion and consistency across every small aligned subtree', () => {
  const data = Array.from({ length: 33 }, (_, i) => Buffer.from([i])),
    root = m.treeHash(data);
  for (let end = 0; end <= data.length; end++)
    for (let start = 0; start <= end; start++)
      if (m.validSubtree(start, end)) {
        const node = m.treeHash(data.slice(start, end)),
          proof = m.consistencyProof(data, start, end);
        m.verifyConsistency({ start, end, size: data.length, node, root, proof });
        for (let index = start; index < end; index++)
          assert(
            c.equal(
              m.evaluateInclusion(
                m.leafHash(data[index]),
                index,
                start,
                end,
                m.inclusionProof(data, index, start, end),
              ),
              node,
            ),
          );
        if (proof.length) {
          const bad = proof.map(Buffer.from);
          bad[0][0] ^= 1;
          assert.throws(() =>
            m.verifyConsistency({ start, end, size: data.length, node, root, proof: bad }),
          );
        }
      }
});
test('MTC standalone real CA + mirror signatures, DER serial, landmark and revoked range', () => {
  const ca = c.generate('ml-dsa-87'),
    leaf = c.generate(),
    mirrors = Array.from({ length: 3 }, (_, i) => ({
      id: `32473.${i + 10}`,
      operatorID: `operator${i}`,
      ...c.generate('ml-dsa-87'),
    })),
    caID = '32473.1';
  const tbs = m.createMTCTBS(
    { publicKey: leaf.publicKey, subject: p.name('Example') },
    { caID, logNumber: 65535, index: 0 },
  );
  const entries = [m.logEntryFromTBS(tbs)];
  const certificate = m.issueMTC(tbs, {
    entries,
    index: 0,
    caID,
    logNumber: 65535,
    cosigners: [{ id: caID, ...ca }, ...mirrors.slice(0, 2)],
  });
  const options = {
    caID,
    caPublicKey: ca.publicKey,
    members: mirrors,
    threshold: 2,
    policyHash: c.random(64),
    rtmHash: c.random(64),
    membershipEpoch: 1,
  };
  const result = m.verifyMTC(certificate, options);
  assert.equal(result.mode, 'STANDALONE');
  assert.throws(() => m.verifyMTC(certificate, { ...options, threshold: 3 }), /QUORUM/);
  assert.throws(
    () =>
      m.verifyMTC(certificate, {
        ...options,
        revokedRanges: [{ logNumber: 65535, start: 0, end: 1 }],
      }),
    /REVOKED/,
  );
  const landmark = p.certificateFromTBS(
    tbs,
    p.OID.mtc,
    m.encodeProof({ start: 0, end: 1, inclusion: [] }),
  );
  assert.equal(
    m.verifyMTC(landmark, {
      ...options,
      trustedSubtrees: [
        {
          ...options,
          logNumber: 65535,
          start: 0,
          end: 1,
          root: result.root,
          mode: 'LIVE',
          validFrom: c.now() - 1,
          expiresAt: c.now() + 60,
        },
      ],
    }).mode,
    'LANDMARK',
  );
  assert.throws(() => m.verifyMTC(landmark, { ...options, trustedSubtrees: [] }), /QUORUM/);
});
for (const aead of ['AES-256-GCM', 'AES-256-KW', 'AES-256-KWP'])
  test(`${aead} metadata-bound PRF wrapper`, () => {
    const h = v.wrapperHeader({
        trustDomainID: c.random(),
        subjectID: c.random(),
        credentialIDHash: c.random(),
        rpID: 'example.org',
        purpose: 'ACCOUNT_WRAP',
        contextID: c.random(),
        aead,
      }),
      prf = c.random(),
      root = c.random(),
      w = v.wrapRoot(prf, root, h);
    assert(c.equal(v.unwrapRoot(prf, w), root));
    assert.throws(() => v.unwrapRoot(c.random(), w));
    w.header.rpID = 'attacker.example';
    assert.throws(() => v.unwrapRoot(prf, w));
  });
test('vault chunk ordering and final length are authenticated', () => {
  const root = c.random(),
    data = c.random(5000),
    e = v.encryptVault(root, data, { chunkSize: 1024 });
  assert(c.equal(v.decryptVault(root, e), data));
  [e.chunks[0], e.chunks[1]] = [e.chunks[1], e.chunks[0]];
  assert.throws(() => v.decryptVault(root, e));
});
test('RFC9629/RFC9936 multi-recipient AuthEnvelopedData', () => {
  const recipients = ['ml-kem-768', 'ml-kem-1024'].map((a) => ({
      ...c.generate(a),
      subjectKeyIdentifier: c.random(),
    })),
    data = c.random(1024),
    envelope = v.encryptCMS(data, recipients);
  for (const r of recipients) assert(c.equal(v.decryptCMS(envelope, r), data));
  envelope[envelope.length - 1] ^= 1;
  assert.throws(() => v.decryptCMS(envelope, recipients[0]));
});
test('direct KEM possession binds audience and challenge ciphertext', () => {
  const k = c.generate('ml-kem-768'),
    { challenge, expected } = v.kemChallenge(k.publicKey, {
      subjectID: c.random(),
      audience: 'https://ra.example',
    });
  assert(
    c.equal(
      expected,
      v.answerKEMChallenge(k.privateKey, challenge, { audience: 'https://ra.example' }),
    ),
  );
  assert.throws(() =>
    v.answerKEMChallenge(k.privateKey, challenge, { audience: 'https://evil.example' }),
  );
});
test('ACB persists single dispatch before signing, replay returns saved result, lost result stays unknown', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord-test-'));
  const path = join(directory, 'journal.sqlite');
  let journal = new s.Journal(path);
  let calls = 0;
  const f = fixture(),
    tbs = c.random(90),
    audience = 'provider:test';
  const a = s.activationContext({
    trustDomainID: c.random(),
    simHash: c.random(64),
    tbs,
    publicKey: f.key.publicKey,
    certificateID: p.parseCertificate(f.certificate).certificateID,
    certificateRepresentationHash: c.sha512(f.certificate),
    transactionID: c.random(),
    policyHash: c.random(64),
    origin: 'https://example.org',
    rpID: 'example.org',
    audience,
  });
  const permit = s.issuePermit(a, {
    certificate: f.certificate,
    privateKey: f.key.privateKey,
    activationEvidenceHash: c.random(64),
    proofMode: 'HUMAN_WEBAUTHN',
  });
  const backend = {
    id: 'test-software',
    capabilities: async () => ({ publicKey: f.key.publicKey, kal: 1 }),
    sign: async ({ tbs }) => {
      calls++;
      return c.sign(tbs, f.key.privateKey);
    },
  };
  const args = {
    permitCertificate: f.certificate,
    receiptCertificate: f.certificate,
    receiptKey: f.key.privateKey,
    audience,
    backend,
    authorize: async () => true,
  };
  try {
    let gateway = new s.SigningGateway({ journal, ...args });
    const r = await gateway.execute({ permit, tbs, keyRef: 'test-key' });
    await gateway.execute({ permit, tbs, keyRef: 'test-key' });
    assert.equal(calls, 1);
    assert(c.verify(tbs, r.signature, f.key.publicKey));
    journal.close();
    journal = new s.Journal(path);
    gateway = new s.SigningGateway({ journal, ...args });
    await gateway.execute({ permit, tbs, keyRef: 'test-key' });
    assert.equal(calls, 1);
    const a2 = { ...a, operationID: c.random() },
      p2 = s.issuePermit(a2, {
        certificate: f.certificate,
        privateKey: f.key.privateKey,
        activationEvidenceHash: c.random(64),
        proofMode: 'HUMAN_WEBAUTHN',
      });
    backend.sign = async () => {
      calls++;
      throw Error('connection lost after device execution');
    };
    await assert.rejects(gateway.execute({ permit: p2, tbs, keyRef: 'test-key' }));
    await assert.rejects(
      gateway.execute({ permit: p2, tbs, keyRef: 'test-key' }),
      /UNKNOWN_EXECUTION/,
    );
    assert.equal(calls, 2);
  } finally {
    journal.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
test('trust LIVE watermark, historical reads, fork and stale decisions', () => {
  const j = new s.Journal(),
    k = c.generate('ml-dsa-87'),
    store = new s.TrustStore(j, { domain: 'example', pins: [k.publicKey], threshold: 1 }),
    ts = c.now();
  const manifest = {
    trustDomainID: 'example',
    serial: 2,
    issuedAt: ts - 10,
    notBefore: ts - 10,
    notAfter: ts + 60,
  };
  const sig = (m) => [
    { keyID: c.keyID(k.publicKey), signature: c.sign(c.D('RootTrustManifest', m), k.privateKey) },
  ];
  try {
    store.accept(manifest, sig(manifest));
    const old = { ...manifest, serial: 1 };
    store.accept(old, sig(old), { mode: 'HISTORICAL' });
    assert.throws(() => store.accept(old, sig(old)), /STALE/);
    const fork = { ...manifest, notAfter: ts + 59 };
    assert.throws(() => store.accept(fork, sig(fork)), /FORK/);
  } finally {
    j.close();
  }
});
test('recovery threshold graph catches indirect signing escrow', () => {
  const graph = {
    nodes: ['admin', 'backup', 'amk', 'sign'],
    edges: [
      { from: ['admin', 'backup'], threshold: 2, to: 'amk' },
      { from: ['amk'], threshold: 1, to: 'sign' },
    ],
  };
  s.assertRecoverySeparation(graph, ['admin'], ['sign']);
  assert.throws(() => s.assertRecoverySeparation(graph, ['admin', 'backup'], ['sign']), /ESCROW/);
  assert.equal(s.quorumProperties(3, 2, 1).forkPrevention, false);
  assert.equal(s.quorumProperties(4, 3, 1).forkPrevention, true);
});
