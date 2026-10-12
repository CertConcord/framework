import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, readControl } from './state.mjs';
import { createCSR, RegistrationAuthority, verifyCSR } from './enrollment.mjs';

function fixture(t, options = {}) {
  const journal = new Journal(),
    root = c.generate('ml-dsa-87'),
    raKey = c.generate('ml-dsa-87'),
    key = c.generate('ec'),
    certificate = p.issueCertificate(
      {
        publicKey: raKey.publicKey,
        issuer: p.name('Synthetic enrollment root'),
        subject: p.name('Synthetic enrollment RA'),
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      root.privateKey,
    ),
    request = {
      csr: createCSR({ subject: p.name('Approved subject'), ...key }),
      subjectID: c.random(),
      profileID: 'CERTCONCORD-PERSON-SIGN-v1',
      policyHash: c.random(64),
      identityEvidenceHash: c.random(64),
      issuanceScope: {
        trustDomainID: c.random(),
        issuerID: 'https://synthetic.example/issuer',
        issuerKeyID: c.keyID(root.publicKey),
        representation: 'X509',
      },
    },
    ra = new RegistrationAuthority({
      journal,
      certificate,
      privateKey: raKey.privateKey,
      approve: async () => ({ approved: true }),
      ...options,
    });
  t.after(() => journal.close());
  return { ra, request, read: (rar) => readControl(rar, 'RegistrationAuthorization', certificate) };
}

function expectedAuthorization(request) {
  const parsed = verifyCSR(request.csr);
  return {
    subjectID: Buffer.from(request.subjectID),
    profileID: request.profileID,
    policyHash: Buffer.from(request.policyHash),
    identityEvidenceHash: Buffer.from(request.identityEvidenceHash),
    csrHash: c.sha512(request.csr),
    spkiHash: c.sha512(parsed.spki),
    possessionMode: parsed.possessionMode,
    issuanceScope: c.decodeCBOR(c.dcbor(request.issuanceScope)),
  };
}

function assertAuthorization(actual, expected) {
  for (const [field, value] of Object.entries(expected))
    assert.deepEqual(actual[field], value, field);
}

for (const field of ['subjectID', 'policyHash', 'identityEvidenceHash', 'csr'])
  test('RA snapshots caller-owned ' + field + ' before asynchronous approval', async (t) => {
    const entered = Promise.withResolvers(),
      release = Promise.withResolvers(),
      f = fixture(t, {
        approve: async () => {
          entered.resolve();
          await release.promise;
          return { approved: true };
        },
      }),
      expected = expectedAuthorization(f.request),
      pending = f.ra.authorize(f.request);
    await entered.promise;
    f.request[field].fill(0x41);
    release.resolve();
    assertAuthorization(f.read(await pending), expected);
  });

for (const source of ['caller', 'approval'])
  for (const field of ['trustDomainID', 'issuerID', 'issuerKeyID', 'representation'])
    test(`RA isolates ${source} mutations to issuance scope ${field}`, async (t) => {
      const entered = Promise.withResolvers(),
        release = Promise.withResolvers(),
        mutate = (scope) => {
          if (Buffer.isBuffer(scope[field])) scope[field].fill(0x53);
          else scope[field] = field === 'representation' ? 'MTC' : 'https://other.example/issuer';
        },
        f = fixture(t, {
          approve: async (view) => {
            if (source === 'approval') mutate(view.issuanceScope);
            entered.resolve();
            await release.promise;
            return { approved: true };
          },
        }),
        expected = expectedAuthorization(f.request),
        pending = f.ra.authorize(f.request);
      await entered.promise;
      if (source === 'caller') mutate(f.request.issuanceScope);
      release.resolve();
      assertAuthorization(f.read(await pending), expected);
      if (source === 'approval') assertAuthorization(expectedAuthorization(f.request), expected);
    });

for (const [description, invalidScope, reason] of [
  ['missing', () => undefined, 'EXPECTED_MAP'],
  ['multiple', (scope) => [scope, scope], 'EXPECTED_MAP'],
  ['missing representation', ({ representation, ...scope }) => scope, 'MISSING_FIELD'],
  ['unknown field', (scope) => ({ ...scope, issuerAlias: scope.issuerID }), 'UNKNOWN_FIELD'],
  ['unknown representation', (scope) => ({ ...scope, representation: 'CMS' }), 'ISSUANCE_SCOPE'],
  ['wrong domain length', (scope) => ({ ...scope, trustDomainID: c.random(31) }), 'ISSUANCE_SCOPE'],
  [
    'wrong key identifier length',
    (scope) => ({ ...scope, issuerKeyID: c.random(32) }),
    'ISSUANCE_SCOPE',
  ],
])
  test(`RA rejects ${description} issuance scope before approval`, async (t) => {
    let approvals = 0;
    const f = fixture(t, {
      approve: async () => {
        approvals++;
        return { approved: true };
      },
    });
    f.request.issuanceScope = invalidScope(f.request.issuanceScope);
    await assert.rejects(f.ra.authorize(f.request), { code: reason });
    assert.equal(approvals, 0);
  });

for (const field of ['subjectID', 'policyHash', 'identityEvidenceHash', 'spki', 'possessionMode'])
  test(
    'RA separates the approval callback view of ' + field + ' from signed content',
    async (t) => {
      const f = fixture(t, {
        approve: async (view) => {
          // A policy integration may retain or mutate its view after deciding to approve it.
          if (field === 'spki') view.csr.spki.fill(0x42);
          else if (field === 'possessionMode') view.csr.possessionMode = 'SIGNED_STATEMENT';
          else view[field].fill(0x42);
          await Promise.resolve();
          return { approved: true };
        },
      });
      const expected = expectedAuthorization(f.request);
      assertAuthorization(f.read(await f.ra.authorize(f.request)), expected);
      assertAuthorization(expectedAuthorization(f.request), expected);
    },
  );

for (const source of ['registry', 'approval'])
  test('RA snapshots passkey admission values exposed by ' + source, async (t) => {
    const entered = Promise.withResolvers(),
      release = Promise.withResolvers(),
      admission = { binding: { bindingID: c.random() }, hash: c.random(64) },
      expectedID = Buffer.from(admission.binding.bindingID),
      expectedHash = Buffer.from(admission.hash),
      f = fixture(t, {
        keyBindings: { forIssuance: () => admission },
        approve: async (view) => {
          if (source === 'approval') view.keyBinding.bindingID.fill(0x43);
          entered.resolve();
          await release.promise;
          return { approved: true };
        },
      });
    f.request.profileID = 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1';
    f.request.keyBindingID = Buffer.from(expectedID);
    const expected = expectedAuthorization(f.request),
      pending = f.ra.authorize(f.request);
    await entered.promise;
    if (source === 'registry') {
      admission.binding.bindingID.fill(0x43);
      admission.hash.fill(0x44);
    }
    f.request.keyBindingID.fill(0x45);
    release.resolve();
    const rar = f.read(await pending);
    assertAuthorization(rar, expected);
    assert.deepEqual(rar.keyBindingID, expectedID);
    assert.deepEqual(rar.keyBindingHash, expectedHash);
  });

test('RA gives passkey admission a separate input view before CSR validation', async (t) => {
  const binding = { bindingID: c.random() },
    f = fixture(t, {
      keyBindings: {
        forIssuance: (id, view) => {
          id.fill(0x46);
          for (const field of ['csr', 'subjectID', 'policyHash', 'identityEvidenceHash'])
            view[field].fill(0x47);
          return { binding, hash: c.random(64) };
        },
      },
    });
  f.request.profileID = 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1';
  f.request.keyBindingID = c.random();
  const expected = expectedAuthorization(f.request),
    expectedID = Buffer.from(f.request.keyBindingID);
  assertAuthorization(f.read(await f.ra.authorize(f.request)), expected);
  assert.deepEqual(f.request.keyBindingID, expectedID);
});

test('RA isolates possession verification inputs and retained KEM evidence', async (t) => {
  const entered = Promise.withResolvers(),
    release = Promise.withResolvers(),
    evidence = { evidenceHash: c.random(64) },
    expectedEvidence = Buffer.from(evidence.evidenceHash),
    f = fixture(t, {
      kemPossession: {
        verify: (requestID, response, { subjectID }) => {
          requestID.fill(0x48);
          response.fill(0x49);
          subjectID.fill(0x50);
          return evidence;
        },
      },
      approve: async () => {
        entered.resolve();
        await release.promise;
        return { approved: true };
      },
    });
  f.request.profileID = 'CERTCONCORD-DOC-ENC-v1';
  f.request.kemProof = { requestID: c.random(), response: c.random() };
  const expected = expectedAuthorization(f.request),
    proof = c.decodeCBOR(c.dcbor(f.request.kemProof)),
    pending = f.ra.authorize(f.request);
  await entered.promise;
  evidence.evidenceHash.fill(0x51);
  release.resolve();
  const rar = f.read(await pending);
  assertAuthorization(rar, expected);
  assert.deepEqual(rar.kemPossessionEvidenceHash, expectedEvidence);
  assert.deepEqual(f.request.kemProof.requestID, proof.requestID);
  assert.deepEqual(f.request.kemProof.response, proof.response);
});

test('RA isolates the possession-certificate policy callback from verified CSR bytes', async (t) => {
  const f = fixture(t),
    subject = p.name('Approved subject'),
    kem = c.generate('ml-kem-768'),
    signer = c.generate('ml-dsa-87'),
    certificate = p.issueCertificate(
      { publicKey: signer.publicKey, issuer: subject, subject, serial: 2 },
      signer.privateKey,
    );
  f.request.csr = createCSR({
    subject,
    publicKey: kem.publicKey,
    privateKey: signer.privateKey,
    possessionCertificate: certificate,
  });
  const expected = c.sha512(f.request.csr);
  f.request.validatePossessionCertificate = (view) => {
    assert.deepEqual(view, certificate);
    view.fill(0x52);
    return true;
  };
  const rar = f.read(await f.ra.authorize(f.request));
  assert.deepEqual(rar.csrHash, expected);
  assert.deepEqual(rar.spkiHash, c.sha512(c.spki(kem.publicKey)));
  assert.equal(rar.possessionMode, 'SIGNED_STATEMENT');
});
