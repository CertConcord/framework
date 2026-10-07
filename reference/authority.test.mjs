import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as e from './enrollment.mjs';
import * as r from './revocation.mjs';
import {
  Journal,
  activationContext,
  issuePermit,
  evidenceObject,
  verifyEvidenceClosure,
} from './state.mjs';
import { EpochTransition, wrapperHeader, wrapRoot, answerKEMChallenge } from './protection.mjs';
import {
  SoftwareProvider,
  RemoteCryptoKey,
  RemoteCryptoKeyService,
  CSCProvider,
} from './providers.mjs';
import { readBody, sendJSON } from './transport.mjs';
import { parseJSON } from './json.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';

test('CRL and OCSP bind issuer, serial, nonce, publication interval and revocation', () => {
  const ca = c.generate('ml-dsa-87'),
    issuer = p.name('Synthetic Issuer'),
    serial = 19n,
    at = c.now();
  const crl = r.issueCRL({
    issuer,
    privateKey: ca.privateKey,
    number: 2n,
    entries: [{ serial, revokedAt: at, invalidityDate: at - 30, reason: 1 }],
  });
  assert.equal(
    r.verifyCRL(crl, { issuer, publicKey: ca.publicKey, serial, at: at - 10, knowledgeTime: at })
      .status,
    'REVOKED',
  );
  assert.throws(
    () => r.verifyCRL(crl, { issuer, publicKey: ca.publicKey, serial, minNumber: 3n }),
    /ROLLBACK/,
  );
  const q = r.ocspRequest({ issuer, issuerPublicKey: ca.publicKey, serial }),
    response = r.issueOCSP(q.raw, {
      issuer,
      issuerPublicKey: ca.publicKey,
      privateKey: ca.privateKey,
      records: new Map([[serial.toString(), { status: 'REVOKED', revokedAt: at - 30, reason: 1 }]]),
    });
  assert.equal(
    r.verifyOCSP(response, { request: q.raw, issuerPublicKey: ca.publicKey }).status,
    'REVOKED',
  );
  const q2 = r.ocspRequest({ issuer, issuerPublicKey: ca.publicKey, serial });
  assert.throws(
    () => r.verifyOCSP(response, { request: q2.raw, issuerPublicKey: ca.publicKey }),
    /NONCE/,
  );
  assert.throws(
    () => r.verifyOCSP(response, { request: q.raw, issuerPublicKey: ca.publicKey, at: at + 301 }),
    /STALE/,
  );
});
test('PKCS10 direct signing proof and RFC9883 signed KEM possession statement', () => {
  const holder = c.generate(),
    kem = c.generate('ml-kem-768'),
    ca = c.generate('ml-dsa-87'),
    subject = p.name('Synthetic Subject'),
    cert = p.issueCertificate(
      { publicKey: holder.publicKey, subject, issuer: p.name('Synthetic CA'), serial: 1 },
      ca.privateKey,
    );
  const csr = e.createCSR({ subject, publicKey: holder.publicKey, privateKey: holder.privateKey });
  assert.equal(e.verifyCSR(csr).possessionMode, 'DIRECT_SIGNATURE');
  const ks = e.createCSR({
    subject,
    publicKey: kem.publicKey,
    privateKey: holder.privateKey,
    possessionCertificate: cert,
  });
  const policy = (raw) => {
    p.validateCertificate(raw, ca.publicKey);
    return true;
  };
  assert.equal(
    e.verifyCSR(ks, { validatePossessionCertificate: policy }).possessionMode,
    'SIGNED_STATEMENT',
  );
  assert.throws(() => e.verifyCSR(ks, { validatePossessionCertificate: () => false }), /TRUST/);
  const wrong = e.createCSR({
    subject: p.name('Other Subject'),
    publicKey: kem.publicKey,
    privateKey: holder.privateKey,
    possessionCertificate: cert,
  });
  assert.throws(() => e.verifyCSR(wrong, { validatePossessionCertificate: policy }), /SUBJECT/);
});
test('RA decision and signed RAR bind issuer policy, profile, subject request and one issuance', async () => {
  const journal = new Journal(),
    ca = c.generate('ml-dsa-87'),
    ra = c.generate(),
    holder = c.generate(),
    issuer = p.name('Synthetic CA'),
    subject = p.name('Synthetic Subject'),
    certificate = p.issueCertificate(
      {
        publicKey: ra.publicKey,
        subject: p.name('Synthetic RA'),
        issuer,
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      ca.privateKey,
    ),
    policyHash = c.random(64),
    issuanceScope = {
      trustDomainID: c.random(),
      issuerID: 'https://synthetic.example/ca',
      issuerKeyID: c.keyID(ca.publicKey),
      representation: 'X509',
    },
    authorityResolver = exampleAuthorityResolver({
      trustDomainID: issuanceScope.trustDomainID,
      authorities: [
        { certificate, roles: ['REGISTRATION_AUTHORITY'] },
        {
          mode: 'RAW_KEY',
          publicKeyDER: c.spki(ca.publicKey),
          roles: ['ISSUER'],
          knownAt: c.now() - 60,
          validFrom: c.now() - 60,
          validUntil: c.now() + 86400,
        },
      ],
    }),
    csr = e.createCSR({ subject, publicKey: holder.publicKey, privateKey: holder.privateKey });
  try {
    const raService = new e.RegistrationAuthority({
        journal,
        certificate,
        privateKey: ra.privateKey,
        approve: async () => ({ approved: true }),
      }),
      rar = await raService.authorize({
        csr,
        subjectID: c.random(),
        profileID: 'CERTCONCORD-PERSON-SIGN-v1',
        policyHash,
        identityEvidenceHash: c.random(64),
        issuanceScope,
      }),
      service = new e.AuthorizedIssuer({
        journal,
        raCertificate: certificate,
        privateKey: ca.privateKey,
        issuer,
        policyHash,
        allowedProfiles: ['CERTCONCORD-PERSON-SIGN-v1'],
        issuanceScope,
        authorityResolver,
      }),
      cert = service.issue({ csr, rar });
    p.validateCertificate(cert, ca.publicKey, { profileID: 'CERTCONCORD-PERSON-SIGN-v1' });
    assert(c.equal(cert, service.issue({ csr, rar })));
    const other = e.createCSR({
      subject,
      publicKey: c.generate().publicKey,
      privateKey: holder.privateKey,
    });
    assert.throws(() => service.issue({ csr: other, rar }));
  } finally {
    journal.close();
  }
});
test('direct KEM challenge consumes once and rejects another subject', () => {
  const journal = new Journal(),
    kem = c.generate('ml-kem-768'),
    subjectID = c.random(),
    service = new e.KEMPossessionService({ journal, audience: 'https://ra.example' });
  try {
    const ch = service.challenge(kem.publicKey, { subjectID }),
      answer = answerKEMChallenge(kem.privateKey, ch, { audience: 'https://ra.example' });
    assert.throws(() =>
      service.verify(ch.context.requestID, answer, {
        subjectID: c.random(),
        publicKey: kem.publicKey,
      }),
    );
    assert.equal(
      service.verify(ch.context.requestID, answer, { subjectID, publicKey: kem.publicKey })
        .possessionMode,
      'DIRECT_PROOF',
    );
    assert.throws(() =>
      service.verify(ch.context.requestID, answer, { subjectID, publicKey: kem.publicKey }),
    );
  } finally {
    journal.close();
  }
});
test('epoch commit requires the same root and evidence closure hashes its dependencies', () => {
  const journal = new Journal(),
    oldPRF = c.random(),
    newPRF = c.random(),
    root = c.random(),
    h = wrapperHeader({
      trustDomainID: c.random(),
      subjectID: c.random(),
      credentialIDHash: c.random(),
      contextID: c.random(),
      rpID: 'example.org',
      purpose: 'ACCOUNT_WRAP',
    }),
    h2 = { ...h, epoch: 1, prfSalt: c.random(), kdfSalt: c.random(), wrapperID: c.random() },
    transition = new EpochTransition(journal);
  try {
    transition.prepare('good', {
      oldWrapper: wrapRoot(oldPRF, root, h),
      newWrapper: wrapRoot(newPRF, root, h2),
    });
    const revision = transition.commit('good', newPRF, oldPRF);
    transition.retire('good', revision);
    transition.prepare('bad', {
      oldWrapper: wrapRoot(oldPRF, root, h),
      newWrapper: wrapRoot(newPRF, c.random(), h2),
    });
    assert.throws(() => transition.commit('bad', newPRF, oldPRF), /ROOT_CHANGED/);
    const leaf = evidenceObject('Certificate', Buffer.from('original')),
      manifest = evidenceObject('Manifest', Buffer.from('plan'), [leaf.id]);
    assert.equal(verifyEvidenceClosure([leaf, manifest], [manifest.id]).closure, 'COMPLETE');
    assert.throws(
      () => verifyEvidenceClosure([leaf, { ...manifest, dependencies: [] }], [manifest.id]),
      /HASH/,
    );
  } finally {
    journal.close();
  }
});
test('Remote CryptoKey uses real signatures, signed permits and durable idempotency over HTTP', async () => {
  const journal = new Journal(),
    holder = c.generate(),
    authority = c.generate(),
    issuer = p.name('Synthetic Authority'),
    certificate = p.issueCertificate(
      {
        publicKey: authority.publicKey,
        issuer,
        subject: issuer,
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      authority.privateKey,
    ),
    auth = c.b64u(c.random()),
    trustDomainID = c.random(),
    authorityResolver = exampleAuthorityResolver({
      trustDomainID,
      authorities: [{ certificate, roles: ['PERMIT_AUTHORITY'] }],
    }),
    provider = new SoftwareProvider(new Map([['document-key', holder]])),
    service = new RemoteCryptoKeyService({
      provider,
      journal,
      permitCertificate: certificate,
      authorityResolver,
      audience: 'test-gateway',
      authorize: async ({ permit }) => {
        assert.equal(permit.proofMode, 'HUMAN_WEBAUTHN');
        return true;
      },
    }),
    server = createServer(async (req, res) => {
      try {
        c.requireThat(req.headers.authorization === 'Bearer ' + auth, 'AUTH');
        const data = parseJSON((await readBody(req)).toString('utf8'));
        sendJSON(res, 200, await service.handle(req.url.split('/').at(-1), data));
      } catch (error) {
        sendJSON(res, 400, { error: error.code ?? 'INVALID_REQUEST' });
      }
    });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const remote = new RemoteCryptoKey({
        url: 'http://127.0.0.1:' + server.address().port,
        token: auth,
        allowLoopback: true,
      }),
      tbs = Buffer.from('Frozen exact synthetic TBS'),
      a = activationContext({
        trustDomainID,
        tbs,
        publicKey: holder.publicKey,
        simHash: c.random(64),
        certificateID: c.random(64),
        certificateRepresentationHash: c.random(64),
        transactionID: c.random(),
        policyHash: c.random(64),
        origin: 'https://example.org',
        rpID: 'example.org',
        audience: 'test-gateway',
      }),
      permit = issuePermit(a, {
        certificate,
        privateKey: authority.privateKey,
        activationEvidenceHash: c.random(64),
        proofMode: 'HUMAN_WEBAUTHN',
      }),
      args = { keyRef: 'document-key', tbs, operationID: c.b64u(a.operationID), permit },
      signature = await remote.sign(args);
    assert(c.verify(tbs, signature, holder.publicKey));
    assert(c.equal(signature, await remote.sign(args)));
    assert.equal((await remote.getOperationResult(args.operationID)).status, 'COMPLETED');
    await assert.rejects(remote.sign({ ...args, tbs: Buffer.from('changed') }), /HTTP_400/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    journal.close();
  }
});
