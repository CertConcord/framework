import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, readControl } from './state.mjs';
import {
  createCSR,
  verifyCSR,
  issueRAR,
  RegistrationAuthority,
  AuthorizedIssuer,
} from './enrollment.mjs';
import { MTCIssuer } from './issuance.mjs';
import { Mirror, createMTCTBS, issueMTC, logEntryFromTBS, verifyMTC } from './mtc.mjs';
import { PersonalMdocCA, verifyPersonalMdoc } from './signer-mdoc.mjs';
import { CredentialIssuer, verifyStatusList } from './openid.mjs';
import { OpenIDWallet } from './wallet.mjs';
import { MDOC_CONFIG } from './mdoc.mjs';
import { verifyDocumentEvidence } from './document-evidence.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { PasskeySigningRegistry } from './passkey-credentials.mjs';

const profileID = 'CERTCONCORD-PERSON-SIGN-v1';

function fixture(t, representation, { statusURI } = {}) {
  const journals = [],
    journal = () => {
      const value = new Journal();
      journals.push(value);
      return value;
    };
  t.after(() => journals.forEach((value) => value.close()));
  const root = c.generate('ml-dsa-87'),
    raKey = c.generate('ml-dsa-87'),
    issuerKey = c.generate(representation === 'MDOC' ? 'ec' : 'ml-dsa-87'),
    documentKey = c.generate('ml-dsa-87'),
    holder = c.generate('ec');
  const certificate = (key, serial) =>
    p.issueCertificate(
      {
        publicKey: key.publicKey,
        serial,
        issuer: p.name('Synthetic registration root'),
        subject: p.name('Synthetic authority ' + serial),
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      root.privateKey,
    );
  const ra = { ...raKey, certificate: certificate(raKey, 1) },
    issuerCertificate = certificate(issuerKey, 2),
    scope = {
      trustDomainID: c.random(),
      issuerID: representation === 'MDOC' ? 'https://issuer.example' : '32473.10',
      issuerKeyID: c.keyID(issuerKey.publicKey),
      representation,
    },
    csr = createCSR({ ...documentKey, subject: p.name('Synthetic registered subject') }),
    body = {
      schemaVersion: 2,
      requestID: c.random(),
      subjectID: c.random(),
      profileID,
      policyHash: c.random(64),
      identityEvidenceHash: c.random(64),
      issuanceScope: scope,
      spkiHash: c.sha512(c.spki(documentKey.publicKey)),
      csrHash: c.sha512(csr),
      possessionMode: verifyCSR(csr).possessionMode,
      issuedAt: c.now(),
      expiresAt: c.now() + 120,
      ...(representation === 'MDOC'
        ? {
            trustDomainID: scope.trustDomainID,
            audience: scope.issuerID,
            credentialFormat: 'mso_mdoc',
            identityAssurance: 'SYNTHETIC',
          }
        : {}),
    },
    members = [0, 1, 2].map((i) => ({
      id: '32473.' + (20 + i),
      operatorID: 'schema-mirror-' + i,
      ...c.generate('ml-dsa-87'),
    })),
    authorityResolver = exampleAuthorityResolver({
      trustDomainID: scope.trustDomainID,
      authorities: [
        { certificate: ra.certificate, roles: ['REGISTRATION_AUTHORITY'] },
        { certificate: issuerCertificate, roles: ['ISSUER'] },
        ...members.map((member) => ({
          mode: 'RAW_KEY',
          publicKeyDER: c.spki(member.publicKey),
          roles: ['COSIGNER'],
          knownAt: c.now() - 60,
          validFrom: c.now() - 60,
          validUntil: c.now() + 86400,
        })),
      ],
    }),
    mtcTrust = {
      caID: scope.issuerID,
      caPublicKey: issuerKey.publicKey,
      members,
      threshold: 2,
      policyHash: body.policyHash,
      rtmHash: c.random(64),
      membershipEpoch: 1,
      profileID,
    },
    issuerJournal = journal(),
    common = {
      journal: issuerJournal,
      raCertificate: ra.certificate,
      privateKey: issuerKey.privateKey,
      issuerCertificate,
      policyHash: body.policyHash,
      allowedProfiles: [profileID],
      issuanceScope: scope,
      authorityResolver,
    };
  // Explicit, independently authored control content; neither authorization
  // producer is used to construct these positive and negative CMS inputs.
  const raw = (schemaVersion) =>
    p.signCMS(
      {
        certificate: ra.certificate,
        content: c.D('RegistrationAuthorization', { ...body, schemaVersion }),
      },
      ra.privateKey,
    );
  let issuer;
  if (representation === 'X509')
    issuer = new AuthorizedIssuer({ ...common, issuer: p.name(scope.issuerID) });
  else if (representation === 'MTC')
    issuer = new MTCIssuer({
      ...common,
      ...mtcTrust,
      logNumber: 1,
      mirrors: members.map(
        (member) =>
          new Mirror({ journal: journal(), id: member.id, privateKey: member.privateKey }),
      ),
    });
  else {
    const binding = {
      trustDomainID: scope.trustDomainID,
      subjectID: body.subjectID,
      policyHash: body.policyHash,
      documentKeyID: c.keyID(documentKey.publicKey),
      holderSPKI: c.spki(holder.publicKey),
      profileID,
      keyAdmission: { type: 'SYNTHETIC' },
    };
    issuer = new PersonalMdocCA({
      ...common,
      issuer: scope.issuerID,
      statusURI,
      certificate: issuerCertificate,
      sealCertificate: ra.certificate,
      sealKey: ra.privateKey,
      credentialLog: { journal: journal() },
      credentialLogTrust: {},
      bindings: { active: () => binding, qualificationClaims: () => ({}) },
    });
  }
  const issue = (bytes) =>
    representation === 'MDOC'
      ? issuer.offer({ csr, rar: bytes, bindingID: Buffer.alloc(32, 1) })
      : issuer.issue({ csr, rar: bytes });
  const namespaces =
    representation === 'MDOC'
      ? ['offers', 'personal-mdoc-approval', 'personal-mdoc-rar']
      : representation === 'MTC'
        ? ['mtc-issuance']
        : ['issuance'];
  const allocated = () => namespaces.map((name) => issuerJournal.list(name));
  const offline = (schemaVersion) => {
    const bytes = raw(schemaVersion),
      request = readControl(bytes, 'RegistrationAuthorization', ra.certificate),
      options = {
        publicKey: documentKey.publicKey,
        subject: p.name('Synthetic registered subject'),
        profileID,
        extraExtensions: [
          p.extension(
            p.RRA['id-pe-certconcordAuthorizationID'],
            c.octet(c.H('RegistrationAuthorization', request)),
          ),
        ],
      };
    let credential, cert;
    if (representation === 'MDOC') {
      // verifyDocumentEvidence receives an already authenticated credential.
      // Bind the exact CMS hash here to isolate its authorization version gate.
      credential = {
        publicKey: documentKey.publicKey,
        credentialIssuedAt: body.issuedAt,
        claims: { ra_authorization_hash: c.sha512(bytes) },
      };
    } else if (representation === 'MTC') {
      const tbs = createMTCTBS(options, { caID: scope.issuerID, logNumber: 1, index: 0 });
      cert = issueMTC(tbs, {
        entries: [logEntryFromTBS(tbs)],
        index: 0,
        caID: scope.issuerID,
        logNumber: 1,
        cosigners: [{ id: scope.issuerID, ...issuerKey }, ...members],
      });
      assert.equal(verifyMTC(cert, mtcTrust).mode, 'STANDALONE');
    } else {
      cert = p.issueCertificate(
        { ...options, issuer: p.name(scope.issuerID), serial: 100 },
        issuerKey.privateKey,
      );
      p.validateCertificate(cert, issuerKey.publicKey, { profileID });
    }
    return () =>
      verifyDocumentEvidence(
        {
          format: representation === 'MDOC' ? 'MDOC' : 'CMS',
          values: { RegistrationAuthorization: bytes, ...(cert ? { Certificate: cert } : {}) },
          sim: {
            trustDomainID: scope.trustDomainID,
            subjectID: body.subjectID,
            profileID,
            policyHash: body.policyHash,
          },
          policy: {},
          receipt: { executedAt: body.issuedAt },
          knowledgeTime: body.issuedAt,
          credential,
        },
        { raCertificate: ra.certificate, issuanceScope: scope, authorityResolver },
      );
  };
  return {
    body,
    raw,
    ra,
    csr,
    journal,
    authorityResolver,
    scope,
    issuer,
    issue,
    allocated,
    offline,
  };
}

for (const representation of ['X509', 'MTC', 'MDOC']) {
  test(`${representation} issuance accepts independently signed schema2 authorization bytes`, async (t) => {
    const f = fixture(t, representation),
      bytes = f.raw(2);
    assert.equal(
      readControl(bytes, 'RegistrationAuthorization', f.ra.certificate).schemaVersion,
      2,
    );
    const issued = await f.issue(bytes);
    assert(issued);
    assert.deepEqual(c.dcbor(await f.issue(bytes)), c.dcbor(issued));
    assert.equal(f.allocated()[0].length, 1);
  });
  test(`${representation} issuance rejects authenticated schema1 before allocating state`, async (t) => {
    const f = fixture(t, representation),
      before = f.allocated(),
      bytes = f.raw(1);
    assert.equal(
      readControl(bytes, 'RegistrationAuthorization', f.ra.certificate).schemaVersion,
      1,
    );
    await assert.rejects(async () => f.issue(bytes), { code: 'ISSUANCE_AUTHORIZATION' });
    assert.deepEqual(f.allocated(), before);
  });
  test(`${representation} offline binding accepts schema2 with matching cryptographic commitments`, (t) => {
    assert.deepEqual(fixture(t, representation).offline(2)(), {
      subjectBinding: 'REGISTRATION_AUTHORIZATION',
    });
  });
  test(`${representation} offline binding rejects schema1 despite matching cryptographic commitments`, (t) => {
    assert.throws(fixture(t, representation).offline(1), { code: 'DOCUMENT_REGISTRATION_BINDING' });
  });
}

test('RAR producer accepts schema2 and rejects schema1', (t) => {
  const f = fixture(t, 'X509');
  assert.equal(
    readControl(issueRAR(f.body, f.ra), 'RegistrationAuthorization', f.ra.certificate)
      .schemaVersion,
    2,
  );
  assert.throws(() => issueRAR({ ...f.body, schemaVersion: 1 }, f.ra), { code: 'RAR_FIELDS' });
});

test('CSR registration authority emits schema2', async (t) => {
  const f = fixture(t, 'X509'),
    ra = new RegistrationAuthority({
      ...f.ra,
      journal: f.journal(),
      approve: async () => ({ approved: true }),
    });
  const bytes = await ra.authorize({
    csr: f.csr,
    subjectID: f.body.subjectID,
    profileID,
    policyHash: f.body.policyHash,
    identityEvidenceHash: f.body.identityEvidenceHash,
    issuanceScope: f.scope,
  });
  assert.equal(readControl(bytes, 'RegistrationAuthorization', f.ra.certificate).schemaVersion, 2);
});

test('identity registration authority emits schema2 for a complete native mdoc document', async () => {
  await runFoundationDemo({
    activationMode: 'HUMAN_WEBAUTHN',
    onComplete: async (result) => {
      assert.equal(
        readControl(result.enrollment.rar, 'RegistrationAuthorization', result.ra.certificate)
          .schemaVersion,
        2,
      );
      assert.equal(result.verification.overall, 'VALID_UNDER_POLICY');
      const certified = verifyPersonalMdoc(result.credential, {
        ...result.credentialTrust,
        seal: result.seal,
        statusToken: result.issuer.status.token(),
      });
      const registration = readControl(
        result.enrollment.rar,
        'RegistrationAuthorization',
        result.ra.certificate,
      );
      assert.deepEqual(certified.claims.ra_authorization_hash, c.sha512(result.enrollment.rar));
      assert.deepEqual(
        certified.claims.ra_authorization_commitment,
        c.H('RegistrationAuthorization', registration),
      );
      assert.equal(certified.claims.status.status_list.uri, 'https://issuer.example/status/1');
      assert.equal(result.wallet.statusURI, 'https://issuer.example/status/1');
      assert.equal(result.wallet.statusEndpoint, result.issuer.issuer + '/status/1');
      const calls = [];
      const receiver = {
        ...result.wallet,
        verifyCredentialExtension: undefined,
        post: async (path) => {
          calls.push(path);
          return { credentials: [{ credential: c.b64u(result.credential) }] };
        },
      };
      const received = await OpenIDWallet.prototype.receive.call(receiver, {
        transactionID: 'captured',
      });
      assert.equal(received.credential, c.b64u(result.credential));
      assert.deepEqual(calls, ['/deferred', '/notification']);
      calls.length = 0;
      await assert.rejects(
        () =>
          OpenIDWallet.prototype.receive.call(
            { ...receiver, statusURI: receiver.statusEndpoint },
            { transactionID: 'captured' },
          ),
        { code: 'CREDENTIAL_STATUS_URI' },
      );
      assert.deepEqual(calls, ['/deferred']);
    },
  });
});

for (const method of ['activate', 'activateMdoc']) {
  test(`Passkey ${method} rejects schema1 before consulting downstream admission`, (t) => {
    const f = fixture(t, 'X509'),
      admission = t.mock.fn(() => {
        throw new Error('Downstream admission reached');
      }),
      registry = {
        registrationAuthorityCertificate: f.ra.certificate,
        admitted: () => ({}),
        forIssuance: admission,
      };
    assert.throws(
      () =>
        PasskeySigningRegistry.prototype[method].call(registry, f.body.requestID, {
          rar: f.raw(1),
        }),
      { code: 'PASSKEY_RA_BINDING' },
    );
    assert.equal(admission.mock.callCount(), 0);
  });
}

test('active Passkey issuance rejects a retained schema1 authorization', (t) => {
  const f = fixture(t, 'X509'),
    binding = {
      csrHash: c.sha512(f.csr),
      subjectID: f.body.subjectID,
      policyHash: f.body.policyHash,
      profileID,
      documentSPKI: verifyCSR(f.csr).spki,
    },
    registry = {
      registrationAuthorityCertificate: f.ra.certificate,
      admitted: () => ({ state: 'ACTIVE', rar: f.raw(1), binding }),
    };
  assert.throws(
    () =>
      PasskeySigningRegistry.prototype.forIssuance.call(registry, f.body.requestID, {
        ...f.body,
        csr: f.csr,
      }),
    { code: 'PASSKEY_RA_BINDING' },
  );
});

const frozen = JSON.parse(
  readFileSync(new URL('./vectors/registration-authorization/contract.json', import.meta.url)),
);
assert.deepEqual(
  frozen.cases.map((entry) => entry.id),
  ['x509-schema2', 'x509-schema1', 'mtc-schema2', 'mtc-schema1', 'mdoc-schema2', 'mdoc-schema1'],
);
for (const entry of frozen.cases) {
  test(`frozen ${entry.id} bytes enforce the offline authorization contract`, () => {
    const { input, trust } = c.decodeCBOR(Buffer.from(entry.material, 'base64'));
    const body = readControl(
      input.values.RegistrationAuthorization,
      'RegistrationAuthorization',
      trust.raCertificate,
    );
    assert.equal(body.schemaVersion, entry.schemaVersion);
    assert.equal(input.knowledgeTime, frozen.at);
    if (input.credential) {
      input.credential.publicKey = c.publicFromDER(input.credential.publicKeyDER);
      assert.deepEqual(
        input.credential.claims.ra_authorization_hash,
        c.sha512(input.values.RegistrationAuthorization),
      );
    } else {
      const cert = p.parseCertificate(input.values.Certificate);
      assert.deepEqual(
        c.parseDER(cert.extensions.get(p.RRA['id-pe-certconcordAuthorizationID']).value).value,
        c.H('RegistrationAuthorization', body),
      );
    }
    trust.authorityResolver = exampleAuthorityResolver({
      at: frozen.at,
      trustDomainID: trust.issuanceScope.trustDomainID,
      authorities: [{ certificate: trust.raCertificate, roles: ['REGISTRATION_AUTHORITY'] }],
    });
    if (entry.schemaVersion === 2)
      assert.deepEqual(verifyDocumentEvidence(input, trust), {
        subjectBinding: 'REGISTRATION_AUTHORIZATION',
      });
    else
      assert.throws(() => verifyDocumentEvidence(input, trust), {
        code: 'DOCUMENT_REGISTRATION_BINDING',
      });
  });
}

test('personal mdoc offer retains separate CMS-byte and signed-body registration commitments', (t) => {
  const f = fixture(t, 'MDOC'),
    bytes = f.raw(2),
    offer = f.issue(bytes);
  const authenticated = readControl(bytes, 'RegistrationAuthorization', f.ra.certificate);
  const claims = f.issuer.journal.get('offers', offer.grants.authorization_code.issuer_state).value
    .claims;
  assert.deepEqual(claims.ra_authorization_hash, c.sha512(bytes));
  assert.deepEqual(
    claims.ra_authorization_commitment,
    c.H('RegistrationAuthorization', authenticated),
  );
  assert.notDeepEqual(claims.ra_authorization_commitment, claims.ra_authorization_hash);
  assert.deepEqual(c.dcbor(f.issue(bytes)), c.dcbor(offer));
  assert.deepEqual(
    f.allocated().map((rows) => rows.length),
    [1, 1, 1],
  );
});

test('credential issuer separates its signed HTTPS status URI from loopback transport', (t) => {
  const f = fixture(t, 'MDOC'),
    statusURI = 'https://status.example/credentials/1';
  const issuer = new CredentialIssuer({
    ...f.issuer,
    issuer: 'http://127.0.0.1:18080',
    statusURI,
    journal: f.journal(),
  });
  const status = issuer.status.allocate().status_list;
  assert.equal(status.uri, statusURI);
  assert.equal(issuer.statusURI, statusURI);
  assert.equal(issuer.metadata().credential_endpoint, 'http://127.0.0.1:18080/credential');
  assert.deepEqual(
    verifyStatusList(issuer.status.token(), {
      publicKey: p.parseCertificate(issuer.certificate).publicKey,
      uri: statusURI,
      index: status.idx,
    }),
    { status: 'GOOD', overall: 'VALID' },
  );
});

for (const [label, statusURI] of [
  ['HTTP', 'http://status.example/list'],
  ['relative', '/status/1'],
  ['user information', 'https://user:pass@status.example/list'],
  ['fragment', 'https://status.example/list#fragment'],
  ['empty fragment', 'https://status.example/list#'],
  ['default port', 'https://status.example:443/list'],
  ['uppercase host', 'https://STATUS.example/list'],
  ['empty', ''],
  ['null', null],
  ['number', 7],
  ['array', ['https://status.example/list']],
]) {
  test('personal mdoc issuer rejects a ' + label + ' status URI', (t) => {
    assert.throws(() => fixture(t, 'MDOC', { statusURI }), { code: 'MDOC_STATUS_REFERENCE' });
  });
}

test('personal mdoc issuer retains a canonical HTTPS status URI with a query', (t) => {
  const statusURI = 'https://status.example/list?tenant=one';
  const f = fixture(t, 'MDOC', { statusURI });
  assert.equal(f.issuer.status.uri, statusURI);
  assert.equal(f.issuer.statusURI, statusURI);
  const allocated = f.issuer.status.allocate().status_list;
  assert.equal(allocated.uri, statusURI);
  assert(Number.isSafeInteger(allocated.idx) && allocated.idx >= 0);
});

for (const preAuthorized of [false, true]) {
  test(
    'restarted personal issuer rejects stale registration commitments for ' +
      (preAuthorized ? 'pre-authorized' : 'authorization-code') +
      ' grants',
    async (t) => {
      for (const defect of ['missing', 'wrong'])
        await t.test(defect, (subtest) => {
          const f = fixture(subtest, 'MDOC'),
            bytes = f.raw(2);
          const request = {
            csr: f.csr,
            rar: bytes,
            bindingID: Buffer.alloc(32, 1),
            preAuthorized,
            ...(preAuthorized ? { txCode: '123456' } : {}),
          };
          const offer = f.issuer.offer(request);
          assert.deepEqual(c.dcbor(f.issuer.offer(request)), c.dcbor(offer));
          const id = preAuthorized
            ? offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
                'pre-authorized_code'
              ]
            : offer.grants.authorization_code.issuer_state;
          const saved = f.issuer.journal.get('offers', id);
          if (defect === 'missing') delete saved.value.claims.ra_authorization_commitment;
          else saved.value.claims.ra_authorization_commitment = Buffer.alloc(64);
          f.issuer.journal.put('offers', id, saved.value, saved.revision);
          const before = f.allocated();
          const restarted = new PersonalMdocCA({ ...f.issuer });
          assert.throws(() => restarted.offer(request), {
            code: 'PERSONAL_MDOC_REGISTRATION_COMMITMENT',
          });
          assert.throws(
            () => restarted.mint({ offer: saved.value, configurationID: MDOC_CONFIG }),
            {
              code: 'PERSONAL_MDOC_REGISTRATION_COMMITMENT',
            },
          );
          assert.deepEqual(f.allocated(), before);
          assert.deepEqual(f.issuer.journal.list('personal-mdoc'), []);
        });
    },
  );
}
