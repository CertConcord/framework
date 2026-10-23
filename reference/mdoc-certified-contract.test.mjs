import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { verifyIssuerSigned, issueMdoc } from './mdoc.mjs';
import { encode, decode, get } from './cose.mjs';
import { signCMS } from './pki.mjs';
import { verifyPersonalMdoc, SIGNER_NAMESPACE } from './signer-mdoc.mjs';
import { verifyDocumentEvidence, DOCUMENT_EVIDENCE_PROFILE } from './document-evidence.mjs';
import { publicJWK } from './jose.mjs';
import { readControl } from './state.mjs';

const clone = (value) => c.decodeCBOR(c.dcbor(value));
const uriCases = [
  ['HTTP', 'http://status.example/list'],
  ['relative', '/status/1'],
  ['userinfo', 'https://user:pass@status.example/list'],
  ['fragment', 'https://status.example/list#fragment'],
  ['empty-fragment', 'https://status.example/list#'],
  ['default-port', 'https://status.example:443/list'],
  ['uppercase-host', 'https://STATUS.example/list'],
  ['null', null],
  ['number', 7],
  ['array', ['https://status.example/list']],
];
const statusCases = [
  ...uriCases.map(([name, uri]) => [name, { status_list: { uri, idx: 0 } }]),
  ...[-1, '0', null].map((idx, i) => [
    'invalid-index-' + i,
    { status_list: { uri: 'https://issuer.example/status/1', idx } },
  ]),
  ['missing-status', null],
  ['missing-list', {}],
  [
    'extra-status-key',
    { status_list: { uri: 'https://issuer.example/status/1', idx: 0 }, extra: 1 },
  ],
  [
    'extra-reference-key',
    { status_list: { uri: 'https://issuer.example/status/1', idx: 0, extra: 1 } },
  ],
];

// Reissue complete credentials under the fixture's real issuer, seal and log keys.
// The HTTP wallet and signing operation are exercised by the original positive run.
async function withCredentials(callback) {
  await runFoundationDemo({
    activationMode: 'HUMAN_WEBAUTHN',
    trustedTime: true,
    onComplete: async (r) => {
      const trust = { ...r.credentialTrust, seal: r.seal, statusToken: r.issuer.status.token() };
      const original = verifyPersonalMdoc(r.credential, trust);
      const originalSeal = readControl(r.seal, 'MdocCredentialSeal', trust.sealCertificate);
      const status = original.claims.status;
      const issue = (edit, selectedStatus = status) => {
        const claims = clone(original.claims);
        edit(claims);
        claims.status = selectedStatus;
        // Use the lower-level issuer primitive to model a dishonest but authorized issuer.
        // No production admission guard is disabled or replaced.
        const credential = issueMdoc({
          claims,
          holderJWK: publicJWK(c.publicFromDER(r.binding.holderSPKI)),
          certificate: r.issuer.certificate,
          privateKey: r.issuer.privateKey,
          docType: r.issuer.mdocDocType,
          namespace: SIGNER_NAMESPACE,
          certificateProfile: r.issuer.certificateProfile,
          validUntil: originalSeal.expiresAt,
        });
        const issuerAuth = encode(get(decode(credential), 'issuerAuth'));
        const credentialID = c.H('MdocIssuerAuth', issuerAuth);
        const logProof = r.issuer.credentialLog.append({
          schemaVersion: 1,
          trustDomainID: claims.trust_domain_id,
          credentialID,
          raAuthorizationHash: claims.ra_authorization_hash,
          documentKeyID: claims.signing_key_id,
          policyHash: claims.policy_hash,
        });
        const seal = signCMS(
          {
            certificate: r.issuer.sealCertificate,
            content: c.D('MdocCredentialSeal', {
              ...originalSeal,
              credentialID,
              issuerAuthHash: c.sha512(issuerAuth),
              logProof,
            }),
          },
          r.issuer.sealKey,
        );
        const selectedTrust = { ...trust, seal };
        const math = verifyIssuerSigned(credential, {
          issuerKey: trust.issuerPublicKey,
          certificate: trust.issuerCertificate,
          docType: trust.docType,
          allowPartial: false,
        });
        assert(math.claims.get(SIGNER_NAMESPACE));
        assert(readControl(seal, 'MdocCredentialSeal', trust.sealCertificate));
        return { credential, trust: selectedTrust };
      };
      await callback(r, issue);
    },
  });
}

test('signed native mdoc status references reject malformed contracts before authority resolution', async (t) => {
  await withCredentials(async (_r, issue) => {
    for (const [name, status] of statusCases)
      await t.test(name, () => {
        const item = issue(() => {}, status);
        let calls = 0;
        assert.throws(
          () =>
            verifyPersonalMdoc(item.credential, {
              ...item.trust,
              statusURI: status?.status_list?.uri,
              authorityResolver: () => {
                calls++;
                throw Error('must not resolve malformed reference');
              },
            }),
          { code: 'MDOC_STATUS_REFERENCE' },
        );
        assert.equal(calls, 0);
      });
    for (const idx of [0.5, Number.MAX_SAFE_INTEGER + 1])
      await t.test('issuer cannot encode non-safe-integer index ' + idx, () => {
        assert.throws(
          () => issue(() => {}, { status_list: { uri: 'https://issuer.example/status/1', idx } }),
          { code: 'CBOR_INTEGER' },
        );
      });
    await t.test('valid URI remains externally pinned', () => {
      const item = issue(() => {}, {
        status_list: { uri: 'https://issuer.example/status/1', idx: 0 },
      });
      assert.throws(
        () =>
          verifyPersonalMdoc(item.credential, {
            ...item.trust,
            statusURI: 'https://other.example/list',
          }),
        { code: 'PERSONAL_MDOC_STATUS' },
      );
      const result = verifyPersonalMdoc(item.credential, item.trust);
      assert.equal(result.statusAssessment.overall, 'VALID');
      assert.deepEqual(result.claims.status.status_list, {
        uri: 'https://issuer.example/status/1',
        idx: 0,
      });
    });
  });
});

test('DOCUMENT requires distinct authenticated CMS-byte and RA-body commitments', async (t) => {
  await withCredentials(async (r, issue) => {
    const values = Object.fromEntries(r.bundle.objects.map(({ type, payload }) => [type, payload]));
    const body = readControl(
      values.RegistrationAuthorization,
      'RegistrationAuthorization',
      r.ra.certificate,
    );
    const input = {
      format: 'MDOC',
      values,
      sim: c.decodeCBOR(values.SIM),
      policy: {
        documentEvidence: { profile: DOCUMENT_EVIDENCE_PROFILE, organizationAuthorization: false },
        requireTrustedTime: false,
      },
      receipt: readControl(values.ExecutionReceipt, 'ExecutionReceipt', r.trust.receiptCertificate),
      knowledgeTime: c.now(),
    };
    const check = (edit) => {
      const item = issue(edit);
      const credential = verifyPersonalMdoc(item.credential, item.trust);
      return () => verifyDocumentEvidence({ ...input, credential }, r.trust);
    };
    const expected = {
      time: 'DECLARED_EXECUTION_TIME',
      stateTime: input.receipt.executedAt,
      subjectBinding: 'NATIVE_MDOC',
    };
    assert.deepEqual(check(() => {})(), expected);
    for (const [name, edit] of [
      [
        'missing-body',
        (claims) => {
          delete claims.ra_authorization_commitment;
        },
      ],
      [
        'null-body',
        (claims) => {
          claims.ra_authorization_commitment = null;
        },
      ],
      [
        'short-body',
        (claims) => {
          claims.ra_authorization_commitment = Buffer.alloc(63);
        },
      ],
      [
        'hex-text-body',
        (claims) => {
          claims.ra_authorization_commitment = c
            .H('RegistrationAuthorization', body)
            .toString('hex');
        },
      ],
      [
        'CMS-hash-as-body',
        (claims) => {
          claims.ra_authorization_commitment = c.sha512(values.RegistrationAuthorization);
        },
      ],
      [
        'different-authenticated-body',
        (claims) => {
          claims.ra_authorization_commitment = c.H('RegistrationAuthorization', {
            ...body,
            identityAssurance: 'DIFFERENT',
          });
        },
      ],
      [
        'body-hash-as-CMS',
        (claims) => {
          claims.ra_authorization_hash = c.H('RegistrationAuthorization', body);
        },
      ],
    ])
      await t.test(name, () =>
        assert.throws(check(edit), { code: 'DOCUMENT_REGISTRATION_BINDING' }),
      );
    await t.test('unselected DOCUMENT retains the separate DCP contract', () => {
      const item = issue((claims) => {
        delete claims.ra_authorization_commitment;
      });
      const credential = verifyPersonalMdoc(item.credential, item.trust);
      assert.deepEqual(verifyDocumentEvidence({ ...input, policy: {}, credential }, r.trust), {
        subjectBinding: 'REGISTRATION_AUTHORIZATION',
      });
    });
  });
});

import { loadVectorCorpus } from './verify-vectors.mjs';
import { createAuthorityResolver } from './authority-history.mjs';

const corpus = loadVectorCorpus();
const certifiedVectors = corpus.config('certified-contract.json');
assert.equal(certifiedVectors.schemaVersion, 1);
assert.equal(certifiedVectors.profile, 'certconcord-mdoc-certified-contract-draft-03-v1');
assert.deepEqual(
  certifiedVectors.cases.map((row) => row.id),
  [
    ...statusCases.map(([name]) => 'status-' + name.toLowerCase()),
    'credential-valid',
    'missing-body',
    'null-body',
    'short-body',
    'hex-text-body',
    'cms-hash-as-body',
    'different-body',
    'body-hash-as-cms',
    'document-valid',
    'dcp-without-document-commitment',
  ],
);
for (const row of certifiedVectors.cases) {
  test('published signed mdoc contract: ' + row.id, () => {
    const input = corpus.config(row.trust),
      trust = {
        ...input.trust,
        at: row.at,
        knowledgeTime: row.at,
        seal: row.seal,
        statusToken: row.statusToken,
        statusURI: row.selectedStatusURI,
        authorityResolver: createAuthorityResolver({
          trustDomainID: input.trust.trustDomainID,
          authorities: input.authorities,
        }),
      };
    const authenticated = verifyIssuerSigned(row.credential, {
      issuerKey: trust.issuerPublicKey,
      certificate: trust.issuerCertificate,
      docType: trust.docType,
      at: row.at,
      allowPartial: false,
    });
    assert(authenticated.claims.get(SIGNER_NAMESPACE));
    const registration = readControl(
      row.registration,
      'RegistrationAuthorization',
      trust.raCertificate,
    );
    assert.equal(registration.schemaVersion, 2);
    const action = () => {
      const credential = verifyPersonalMdoc(row.credential, trust);
      if (row.mode === 'credential') return { status: credential.statusAssessment.overall };
      assert(['document', 'dcp'].includes(row.mode));
      return {
        result: verifyDocumentEvidence(
          {
            format: 'MDOC',
            credential,
            values: { RegistrationAuthorization: row.registration },
            sim: row.sim,
            receipt: row.receipt,
            knowledgeTime: row.at,
            policy:
              row.mode === 'dcp'
                ? {}
                : {
                    documentEvidence: {
                      profile: DOCUMENT_EVIDENCE_PROFILE,
                      organizationAuthorization: false,
                    },
                    requireTrustedTime: false,
                  },
          },
          trust,
        ),
      };
    };
    if (row.id.startsWith('status-')) {
      assert.deepEqual(row.expected, { outcome: 'THREW', code: 'MDOC_STATUS_REFERENCE' });
    } else if (
      [
        'missing-body',
        'null-body',
        'short-body',
        'hex-text-body',
        'cms-hash-as-body',
        'different-body',
        'body-hash-as-cms',
      ].includes(row.id)
    ) {
      assert.deepEqual(row.expected, { outcome: 'THREW', code: 'DOCUMENT_REGISTRATION_BINDING' });
    } else assert.equal(row.expected.outcome, 'RETURNED');
    if (row.expected.outcome === 'THREW') assert.throws(action, { code: row.expected.code });
    else assert.deepEqual({ outcome: 'RETURNED', ...action() }, row.expected);
  });
}
