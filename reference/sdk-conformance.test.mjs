import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, sign as nativeSign } from 'node:crypto';
import {
  dcbor,
  decodeCBOR,
  parseDER,
  seq,
  set,
  der,
  oid,
  now,
  ProtocolError,
  spki,
  equal,
} from './core.mjs';
import { OID } from './pki.mjs';
import { encode, decode, get, embedded, unembed } from './cose.mjs';
import { verifyIssuerSigned } from './mdoc.mjs';
import { SIGNER_DOCTYPE } from './signer-mdoc.mjs';
import { createEvidencePackage, evidenceLeaf } from './evidence-plan.mjs';
import { runDemo } from './demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { runDocumentDemo } from './document-demo.mjs';
import { createVerifier } from './sdk/index.mjs';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { readControl, activationContext, issuePermit } from './state.mjs';
import { createSignaturePackage } from './evidence.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';

const fixtures = new Map();
function fixture(format, trustedTime = false) {
  const id = `${format}/${trustedTime}`;
  if (!fixtures.has(id)) {
    let issuer, signStatus;
    const run = format === 'CMS' ? runDemo : runFoundationDemo;
    fixtures.set(
      id,
      run({
        activationMode: 'HUMAN_WEBAUTHN',
        trustedTime,
        onComplete: (result) => {
          issuer = result.issuer;
          signStatus = result.signStatus;
        },
      }).then((result) => ({ ...result, issuer, signStatus })),
    );
  }
  return fixtures.get(id);
}
const copy = (value) => decodeCBOR(dcbor(value));
const payload = (bundle, type) => bundle.objects.find((object) => object.type === type).payload;
function replace(bundle, type, value) {
  return createEvidencePackage(
    bundle.plan.profile,
    bundle.objects.map((object) => (object.type === type ? evidenceLeaf(type, value) : object)),
  );
}
function corrupt(bundle, type) {
  const bytes = Buffer.from(payload(bundle, type));
  bytes[bytes.length - 1] ^= 1;
  return replace(bundle, type, bytes);
}
const verdict = (format, f, bundle = f.bundle, trust = f.trust) =>
  createVerifier({ format, trust }).verify(dcbor(bundle));
function without(bundle, type) {
  return { ...bundle, objects: bundle.objects.filter((object) => object.type !== type) };
}
function mdocVariant(f, change, { badSignature = false } = {}) {
  const credential = decode(payload(f.bundle, 'PersonalMdoc'));
  const auth = get(credential, 'issuerAuth');
  const mso = unembed(decode(auth[2]));
  const headers = decode(auth[0]);
  change({ credential, auth, headers, mso });
  auth[0] = encode(headers);
  auth[2] = encode(embedded(mso));
  auth[3] = nativeSign('sha256', encode(['Signature1', auth[0], Buffer.alloc(0), auth[2]]), {
    key: f.issuer.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  if (badSignature) auth[3][0] ^= 1;
  return encode(credential);
}
function cmsAlgorithm(bundle, algorithm, { badSignature = false, digest = false } = {}) {
  const root = parseDER(payload(bundle, 'CMS'));
  const signedData = root.children[1].children[0].children.map((node) => Buffer.from(node.raw));
  const signer = parseDER(signedData[4]).children[0].children.map((node) => Buffer.from(node.raw));
  const alg = seq(oid(algorithm));
  if (digest) {
    signedData[1] = set(alg);
    signer[2] = alg;
  } else signer[4] = alg;
  if (badSignature) signer[5][signer[5].length - 1] ^= 1;
  signedData[4] = set(seq(...signer));
  return replace(bundle, 'CMS', seq(root.children[0].raw, der(0xa0, seq(...signedData))));
}

for (const format of ['CMS', 'MDOC']) {
  test(`${format} SDK returns stable identity and immutable evaluated dimensions`, async () => {
    const f = await fixture(format, true);
    const good = verdict(format, f);
    assert.equal(good.overall, 'VALID', good.reason);
    assert.equal(good.coreRevision, 'draft-03');
    assert.equal(good.profile, f.bundle.plan.profile);
    assert.equal(typeof good.reason, 'string');
    const dimensions = [
      'integrity',
      'issuerTrust',
      'qualification',
      'keyBinding',
      'authorization',
      'status',
      'time',
      'transparency',
    ];
    assert.deepEqual(Object.keys(good.dimensions).sort(), dimensions.sort());
    for (const dimension of dimensions) {
      assert.equal(good.dimensions[dimension].overall, 'VALID', dimension);
      assert.equal(typeof good.dimensions[dimension].reason, 'string');
      assert(Object.isFrozen(good.dimensions[dimension]));
    }
    assert(Object.isFrozen(good));
    assert(Object.isFrozen(good.dimensions));
    const missing = verdict(format, f, without(f.bundle, 'DocumentTimestamp'));
    assert.equal(missing.overall, 'INDETERMINATE');
    assert.equal(missing.profile, f.bundle.plan.profile);
    assert.equal(missing.dimensions.time.overall, 'INDETERMINATE');
    assert.notEqual(missing.dimensions.integrity?.overall, 'VALID');
    const unsupported = verdict(format, f, {
      ...f.bundle,
      plan: { ...f.bundle.plan, profile: 'urn:example:unknown-plan' },
    });
    assert.equal(unsupported.overall, 'UNSUPPORTED');
    assert.equal(unsupported.profile, 'urn:example:unknown-plan');
    assert.deepEqual(unsupported.dimensions, {});
    const malformed = createVerifier({ format, trust: f.trust }).verify(Buffer.from('not CBOR'));
    assert.equal(malformed.overall, 'INVALID');
    assert.equal(malformed.profile, null);
    assert.equal(malformed.coreRevision, 'draft-03');
    assert.equal(typeof malformed.reason, 'string');
  });

  test(`${format} supported leaf commitments precede unsupported semantics and missing evidence`, async () => {
    const f = await fixture(format);
    for (const mutate of [
      (bundle) => {
        bundle.schemaVersion = 3;
      },
      (bundle) => {
        bundle.plan.schemaVersion = 3;
      },
      (bundle) => {
        bundle.plan.profile = 'urn:example:unsupported';
      },
    ]) {
      const changed = copy(without(f.bundle, 'Document'));
      mutate(changed);
      assert.equal(verdict(format, f, changed).overall, 'UNSUPPORTED');
      changed.objects[0].payload[0] ^= 1;
      const invalid = verdict(format, f, changed);
      assert.equal(invalid.overall, 'INVALID');
      assert.equal(invalid.reason, 'ECP_HASH');
      assert.equal(invalid.dimensions.integrity.overall, 'INVALID');
    }
  });

  test(`${format} missing timestamp cannot hide an available invalid permit signature`, async () => {
    const f = await fixture(format, true);
    assert.equal(
      verdict(format, f, without(f.bundle, 'DocumentTimestamp')).overall,
      'INDETERMINATE',
    );
    const bad = without(corrupt(f.bundle, 'OperationPermit'), 'DocumentTimestamp');
    for (const objects of [bad.objects, [...bad.objects].reverse()]) {
      const result = verdict(format, f, { ...bad, objects });
      assert.equal(result.overall, 'INVALID');
      assert.equal(result.reason, 'CMS_SIGNATURE');
      assert.equal(result.dimensions.integrity.overall, 'INVALID');
    }
  });

  test(`${format} stale status does not erase completed document integrity`, async () => {
    const f = await fixture(format);
    const result = verdict(format, f, f.bundle, { ...f.trust, knowledgeTime: now() + 86400 });
    assert.equal(result.overall, 'INDETERMINATE');
    assert.equal(result.dimensions.status.overall, 'INDETERMINATE');
    assert.equal(result.dimensions.integrity.overall, 'VALID');
    assert.notEqual(result.dimensions.issuerTrust?.overall, 'VALID');
  });
}

test('native mdoc signed digest and version capability outcomes survive the SDK boundary', async () => {
  const f = await fixture('MDOC');
  for (const [reason, change] of [
    ['MDOC_VERSION_UNSUPPORTED', ({ mso }) => mso.set('version', '1.1')],
    [
      'MDOC_DIGEST_UNSUPPORTED',
      ({ credential, mso }) => {
        mso.set('digestAlgorithm', 'SHA-384');
        for (const [namespace, items] of get(credential, 'nameSpaces')) {
          const digests = new Map();
          for (const item of items)
            digests.set(
              get(unembed(item), 'digestID'),
              createHash('sha384').update(encode(item)).digest(),
            );
          get(mso, 'valueDigests').set(namespace, digests);
        }
      },
    ],
  ]) {
    const credential = mdocVariant(f, change);
    assert.throws(
      () =>
        verifyIssuerSigned(credential, {
          certificate: f.trust.issuerCertificate,
          issuerKey: f.trust.issuerPublicKey,
          docType: SIGNER_DOCTYPE,
          at: now(),
          allowPartial: false,
        }),
      (error) => error.overall === 'UNSUPPORTED' && error.code === reason,
    );
    const result = verdict('MDOC', f, replace(f.bundle, 'PersonalMdoc', credential));
    assert.equal(result.overall, 'UNSUPPORTED');
    assert.equal(result.reason, reason);
    assert.notEqual(result.dimensions.integrity?.overall, 'VALID');
    const bad = mdocVariant(f, change, { badSignature: true });
    const invalid = verdict('MDOC', f, replace(f.bundle, 'PersonalMdoc', bad));
    assert.equal(invalid.overall, 'INVALID');
    assert.equal(invalid.reason, 'COSE_SIGNATURE');
  }
});

test('native mdoc malformed capability discriminators remain invalid', async () => {
  const f = await fixture('MDOC');
  for (const change of [
    ({ headers }) => headers.delete(1),
    ({ headers }) => headers.set(1, null),
    ({ headers }) => headers.set(1, [-7]),
    ({ headers }) => headers.set(1, true),
    ({ mso }) => mso.set('version', 1),
    ({ mso }) => mso.set('version', null),
    ({ mso }) => mso.set('digestAlgorithm', null),
  ]) {
    const result = verdict('MDOC', f, replace(f.bundle, 'PersonalMdoc', mdocVariant(f, change)));
    assert.equal(result.overall, 'INVALID');
    assert.notEqual(result.reason, 'MALFORMED_EVIDENCE');
    assert.notEqual(result.dimensions.integrity?.overall, 'VALID');
  }
});

test('native mdoc unknown text algorithms are capabilities rather than malformed labels', async () => {
  const f = await fixture('MDOC');
  for (const algorithm of ['-7', 'urn:example:signature-algorithm']) {
    const credential = mdocVariant(f, ({ headers }) => headers.set(1, algorithm));
    const result = verdict('MDOC', f, replace(f.bundle, 'PersonalMdoc', credential));
    assert.equal(result.overall, 'UNSUPPORTED');
    assert.notEqual(result.dimensions.integrity?.overall, 'VALID');
  }
});

test('native mdoc unsupported critical semantics cannot hide supported signature mathematics', async () => {
  const f = await fixture('MDOC');
  const change = ({ headers }) => {
    headers.set(2, ['urn:example:critical']);
    headers.set('urn:example:critical', true);
  };
  const result = verdict('MDOC', f, replace(f.bundle, 'PersonalMdoc', mdocVariant(f, change)));
  assert.equal(result.overall, 'UNSUPPORTED');
  assert.equal(result.reason, 'COSE_CRITICAL_UNSUPPORTED');
  const invalid = verdict(
    'MDOC',
    f,
    replace(f.bundle, 'PersonalMdoc', mdocVariant(f, change, { badSignature: true })),
  );
  assert.equal(invalid.overall, 'INVALID');
  assert.equal(invalid.reason, 'COSE_SIGNATURE');
});

test('CMS unknown algorithm capability differs from implemented algorithm mismatch', async () => {
  const f = await fixture('CMS');
  for (const digest of [false, true]) {
    const unknown = cmsAlgorithm(f.bundle, '1.3.6.1.4.1.55555.990.1', { digest });
    const result = verdict('CMS', f, unknown);
    assert.equal(result.overall, 'UNSUPPORTED');
    assert.equal(
      result.reason,
      digest ? 'CMS_DIGEST_UNSUPPORTED' : 'CMS_SIGNATURE_ALGORITHM_UNSUPPORTED',
    );
    const mismatch = cmsAlgorithm(f.bundle, digest ? OID.sha256 : '1.3.101.112', { digest });
    assert.equal(verdict('CMS', f, mismatch).overall, 'INVALID');
  }
  const bad = cmsAlgorithm(f.bundle, '1.3.6.1.4.1.55555.990.2', {
    digest: true,
    badSignature: true,
  });
  const result = verdict('CMS', f, bad);
  assert.equal(result.overall, 'INVALID');
  assert.equal(result.reason, 'CMS_SIGNATURE');
});

test('different evaluated dimensions retain independent failures with the same code', async () => {
  const f = await fixture('CMS', true);
  const bundle = without(
    corrupt(corrupt(f.bundle, 'OperationPermit'), 'CertificateStatus'),
    'DocumentTimestamp',
  );
  const result = verdict('CMS', f, bundle);
  assert.equal(result.overall, 'INVALID');
  assert.equal(result.dimensions.integrity.overall, 'INVALID');
  assert.equal(result.dimensions.integrity.reason, 'CMS_SIGNATURE');
  assert.equal(result.dimensions.status.overall, 'INVALID');
  assert.equal(result.dimensions.status.reason, 'CMS_SIGNATURE');
  assert.equal(result.dimensions.time.overall, 'INDETERMINATE');
});

test('authority dimensions follow the evaluated role rather than shared reason text', async () => {
  const f = await fixture('CMS', true);
  const result = verdict('CMS', f, f.bundle, {
    ...f.trust,
    authorityResolver(query) {
      if (['REGISTRATION_AUTHORITY', 'TIMESTAMP_AUTHORITY'].includes(query.role))
        return { overall: 'INVALID', reason: 'AUTHORITY_REVOKED' };
      return f.trust.authorityResolver(query);
    },
  });
  assert.equal(result.overall, 'INVALID');
  assert.equal(result.dimensions.qualification.overall, 'INVALID');
  assert.equal(result.dimensions.qualification.reason, 'AUTHORITY_REVOKED');
  assert.equal(result.dimensions.time.overall, 'INVALID');
  assert.equal(result.dimensions.time.reason, 'AUTHORITY_REVOKED');
  assert.equal(result.dimensions.integrity.overall, 'VALID');
  assert.notEqual(result.dimensions.issuerTrust?.overall, 'VALID');
});

test('transparency dimensions reflect the admitted operator quorum rather than every vote', async () => {
  const f = await fixture('CMS');
  assert.equal(f.trust.mtc.members.length, 3);
  assert.equal(f.trust.mtc.threshold, 2);
  for (const rejectedCount of [1, 2]) {
    const rejectedKeys = f.trust.mtc.members
      .slice(0, rejectedCount)
      .map((member) => spki(member.publicKey));
    const result = verdict('CMS', f, f.bundle, {
      ...f.trust,
      authorityResolver(query) {
        if (query.role === 'COSIGNER' && rejectedKeys.some((key) => equal(key, query.publicKeyDER)))
          return { overall: 'INVALID', reason: 'AUTHORITY_REVOKED' };
        return f.trust.authorityResolver(query);
      },
    });
    assert.equal(result.overall, rejectedCount === 1 ? 'VALID' : 'INVALID');
    assert.equal(result.dimensions.transparency.overall, result.overall);
    if (rejectedCount === 2)
      assert.equal(result.dimensions.transparency.reason, 'COSIGNER_AUTHORITY_QUORUM_REJECTED');
  }
});

test('reason strings alone do not create a capability outcome or move dimensions', async () => {
  const f = await fixture('CMS');
  for (const reason of ['PRIVATE_ALGORITHM_UNSUPPORTED', 'ECP_STATUS_STALE_SUFFIX']) {
    const result = verdict('CMS', f, f.bundle, {
      ...f.trust,
      authorityResolver() {
        throw new ProtocolError(reason);
      },
    });
    assert.equal(result.overall, 'INVALID');
    assert.equal(result.reason, reason);
  }
  const typed = verdict('CMS', f, f.bundle, {
    ...f.trust,
    authorityResolver(query) {
      if (query.role === 'REGISTRATION_AUTHORITY')
        return { overall: 'UNSUPPORTED', reason: 'COSIGNER_AUTHORITY_QUORUM_REJECTED' };
      return f.trust.authorityResolver(query);
    },
  });
  assert.equal(typed.overall, 'UNSUPPORTED');
  assert.equal(typed.dimensions.qualification.overall, 'UNSUPPORTED');
  assert.equal(typed.dimensions.transparency, undefined);
  assert.equal(typed.dimensions.integrity.overall, 'VALID');
});

test('incomplete resolver decisions cannot omit the stable result reason', async () => {
  const f = await fixture('CMS');
  for (const overall of ['VALID', 'INVALID', 'INDETERMINATE', 'UNSUPPORTED']) {
    const result = verdict('CMS', f, f.bundle, {
      ...f.trust,
      authorityResolver(query) {
        return query.role === 'REGISTRATION_AUTHORITY'
          ? { overall }
          : f.trust.authorityResolver(query);
      },
    });
    assert.equal(result.overall, overall === 'VALID' ? 'INDETERMINATE' : overall);
    assert.equal(typeof result.reason, 'string');
    assert(result.reason.length > 0);
    assert.equal(result.dimensions.qualification?.overall, result.overall);
  }
});

for (const format of ['CMS', 'MDOC']) {
  test(`${format} missing mapped type still reports its required time dimension`, async () => {
    const f = await fixture(format, true);
    const bundle = copy(without(f.bundle, 'DocumentTimestamp'));
    delete bundle.plan.objects.DocumentTimestamp;
    const result = verdict(format, f, bundle);
    assert.equal(result.overall, 'INDETERMINATE');
    assert.equal(result.dimensions.time?.overall, 'INDETERMINATE');
    assert.notEqual(result.dimensions.integrity?.overall, 'VALID');
  });

  test(`${format} registration signature failures are integrity failures`, async () => {
    const f = await fixture(format);
    const result = verdict(format, f, corrupt(f.bundle, 'RegistrationAuthorization'));
    assert.equal(result.overall, 'INVALID');
    assert.equal(result.reason, 'CMS_SIGNATURE');
    assert.equal(result.dimensions.integrity?.overall, 'INVALID');
  });

  test(`${format} missing registration cannot hide an independently invalid timestamp signature`, async () => {
    const f = await fixture(format, true);
    const missing = without(f.bundle, 'RegistrationAuthorization');
    assert.equal(verdict(format, f, missing).overall, 'INDETERMINATE');
    const bad = without(corrupt(f.bundle, 'DocumentTimestamp'), 'RegistrationAuthorization');
    const result = verdict(format, f, bad);
    assert.equal(result.overall, 'INVALID');
    assert.equal(result.reason, 'CMS_SIGNATURE');
    assert.equal(result.dimensions.time?.overall, 'INVALID');
  });
}

test('missing registration preserves only authenticated subject-bound certificate revocation', async () => {
  const f = await fixture('CMS');
  const original = readControl(
    payload(f.bundle, 'CertificateStatus'),
    'CertificateStatus',
    f.trust.statusCertificate,
  );
  const receipt = readControl(
    payload(f.bundle, 'ExecutionReceipt'),
    'ExecutionReceipt',
    f.trust.receiptCertificate,
  );
  const status = { ...original, status: 'REVOKED', effectiveTime: receipt.executedAt };
  const changed = (statement) =>
    without(
      replace(f.bundle, 'CertificateStatus', f.signStatus(statement)),
      'RegistrationAuthorization',
    );
  assert.equal(
    verdict('CMS', f, without(f.bundle, 'RegistrationAuthorization')).overall,
    'INDETERMINATE',
  );
  const result = verdict('CMS', f, changed(status));
  assert.equal(result.overall, 'INVALID');
  assert.equal(result.reason, 'ECP_STATUS_REVOKED');
  assert.equal(result.dimensions.status?.reason, 'ECP_STATUS_REVOKED');
  for (const field of ['certificateID', 'trustDomainID']) {
    const wrong = verdict(
      'CMS',
      f,
      changed({ ...status, [field]: Buffer.alloc(status[field].length) }),
    );
    assert.notEqual(wrong.overall, 'VALID');
    assert.notEqual(wrong.reason, 'ECP_STATUS_REVOKED');
    assert.notEqual(wrong.dimensions.status?.reason, 'ECP_STATUS_REVOKED');
  }
  const unavailable = verdict('CMS', f, changed(status), {
    ...f.trust,
    authorityResolver(query) {
      if (query.role === 'STATUS_AUTHORITY')
        return { overall: 'INDETERMINATE', reason: 'AUTHORITY_STATUS_MISSING' };
      return f.trust.authorityResolver(query);
    },
  });
  assert.equal(unavailable.overall, 'INDETERMINATE');
  assert.notEqual(unavailable.dimensions.status?.reason, 'ECP_STATUS_REVOKED');
});

function x509Fixture(f) {
  const ca = c.generate('ml-dsa-87'),
    key = c.generate('ml-dsa-87'),
    control = c.generate('ml-dsa-87');
  const at = now(),
    policy = f.trust.expectedPolicy,
    trustDomainID = f.trust.trustDomainID;
  const controlCertificate = p.issueCertificate(
    {
      publicKey: control.publicKey,
      issuer: p.name('SDK fixture CA'),
      subject: p.name('SDK fixture controls'),
      serial: 1,
      profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
    },
    ca.privateKey,
  );
  const issuanceScope = {
    trustDomainID,
    issuerID: '32473.90',
    issuerKeyID: c.keyID(ca.publicKey),
    representation: 'X509',
  };
  const original = readControl(
    payload(f.bundle, 'RegistrationAuthorization'),
    'RegistrationAuthorization',
    f.trust.raCertificate,
  );
  const authorization = {
    ...original,
    issuanceScope,
    spkiHash: c.sha512(c.spki(key.publicKey)),
    issuedAt: at,
    expiresAt: at + 120,
  };
  const rar = p.signCMS(
    { content: c.D('RegistrationAuthorization', authorization), certificate: controlCertificate },
    control.privateKey,
  );
  const certificate = p.issueCertificate(
    {
      publicKey: key.publicKey,
      issuer: p.name('SDK fixture CA'),
      subject: p.name('SDK fixture subject'),
      serial: 2,
      profileID: original.profileID,
      extraExtensions: [
        p.extension(
          p.RRA['id-pe-certconcordAuthorizationID'],
          c.octet(c.H('RegistrationAuthorization', authorization)),
        ),
      ],
    },
    ca.privateKey,
  );
  const cert = p.parseCertificate(certificate),
    document = payload(f.bundle, 'Document');
  const sim = {
    ...decodeCBOR(payload(f.bundle, 'SIM')),
    keyID: c.keyID(key.publicKey),
    certificateID: cert.certificateID,
    certificateRepresentationHash: cert.representationHash,
    issuedAt: at,
    expiresAt: at + 120,
  };
  const prepared = p.prepareCMS({
    content: document,
    certificate,
    detached: true,
    context: {
      schemaVersion: 1,
      trustDomainID,
      profileID: sim.profileID,
      container: 'CMS',
      adapterID: sim.adapterID,
    },
    simHash: c.H('SIM', sim),
    policyHash: c.H('SignaturePolicy', policy),
  });
  const activation = activationContext({
    trustDomainID,
    tbsKind: 'CMS_SIGNED_ATTRS_DER',
    tbs: prepared.tbs,
    publicKey: key.publicKey,
    simHash: c.H('SIM', sim),
    certificateID: cert.certificateID,
    certificateRepresentationHash: cert.representationHash,
    transactionID: sim.transactionID,
    policyHash: sim.policyHash,
    origin: sim.origin,
    rpID: policy.rpID,
    audience: policy.audience,
    issuedAt: at,
  });
  const permit = issuePermit(activation, {
    certificate: controlCertificate,
    privateKey: control.privateKey,
    activationEvidenceHash: c.random(64),
    proofMode: policy.activationMode,
  });
  const signature = c.sign(prepared.tbs, key.privateKey);
  const receipt = p.signCMS(
    {
      content: c.D('ExecutionReceipt', {
        schemaVersion: 1,
        operationID: activation.operationID,
        activationHash: c.H('ActivationContext', activation),
        permitHash: c.sha512(permit),
        keyID: sim.keyID,
        tbsHash: c.sha512(prepared.tbs),
        signatureHash: c.sha512(signature),
        executedAt: at,
        provider: 'synthetic-sdk-fixture',
      }),
      certificate: controlCertificate,
    },
    control.privateKey,
  );
  const status = p.signCMS(
    {
      content: c.D('CertificateStatus', {
        schemaVersion: 1,
        trustDomainID,
        certificateID: cert.certificateID,
        scope: 'CERTIFICATE',
        status: 'GOOD',
        publishedAt: at,
        nextUpdate: at + 3600,
      }),
      certificate: controlCertificate,
    },
    control.privateKey,
  );
  const bundle = createSignaturePackage({
    document,
    certificate,
    registrationAuthorization: rar,
    sim,
    policy,
    permit,
    receipt,
    status,
    cms: prepared.finish(signature),
  });
  const trust = {
    expectedPolicy: policy,
    trustDomainID,
    issuanceScope,
    issuerPublicKey: ca.publicKey,
    raCertificate: controlCertificate,
    permitCertificate: controlCertificate,
    receiptCertificate: controlCertificate,
    statusCertificate: controlCertificate,
    authorityResolver: exampleAuthorityResolver({
      trustDomainID,
      at,
      authorities: [
        {
          certificate: controlCertificate,
          roles: [
            'REGISTRATION_AUTHORITY',
            'PERMIT_AUTHORITY',
            'RECEIPT_AUTHORITY',
            'STATUS_AUTHORITY',
          ],
        },
        {
          mode: 'RAW_KEY',
          publicKeyDER: c.spki(ca.publicKey),
          roles: ['ISSUER'],
          knownAt: at - 60,
          validFrom: at - 60,
          validUntil: at + 3600,
        },
      ],
    }),
  };
  return {
    bundle,
    trust,
    signControl: (label, body) =>
      p.signCMS({ content: c.D(label, body), certificate: controlCertificate }, control.privateKey),
  };
}

test('unused MTC configuration does not claim transparency for an X509 signature', async () => {
  const f = x509Fixture(await fixture('CMS'));
  const original = verdict('CMS', f);
  assert.equal(original.overall, 'VALID', original.reason);
  assert.equal(original.dimensions.transparency, undefined);
  const extra = verdict('CMS', f, f.bundle, { ...f.trust, mtc: {} });
  assert.equal(extra.overall, 'VALID', extra.reason);
  assert.equal(extra.dimensions.transparency, undefined);
});

for (const format of ['CMS', 'MDOC']) {
  test(`${format} incomplete evidence binds every receipt field before using operation time`, async (t) => {
    const original = await fixture(format),
      key = c.generate('ml-dsa-87'),
      certificate = p.issueCertificate(
        {
          publicKey: key.publicKey,
          serial: 1,
          issuer: p.name('SDK receipt binding fixture'),
          subject: p.name('SDK receipt binding fixture'),
          profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
        },
        key.privateKey,
      ),
      receipt = readControl(
        payload(original.bundle, 'ExecutionReceipt'),
        'ExecutionReceipt',
        original.trust.receiptCertificate,
      ),
      signReceipt = (body) =>
        p.signCMS({ content: c.D('ExecutionReceipt', body), certificate }, key.privateKey),
      trust = {
        ...original.trust,
        receiptCertificate: certificate,
        authorityResolver(query) {
          if (query.role === 'RECEIPT_AUTHORITY' && equal(query.certificate, certificate))
            return { overall: 'VALID', reason: 'FIXTURE_RECEIPT_AUTHORITY' };
          return original.trust.authorityResolver(query);
        },
      },
      candidate = (body) =>
        without(
          replace(original.bundle, 'ExecutionReceipt', signReceipt(body)),
          'RegistrationAuthorization',
        );
    assert.equal(verdict(format, original, candidate(receipt), trust).overall, 'INDETERMINATE');
    for (const field of [
      'operationID',
      'activationHash',
      'permitHash',
      'keyID',
      'tbsHash',
      'signatureHash',
    ])
      await t.test(field, () => {
        const changed = { ...receipt, [field]: c.random(receipt[field].length) },
          result = verdict(format, original, candidate(changed), trust);
        assert.equal(result.overall, 'INVALID');
        assert.equal(
          result.reason,
          format === 'CMS' ? 'ECP_EXECUTION_RECEIPT' : 'MDOC_ECP_RECEIPT',
        );
        assert.equal(result.dimensions.authorization?.overall, 'INVALID');
        assert.notEqual(result.dimensions.status?.reason, 'ECP_STATUS_REVOKED');
      });
  });
}

test('certificate status fallback never borrows another operation receipt time', async (t) => {
  const f = x509Fixture(await fixture('CMS')),
    receipt = readControl(
      payload(f.bundle, 'ExecutionReceipt'),
      'ExecutionReceipt',
      f.trust.receiptCertificate,
    ),
    status = readControl(
      payload(f.bundle, 'CertificateStatus'),
      'CertificateStatus',
      f.trust.statusCertificate,
    ),
    revoked = f.signControl('CertificateStatus', {
      ...status,
      status: 'REVOKED',
      effectiveTime: receipt.executedAt + 1,
    }),
    bundle = replace(f.bundle, 'CertificateStatus', revoked),
    trust = { ...f.trust, knowledgeTime: receipt.executedAt + 3 },
    missing = (value) => without(value, 'RegistrationAuthorization');
  const actual = verdict('CMS', f, missing(bundle), trust);
  assert.equal(actual.overall, 'INDETERMINATE');
  assert.notEqual(actual.dimensions.status?.reason, 'ECP_STATUS_REVOKED');
  await t.test('another signed operation cannot move the revocation evaluation time', () => {
    const unrelated = f.signControl('ExecutionReceipt', {
      ...receipt,
      operationID: c.random(32),
      executedAt: receipt.executedAt + 2,
    });
    const result = verdict(
      'CMS',
      f,
      missing(replace(bundle, 'ExecutionReceipt', unrelated)),
      trust,
    );
    assert.equal(result.overall, 'INVALID');
    assert.equal(result.reason, 'ECP_EXECUTION_RECEIPT');
    assert.equal(result.dimensions.authorization?.overall, 'INVALID');
    assert.notEqual(result.dimensions.status?.reason, 'ECP_STATUS_REVOKED');
  });
  const effective = replace(
    f.bundle,
    'CertificateStatus',
    f.signControl('CertificateStatus', {
      ...status,
      status: 'REVOKED',
      effectiveTime: receipt.executedAt,
    }),
  );
  for (const type of ['Document', 'Certificate', 'CMS', 'OperationPermit'])
    await t.test(`missing ${type} prevents a status-time inference`, () => {
      const result = verdict('CMS', f, without(missing(effective), type), trust);
      assert.equal(result.overall, 'INDETERMINATE');
      assert.notEqual(result.dimensions.status?.reason, 'ECP_STATUS_REVOKED');
    });
});

test('organization status fallback requires the authorization bound to this operation', async (t) => {
  await runDocumentDemo({
    onComplete: async (f) => {
      const receipt = readControl(
          payload(f.bundle, 'ExecutionReceipt'),
          'ExecutionReceipt',
          f.trust.receiptCertificate,
        ),
        originalStatus = readControl(
          payload(f.bundle, 'OrganizationAuthorizationStatus'),
          'OrganizationAuthorizationStatus',
          f.organizationAuthority.certificate,
        ),
        revoked = (raw, authorization) =>
          f.signControl(
            'OrganizationAuthorizationStatus',
            {
              ...originalStatus,
              authorizationID: authorization.authorizationID,
              authorizationHash: c.sha512(raw),
              status: 'REVOKED',
              effectiveTime: receipt.executedAt,
            },
            f.organizationAuthority,
          ),
        candidate = (raw, authorization) =>
          without(
            replace(
              replace(f.bundle, 'OrganizationAuthorization', raw),
              'OrganizationAuthorizationStatus',
              revoked(raw, authorization),
            ),
            'RegistrationAuthorization',
          );
      const current = verdict(
        'CMS',
        f,
        candidate(payload(f.bundle, 'OrganizationAuthorization'), f.authorizationBody),
      );
      assert.equal(current.overall, 'INVALID');
      assert.equal(current.reason, 'DOCUMENT_ORGANIZATION_STATUS_REVOKED');
      for (const field of [
        'organizationID',
        'authorizationID',
        'activationHash',
        'policyHash',
        'keyID',
        'actorID',
      ])
        await t.test(field, () => {
          const body = {
              ...f.authorizationBody,
              [field]: c.random(f.authorizationBody[field].length),
            },
            raw = f.signControl('OrganizationAuthorization', body, f.organizationAuthority),
            result = verdict('CMS', f, candidate(raw, body));
          assert.equal(result.overall, 'INVALID');
          assert.equal(result.reason, 'DOCUMENT_ORGANIZATION_BINDING');
          assert.equal(result.dimensions.authorization?.overall, 'INVALID');
          assert.notEqual(result.dimensions.status?.reason, 'DOCUMENT_ORGANIZATION_STATUS_REVOKED');
        });
    },
  });
});
