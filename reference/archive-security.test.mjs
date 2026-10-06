import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as a from './archive.mjs';
import { Journal, evidenceObject } from './state.mjs';
import { runArchiveDemo } from './archive-demo.mjs';
import { runDocumentDemo } from './document-demo.mjs';
import { createVerifier } from './sdk/index.mjs';

function fixture(t, start = 1800000000) {
  const journal = new Journal(),
    root = c.generate('ml-dsa-87'),
    key = c.generate('ml-dsa-87'),
    policy = '1.3.6.1.4.1.32473.90.2',
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        serial: 1,
        issuer: p.name('Test root'),
        subject: p.name('Test archive TSA'),
        profileID: 'CERTCONCORD-TSA-v1',
        notBefore: start - 10,
        notAfter: start + 10000,
      },
      root.privateKey,
    );
  let clock = start;
  const authority = new a.TimestampAuthority({
      certificate,
      privateKey: key.privateKey,
      policy,
      journal,
      clock: () => clock,
      accuracySeconds: 0,
    }),
    trust = {
      certificate,
      issuerKey: root.publicKey,
      policy,
      validUntil: start + 10000,
      status: () => true,
    },
    preservation = {
      at: start + 1000,
      dataValidUntil: start + 50,
      hashValidUntil: { [p.OID.sha256]: start + 300, [p.OID.sha512]: start + 2000 },
      resolveTimestamp: () => trust,
    };
  t.after(() => journal.close());
  return {
    start,
    trust,
    preservation,
    accuracy: (seconds) => {
      authority.accuracySeconds = seconds;
    },
    clock: (at) => {
      clock = at;
    },
    tsa: async (imprint, hashOID) =>
      a.tokenFromResponse(authority.issue(a.timestampRequest(imprint, { hashOID, policy }).der)),
  };
}

test('ERS preservation enforces initial, TSA and hash lifetimes across renewal', async (t) => {
  const f = fixture(t),
    data = Buffer.from('Original signed document and validation material'),
    first = await a.createERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
  f.clock(f.start + 100);
  const renewed = await a.renewERS(first, data, { tsa: f.tsa });
  f.clock(f.start + 200);
  const record = await a.renewERS(renewed, data, { tsa: f.tsa, hashRenewal: true });
  const verify = (r = record, policy = f.preservation) => a.verifyERSPreservation(r, data, policy);
  assert.deepEqual(verify(), {
    chains: 2,
    timestamps: 3,
    integrity: 'VALID',
    preservation: 'VALID',
    proofOfExistenceUpperBound: f.start,
    latestRenewalUpperBound: f.start + 200,
    verifiedAt: f.start + 1000,
  });
  assert.equal(
    a.verifyERS(record, data, { ...f.trust, at: f.preservation.at }).preservation,
    'NOT_EVALUATED',
  );
  assert.throws(() => verify(renewed), /ERS_HASH_RENEWAL_LATE/);
  assert.throws(
    () => verify(record, { ...f.preservation, dataValidUntil: f.start }),
    /ERS_INITIAL_PROTECTION_LATE/,
  );
  assert.throws(
    () => verify(record, { ...f.preservation, hashValidUntil: {} }),
    /ERS_HASH_LIFETIME_REQUIRED/,
  );
  assert.throws(
    () =>
      verify(record, {
        ...f.preservation,
        resolveTimestamp: () => ({ ...f.trust, status: () => false }),
      }),
    /ERS_TSA_STATUS/,
  );
  assert.throws(
    () => verify(record, { ...f.preservation, resolveTimestamp: () => undefined }),
    /ERS_TSA_TRUST_REQUIRED/,
  );
  assert.throws(
    () => verify(record, { ...f.preservation, at: f.start + 10000 }),
    /ERS_FINAL_PROTECTION_EXPIRED|ERS_HASH_RENEWAL_LATE/,
  );
  assert.throws(
    () => a.verifyERSPreservation(record, Buffer.from('substitution'), f.preservation),
    /TSA_REQUEST_BINDING/,
  );
  assert.throws(() => verify(record.subarray(0, record.length - 1)));
  // A well-formed, genuinely signed but late renewal cannot repair the expired data hash.
  f.clock(f.start + 300);
  const late = await a.renewERS(renewed, data, { tsa: f.tsa, hashRenewal: true });
  assert.throws(() => verify(late), /ERS_HASH_RENEWAL_LATE/);
  const oldToken = c.parseDER(first).children[2].children[0].children[0].children.at(-1).raw;
  assert.throws(
    () =>
      verify(record, {
        ...f.preservation,
        resolveTimestamp: (token) => ({
          ...f.trust,
          validUntil: c.equal(token, oldToken) ? f.start + 100 : f.trust.validUntil,
        }),
      }),
    /ERS_RENEWAL_LATE/,
  );
});

test('ERS preservation uses whole accuracy intervals and the timestamp hash when omitted', async (t) => {
  const f = fixture(t),
    data = Buffer.from('Archive accuracy boundary');
  let first = await a.createERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
  f.clock(f.start + 100);
  f.accuracy(2);
  let record = await a.renewERS(first, data, { tsa: f.tsa, hashRenewal: true });
  const nodes = c.parseDER(record).children,
    chains = nodes[2].children;
  // The global algorithm list begins with SHA-256; the new timestamp uses SHA-512.
  const omitted = c.seq(
    nodes[0].raw,
    nodes[1].raw,
    c.seq(chains[0].raw, c.seq(c.seq(chains[1].children[0].children.at(-1).raw))),
  );
  assert.equal(a.verifyERSPreservation(omitted, data, f.preservation).preservation, 'VALID');
  assert.throws(
    () => a.verifyERSPreservation(record, data, { ...f.preservation, at: f.start + 101 }),
    /ERS_TIMESTAMP_INTERVAL/,
  );
  assert.throws(
    () =>
      a.verifyERSPreservation(record, data, {
        ...f.preservation,
        resolveTimestamp: () => ({ ...f.trust, revokedAt: f.start + 101 }),
      }),
    /ERS_TIMESTAMP_LIFETIME/,
  );
  f.clock(f.start);
  first = await a.createERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
  f.clock(f.start + 3);
  record = await a.renewERS(first, data, { tsa: f.tsa, hashRenewal: true });
  assert.throws(() => a.verifyERSPreservation(record, data, f.preservation), /ERS_INTERVAL_ORDER/);
});

test('ERS reduced trees use sibling-only later levels and reject empty chains', async (t) => {
  const f = fixture(t),
    data = Buffer.from('Detached document bytes'),
    h = c.sha512,
    firstLevel = [h(data), h(Buffer.from('other document'))].sort(Buffer.compare),
    sibling = h(Buffer.from('other subtree')),
    root = h(Buffer.concat([h(Buffer.concat(firstLevel)), sibling].sort(Buffer.compare))),
    token = await f.tsa(root, p.OID.sha512),
    algorithm = c.der(0xa0, c.parseDER(p.algID(p.OID.sha512)).value),
    tree = c.der(0xa2, Buffer.concat([c.seq(...firstLevel.map(c.octet)), c.seq(c.octet(sibling))])),
    record = c.seq(
      c.integer(1),
      c.seq(p.algID(p.OID.sha512)),
      c.seq(c.seq(c.seq(algorithm, tree, token))),
    );
  assert.equal(a.verifyERS(record, data, { ...f.trust, at: f.start }).integrity, 'VALID');
  const reversed = c.seq(
    c.integer(1),
    c.seq(p.algID(p.OID.sha512)),
    c.seq(c.seq(c.seq(tree, algorithm, token))),
  );
  assert.throws(() => a.verifyERS(reversed, data, f.trust), /ERS_ATS_ORDER/);
  const nodes = c.parseDER(record).children;
  assert.throws(
    () =>
      a.verifyERS(
        c.seq(nodes[0].raw, nodes[1].raw, c.seq(...nodes[2].children.map((n) => n.raw), c.seq())),
        data,
        f.trust,
      ),
    /ERS_STAMP_LIMIT/,
  );
});

test('ERS hash renewal selects sorted Figure 4 inputs and rejects legacy unsorted input', async (t) => {
  const f = fixture(t),
    h = c.sha512;
  let data, first, values;
  for (let n = 0; n < 64; n++) {
    data = Buffer.from('Document ' + n);
    first = await a.createERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
    values = [h(data), h(c.parseDER(first).children[2].raw)];
    if (Buffer.compare(values[0], values[1]) > 0) break;
  }
  assert(Buffer.compare(values[0], values[1]) > 0, 'Expected an unsorted hash pair');
  f.clock(f.start + 100);
  const record = await a.renewERS(first, data, { tsa: f.tsa, hashRenewal: true });
  const nodes = c.parseDER(record).children,
    token = nodes[2].children[1].children[0].children.at(-1).raw;
  a.verifyTimestampToken(token, {
    ...f.trust,
    at: f.start + 100,
    imprint: h(Buffer.concat([...values].sort(Buffer.compare))),
  });
  const wrong = await f.tsa(h(Buffer.concat(values)), p.OID.sha512),
    forged = c.seq(
      nodes[0].raw,
      nodes[1].raw,
      c.seq(
        nodes[2].children[0].raw,
        c.seq(c.seq(c.der(0xa0, c.parseDER(p.algID(p.OID.sha512)).value), wrong)),
      ),
    );
  assert.throws(
    () => a.verifyERS(forged, data, { ...f.trust, at: f.start + 100 }),
    /TSA_REQUEST_BINDING/,
  );
});

test('standalone MTC document evidence survives certificate expiry with a distinct historical result', async (t) => {
  const r = await runArchiveDemo();
  const network = t.mock.method(globalThis, 'fetch', () => {
    throw Error('Network unavailable');
  });
  assert.equal(r.summary.certificateExpiredAtEvaluation, true);
  assert.equal(r.summary.preservation.preservation, 'VALID');
  assert.equal(r.summary.historical.overall, 'VALID');
  assert.equal(
    r.summary.historical.knowledgeTime,
    r.summary.preservation.proofOfExistenceUpperBound,
  );
  assert.equal(r.summary.current.overall, 'INDETERMINATE');
  assert.equal(r.summary.current.reason, 'ECP_STATUS_STALE');
  assert.equal(
    a.verifyERSPreservation(r.record, r.bytes, r.preservationTrust).preservation,
    'VALID',
  );
  const verify = (trust) =>
    createVerifier({
      format: 'CMS',
      trust: { ...trust, knowledgeTime: r.summary.historical.knowledgeTime },
    }).verify(r.bytes);
  assert.equal(verify(r.document.trust).overall, 'VALID');
  assert.equal(
    verify({
      ...r.document.trust,
      timestamp: { ...r.document.trust.timestamp, status: () => false },
    }).overall,
    'INVALID',
  );
  assert.equal(
    verify({
      ...r.document.trust,
      mtc: { ...r.document.trust.mtc, caPublicKey: c.generate('ml-dsa-87').publicKey },
    }).overall,
    'INVALID',
  );
  assert.equal(network.mock.callCount(), 0);
});

test('preserved GOOD evidence cannot override subsequently known certificate compromise', async (t) => {
  await runDocumentDemo({
    onComplete: async (r) => {
      const f = fixture(t, c.now() + 2),
        bytes = c.dcbor(r.bundle),
        record = await a.createERS(bytes, { tsa: f.tsa }),
        preservation = a.verifyERSPreservation(record, bytes, f.preservation),
        historical = createVerifier({
          format: 'CMS',
          trust: { ...r.trust, knowledgeTime: preservation.proofOfExistenceUpperBound },
        }).verify(bytes);
      assert.equal(historical.overall, 'VALID');
      const knowledgeTime = f.preservation.at,
        certificate = r.bundle.objects.find((o) => o.type === 'Certificate').payload,
        status = r.statusFor(certificate, {
          status: 'REVOKED',
          publishedAt: knowledgeTime,
          nextUpdate: knowledgeTime + 300,
          effectiveTime: knowledgeTime,
          compromiseStart: historical.stateTime - 1,
        }),
        objects = r.bundle.objects
          .filter((o) => o.type !== 'VerificationPlan')
          .map((o) => (o.type === 'CertificateStatus' ? evidenceObject(o.type, status) : o)),
        oldPlan = c.decodeCBOR(r.bundle.objects.find((o) => o.type === 'VerificationPlan').payload),
        plan = evidenceObject(
          'VerificationPlan',
          c.dcbor({ ...oldPlan, objects: Object.fromEntries(objects.map((o) => [o.type, o.id])) }),
          objects.map((o) => o.id),
        ),
        augmented = c.dcbor({ schemaVersion: 1, root: plan.id, objects: [...objects, plan] }),
        current = createVerifier({ format: 'CMS', trust: { ...r.trust, knowledgeTime } }).verify(
          augmented,
        );
      assert.equal(current.overall, 'INVALID');
      assert.equal(current.reason, 'ECP_STATUS_REVOKED');
      assert.equal(a.verifyERSPreservation(record, bytes, f.preservation).preservation, 'VALID');
      assert.throws(
        () => a.verifyERSPreservation(record, augmented, f.preservation),
        /TSA_REQUEST_BINDING/,
      );
    },
  });
});
