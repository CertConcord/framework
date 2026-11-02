import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as a from './archive.mjs';
import { createVerifier } from './sdk/index.mjs';
import { runDemo } from './demo.mjs';
import { evidenceLeaf, createEvidencePackage } from './evidence-plan.mjs';
import { documentTimestampImprint } from './document-evidence.mjs';
import { assertPreservationLifetimes } from './preservation-lifetimes.mjs';

function fixture({ epoch = 1793275200, notBefore = epoch - 10, notAfter = epoch + 100 } = {}) {
  const root = c.generate('ml-dsa-65'),
    key = c.generate('ml-dsa-65'),
    policy = '2.25.3161202611021',
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        serial: 1,
        issuer: p.name('Synthetic interval integration root'),
        subject: p.name('Synthetic interval integration TSA'),
        profileID: 'CERTCONCORD-TSA-v1',
        notBefore,
        notAfter,
      },
      root.privateKey,
    ),
    queries = [],
    trust = {
      certificate,
      issuerKey: root.publicKey,
      policy,
      validUntil: epoch + 50,
      status: (query) => {
        queries.push(query);
        return { overall: 'VALID', reason: 'SYNTHETIC_TSA_STATUS' };
      },
    },
    sign = (imprint, hashOID = p.OID.sha512, { millis = 2, accuracyMicros = 1 } = {}) => {
      const whole = c.parseDER(p.generalizedTime(epoch)).value.toString('ascii'),
        fraction = millis ? '.' + String(millis).padStart(3, '0').replace(/0+$/, '') : '',
        seconds = Math.floor(accuracyMicros / 1000000),
        ms = Math.floor((accuracyMicros % 1000000) / 1000),
        us = accuracyMicros % 1000;
      return p.signCMS(
        {
          certificate,
          contentType: p.OID.tstInfo,
          content: c.seq(
            c.integer(1),
            c.oid(policy),
            c.seq(p.algID(hashOID), c.octet(imprint)),
            c.integer(1),
            c.der(24, Buffer.from(whole.replace('Z', fraction + 'Z'))),
            c.seq(
              c.integer(seconds),
              ...(ms ? [c.der(0x80, c.parseDER(c.integer(ms)).value)] : []),
              ...(us ? [c.der(0x81, c.parseDER(c.integer(us)).value)] : []),
            ),
          ),
        },
        key.privateKey,
      );
    };
  return {
    epoch,
    trust,
    queries,
    sign,
    preservation: {
      at: epoch + 10,
      dataValidUntil: epoch + 20,
      hashValidUntil: { [p.OID.sha512]: epoch + 40 },
      resolveTimestamp: () => trust,
    },
  };
}

for (const format of ['DER', 'XML']) {
  const create = format === 'DER' ? a.createERS : a.createXMLERS,
    renew = format === 'DER' ? a.renewERS : a.renewXMLERS,
    verify = format === 'DER' ? a.verifyERSPreservation : a.verifyXMLERSPreservation;
  test(`${format} preservation accepts the signed rounded millisecond interval with later deadlines`, async () => {
    const f = fixture(),
      data = Buffer.from('Preserved exact millisecond interval'),
      tsa = (imprint, hashOID) => f.sign(imprint, hashOID, { millis: 1, accuracyMicros: 1000 }),
      record = await create(data, { tsa }),
      result = verify(record, data, f.preservation);
    assert.equal(result.preservation, 'VALID');
    assert(result.proofOfExistenceUpperBound >= f.epoch + 0.002);
    assert.notEqual(result.proofOfExistenceUpperBound, f.epoch + 0.001 + 0.001);
    assert.equal(f.queries.at(-1).stateTime, result.proofOfExistenceUpperBound);
    if (format === 'DER')
      assert.equal(
        a.verifyERSOriginalProof(record, data, f.preservation).proofOfExistenceUpperBound,
        result.proofOfExistenceUpperBound,
      );
    f.trust.revokedAt = f.epoch + 0.002;
    assert.throws(() => verify(record, data, f.preservation), { code: 'TSA_TIME_OR_REVOCATION' });
    if (format === 'DER')
      assert.throws(() => a.verifyERSOriginalProof(record, data, f.preservation), {
        code: 'TSA_TIME_OR_REVOCATION',
      });
  });
  test(`${format} renewal preserves representable adjacent intervals and rejects true overlap`, async () => {
    const f = fixture(),
      data = Buffer.from('Preserved interval ordering'),
      first = await create(data, {
        tsa: (imprint, hashOID) =>
          f.sign(imprint, hashOID, { millis: 125, accuracyMicros: 125000 }),
      });
    const adjacent = await renew(first, data, {
      tsa: (imprint, hashOID) => f.sign(imprint, hashOID, { millis: 375, accuracyMicros: 125000 }),
    });
    assert.equal(verify(adjacent, data, f.preservation).preservation, 'VALID');
    const overlap = await renew(first, data, {
      tsa: (imprint, hashOID) => f.sign(imprint, hashOID, { millis: 374, accuracyMicros: 125001 }),
    });
    assert.throws(() => verify(overlap, data, f.preservation), { code: 'ERS_INTERVAL_ORDER' });
  });
  for (const [id, bounds, options, accepted] of [
    ['lower-equal', { notBefore: 1793275200 }, { millis: 1, accuracyMicros: 1000 }, true],
    ['lower-before', { notBefore: 1793275200 }, { millis: 1, accuracyMicros: 1001 }, false],
    ['upper-equal', { notAfter: 1793275201 }, { millis: 999, accuracyMicros: 1000 }, false],
  ])
    test(`${format} complete signed interval certificate boundary: ${id}`, async () => {
      const f = fixture(bounds),
        data = Buffer.from('Whole certificate interval ' + id),
        record = await create(data, {
          tsa: (imprint, hashOID) => f.sign(imprint, hashOID, options),
        });
      if (accepted) {
        assert.equal(verify(record, data, f.preservation).preservation, 'VALID');
        if (format === 'DER')
          assert.equal(
            a.verifyERSOriginalProof(record, data, f.preservation).preservation,
            'ORIGINAL_PROOF_ONLY',
          );
      } else {
        assert.throws(() => verify(record, data, f.preservation), {
          code: 'ERS_TIMESTAMP_INTERVAL',
        });
        if (format === 'DER')
          assert.throws(() => a.verifyERSOriginalProof(record, data, f.preservation), {
            code: 'ERS_TIMESTAMP_INTERVAL',
          });
      }
    });
}

test('complete DOCUMENT authority and status queries use authenticated outward endpoints', async () => {
  await runDemo({
    trustedTime: true,
    activationMode: 'HUMAN_WEBAUTHN',
    onComplete: async (r) => {
      const epoch = c.now(),
        f = fixture({ epoch }),
        imprint = documentTimestampImprint('CMS', r.bundle.objects),
        token = f.sign(imprint),
        info = a.parseTSTInfo(p.verifyCMS(token, { expectedContentType: p.OID.tstInfo }).content),
        objects = r.bundle.objects.map((o) =>
          o.type === 'DocumentTimestamp' ? evidenceLeaf(o.type, token) : o,
        ),
        bundle = createEvidencePackage(r.bundle.plan.profile, objects),
        queries = [],
        trust = {
          ...r.trust,
          knowledgeTime: epoch + 1,
          timestamp: f.trust,
          authorityResolver: (query) => {
            if (query.role === 'TIMESTAMP_AUTHORITY') {
              assert.deepEqual(query.certificate, f.trust.certificate);
              queries.push(query);
              return { overall: 'VALID', reason: 'SYNTHETIC_TSA_APPOINTMENT' };
            }
            return r.trust.authorityResolver(query);
          },
        },
        run = (extra) =>
          createVerifier({ format: 'CMS', trust: { ...trust, ...extra } }).verify(c.dcbor(bundle));
      assert.equal(run().overall, 'VALID');
      assert.notEqual(info.poeLowerBound, info.genTime - info.accuracy);
      assert.deepEqual(
        queries.map((q) => q.stateTime),
        [info.poeLowerBound, info.poeUpperBound],
      );
      assert.equal(f.queries.at(-1).stateTime, info.poeUpperBound);
      assert.equal(f.queries.at(-1).knowledgeTime, epoch + 1);
      const future = run({ knowledgeTime: epoch });
      assert.equal(future.overall, 'INVALID');
      assert.equal(future.reason, 'TSA_TIME_OR_REVOCATION');
      const revoked = run({ timestamp: { ...f.trust, revokedAt: info.poeUpperBound } });
      assert.equal(revoked.overall, 'INVALID');
      assert.equal(revoked.reason, 'TSA_TIME_OR_REVOCATION');
      const unknown = run({
        timestamp: {
          ...f.trust,
          status: () => ({ overall: 'INDETERMINATE', reason: 'SYNTHETIC_STATUS_UNKNOWN' }),
        },
      });
      assert.equal(unknown.overall, 'INDETERMINATE');
      assert.equal(unknown.reason, 'SYNTHETIC_STATUS_UNKNOWN');
    },
  });
});

test('Framework lifetime adapter retains each independent chain and protection gate', () => {
  const records = [
      {
        chain: 0,
        hashOID: p.OID.sha512,
        genTime: 10,
        accuracy: 1,
        poeLowerBound: 9,
        poeUpperBound: 11,
        validUntil: 30,
      },
      {
        chain: 1,
        hashOID: p.OID.sha512,
        genTime: 20,
        accuracy: 1,
        poeLowerBound: 19,
        poeUpperBound: 21,
        validUntil: 40,
      },
    ],
    policy = { at: 25, dataValidUntil: 12, hashValidUntil: { [p.OID.sha512]: 35 } };
  assert.equal(assertPreservationLifetimes(records, policy), true);
  for (const [code, changeRecords, changePolicy] of [
    ['ERS_PRESERVATION_POLICY', (r) => r, { at: NaN }],
    [
      'ERS_RECORD_FACTS',
      (r) => {
        r[1].chain = 3;
        return r;
      },
      {},
    ],
    [
      'ERS_RECORD_FACTS',
      (r) => {
        r[0].poeLowerBound = NaN;
        return r;
      },
      {},
    ],
    ['ERS_INITIAL_PROTECTION_LATE', (r) => r, { dataValidUntil: 11 }],
    [
      'ERS_RENEWAL_LATE',
      (r) => {
        r[0].validUntil = 21;
        return r;
      },
      {},
    ],
    ['ERS_FINAL_PROTECTION_EXPIRED', (r) => r, { at: 40 }],
    ['ERS_HASH_LIFETIME_REQUIRED', (r) => r, { hashValidUntil: {} }],
    ['ERS_HASH_RENEWAL_LATE', (r) => r, { hashValidUntil: { [p.OID.sha512]: 21 } }],
  ])
    assert.throws(
      () =>
        assertPreservationLifetimes(changeRecords(structuredClone(records)), {
          ...policy,
          ...changePolicy,
        }),
      { code },
    );
});

test('independent OpenSSL verifies time corpus signatures without certifying interval policy', (t) => {
  const executable = process.env.OPENSSL_BIN ?? 'openssl',
    probe = spawnSync(executable, ['version'], { encoding: 'utf8' });
  if (probe.status !== 0) {
    assert.notEqual(process.env.CERTCONCORD_REQUIRE_OPENSSL, '1');
    t.skip('Independent OpenSSL is unavailable');
    return;
  }
  const corpus = JSON.parse(
      readFileSync(new URL('./vectors/timestamp-time-contract.json', import.meta.url)),
    ),
    dir = mkdtempSync(join(tmpdir(), 'certconcord-timestamp-time-'));
  try {
    for (const row of corpus.cases) {
      const input = join(dir, 'token.der'),
        output = join(dir, 'content.der');
      writeFileSync(input, Buffer.from(row.raw, 'base64'));
      const result = spawnSync(
        executable,
        ['cms', '-verify', '-binary', '-inform', 'DER', '-in', input, '-noverify', '-out', output],
        { encoding: 'utf8' },
      );
      const negative = ['signature-tamper', 'content-tamper'].includes(row.id);
      assert.equal(result.status === 0, !negative, row.id + ': ' + result.stderr);
      if (!negative) assert.deepEqual(readFileSync(output), Buffer.from(row.tstInfo, 'base64'));
    }
  } finally {
    assert(
      resolve(dir).startsWith(resolve(tmpdir()) + '/certconcord-timestamp-time-') ||
        resolve(dir).startsWith(resolve(tmpdir()) + '\\certconcord-timestamp-time-'),
    );
    rmSync(dir, { recursive: true });
  }
});
