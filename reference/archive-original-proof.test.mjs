import test from 'node:test';
import assert from 'node:assert/strict';
import { generate, seq, integer, oid, octet, der, parseDER, sha512 } from './core.mjs';
import { algID, OID, issueCertificate, name, signCMS, generalizedTime } from './pki.mjs';
import { createERS, renewERS, verifyERSOriginalProof, verifyERSPreservation } from './archive.mjs';
import { verificationOutcome } from './verification-result.mjs';

function fixture({ millis = 0, status } = {}) {
  const at = 1800000000,
    issuer = generate('ml-dsa-87'),
    tsaKey = generate('ml-dsa-87');
  const policy = '1.3.6.1.4.1.32473.90.2';
  const certificate = issueCertificate(
    {
      publicKey: tsaKey.publicKey,
      serial: 11,
      issuer: name('Original proof issuer'),
      subject: name('Original proof TSA'),
      profileID: 'CERTCONCORD-TSA-v1',
      notBefore: at - 10,
      notAfter: at + 1000,
    },
    issuer.privateKey,
  );
  let time = at,
    serial = 0;
  const queries = [],
    trust = {
      certificate,
      issuerKey: issuer.publicKey,
      policy,
      validUntil: at + 500,
      status: (query) => {
        queries.push(query);
        return status ? status(query) : { overall: 'VALID', reason: 'TEST_TSA_AUTHORIZED' };
      },
    };
  const tsa = async (imprint, hashOID) =>
    signCMS(
      {
        certificate,
        contentType: OID.tstInfo,
        content: seq(
          integer(1),
          oid(policy),
          seq(algID(hashOID), octet(imprint)),
          integer(++serial),
          generalizedTime(time),
          seq(integer(0), ...(millis ? [der(0x80, parseDER(integer(millis)).value)] : [])),
        ),
      },
      tsaKey.privateKey,
    );
  return {
    at,
    tsa,
    trust,
    queries,
    clock: (next) => {
      time = next;
    },
    policy: {
      dataValidUntil: at + 20,
      hashValidUntil: { [OID.sha512]: at + 300 },
      resolveTimestamp: () => trust,
    },
  };
}

test('original ERS proof authenticates the first whole-data bound independently of later renewal', async () => {
  const f = fixture(),
    data = Buffer.from('The exact original evidence package');
  const first = await createERS(data, { tsa: f.tsa });
  f.clock(f.at + 100);
  const renewed = await renewERS(first, data, { tsa: f.tsa });
  const broken = Buffer.from(renewed);
  broken[broken.length - 1] ^= 1;
  assert.throws(() => verifyERSPreservation(broken, data, { ...f.policy, at: f.at + 200 }));
  const original = verifyERSOriginalProof(broken, data, f.policy);
  assert.equal(original.proofOfExistenceUpperBound, f.at);
  assert.equal(original.preservation, 'ORIGINAL_PROOF_ONLY');
  assert.equal(f.queries.at(-1).knowledgeTime, f.at);
  assert.equal(f.queries.at(-1).stateTime, f.at);
});

test('original ERS proof preserves fractional accuracy and exclusive protection boundaries', async () => {
  const f = fixture({ millis: 500 }),
    data = Buffer.from('Fractional original proof');
  const record = await createERS(data, { tsa: f.tsa });
  const result = verifyERSOriginalProof(record, data, f.policy);
  assert.equal(result.proofOfExistenceUpperBound, f.at + 0.5);
  assert.equal(f.queries[0].knowledgeTime, f.at + 0.5);
  assert.throws(
    () => verifyERSOriginalProof(record, data, { ...f.policy, dataValidUntil: f.at }),
    /ERS_INITIAL_PROOF_LATE/,
  );
  assert.throws(
    () =>
      verifyERSOriginalProof(record, data, { ...f.policy, hashValidUntil: { [OID.sha512]: f.at } }),
    /ERS_HASH_EXPIRED/,
  );
  const exact = fixture(),
    exactRecord = await createERS(data, { tsa: exact.tsa });
  assert.throws(
    () => verifyERSOriginalProof(exactRecord, data, { ...exact.policy, dataValidUntil: exact.at }),
    /ERS_INITIAL_PROOF_LATE/,
  );
});

test('original ERS proof rejects substituted bytes, signer, token mathematics and reduced-tree membership', async () => {
  const f = fixture(),
    data = Buffer.from('Original membership');
  const record = await createERS(data, { tsa: f.tsa });
  assert.throws(
    () => verifyERSOriginalProof(record, Buffer.from('Different bytes'), f.policy),
    /TSA_REQUEST_BINDING/,
  );
  const broken = Buffer.from(record);
  broken[broken.length - 1] ^= 1;
  assert.throws(() => verifyERSOriginalProof(broken, data, f.policy), /CMS_SIGNATURE/);
  const other = fixture();
  assert.throws(() =>
    verifyERSOriginalProof(record, data, { ...f.policy, resolveTimestamp: () => other.trust }),
  );
  const nodes = parseDER(record).children,
    stamp = nodes[2].children[0].children[0].children;
  const tree = der(0xa2, seq(octet(sha512(Buffer.from('Absent member')))));
  const wrongMembership = seq(
    nodes[0].raw,
    nodes[1].raw,
    seq(seq(seq(stamp[0].raw, tree, stamp.at(-1).raw))),
  );
  assert.throws(
    () => verifyERSOriginalProof(wrongMembership, data, f.policy),
    /ERS_TREE_MEMBERSHIP/,
  );
});

for (const overall of ['INVALID', 'UNSUPPORTED', 'INDETERMINATE'])
  test('original ERS proof preserves typed TSA ' + overall + ' at its original bound', async () => {
    const f = fixture({ status: () => ({ overall, reason: 'TEST_TSA_' + overall }) });
    const data = Buffer.from('Typed original proof'),
      record = await createERS(data, { tsa: f.tsa });
    assert.throws(
      () => verifyERSOriginalProof(record, data, f.policy),
      (error) => {
        assert.deepEqual(verificationOutcome(error), { overall, reason: 'TEST_TSA_' + overall });
        return true;
      },
    );
  });

test('original ERS proof does not let status callback exceptions select an outcome', async () => {
  const f = fixture({
    status: () => {
      throw { overall: 'VALID', reason: 'CALLER_ACCEPTANCE' };
    },
  });
  const data = Buffer.from('Unavailable TSA status'),
    record = await createERS(data, { tsa: f.tsa });
  assert.throws(
    () => verifyERSOriginalProof(record, data, f.policy),
    (error) => {
      assert.deepEqual(verificationOutcome(error), {
        overall: 'INDETERMINATE',
        reason: 'ERS_TSA_STATUS_UNAVAILABLE',
      });
      return true;
    },
  );
});
