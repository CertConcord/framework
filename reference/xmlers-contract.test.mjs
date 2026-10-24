import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as a from './archive.mjs';
import { Journal } from './state.mjs';
import { VerificationError, verificationOutcome } from './verification-result.mjs';

const namespace = 'urn:ietf:params:xml:ns:ers';
const start = 1800000000;

function fixture(t, { notBefore = start - 10, notAfter = start + 10000 } = {}) {
  const root = c.generate('ml-dsa-87'),
    key = c.generate('ml-dsa-87'),
    journal = new Journal(),
    policy = '1.3.6.1.4.1.32473.90.2',
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        serial: 1,
        issuer: p.name('XMLERS test root'),
        subject: p.name('XMLERS test TSA'),
        profileID: 'CERTCONCORD-TSA-v1',
        notBefore,
        notAfter,
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
  });
  t.after(() => journal.close());
  return {
    trust: {
      certificate,
      issuerKey: root.publicKey,
      policy,
      validUntil: notAfter,
      status: () => true,
    },
    clock: (at) => {
      clock = at;
    },
    accuracy: (seconds) => {
      authority.accuracySeconds = seconds;
    },
    tsa: async (imprint, hashOID) =>
      a.tokenFromResponse(authority.issue(a.timestampRequest(imprint, { hashOID, policy }).der)),
    rewriteToken: (token, transform) =>
      p.signCMS(
        {
          content: transform(
            c.parseDER(p.verifyCMS(token, { expectedContentType: p.OID.tstInfo }).content),
          ),
          contentType: p.OID.tstInfo,
          certificate,
        },
        key.privateKey,
      ),
  };
}

function qualify(xml, name, uri) {
  return xml
    .replace(
      new RegExp('<' + name + '(?=[ >])'),
      '<selected:' + name + ' xmlns:selected="' + uri + '"',
    )
    .replace('</' + name + '>', '</selected:' + name + '>');
}

for (const name of [
  'ArchiveTimeStampChain',
  'ArchiveTimeStamp',
  'HashTree',
  'Sequence',
  'DigestValue',
]) {
  test(`XMLERS rejects a foreign namespace on ${name}`, async (t) => {
    const f = fixture(t),
      data = Buffer.from('Namespace-bound archive object');
    let record = await a.createXMLERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
    if (['HashTree', 'Sequence', 'DigestValue'].includes(name))
      record = record.replace(
        '<TimeStamp>',
        '<HashTree><Sequence Order="1"><DigestValue>' +
          c.sha256(data).toString('base64') +
          '</DigestValue></Sequence></HashTree><TimeStamp>',
      );
    const trust = { ...f.trust, at: start + 1000 };
    const expected = {
      chains: 1,
      poeUpperBound: start,
      integrity: 'VALID',
      preservation: 'NOT_EVALUATED',
    };
    assert.deepEqual(a.verifyXMLERS(record, data, trust), expected);
    assert.deepEqual(a.verifyXMLERS(qualify(record, name, namespace), data, trust), expected);
    assert.throws(() => a.verifyXMLERS(qualify(record, name, 'urn:foreign:xmlers'), data, trust), {
      code: 'XMLERS_NAMESPACE',
    });
  });
}

test('XMLERS accepts 64 timestamps in a chain and rejects a genuine 65th renewal', async (t) => {
  const f = fixture(t),
    data = Buffer.from('Bounded archive timestamp chain'),
    trust = { ...f.trust, at: start + 1000 };
  let record = await a.createXMLERS(data, { tsa: f.tsa });
  for (let i = 1; i < 64; i++) record = await a.renewXMLERS(record, data, { tsa: f.tsa });
  assert.equal(a.verifyXMLERS(record, data, trust).integrity, 'VALID');
  const extra = await a.renewXMLERS(record, data, { tsa: f.tsa });
  assert.throws(() => a.verifyXMLERS(extra, data, trust), { code: 'XMLERS_STAMP_LIMIT' });
});

function preservation(trust) {
  return {
    at: start + 1000,
    dataValidUntil: start + 50,
    hashValidUntil: { [p.OID.sha256]: start + 300, [p.OID.sha512]: start + 2000 },
    resolveTimestamp: () => trust,
  };
}

async function lifecycle(t) {
  const f = fixture(t),
    data = Buffer.from('Original XML archive and validation material');
  const first = await a.createXMLERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
  f.clock(start + 100);
  const renewed = await a.renewXMLERS(first, data, { tsa: f.tsa });
  f.clock(start + 200);
  const record = await a.renewXMLERS(renewed, data, { tsa: f.tsa, hashRenewal: true });
  return { ...f, data, first, renewed, record, policy: preservation(f.trust) };
}

function rejects(operation, overall, reason) {
  assert.throws(operation, (error) => {
    assert.deepEqual(verificationOutcome(error), { overall, reason });
    return true;
  });
}

test('XMLERS preservation retains the original proof across TSA and hash renewal', async (t) => {
  const old = fixture(t, { notAfter: start + 150 }),
    next = fixture(t),
    data = Buffer.from('Archive protected across TSA retirement'),
    authorities = new Map(),
    queries = [];
  const selected = (f) => async (imprint, hashOID) => {
    const token = await f.tsa(imprint, hashOID);
    authorities.set(token.toString('base64'), {
      ...f.trust,
      status: (query) => {
        queries.push(query);
        return { overall: 'VALID', reason: 'AUTHORITY_ADMITTED' };
      },
    });
    return token;
  };
  const first = await a.createXMLERS(data, { tsa: selected(old), hashOID: p.OID.sha256 });
  next.clock(start + 100);
  const renewed = await a.renewXMLERS(first, data, { tsa: selected(next) });
  next.clock(start + 200);
  const record = await a.renewXMLERS(renewed, data, { tsa: selected(next), hashRenewal: true });
  const policy = {
    ...preservation(next.trust),
    resolveTimestamp: (token) => authorities.get(token.toString('base64')),
  };
  const result = a.verifyXMLERSPreservation(record, data, policy);
  assert.deepEqual(result, {
    chains: 2,
    timestamps: 3,
    integrity: 'VALID',
    preservation: 'VALID',
    proofOfExistenceUpperBound: start,
    latestRenewalUpperBound: start + 200,
    verifiedAt: start + 1000,
  });
  assert.deepEqual(
    queries.map((q) => [q.genTime, q.stateTime, q.knowledgeTime]),
    [0, 100, 200].map((offset) => [start + offset, start + offset, start + 1000]),
  );
  assert.deepEqual(
    queries.map((q) => q.certificate),
    [old.trust.certificate, next.trust.certificate, next.trust.certificate],
  );
  assert.equal(
    a.verifyXMLERS(first, data, { ...old.trust, at: policy.at }).preservation,
    'NOT_EVALUATED',
  );
  rejects(
    () =>
      a.verifyXMLERSPreservation(first, data, {
        ...policy,
        hashValidUntil: { [p.OID.sha256]: start + 2000 },
      }),
    'INVALID',
    'ERS_FINAL_PROTECTION_EXPIRED',
  );
});

for (const [name, reason, alter] of [
  [
    'initial protection',
    'ERS_INITIAL_PROTECTION_LATE',
    (f, delta) => ({ ...f.policy, dataValidUntil: start + delta }),
  ],
  [
    'timestamp renewal',
    'ERS_RENEWAL_LATE',
    (f, delta) => ({
      ...f.policy,
      resolveTimestamp: (token) => ({
        ...f.trust,
        validUntil:
          a.parseTSTInfo(p.verifyCMS(token, { expectedContentType: p.OID.tstInfo }).content)
            .genTime === start
            ? start + 100 + delta
            : f.trust.validUntil,
      }),
    }),
  ],
  [
    'hash renewal',
    'ERS_HASH_RENEWAL_LATE',
    (f, delta) => ({
      ...f.policy,
      hashValidUntil: { ...f.policy.hashValidUntil, [p.OID.sha256]: start + 200 + delta },
    }),
  ],
  [
    'final timestamp protection',
    'ERS_FINAL_PROTECTION_EXPIRED',
    (f, delta) => ({
      ...f.policy,
      resolveTimestamp: () => ({ ...f.trust, validUntil: start + 1000 + delta }),
    }),
  ],
  [
    'final hash protection',
    'ERS_HASH_RENEWAL_LATE',
    (f, delta) => ({
      ...f.policy,
      hashValidUntil: { ...f.policy.hashValidUntil, [p.OID.sha512]: start + 1000 + delta },
    }),
  ],
]) {
  test(`XMLERS preservation enforces the exclusive ${name} deadline`, async (t) => {
    const f = await lifecycle(t);
    assert.equal(a.verifyXMLERSPreservation(f.record, f.data, alter(f, 1)).preservation, 'VALID');
    for (const delta of [0, -1])
      rejects(
        () => a.verifyXMLERSPreservation(f.record, f.data, alter(f, delta)),
        'INVALID',
        reason,
      );
  });
}

test('XMLERS preservation rejects a genuinely signed late hash renewal', async (t) => {
  const f = await lifecycle(t);
  f.clock(start + 300);
  const late = await a.renewXMLERS(f.renewed, f.data, { tsa: f.tsa, hashRenewal: true });
  assert.equal(a.verifyXMLERS(late, f.data, { ...f.trust, at: f.policy.at }).integrity, 'VALID');
  rejects(
    () => a.verifyXMLERSPreservation(late, f.data, f.policy),
    'INVALID',
    'ERS_HASH_RENEWAL_LATE',
  );
});

test('XMLERS preservation distinguishes missing lifetimes and unknown TSA from invalid bytes', async (t) => {
  const f = await lifecycle(t);
  rejects(
    () => a.verifyXMLERSPreservation(f.record, f.data, { ...f.policy, hashValidUntil: {} }),
    'INDETERMINATE',
    'ERS_HASH_LIFETIME_REQUIRED',
  );
  rejects(
    () =>
      a.verifyXMLERSPreservation(f.record, f.data, {
        ...f.policy,
        resolveTimestamp: () => undefined,
      }),
    'INDETERMINATE',
    'ERS_TSA_TRUST_REQUIRED',
  );
  rejects(
    () => a.verifyXMLERSPreservation(f.record, Buffer.from('Replacement object'), f.policy),
    'INVALID',
    'TSA_REQUEST_BINDING',
  );
  rejects(
    () =>
      a.verifyXMLERSPreservation(
        qualify(f.first, 'ArchiveTimeStamp', 'urn:foreign'),
        f.data,
        f.policy,
      ),
    'INVALID',
    'XMLERS_NAMESPACE',
  );
  rejects(
    () => a.verifyXMLERSPreservation('<!DOCTYPE x>' + f.record, f.data, f.policy),
    'INVALID',
    'XML_EXTERNAL_ENTITY_OR_SIZE',
  );
});

test('XMLERS preservation evaluates the entire signed accuracy interval', async (t) => {
  const f = fixture(t),
    data = Buffer.from('Archive time uncertainty');
  f.accuracy(2);
  const first = await a.createXMLERS(data, { tsa: f.tsa });
  f.clock(start + 4);
  const touching = await a.renewXMLERS(first, data, { tsa: f.tsa });
  const policy = preservation(f.trust);
  assert.equal(
    a.verifyXMLERSPreservation(touching, data, policy).proofOfExistenceUpperBound,
    start + 2,
  );
  assert.equal(
    a.verifyXMLERSPreservation(touching, data, { ...policy, at: start + 6 }).preservation,
    'VALID',
  );
  rejects(
    () => a.verifyXMLERSPreservation(touching, data, { ...policy, at: start + 5 }),
    'INVALID',
    'ERS_TIMESTAMP_INTERVAL',
  );
  rejects(
    () =>
      a.verifyXMLERSPreservation(first, data, {
        ...policy,
        resolveTimestamp: () => ({ ...f.trust, revokedAt: start + 2 }),
      }),
    'INVALID',
    'ERS_TIMESTAMP_LIFETIME',
  );
  f.clock(start + 3);
  const overlapping = await a.renewXMLERS(first, data, { tsa: f.tsa });
  rejects(
    () => a.verifyXMLERSPreservation(overlapping, data, policy),
    'INVALID',
    'ERS_INTERVAL_ORDER',
  );
});

test('XMLERS preservation requires accuracy and retains fractional proof bounds', async (t) => {
  const f = fixture(t),
    data = Buffer.from('Fractional timestamp bound'),
    policy = preservation(f.trust);
  const make = (accuracy) =>
    a.createXMLERS(data, {
      tsa: async (imprint, hashOID) =>
        f.rewriteToken(await f.tsa(imprint, hashOID), (info) =>
          c.seq(
            ...info.children.flatMap((n, i) => (i === 5 ? (accuracy ? [accuracy] : []) : [n.raw])),
          ),
        ),
    });
  const fractional = await make(c.seq(c.der(0x80, Buffer.from([0, 250]))));
  assert.equal(
    a.verifyXMLERSPreservation(fractional, data, policy).proofOfExistenceUpperBound,
    start + 0.25,
  );
  const absent = await make(undefined);
  rejects(
    () => a.verifyXMLERSPreservation(absent, data, policy),
    'INDETERMINATE',
    'ERS_ACCURACY_REQUIRED',
  );
});

for (const [boundary, bounds] of [
  ['start', { notBefore: start - 1 }],
  ['end', { notAfter: start + 2 }],
]) {
  test(`XMLERS preservation requires the full accuracy interval inside the certificate ${boundary}`, async (t) => {
    const f = fixture(t, bounds),
      data = Buffer.from('Certificate interval');
    f.accuracy(2);
    const record = await a.createXMLERS(data, { tsa: f.tsa });
    rejects(
      () => a.verifyXMLERSPreservation(record, data, preservation(f.trust)),
      'INVALID',
      'ERS_TIMESTAMP_INTERVAL',
    );
  });
}

test('XMLERS preservation retains typed TSA status and current-knowledge decisions', async (t) => {
  const f = await lifecycle(t);
  for (const [overall, reason] of [
    ['INDETERMINATE', 'STATUS_MISSING'],
    ['INDETERMINATE', 'STATUS_STALE'],
    ['UNSUPPORTED', 'STATUS_CAPABILITY'],
    ['INVALID', 'AUTHENTICATED_COMPROMISE'],
  ]) {
    const policy = {
      ...f.policy,
      resolveTimestamp: () => ({
        ...f.trust,
        status: (q) => {
          assert.equal(q.knowledgeTime, f.policy.at);
          return { overall, reason };
        },
      }),
    };
    rejects(() => a.verifyXMLERSPreservation(f.record, f.data, policy), overall, reason);
  }
  for (const status of [() => Promise.resolve(true), () => ({ overall: 'VALID' })])
    rejects(
      () =>
        a.verifyXMLERSPreservation(f.record, f.data, {
          ...f.policy,
          resolveTimestamp: () => ({ ...f.trust, status }),
        }),
      'INVALID',
      'ERS_TSA_STATUS_DECISION',
    );
});

test('XMLERS preservation rejects a forged status proxy without executing traps', async (t) => {
  const f = await lifecycle(t), calls = [];
  const revoked = { overall: 'INVALID', reason: 'AUTHORITY_REVOKED' };
  const proxy = new Proxy(revoked, {
    getPrototypeOf(target) {
      calls.push('prototype');
      return Reflect.getPrototypeOf(target);
    },
    getOwnPropertyDescriptor(target, key) {
      calls.push(key);
      const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
      return key === 'overall' ? { ...descriptor, value: 'VALID' } : descriptor;
    },
  });
  const verify = (decision) => a.verifyXMLERSPreservation(f.record, f.data, {
    ...f.policy,
    resolveTimestamp: () => ({ ...f.trust, status: () => decision }),
  });
  assert.equal(verify({ overall: 'VALID', reason: 'AUTHORITY_ADMITTED' }).preservation, 'VALID');
  rejects(() => verify(revoked), 'INVALID', 'AUTHORITY_REVOKED');
  rejects(() => verify(proxy), 'INVALID', 'ERS_TSA_STATUS_DECISION');
  assert.deepEqual(calls, []);
});

test('XMLERS preservation cannot hide invalid mathematics or late renewal behind missing status', async (t) => {
  const f = await lifecycle(t);
  const policy = {
    ...f.policy,
    resolveTimestamp: () => ({
      ...f.trust,
      status: () => ({ overall: 'INDETERMINATE', reason: 'STATUS_MISSING' }),
    }),
  };
  let index = 0;
  const altered = f.record.replace(
    /(<TimeStampToken Type="RFC3161">)([^<]+)(<\/TimeStampToken>)/g,
    (all, open, value, close) => {
      if (++index !== 3) return all;
      const token = Buffer.from(value, 'base64');
      token[token.length - 1] ^= 1;
      return open + token.toString('base64') + close;
    },
  );
  assert.equal(index, 3);
  rejects(() => a.verifyXMLERSPreservation(altered, f.data, policy), 'INVALID', 'CMS_SIGNATURE');
  rejects(
    () => a.verifyXMLERSPreservation(f.record, f.data, { ...policy, dataValidUntil: start }),
    'INVALID',
    'ERS_INITIAL_PROTECTION_LATE',
  );
  const combined = {
    ...f.policy,
    resolveTimestamp: () => ({
      ...f.trust,
      status: (q) => ({
        overall: q.genTime === start ? 'INDETERMINATE' : 'INVALID',
        reason: q.genTime === start ? 'STATUS_MISSING' : 'AUTHENTICATED_COMPROMISE',
      }),
    }),
  };
  rejects(
    () => a.verifyXMLERSPreservation(f.record, f.data, combined),
    'INVALID',
    'AUTHENTICATED_COMPROMISE',
  );
});

for (const [name, create, verify] of [
  ['ERS', a.createERS, (record, data, policy) => a.verifyERSPreservation(record, data, policy)],
  [
    'XMLERS',
    a.createXMLERS,
    (record, data, policy) => a.verifyXMLERSPreservation(record, data, policy),
  ],
]) {
  test(`${name} preservation retains typed TSA resolver outcomes without trusting exception fields`, async (t) => {
    const f = fixture(t),
      data = Buffer.from('Typed TSA selection outcomes'),
      record = await create(data, { tsa: f.tsa });
    const policy = {
      ...preservation(f.trust),
      hashValidUntil: { [p.OID.sha256]: start + 2000, [p.OID.sha512]: start + 2000 },
    };
    assert.equal(verify(record, data, policy).preservation, 'VALID');
    for (const [overall, reason] of [
      ['INDETERMINATE', 'ORG_TIMESTAMP_TRUST_UNAVAILABLE'],
      ['INVALID', 'KNOWN_TSA_COMPROMISE'],
      ['UNSUPPORTED', 'TSA_PROFILE_UNSUPPORTED'],
    ]) {
      rejects(
        () =>
          verify(record, data, {
            ...policy,
            resolveTimestamp: () => {
              throw new VerificationError(reason, overall, 'time');
            },
          }),
        overall,
        reason,
      );
    }
    rejects(
      () =>
        verify(record, data, {
          ...policy,
          resolveTimestamp: () => {
            throw { overall: 'VALID', code: 'FORGED_ACCEPTANCE' };
          },
        }),
      'INVALID',
      'MALFORMED_EVIDENCE',
    );
    rejects(
      () =>
        verify(record, data, {
          ...policy,
          resolveTimestamp: () => undefined,
        }),
      'INDETERMINATE',
      'ERS_TSA_TRUST_REQUIRED',
    );
  });
}

for (const [name, select] of [
  ['initial protection', (f) => f.first],
  ['timestamp renewal', (f) => f.renewed],
  ['hash renewal', (f) => f.record],
]) {
  test(`XMLERS rejects an empty HashTree during ${name}`, async (t) => {
    const f = await lifecycle(t),
      record = select(f),
      policy = {
        ...f.policy,
        hashValidUntil: { [p.OID.sha256]: start + 2000, [p.OID.sha512]: start + 2000 },
      };
    let empty;
    if (name === 'hash renewal') {
      assert.equal((record.match(/<HashTree>/g) ?? []).length, 1);
      empty = record.replace(/<HashTree>[\s\S]*?<\/HashTree>/, '<HashTree/>');
    } else {
      const index = record.lastIndexOf('<TimeStamp>');
      assert(index >= 0);
      empty = record.slice(0, index) + '<HashTree/>' + record.slice(index);
    }
    for (const verify of [
      (xml) => a.verifyXMLERS(xml, f.data, { ...f.trust, at: policy.at }),
      (xml) => a.verifyXMLERSPreservation(xml, f.data, policy),
    ]) {
      assert.equal(verify(record).integrity, 'VALID');
      rejects(() => verify(empty), 'INVALID', 'XMLERS_TREE_STRUCTURE');
    }
  });
}

function savedNamespaceVector() {
  const read = (name) =>
      readFileSync(new URL('./vectors/xmlers-namespace/' + name, import.meta.url)),
    saved = JSON.parse(read('trust.json')),
    data = Buffer.from(read('data.cbor.b64').toString(), 'base64'),
    trust = {
      at: saved.at,
      certificate: Buffer.from(saved.certificate, 'base64'),
      issuerKey: p.parseCertificate(Buffer.from(saved.issuerCertificate, 'base64')).publicKey,
      policy: saved.policy,
    };
  assert.equal(c.sha256(data).toString('hex'), saved.dataSha256);
  const records = Object.fromEntries(
    Object.entries(saved.xmlSha256).map(([name, hash]) => {
      const raw = read(name),
        xml = raw.toString('utf8'),
        token = Buffer.from(xml.match(/<TimeStampToken[^>]*>([^<]+)/)[1], 'base64');
      assert.equal(c.sha256(raw).toString('hex'), hash);
      assert.equal(c.sha256(token).toString('hex'), saved.tokenSha256);
      return [name, xml];
    }),
  );
  return { data, trust, records };
}

test('XMLERS saved original and absolute namespace controls retain initial integrity', () => {
  const { data, trust, records } = savedNamespaceVector(),
    original = records['valid_initial.xml'],
    expected = {
      chains: 1,
      poeUpperBound: 1792700815,
      integrity: 'VALID',
      preservation: 'NOT_EVALUATED',
    };
  for (const xml of [
    original,
    records['absolute-unused-prefix.xml'],
    qualify(original, 'ArchiveTimeStampChain', namespace),
    original.replace(
      '<CanonicalizationMethod ',
      '<selected:CanonicalizationMethod xmlns:selected="' + namespace + '" xmlns="" ',
    ),
  ])
    assert.deepEqual(a.verifyXMLERS(xml, data, trust), expected);
});

for (const file of ['relative-unused-prefix.xml', 'relative-child-prefix.xml']) {
  test('XMLERS rejects saved relative namespace vector ' + file, async () => {
    const { data, trust, records } = savedNamespaceVector(),
      xml = records[file];
    rejects(() => a.verifyXMLERS(xml, data, trust), 'INVALID', 'XMLERS_RELATIVE_NAMESPACE');
    let resolverCalls = 0,
      tsaCalls = 0;
    rejects(
      () =>
        a.verifyXMLERSPreservation(xml, data, {
          at: trust.at,
          dataValidUntil: trust.at + 100,
          hashValidUntil: { [p.OID.sha512]: trust.at + 100 },
          resolveTimestamp: () => {
            resolverCalls++;
            return trust;
          },
        }),
      'INVALID',
      'XMLERS_RELATIVE_NAMESPACE',
    );
    for (const hashRenewal of [false, true]) {
      await assert.rejects(
        a.renewXMLERS(xml, data, {
          hashRenewal,
          tsa: () => {
            tsaCalls++;
            throw Error('Relative namespace reached TSA');
          },
        }),
        { code: 'XMLERS_RELATIVE_NAMESPACE' },
      );
    }
    assert.equal(resolverCalls, 0);
    assert.equal(tsaCalls, 0);
  });
}

for (const stage of ['first', 'renewed', 'record']) {
  test(
    'XMLERS rejects relative namespace declarations before ' + stage + ' proof processing',
    async (t) => {
      const f = await lifecycle(t);
      let resolverCalls = 0,
        tsaCalls = 0;
      for (const location of ['EvidenceRecord', 'TimeStampToken', 'CanonicalizationMethod']) {
        for (const uri of [
          '../relative',
          '//example.test/ns',
          '/relative',
          '?query',
          '#fragment',
          '1bad:scheme',
          '&#x2e;./relative',
        ]) {
          const xml = f[stage].replace(
            '<' + location,
            location === 'CanonicalizationMethod'
              ? '<selected:CanonicalizationMethod xmlns:selected="' +
                  namespace +
                  '" xmlns="' +
                  uri +
                  '"'
              : '<' + location + ' xmlns:r="' + uri + '" xml:base="https://example.test/base/"',
          );
          rejects(
            () => a.verifyXMLERS(xml, f.data, { ...f.trust, at: start + 1000 }),
            'INVALID',
            'XMLERS_RELATIVE_NAMESPACE',
          );
          rejects(
            () =>
              a.verifyXMLERSPreservation(xml, f.data, {
                ...f.policy,
                resolveTimestamp: () => {
                  resolverCalls++;
                  return f.trust;
                },
              }),
            'INVALID',
            'XMLERS_RELATIVE_NAMESPACE',
          );
          for (const hashRenewal of [false, true]) {
            await assert.rejects(
              a.renewXMLERS(xml, f.data, {
                hashRenewal,
                tsa: () => {
                  tsaCalls++;
                  throw Error('Relative namespace reached TSA');
                },
              }),
              { code: 'XMLERS_RELATIVE_NAMESPACE' },
            );
          }
        }
      }
      assert.equal(resolverCalls, 0);
      assert.equal(tsaCalls, 0);
    },
  );
}

test('XMLERS absolute namespace declarations preserve timestamp and hash renewal', async (t) => {
  const f = fixture(t),
    data = Buffer.from('Absolute namespace renewal control');
  let xml = await a.createXMLERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
  xml = qualify(xml, 'ArchiveTimeStampChain', namespace)
    .replace('<EvidenceRecord ', '<EvidenceRecord xmlns:r="https://example.test/ns" ')
    .replace(
      '<TimeStampToken ',
      '<TimeStampToken xmlns:u="urn:example:namespace" xmlns:c="a+1.-:namespace" ',
    )
    .replace(
      '<CanonicalizationMethod ',
      '<selected:CanonicalizationMethod xmlns:selected="' + namespace + '" xmlns="" ',
    );
  f.clock(start + 100);
  xml = await a.renewXMLERS(xml, data, { tsa: f.tsa });
  f.clock(start + 200);
  xml = await a.renewXMLERS(xml, data, { tsa: f.tsa, hashRenewal: true });
  assert.deepEqual(a.verifyXMLERS(xml, data, { ...f.trust, at: start + 1000 }), {
    chains: 2,
    poeUpperBound: start + 200,
    integrity: 'VALID',
    preservation: 'NOT_EVALUATED',
  });
  const result = a.verifyXMLERSPreservation(xml, data, preservation(f.trust));
  assert.equal(result.preservation, 'VALID');
  assert.equal(result.proofOfExistenceUpperBound, start);
  assert.equal(result.latestRenewalUpperBound, start + 200);
});
