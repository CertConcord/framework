import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { createIndependentOrganizationHistoryFixture } from './fixtures-history-independent.mjs';
import {
  createOrganizationHistorySource,
  createOrganizationHistoryVerifier,
} from './sdk/index.mjs';

const copy = (value) => c.decodeCBOR(c.dcbor(value));
let fixture;
test.before(async () => {
  fixture = await createIndependentOrganizationHistoryFixture();
});
test.after(() => fixture?.close());

function descriptor(f = fixture) {
  const pin = (tsa) => ({
    certificate: tsa.certificate,
    issuerPublicKeyDER: c.spki(tsa.issuerKey),
    policy: tsa.policy,
    validUntil: tsa.validUntil,
    signatureProfile: 'CERTCONCORD-PQ',
  });
  const publicationCertificate = p.verifyCMS(f.history[0].publicationProof, {
    expectedContentType: p.OID.tstInfo,
  }).certificate;
  return copy({
    configuration: {
      schemaVersion: 1,
      trust: f.trust,
      retainedAuthorities: {
        governance: {
          roots: [
            { publicKeyDER: c.spki(f.root.publicKey), validFrom: f.A - 60, validUntil: f.end },
          ],
          threshold: 1,
        },
        algorithmDeadlines: { 'ml-dsa-65': f.end, 'ml-dsa-87': f.end, ec: f.end },
        publication: {
          format: 'RFC3161',
          timestampAuthorities: [
            {
              certificate: publicationCertificate,
              issuerPublicKeyDER: c.spki(f.root.publicKey),
              policy: f.initialTSA.policy,
              validFrom: f.A - 60,
              validUntil: f.end,
              knowledgeValidUntil: f.end,
              signatureProfile: 'CERTCONCORD-PQ',
            },
          ],
          hashValidUntil: { [p.OID.sha512]: f.end },
        },
      },
      preservation: {
        hashValidUntil: f.options.preservationPolicy.hashValidUntil,
        dataValidUntil: f.options.preservationPolicy.dataValidUntil,
        timestampAuthorities: [pin(f.initialTSA), pin(f.renewalTSA)],
      },
    },
    knowledge: {
      ...f.knowledge,
      authorityHistory: f.history.map((entry) => ({
        manifest: c.dcbor(entry.manifest),
        signatures: entry.signatures,
        publicationProof: entry.publicationProof,
      })),
    },
  });
}
function sourceFor(value = descriptor()) {
  return createOrganizationHistorySource({
    configuration: value.configuration,
    readKnowledge: () => value.knowledge,
  });
}
function verify(value = descriptor(), input = fixture.input) {
  const source = sourceFor(value);
  try {
    return createOrganizationHistoryVerifier({ source }).verify(input);
  } finally {
    source.close();
  }
}

test('declarative source verifies the saved original using only declared public material', () => {
  const expected = createOrganizationHistoryVerifier(fixture.options).verify(fixture.input);
  assert.equal(expected.overall, 'VALID');
  const fetch = globalThis.fetch;
  globalThis.fetch = () => {
    throw Error('offline verification attempted a network call');
  };
  try {
    assert.deepEqual(verify(), expected);
    assert.equal(fixture.source.calls.sign, 1);
  } finally {
    globalThis.fetch = fetch;
  }
});

test('declarative memory results preserve the legacy complete result and have no receipt', () => {
  const value = descriptor();
  value.knowledge.statusMaterial = [];
  value.knowledge.certificateStatusMaterial = [];
  const { authorityHistory: ignored, ...knowledge } = value.knowledge;
  const expected = createOrganizationHistoryVerifier({
    ...fixture.options,
    readKnowledge: () => knowledge,
  }).verify(fixture.input);
  assert.equal(expected.overall, 'INDETERMINATE');
  assert.deepEqual(verify(value), expected);
  assert.equal(Object.hasOwn(expected, 'knowledgeReceipt'), false);
});

test('one memory source shares admitted incidents across verifier instances', () => {
  const value = descriptor(),
    f = fixture;
  value.knowledge.statusMaterial.push(
    f.organizationStatus(f.originalStatusMembers[0], {
      epoch: 3,
      status: 'REVOKED',
      effectiveTime: f.K - 1,
      compromiseStart: f.A,
    }),
  );
  const source = sourceFor(value);
  try {
    const first = createOrganizationHistoryVerifier({ source }).verify(f.input);
    assert.equal(first.currentAdmissibility.overall, 'INVALID');
    const { authorityHistory: ignored, ...knowledge } = value.knowledge;
    assert.deepEqual(
      first,
      createOrganizationHistoryVerifier({ ...f.options, readKnowledge: () => knowledge }).verify(
        f.input,
      ),
    );
    value.knowledge.knowledgeTime++;
    value.knowledge.statusMaterial = f.originalStatusMembers.map((member) =>
      f.organizationStatus(member, { epoch: 4, publishedAt: f.K }),
    );
    const second = createOrganizationHistoryVerifier({ source }).verify(f.input);
    assert.equal(second.overall, 'INVALID');
    assert.equal(second.historicalAuthorization.overall, 'VALID');
    assert.equal(second.currentAdmissibility.overall, 'INVALID');
    assert.equal(verify(value).overall, 'VALID', 'a new memory source is not a durable source');
  } finally {
    source.close();
  }
});

test('one reader snapshot per verification preserves equality and rejects K rollback', () => {
  const value = descriptor();
  let reads = 0;
  const source = createOrganizationHistorySource({
    configuration: value.configuration,
    readKnowledge: () => {
      reads++;
      return value.knowledge;
    },
  });
  try {
    const first = createOrganizationHistoryVerifier({ source });
    assert.equal(first.verify(fixture.input).overall, 'VALID');
    assert.equal(reads, 1);
    assert.equal(
      createOrganizationHistoryVerifier({ source }).verify(fixture.input).overall,
      'VALID',
    );
    assert.equal(reads, 2);
    value.knowledge.knowledgeTime--;
    const rollback = first.verify(fixture.input);
    assert.equal(rollback.overall, 'INVALID');
    assert.equal(rollback.reason, 'ORG_KNOWLEDGE_ROLLBACK');
    assert.equal(reads, 3);
  } finally {
    source.close();
  }
});

test('empty retained history supplies no historical authority or preservation', () => {
  const value = descriptor();
  value.knowledge.authorityHistory = [];
  const result = verify(value);
  assert.equal(result.overall, 'INDETERMINATE');
  assert.equal(result.historicalAuthorization.overall, 'INDETERMINATE');
  assert.equal(result.currentAdmissibility.overall, 'INDETERMINATE');
  assert.equal(result.preservation.overall, 'INDETERMINATE');
  assert.equal(result.proofOfExistenceUpperBound, null);
});

test('declarative source retains exact fractional P for scoped authority queries', async () => {
  const f = await createIndependentOrganizationHistoryFixture({ firstAccuracyMillis: 500 });
  try {
    const result = verify(descriptor(f), f.input);
    assert.equal(result.overall, 'VALID', JSON.stringify(result));
    assert.equal(result.proofOfExistenceUpperBound, f.A + 1.5);
    assert.equal(result.historicalAuthorization.stateTime, f.A + 1.5);
    assert.equal(result.historicalAuthorization.knowledgeTime, f.A + 1.5);
    assert.equal(result.currentAdmissibility.stateTime, f.A + 1.5);
    assert.equal(result.currentAdmissibility.knowledgeTime, f.K);
  } finally {
    f.close();
  }
});

for (const kind of ['knowledge coverage', 'direct proof protection', 'hash protection'])
  test(`publication ${kind} ending at latest K preserves the earlier historical view`, () => {
    const value = descriptor(),
      publication = value.configuration.retainedAuthorities.publication;
    if (kind === 'knowledge coverage')
      publication.timestampAuthorities[0].knowledgeValidUntil = fixture.K;
    if (kind === 'direct proof protection')
      publication.timestampAuthorities[0].validUntil = fixture.K;
    if (kind === 'hash protection') publication.hashValidUntil[p.OID.sha512] = fixture.K;
    const result = verify(value);
    assert.equal(result.overall, 'INDETERMINATE', JSON.stringify(result));
    assert.equal(result.historicalAuthorization.overall, 'VALID');
    assert.equal(result.proofOfExistenceUpperBound, fixture.P);
    assert.equal(result.currentAdmissibility.overall, 'INDETERMINATE');
    assert.equal(result.preservation.overall, 'INDETERMINATE');
  });

test('publication coverage immediately beyond latest K remains usable', () => {
  const value = descriptor();
  value.configuration.retainedAuthorities.publication.timestampAuthorities[0].knowledgeValidUntil =
    fixture.K + 1;
  assert.equal(verify(value).overall, 'VALID');
});

test('selected publication revocation cannot become a default true status', () => {
  const value = descriptor();
  value.configuration.retainedAuthorities.publication.timestampAuthorities[0].revokedAt = fixture.K;
  const result = verify(value);
  assert.equal(result.overall, 'INVALID');
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
});

test('mutating descriptor buffers after construction does not change selected trust', () => {
  const value = descriptor(),
    source = sourceFor(value);
  value.configuration.trust.organizationID.fill(0);
  value.configuration.retainedAuthorities.governance.roots[0].publicKeyDER.fill(0);
  value.configuration.preservation.timestampAuthorities[0].certificate.fill(0);
  try {
    assert.equal(
      createOrganizationHistoryVerifier({ source }).verify(fixture.input).overall,
      'VALID',
    );
  } finally {
    source.close();
  }
});

for (const [name, mutate] of [
  [
    'an in-memory database path claiming durability',
    (value) => {
      value.databasePath = ':memory:';
    },
  ],
  [
    'an outcome callback',
    (value) => {
      value.configuration.authorityResolver = () => ({ overall: 'VALID' });
    },
  ],
  [
    'a private key field',
    (value) => {
      value.configuration.retainedAuthorities.governance.roots[0].privateKey =
        Buffer.from('private');
    },
  ],
  [
    'a KeyObject',
    (value) => {
      value.configuration.preservation.timestampAuthorities[0].issuerPublicKeyDER =
        fixture.root.publicKey;
    },
  ],
  [
    'an ambiguous timestamp certificate',
    (value) => {
      value.configuration.preservation.timestampAuthorities.push(
        copy(value.configuration.preservation.timestampAuthorities[0]),
      );
    },
  ],
  [
    'a duplicate governance root',
    (value) => {
      value.configuration.retainedAuthorities.governance.roots.push(
        copy(value.configuration.retainedAuthorities.governance.roots[0]),
      );
    },
  ],
  [
    'an unknown policy field',
    (value) => {
      value.configuration.trust.policy.callerOutcome = 'VALID';
    },
  ],
  [
    'an unbounded publication status',
    (value) => {
      delete value.configuration.retainedAuthorities.publication.timestampAuthorities[0]
        .knowledgeValidUntil;
    },
  ],
])
  test(`source constructor rejects ${name}`, () => {
    const value = descriptor(),
      options = { configuration: value.configuration, readKnowledge: () => value.knowledge };
    mutate(options);
    assert.throws(() => createOrganizationHistorySource(options));
  });

test('source rejects accessors without reading their values', () => {
  const value = descriptor();
  let reads = 0;
  Object.defineProperty(value.configuration, 'extra', {
    enumerable: true,
    get() {
      reads++;
      return true;
    },
  });
  assert.throws(() => sourceFor(value), { code: 'ORG_OBJECT_SCHEMA' });
  assert.equal(reads, 0);
});

test('source rejects noncanonical public SPKI and encoded private keys', () => {
  const noncanonical = descriptor();
  const pin = noncanonical.configuration.preservation.timestampAuthorities[0];
  pin.issuerPublicKeyDER = Buffer.concat([pin.issuerPublicKeyDER, Buffer.from([0])]);
  assert.throws(() => sourceFor(noncanonical), { code: 'ORG_HISTORY_SOURCE_PUBLIC_KEY' });
  const privateKey = descriptor();
  privateKey.configuration.retainedAuthorities.governance.roots[0].publicKeyDER =
    fixture.root.privateKey.export({ format: 'der', type: 'pkcs8' });
  assert.throws(() => sourceFor(privateKey));
});

test('source configuration byte budget rejects an oversized descriptor before use', () => {
  const value = descriptor();
  value.configuration.trust.policy.audience = 'x'.repeat(4 * 1024 * 1024);
  assert.throws(() => sourceFor(value), {
    code: 'ORG_HISTORY_SOURCE_LIMIT',
    overall: 'UNSUPPORTED',
  });
});

test('opaque source cannot be forged or mixed with caller decision overrides', () => {
  assert.throws(() =>
    createOrganizationHistoryVerifier({ source: { close() {}, readEvidence() {} } }),
  );
  const source = sourceFor();
  try {
    assert.throws(() =>
      createOrganizationHistoryVerifier({
        source,
        authorityResolver: () => ({ overall: 'VALID', reason: 'caller' }),
      }),
    );
    let reads = 0;
    assert.throws(
      () =>
        createOrganizationHistoryVerifier({
          get source() {
            reads++;
            return source;
          },
        }),
      { code: 'ORG_OBJECT_SCHEMA' },
    );
    assert.equal(reads, 0);
  } finally {
    source.close();
  }
});

test('closed memory source never returns a cached positive or an artifact', () => {
  const source = sourceFor(),
    verifier = createOrganizationHistoryVerifier({ source });
  assert.equal(verifier.verify(fixture.input).overall, 'VALID');
  assert.equal(source.readEvidence('candidate'), undefined);
  source.close();
  source.close();
  assert.equal(source.readEvidence('candidate'), undefined);
  const result = verifier.verify(fixture.input);
  assert.notEqual(result.overall, 'VALID');
  assert.notEqual(result.currentAdmissibility.overall, 'VALID');
});

for (const [name, mutate] of [
  [
    'a decoded manifest',
    (value) => {
      value.authorityHistory[0].manifest = c.decodeCBOR(value.authorityHistory[0].manifest);
    },
  ],
  [
    'a noncanonical manifest header',
    (value) => {
      const raw = value.authorityHistory[0].manifest;
      value.authorityHistory[0].manifest = Buffer.concat([
        Buffer.from([0xb8, raw[0] & 31]),
        raw.subarray(1),
      ]);
    },
  ],
  [
    'trailing manifest bytes',
    (value) => {
      value.authorityHistory[0].manifest = Buffer.concat([
        value.authorityHistory[0].manifest,
        Buffer.from([0]),
      ]);
    },
  ],
  [
    'unknown knowledge fields',
    (value) => {
      value.overall = 'VALID';
    },
  ],
  [
    'more than 64 status members',
    (value) => {
      value.statusMaterial = Array(65).fill(value.statusMaterial[0]);
    },
  ],
  [
    'more than 256 history entries',
    (value) => {
      value.authorityHistory = Array(257).fill(value.authorityHistory[0]);
    },
  ],
  [
    'a malformed status member',
    (value) => {
      value.statusMaterial[0].cms = {};
    },
  ],
  [
    'an oversized knowledge snapshot',
    (value) => {
      value.authorityHistory[0].manifest = Buffer.alloc(16 * 1024 * 1024);
    },
  ],
])
  test(`malformed source knowledge returns a typed failure for ${name}`, () => {
    const value = descriptor();
    mutate(value.knowledge);
    const result = verify(value);
    assert.equal(result.overall, 'INDETERMINATE');
    assert.equal(result.coreRevision, 'draft-03');
    assert.equal(result.knowledgeTime, null);
  });

test('async and throwing readers cannot choose the verification outcome', async () => {
  const value = descriptor();
  for (const readKnowledge of [
    () => Promise.reject({ overall: 'VALID', reason: 'caller' }),
    () => {
      throw { overall: 'VALID', reason: 'caller' };
    },
  ]) {
    const source = createOrganizationHistorySource({
      configuration: value.configuration,
      readKnowledge,
    });
    try {
      const result = createOrganizationHistoryVerifier({ source }).verify(fixture.input);
      assert.equal(result.overall, 'INDETERMINATE');
      assert.equal(result.reason, 'ORG_HISTORY_KNOWLEDGE_UNAVAILABLE');
    } finally {
      source.close();
    }
  }
  await new Promise((resolve) => setImmediate(resolve));
});

for (const [name, mutate] of [
  [
    'publication signature',
    (value) => {
      const raw = value.knowledge.authorityHistory[0].publicationProof;
      raw[raw.length - 1] ^= 1;
    },
  ],
  [
    'governance signature',
    (value) => {
      value.knowledge.authorityHistory[0].signatures[0].signature[0] ^= 1;
    },
  ],
  [
    'publication issuer pin',
    (value) => {
      value.configuration.retainedAuthorities.publication.timestampAuthorities[0].issuerPublicKeyDER =
        c.spki(fixture.successorRoot.publicKey);
    },
  ],
  [
    'archive issuer pin',
    (value) => {
      value.configuration.preservation.timestampAuthorities[0].issuerPublicKeyDER = c.spki(
        fixture.successorRoot.publicKey,
      );
    },
  ],
])
  test(`changed ${name} never authenticates retained history`, () => {
    const value = descriptor();
    mutate(value);
    const result = verify(value);
    assert.equal(result.overall, 'INVALID', JSON.stringify(result));
    assert.notEqual(result.historicalAuthorization.overall, 'VALID');
  });
