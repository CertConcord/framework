import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import { TimestampResponseVerifier } from './timestamp-service.mjs';
import { encodeTimestampResponse, parseTimestampResponse } from './timestamp-protocol.mjs';
import { attr } from './cades-fixtures.mjs';
import { revokedTSAStatus } from './timestamp-revocation-fixtures.mjs';
import {
  O,
  epoch,
  applicationFixture,
  clone,
  deferred,
  assertVerdict,
  cmsView,
  rewriteCMS,
} from './timestamp-application-fixtures.mjs';

let f;
before(() => {
  f = applicationFixture();
});
after(() => f?.close());
const verify = (requestDER, responseDER, context = f.context()) =>
  new TimestampResponseVerifier({ readContext: async () => context }).verify({
    requestDER,
    responseDER,
  });
const badSignature = (token) => {
  const signature = Buffer.from(cmsView(token).signature);
  signature[signature.length - 1] ^= 1;
  return rewriteCMS(token, { signature });
};

for (const hashAlgorithm of ['sha256', 'sha512'])
  for (const certReq of [true, false])
    test(`${hashAlgorithm} imprint and certReq=${certReq} pass complete external-context verification`, async () => {
      const requestDER = f.request({
        hashAlgorithm,
        imprint: Buffer.alloc(hashAlgorithm === 'sha256' ? 32 : 64, 0x37),
        certReq,
      });
      const responseDER = f.response(requestDER),
        result = await verify(requestDER, responseDER);
      assertVerdict(result, 'VALID');
      assert.equal(result.nonceBound, true);
      assert.equal(result.genTime, epoch + 20);
      assert.equal(result.knowledgeTime, epoch + 40);
      assert.equal(result.lowerMicros, BigInt(epoch + 20) * 1000000n);
      assert.equal(result.upperMicros, result.lowerMicros);
      assert.equal(result.embeddedCertificates.length, certReq ? 2 : 0);
      assert(result.usedCertificates.some((raw) => raw.equals(f.tsa.der)));
      assert(result.usedCRLs.some((raw) => raw.equals(f.material().crls[0])));
      if (certReq) f.checkOpenSSL(result.tokenDER);
    });

test('nonce-free standalone proof is valid without claiming a nonce binding', async () => {
  const requestDER = f.request({ nonce: null });
  const result = await verify(requestDER, f.response(requestDER));
  assertVerdict(result, 'VALID');
  assert.equal(result.nonceBound, false);
});

for (const [name, change] of [
  ['imprint', { imprint: Buffer.alloc(32, 0x99) }],
  ['nonce', { nonce: 43n }],
  ['requested policy', { policy: '1.2.3.99' }],
])
  test(`valid CMS math cannot excuse a substituted ${name}`, async () => {
    const requestDER = f.request();
    assertVerdict(await verify(requestDER, f.response(requestDER, change)), 'INVALID');
  });

for (const certReq of [true, false])
  test(`certReq=${certReq} checks actual embedded certificate presence`, async () => {
    const requestDER = f.request({ certReq });
    assertVerdict(
      await verify(requestDER, f.response(requestDER, { includeCertificates: !certReq })),
      'INVALID',
      'TSP_CERTREQ_BINDING',
    );
  });

test('external signer candidates cannot replace the exact ESS-bound TSU', async () => {
  const requestDER = f.request({ certReq: false });
  const context = f.context();
  context.policy.currentMaterial.certificates = [f.root.der, f.successor.der];
  const result = await verify(requestDER, f.response(requestDER), context);
  assert.notEqual(result.overall, 'VALID');
  assert.equal(result.embeddedCertificates?.length ?? 0, 0);
});

for (const [status, reason] of [
  [2, 'TSP_REQUEST_REJECTED'],
  [3, 'TSP_WAITING'],
  [4, 'TSP_NO_TOKEN'],
  [5, 'TSP_NO_TOKEN'],
])
  test(`unsigned status ${status} is retained without becoming a timestamp proof or revocation fact`, async () => {
    const result = await verify(f.request(), encodeTimestampResponse({ status }));
    assertVerdict(result, 'INDETERMINATE', reason);
    assert.equal(result.protocol.status, status);
    assert.equal(result.tokenDER, undefined);
  });

test('grantedWithMods still enforces all request bindings', async () => {
  const requestDER = f.request();
  assertVerdict(await verify(requestDER, f.response(requestDER, { status: 1 })), 'VALID');
  assertVerdict(
    await verify(requestDER, f.response(requestDER, { status: 1, nonce: 44n })),
    'INVALID',
  );
});

test('unsupported response status retains bad-signature INVALID precedence', async () => {
  const requestDER = f.request(),
    token = f.token(requestDER);
  assertVerdict(await verify(requestDER, c.seq(c.seq(c.integer(6)), token)), 'UNSUPPORTED');
  assertVerdict(
    await verify(requestDER, c.seq(c.seq(c.integer(6)), badSignature(token))),
    'INVALID',
    'CADES_SIGNATURE_INVALID',
  );
});

for (const [name, statusInfo] of [
  ['wide status INTEGER', () => c.seq(c.integer(1n << 40n))],
  [
    'long failure BIT STRING',
    () => c.seq(c.integer(6), c.der(3, Buffer.concat([Buffer.from([0]), Buffer.alloc(4096, 255)]))),
  ],
])
  test(`${name} cannot conceal a safely retained token with bad signature math`, async () => {
    const requestDER = f.request(),
      token = f.token(requestDER);
    assertVerdict(await verify(requestDER, c.seq(statusInfo(), token)), 'UNSUPPORTED');
    assertVerdict(
      await verify(requestDER, c.seq(statusInfo(), badSignature(token))),
      'INVALID',
      'CADES_SIGNATURE_INVALID',
    );
  });

test('unavailable trusted context cannot conceal known bad signature math', async () => {
  const requestDER = f.request(),
    token = badSignature(f.token(requestDER));
  const verifier = new TimestampResponseVerifier({
    readContext: async () => {
      throw Error('offline');
    },
  });
  assertVerdict(
    await verifier.verify({
      requestDER,
      responseDER: encodeTimestampResponse({ status: 0, tokenDER: token }),
    }),
    'INVALID',
    'CADES_SIGNATURE_INVALID',
  );
});

test('caller cannot select an old knowledgeTime as a per-response option', async () => {
  const requestDER = f.request(),
    verifier = new TimestampResponseVerifier({ readContext: async () => f.context() });
  assertVerdict(
    await verifier.verify({
      requestDER,
      responseDER: f.response(requestDER),
      knowledgeTime: epoch + 20,
    }),
    'INVALID',
    'TSP_UNKNOWN_OPTION',
  );
});

test('a half-second accuracy bound waits for actual knowledge without future authority queries', async () => {
  const requestDER = f.request(),
    responseDER = f.response(requestDER, { accuracyMicros: 500000 });
  const queries = [],
    base = f.resolver(),
    context = f.context({ knowledgeTime: epoch + 20 });
  context.policy.authorityResolver = (query) => {
    queries.push(clone(query));
    return base(query);
  };
  const pending = await verify(requestDER, responseDER, context);
  assertVerdict(pending, 'INDETERMINATE', 'TSP_NOT_YET_OBSERVABLE');
  assert.equal(pending.upperMicros, BigInt(epoch + 20) * 1000000n + 500000n);
  assert(queries.every((query) => query.stateTime <= context.knowledgeTime));
  assert(queries.every((query) => query.knowledgeTime === context.knowledgeTime));
  context.knowledgeTime++;
  assertVerdict(await verify(requestDER, responseDER, context), 'VALID');
});

test('an authority appointment gap inside the uncertainty interval cannot hide behind valid endpoints', async () => {
  const requestDER = f.request(),
    context = f.context(),
    base = f.resolver();
  const queried = [];
  context.policy.authorityResolver = (query) => {
    queried.push(query.stateTime);
    return query.role === 'TIMESTAMP_AUTHORITY' && query.stateTime === epoch + 20
      ? { overall: 'INDETERMINATE', reason: 'TEST_APPOINTMENT_GAP' }
      : base(query);
  };
  assertVerdict(
    await verify(requestDER, f.response(requestDER, { accuracyMicros: 2000000 }), context),
    'INDETERMINATE',
    'TEST_APPOINTMENT_GAP',
  );
  assert(
    queried.includes(epoch + 18) && queried.includes(epoch + 20) && queried.includes(epoch + 22),
  );
});

test('the entire uncertainty interval must fit inside the TSU certificate period', async () => {
  const requestDER = f.request();
  assertVerdict(
    await verify(
      requestDER,
      f.response(requestDER, { genTime: epoch + 999, accuracyMicros: 1000000 }),
      f.context({ knowledgeTime: epoch + 1000 }),
    ),
    'INVALID',
  );
});

test('missing accuracy is uncertainty and excessive admitted accuracy is invalid', async () => {
  const requestDER = f.request();
  assertVerdict(
    await verify(requestDER, f.response(requestDER, { accuracyMicros: null })),
    'INDETERMINATE',
    'CADES_TIMESTAMP_ACCURACY_MISSING',
  );
  const context = f.context();
  context.policy.maxAccuracyMicros = 100;
  assertVerdict(
    await verify(requestDER, f.response(requestDER, { accuracyMicros: 101 }), context),
    'INVALID',
    'TSP_ACCURACY_POLICY',
  );
});

for (const role of ['ISSUER', 'TIMESTAMP_AUTHORITY', 'STATUS_AUTHORITY'])
  test(`current ${role} authorization is required with actual knowledge time`, async () => {
    const requestDER = f.request(),
      context = f.context(),
      base = f.resolver(),
      queries = [];
    context.policy.authorityResolver = (query) => {
      queries.push(clone(query));
      return query.role === role
        ? { overall: 'INVALID', reason: 'TEST_ROLE_WITHDRAWN' }
        : base(query);
    };
    assertVerdict(
      await verify(requestDER, f.response(requestDER), context),
      'INVALID',
      'TEST_ROLE_WITHDRAWN',
    );
    assert(queries.every((query) => query.knowledgeTime === epoch + 40));
    if (role === 'STATUS_AUTHORITY')
      assert(queries.some((query) => query.role === role && query.stateTime === epoch));
  });

test('an old claimed generation time cannot outlive a current key protection cutoff', async () => {
  const requestDER = f.request(),
    context = f.context();
  context.policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')] = epoch + 30;
  assertVerdict(
    await verify(requestDER, f.response(requestDER), context),
    'INVALID',
    'CADES_PROTECTION_GAP',
  );
});

for (const reason of [undefined, 1, 0, 3])
  test(`standalone TSU revocation reason ${reason ?? 'absent'} uses current authenticated status without self-POE`, async () => {
    const requestDER = f.request(),
      context = f.context({ knowledgeTime: epoch + 80 });
    context.policy.currentMaterial.crls = [revokedTSAStatus(f, { reason })];
    const result = await verify(requestDER, f.response(requestDER), context);
    if (reason === undefined || reason === 1)
      assertVerdict(result, 'INDETERMINATE', 'CADES_TSA_REVOKED_NO_POE');
    else assertVerdict(result, 'VALID');
  });

test('authenticated revocation effective before token generation remains INVALID', async () => {
  const requestDER = f.request(),
    context = f.context({ knowledgeTime: epoch + 80 });
  context.policy.currentMaterial.crls = [revokedTSAStatus(f, { reason: 0, revokedAt: epoch + 10 })];
  assertVerdict(
    await verify(requestDER, f.response(requestDER), context),
    'INVALID',
    'CADES_CERTIFICATE_REVOKED',
  );
});

test('stale CRL information cannot conceal a known token-signature failure', async () => {
  const requestDER = f.request(),
    context = f.context();
  context.policy.currentMaterial.crls = [f.crl({ nextUpdate: epoch + 30 })];
  const raw = f.token(requestDER);
  assertVerdict(
    await verify(requestDER, encodeTimestampResponse({ status: 0, tokenDER: raw }), context),
    'INDETERMINATE',
  );
  assertVerdict(
    await verify(
      requestDER,
      encodeTimestampResponse({ status: 0, tokenDER: badSignature(raw) }),
      context,
    ),
    'INVALID',
    'CADES_SIGNATURE_INVALID',
  );
});

test('unknown signed semantics are explicit unsupported capabilities', async () => {
  const requestDER = f.request();
  assertVerdict(
    await verify(
      requestDER,
      f.response(requestDER, { extraSigned: [attr('1.2.3.90', c.integer(1))] }),
    ),
    'UNSUPPORTED',
    'TSP_ATTRIBUTE_UNSUPPORTED',
  );
});

const claimedSigningTime = (at) =>
  attr(
    O.signingTime,
    c.der(
      23,
      Buffer.from(
        new Date(at * 1000).toISOString().replace(/[-:T]/g, '').replace('.000Z', 'Z').slice(2),
      ),
    ),
  );

test('optional signed signingTime is accepted as a non-authoritative claim distinct from genTime', async () => {
  const requestDER = f.request();
  for (const at of [epoch + 5, epoch + 90]) {
    const result = await verify(
      requestDER,
      f.response(requestDER, { extraSigned: [claimedSigningTime(at)] }),
    );
    assertVerdict(result, 'VALID');
    assert.equal(result.genTime, epoch + 20);
    assert.equal(result.knowledgeTime, epoch + 40);
  }
});

test('an earlier signed signingTime cannot make a not-yet-observable genTime current', async () => {
  const requestDER = f.request(),
    result = await verify(
      requestDER,
      f.response(requestDER, { genTime: epoch + 41, extraSigned: [claimedSigningTime(epoch + 5)] }),
    );
  assertVerdict(result, 'INDETERMINATE', 'TSP_NOT_YET_OBSERVABLE');
  assert.equal(result.genTime, epoch + 41);
  assert.equal(result.knowledgeTime, epoch + 40);
});

test('an earlier signed signingTime cannot override a currently withdrawn TSU role', async () => {
  const requestDER = f.request(),
    context = f.context(),
    base = f.resolver();
  context.policy.authorityResolver = (query) =>
    query.role === 'TIMESTAMP_AUTHORITY'
      ? { overall: 'INVALID', reason: 'TEST_CURRENT_WITHDRAWAL' }
      : base(query);
  assertVerdict(
    await verify(
      requestDER,
      f.response(requestDER, { extraSigned: [claimedSigningTime(epoch + 5)] }),
      context,
    ),
    'INVALID',
    'TEST_CURRENT_WITHDRAWAL',
  );
});

test('optional signed signingTime cannot conceal bad CMS signature math', async () => {
  const requestDER = f.request(),
    token = f.token(requestDER, { extraSigned: [claimedSigningTime(epoch + 5)] });
  assertVerdict(
    await verify(requestDER, encodeTimestampResponse({ status: 0, tokenDER: badSignature(token) })),
    'INVALID',
    'CADES_SIGNATURE_INVALID',
  );
});

test('request and response are snapshotted before the first context await', async () => {
  const requestDER = f.request(),
    responseDER = f.response(requestDER),
    entered = deferred(),
    release = deferred();
  const verifier = new TimestampResponseVerifier({
    readContext: async () => {
      entered.resolve();
      return release.promise;
    },
  });
  const waiting = verifier.verify({ requestDER, responseDER });
  await entered.promise;
  requestDER.fill(0);
  responseDER.fill(0);
  release.resolve(f.context());
  assertVerdict(await waiting, 'VALID');
});

test('every standalone verification reads fresh authority context and rejects knowledge rollback', async () => {
  const requestDER = f.request(),
    responseDER = f.response(requestDER),
    context = f.context();
  const verifier = new TimestampResponseVerifier({ readContext: async () => context });
  assertVerdict(await verifier.verify({ requestDER, responseDER }), 'VALID');
  const base = context.policy.authorityResolver;
  context.policy.authorityResolver = (query) =>
    query.role === 'TIMESTAMP_AUTHORITY'
      ? { overall: 'INVALID', reason: 'TEST_REVOKED' }
      : base(query);
  assertVerdict(await verifier.verify({ requestDER, responseDER }), 'INVALID', 'TEST_REVOKED');
  context.policy.authorityResolver = base;
  context.knowledgeTime--;
  assertVerdict(
    await verifier.verify({ requestDER, responseDER }),
    'INDETERMINATE',
    'TSP_CLOCK_ROLLBACK',
  );
});

test('returned token and material buffers do not alias the caller response', async () => {
  const requestDER = f.request(),
    responseDER = f.response(requestDER),
    expected = parseTimestampResponse(responseDER).tokenDER;
  const result = await verify(requestDER, responseDER);
  result.tokenDER.fill(0);
  result.certificate.fill(0);
  result.usedCRLs[0].fill(0);
  assert.deepEqual(parseTimestampResponse(responseDER).tokenDER, expected);
  assertVerdict(await verify(requestDER, responseDER), 'VALID');
});
