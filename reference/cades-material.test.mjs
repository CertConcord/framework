import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { validateCAdESMaterial } from './cades-validation.mjs';
import { O, epoch, fixture, expectOverall } from './cades-fixtures.mjs';

let f, good;
before(() => {
  f = fixture({ signerNotAfter: epoch + 1000 });
  good = f.crl({ thisUpdate: epoch + 20, nextUpdate: epoch + 100 });
});
after(() => f?.close());
const policy = (changes = {}) => f.policy({ currentMaterial: undefined, ...changes });
const run = (changes = {}) =>
  validateCAdESMaterial({
    certificate: f.signer.der,
    certificates: [f.root.der, f.signer.der],
    crls: [good],
    purpose: 'SIGNER',
    stateTime: epoch + 10,
    knowledgeTime: epoch + 60,
    policy: policy(),
    ...changes,
  });
const rootCutoff = (kind = 'key') => {
  const value = policy();
  if (kind === 'key') value.keyDeadlines[c.keyID(f.root.publicKey).toString('hex')] = epoch + 40;
  else
    value[kind === 'hash' ? 'hashDeadlines' : 'algorithmDeadlines'][
      kind === 'hash' ? O.sha256 : O.es256
    ] = epoch + 40;
  return value;
};
const crl = (changes = {}) =>
  f.crl({ thisUpdate: epoch + 20, nextUpdate: epoch + 100, ...changes });
const mutateCRL = (input, change) => {
  const [tbs, alg] = c.parseDER(input).children,
    fields = tbs.children.map((n) => n.raw);
  const old = tbs.children.at(-1).children[0].children.map((n) => n.raw);
  fields[fields.length - 1] = c.der(0xa0, c.seq(...change(old)));
  const next = c.seq(...fields);
  return c.seq(next, alg.raw, c.bit(c.sign(next, f.root.privateKey)));
};

test('selected material baseline uses a real direct-root certificate and signed full CRL', () =>
  expectOverall(run(), 'VALID'));
test('material evaluation snapshots reused authority decision objects', () => {
  const shared = {};
  const authorityResolver = (q) => {
    Object.assign(
      shared,
      q.role === 'ISSUER'
        ? { overall: 'INVALID', reason: 'ISSUER_DENIED' }
        : { overall: 'VALID', reason: 'STATUS_ALLOWED' },
    );
    return shared;
  };
  const result = run({ policy: policy({ authorityResolver }) });
  expectOverall(result, 'INVALID');
  assert.equal(result.reason, 'ISSUER_DENIED');
});
test('later-known authenticated CRL revocation still applies to historical evidence', () => {
  expectOverall(
    run({
      evidenceTime: epoch + 30,
      knownCRLs: [crl({ number: 2, thisUpdate: epoch + 50, entries: [{ revokedAt: epoch + 5 }] })],
    }),
    'INVALID',
  );
});
test('external current CRL cannot supply positive historical closure', () => {
  expectOverall(
    run({
      evidenceTime: epoch + 30,
      crls: [],
      policy: policy({ currentMaterial: { crls: [good] } }),
    }),
    'INDETERMINATE',
  );
});
test('CRL published after certificate expiry cannot establish GOOD without retention semantics', () => {
  const result = run({
    knowledgeTime: epoch + 1200,
    crls: [crl({ thisUpdate: epoch + 1100, nextUpdate: epoch + 1300 })],
  });
  expectOverall(result, 'INDETERMINATE');
  assert.equal(result.reason, 'CADES_CRL_STALE');
});
test('CRL issued before certificate expiry may remain fresh after ordinary certificate expiry', () => {
  expectOverall(
    run({
      knowledgeTime: epoch + 1200,
      crls: [crl({ thisUpdate: epoch + 990, nextUpdate: epoch + 1500 })],
    }),
    'VALID',
  );
});
test('bad CRL signature outranks missing external authority resolver', () => {
  const bad = Buffer.from(good);
  bad[bad.length - 1] ^= 1;
  const result = run({ crls: [bad], policy: policy({ authorityResolver: undefined }) });
  expectOverall(result, 'INVALID');
  assert.equal(result.reason, 'CADES_CRL_SIGNATURE');
});
for (const kind of ['key', 'algorithm', 'hash']) {
  for (const publication of [25, 50])
    test(`unprotected ${publication === 25 ? 'backdated' : 'later'} negative CRL after root ${kind} cutoff is not authenticated`, () => {
      const result = run({
        evidenceTime: epoch + 30,
        policy: rootCutoff(kind),
        knownCRLs: [
          crl({ number: 2, thisUpdate: epoch + publication, entries: [{ revokedAt: epoch + 5 }] }),
        ],
      });
      expectOverall(result, 'INDETERMINATE');
      assert.equal(result.reason, 'CADES_CRL_AUTHENTICITY_UNPROVEN');
    });
}
test('negative CRL protected before root cutoff remains authenticated and INVALID', () => {
  const result = run({
    evidenceTime: epoch + 30,
    policy: rootCutoff(),
    crls: [crl({ entries: [{ revokedAt: epoch + 5 }] })],
  });
  expectOverall(result, 'INVALID');
  assert.equal(result.reason, 'CADES_CERTIFICATE_REVOKED');
});
test('positive CRL protected before root cutoff remains usable with current knowledge', () => {
  expectOverall(run({ evidenceTime: epoch + 30, policy: rootCutoff() }), 'VALID');
});
test('unprotected GOOD after root cutoff cannot be accepted on its claimed publication time', () => {
  expectOverall(run({ policy: rootCutoff() }), 'INDETERMINATE');
});
test('CRL proof at the exclusive root cutoff is too late', () => {
  expectOverall(run({ evidenceTime: epoch + 40, policy: rootCutoff() }), 'INDETERMINATE');
});
test('two valid ECDSA signatures on the exact same CRL TBS do not create a content fork', () => {
  const repeated = crl();
  assert.deepEqual(c.parseDER(good).children[0].raw, c.parseDER(repeated).children[0].raw);
  assert.notDeepEqual(good, repeated);
  expectOverall(run({ crls: [good, repeated] }), 'VALID');
});
test('same CRL number with two different authenticated GOOD contents is indeterminate', () => {
  const result = run({ crls: [good, crl({ thisUpdate: epoch + 25 })] });
  expectOverall(result, 'INDETERMINATE');
  assert.equal(result.reason, 'CADES_CRL_CONFLICT');
});
test('bad CRL signature remains INVALID despite unavailable post-cutoff authenticity', () => {
  const bad = Buffer.from(good);
  bad[bad.length - 1] ^= 1;
  const result = run({ evidenceTime: epoch + 30, policy: rootCutoff(), knownCRLs: [bad] });
  expectOverall(result, 'INVALID');
  assert.equal(result.reason, 'CADES_CRL_SIGNATURE');
});
test('a full CRL without AKI is missing required selected-profile evidence', () => {
  const missing = mutateCRL(good, (values) =>
    values.filter((raw) => c.oidText(c.parseDER(raw).children[0]) !== '2.5.29.35'),
  );
  const result = run({ crls: [missing] });
  expectOverall(result, 'INDETERMINATE');
  assert.equal(result.reason, 'CADES_AUTHORITY_KEY_IDENTIFIER_REQUIRED');
});
test('a full CRL with valid signature but mismatched AKI is INVALID', () => {
  const mismatch = mutateCRL(good, (values) =>
    values.map((raw) =>
      c.oidText(c.parseDER(raw).children[0]) === '2.5.29.35'
        ? p.extension('2.5.29.35', c.seq(c.der(0x80, Buffer.alloc(20, 0x55))))
        : raw,
    ),
  );
  const result = run({ crls: [mismatch] });
  expectOverall(result, 'INVALID');
  assert.equal(result.reason, 'CADES_AUTHORITY_KEY_BINDING');
});
test('authority callback receives original current knowledge for protected historical status', () => {
  const queries = [],
    resolver = f.authorities();
  expectOverall(
    run({
      evidenceTime: epoch + 30,
      policy: policy({
        authorityResolver: (q) => {
          queries.push(q);
          return resolver(q);
        },
      }),
    }),
    'VALID',
  );
  assert(queries.length > 0);
  assert(queries.every((q) => q.knowledgeTime === epoch + 60));
});
