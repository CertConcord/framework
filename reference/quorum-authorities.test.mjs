import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { evidenceLeaf, createEvidencePackage } from './evidence-plan.mjs';
import { readControl } from './state.mjs';
import { runDemo } from './demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { createVerifier } from './sdk/index.mjs';
import { documentTimestampImprint } from './document-evidence.mjs';

const quorumRoles = new Set(['COSIGNER', 'MIRROR', 'TRANSPARENCY_LOG']);

function appointments({ bundle, trust }, format) {
  const payload = (type) => bundle.objects.find((object) => object.type === type).payload;
  const sim = c.decodeCBOR(payload('SIM'));
  const issuedAt =
    format === 'CMS'
      ? readControl(
          payload('RegistrationAuthorization'),
          'RegistrationAuthorization',
          trust.raCertificate,
        ).issuedAt
      : readControl(payload('CredentialSeal'), 'MdocCredentialSeal', trust.sealCertificate)
          .issuedAt;
  const { trustDomainID, issuerID } = trust.issuanceScope;
  const scope = {
    trustDomainID,
    issuerID,
    representation: format === 'CMS' ? 'MTC' : 'MDOC',
    profileID: sim.profileID,
  };
  const record = (member, role) => ({
    mode: 'RAW_KEY',
    publicKeyDER: c.spki(member.publicKey),
    roles: [role],
    scopes: [scope],
    knownAt: issuedAt - 60,
    validFrom: issuedAt - 60,
    validUntil: issuedAt + 3600,
    status: {
      scope: 'AUTHORITY',
      authorityID: c.keyID(member.publicKey),
      trustDomainID,
      status: 'GOOD',
      publishedAt: issuedAt - 60,
      nextUpdate: issuedAt + 3600,
    },
  });
  const members = format === 'CMS' ? trust.mtc.members : trust.credentialLogTrust.members;
  const role = format === 'CMS' ? 'COSIGNER' : 'MIRROR';
  const records = members.map((member) => record(member, role));
  if (format === 'MDOC') records.push(record(trust.credentialLogTrust.log, 'TRANSPARENCY_LOG'));
  const threshold = format === 'CMS' ? trust.mtc.threshold : trust.credentialLogTrust.threshold;
  assert.equal(members.length, 3);
  assert.equal(threshold, 2);
  const verify = (authorities, input = bundle) => {
    const resolveQuorum = createAuthorityResolver({ trustDomainID, authorities });
    return createVerifier({
      format,
      trust: {
        ...trust,
        authorityResolver: (query) =>
          quorumRoles.has(query.role) ? resolveQuorum(query) : trust.authorityResolver(query),
      },
    }).verify(c.dcbor(input));
  };
  const revoke = (record) => ({
    ...record,
    status: {
      ...record.status,
      status: 'REVOKED',
      publishedAt: issuedAt,
      effectiveTime: issuedAt,
      compromiseStart: issuedAt - 1,
    },
  });
  const forRole = (transform, selectedRole = role) =>
    records.flatMap((record, index) =>
      record.roles.includes(selectedRole) ? transform(record, index) : [record],
    );
  return { records, issuedAt, role, verify, revoke, forRole };
}

for (const format of ['CMS', 'MDOC']) {
  test(`${format} accepts only a quorum of independently authorized signing members`, async (t) => {
    const fixture = await (format === 'CMS' ? runDemo : runFoundationDemo)();
    const f = appointments(fixture, format);
    await t.test('finite raw-key appointments preserve the accepted operation', () => {
      assert.equal(f.verify(f.records).overall, 'VALID');
    });
    await t.test('missing appointments cannot provide the required quorum', () => {
      const result = f.verify(f.forRole((record, index) => (index === 0 ? [record] : [])));
      assert.equal(result.overall, 'INDETERMINATE', result.reason);
    });
    await t.test('expired appointments do not authorize historical signatures', () => {
      const result = f.verify(f.forRole((record) => [{ ...record, validUntil: f.issuedAt }]));
      assert.equal(result.overall, 'INVALID', result.reason);
    });
    await t.test('known compromise removes enough signatures to break the quorum', () => {
      const result = f.verify(
        f.forRole((record, index) => [index < 2 ? f.revoke(record) : record]),
      );
      assert.equal(result.overall, 'INVALID', result.reason);
    });
    await t.test('an extra revoked signing member does not veto two valid operators', () => {
      const result = f.verify(
        f.forRole((record, index) => [index === 2 ? f.revoke(record) : record]),
      );
      assert.equal(result.overall, 'VALID', result.reason);
    });
    await t.test('appointments for another issuer cannot satisfy the quorum', () => {
      const result = f.verify(
        f.forRole((record) => [
          { ...record, scopes: [{ ...record.scopes[0], issuerID: 'another-issuer' }] },
        ]),
      );
      assert.equal(result.overall, 'INVALID', result.reason);
    });
    const stale = f.forRole((record) => [
      { ...record, status: { ...record.status, nextUpdate: f.issuedAt } },
    ]);
    await t.test('stale member status leaves the authority quorum indeterminate', () => {
      const result = f.verify(stale);
      assert.equal(result.overall, 'INDETERMINATE', result.reason);
    });
    const unsupported = (record) => ({
      ...record,
      status: { ...record.status, critical: ['future-authority-condition'] },
    });
    await t.test('a quorum requiring unsupported votes is unsupported', () => {
      const result = f.verify(
        f.forRole((record, index) => [index < 2 ? unsupported(record) : record]),
      );
      assert.equal(result.overall, 'UNSUPPORTED', result.reason);
    });
    await t.test('an extra unsupported vote does not veto two valid operators', () => {
      const result = f.verify(
        f.forRole((record, index) => [index === 2 ? unsupported(record) : record]),
      );
      assert.equal(result.overall, 'VALID', result.reason);
    });
    await t.test(
      'two unavailable operators remain indeterminate without requiring an unsupported vote',
      () => {
        const result = f.verify(
          f.forRole((record, index) => [
            index === 2
              ? unsupported(record)
              : { ...record, status: { ...record.status, nextUpdate: f.issuedAt } },
          ]),
        );
        assert.equal(result.overall, 'INDETERMINATE', result.reason);
      },
    );
    await t.test('a bad operation signature is invalid despite stale member status', () => {
      const type = format === 'CMS' ? 'CMS' : 'COSE';
      const objects = fixture.bundle.objects.map((object) => {
        if (object.type !== type) return object;
        const payload = Buffer.from(object.payload);
        payload[payload.length - 1] ^= 1;
        return evidenceLeaf(type, payload);
      });
      const changed = createEvidencePackage(fixture.bundle.plan.profile, objects);
      assert.equal(f.verify(stale, changed).overall, 'INVALID');
    });
  });

  test(`${format} requires the same authority quorum through the trusted proof upper bound`, async (t) => {
    await (format === 'CMS' ? runDemo : runFoundationDemo)({
      trustedTime: true,
      onComplete: async (original) => {
        const initial = appointments(original, format),
          poeTime = initial.issuedAt + 10;
        const trust = { ...original.trust, knowledgeTime: poeTime + 2 };
        const f = appointments({ ...original, trust }, format);
        const laterCompromise = (record) => ({
          ...record,
          status: {
            ...record.status,
            status: 'REVOKED',
            publishedAt: poeTime + 1,
            effectiveTime: poeTime + 1,
            compromiseStart: poeTime,
          },
        });
        const compromised = f.forRole((record, index) => [
          index < 2 ? laterCompromise(record) : record,
        ]);
        assert.equal(f.verify(compromised).overall, 'VALID');
        const clock = t.mock.method(Date, 'now', () => poeTime * 1000);
        let token;
        try {
          token = original.timestamp.issue(
            documentTimestampImprint(format, original.bundle.objects),
          );
        } finally {
          clock.mock.restore();
        }
        const objects = original.bundle.objects.map((object) =>
          object.type === 'DocumentTimestamp' ? evidenceLeaf(object.type, token) : object,
        );
        const later = createEvidencePackage(original.bundle.plan.profile, objects);
        assert.equal(f.verify(f.records, later).overall, 'VALID');
        assert.equal(f.verify(compromised, later).overall, 'INVALID');
        if (format === 'MDOC') {
          const revokedLog = f.forRole((record) => [laterCompromise(record)], 'TRANSPARENCY_LOG');
          assert.equal(f.verify(revokedLog).overall, 'VALID');
          assert.equal(f.verify(revokedLog, later).overall, 'INVALID');
        }
      },
    });
  });
}

test('native mdoc log signatures require their own scoped authority appointment', async (t) => {
  const fixture = await runFoundationDemo();
  const f = appointments(fixture, 'MDOC');
  const cases = [
    ['missing log appointment', () => [], 'INDETERMINATE'],
    ['expired log appointment', (record) => [{ ...record, validUntil: f.issuedAt }], 'INVALID'],
    ['known compromised log', (record) => [f.revoke(record)], 'INVALID'],
    [
      'log appointed for another issuer',
      (record) => [{ ...record, scopes: [{ ...record.scopes[0], issuerID: 'another-issuer' }] }],
      'INVALID',
    ],
    [
      'stale log status',
      (record) => [{ ...record, status: { ...record.status, nextUpdate: f.issuedAt } }],
      'INDETERMINATE',
    ],
  ];
  for (const [label, transform, overall] of cases)
    await t.test(label, () => {
      const result = f.verify(f.forRole(transform, 'TRANSPARENCY_LOG'));
      assert.equal(result.overall, overall, result.reason);
    });
});
