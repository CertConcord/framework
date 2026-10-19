import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { runDemo } from './demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { runDocumentDemo } from './document-demo.mjs';
import { decodeJWS, signJWS } from './jose.mjs';
import { createVerifier } from './sdk/index.mjs';
import { createERS, renewERS } from './archive.mjs';
import { evidenceLeaf, createEvidencePackage } from './evidence-plan.mjs';
import { documentTimestampImprint } from './document-evidence.mjs';
import { verifyPreservedDocument } from './historical-validation.mjs';

const variants = [
  ['CMS certificate status', 'CMS', 'CertificateStatus', runDemo],
  ['native mdoc status list', 'MDOC', 'CredentialStatusList', runFoundationDemo],
  ['organization authorization status', 'CMS', 'OrganizationAuthorizationStatus', runDocumentDemo],
];
function replace(bundle, type, payload) {
  return createEvidencePackage(
    bundle.plan.profile,
    bundle.objects.map((leaf) => (leaf.type === type ? evidenceLeaf(type, payload) : leaf)),
  );
}
function statusWriter(r, type) {
  const raw = r.bundle.objects.find((leaf) => leaf.type === type).payload;
  if (type === 'CertificateStatus') {
    const body = c.decodeCBOR(p.verifyCMS(raw).content)[3];
    return (publishedAt, nextUpdate) => r.signStatus({ ...body, publishedAt, nextUpdate });
  }
  if (type === 'OrganizationAuthorizationStatus')
    return (publishedAt, nextUpdate) => r.organizationStatus({ publishedAt, nextUpdate });
  const body = JSON.parse(decodeJWS(raw.toString()).payload.toString());
  return (publishedAt, nextUpdate) =>
    Buffer.from(
      signJWS({ ...body, iat: publishedAt, exp: nextUpdate }, r.issuer.status.privateKey, {
        typ: 'statuslist+jwt',
        x5c: [r.trust.issuerCertificate.toString('base64')],
      }),
    );
}

for (const [label, format, type, demo] of variants)
  test(label + ' historical visibility and authority bounds', async (t) => {
    let clock = 1_800_000_000;
    t.mock.method(Date, 'now', () => clock * 1000);
    await demo({
      trustedTime: true,
      activationMode: 'HUMAN_WEBAUTHN',
      onComplete: async (r) => {
        const initial = createVerifier({ format, trust: r.trust }).verify(c.dcbor(r.bundle));
        assert.equal(initial.overall, 'VALID', initial.reason);
        const H = Math.ceil(initial.proofOfExistenceUpperBound) + 3,
          K = H + 5;
        const originalBytes = c.dcbor(r.bundle),
          writeStatus = statusWriter(r, type);
        clock = H - 1;
        const postdatedBytes = c.dcbor(replace(r.bundle, type, writeStatus(H, H + 200)));
        const postdatedRecord = await createERS(postdatedBytes, { tsa: r.timestamp.issue });
        const records = new Map();
        for (const offset of [-1, 0, 1]) {
          clock = H + offset;
          records.set(offset, await createERS(originalBytes, { tsa: r.timestamp.issue }));
        }
        clock = K;
        const currentBytes = c.dcbor(replace(r.bundle, type, writeStatus(K, K + 200)));
        const options = {
          format,
          originalBytes,
          currentBytes,
          evidenceRecord: records.get(0),
          historicalTrust: r.trust,
          currentTrust: r.trust,
          authorityResolver: r.trust.authorityResolver,
          historicalKnowledgeTime: H,
          currentKnowledgeTime: K,
          preservationPolicy: {
            dataValidUntil: H + 60,
            hashValidUntil: { [p.OID.sha512]: H + 60 },
            resolveTimestamp: () => ({ ...r.timestamp.trust, validUntil: H + 60 }),
          },
        };
        for (const [offset, boundary] of [
          [-1, 'before'],
          [0, 'at'],
          [1, 'after'],
        ])
          await t.test(label + ' first complete proof ' + boundary + ' historical cutoff', () => {
            const result = verifyPreservedDocument({
              ...options,
              evidenceRecord: records.get(offset),
            });
            assert.equal(result.preservation.overall, 'VALID');
            assert.equal(result.preservation.proofOfExistenceUpperBound, H + offset);
            assert.equal(result.currentAdmissibility.overall, 'VALID');
            assert.equal(
              result.historicalAuthorization.overall,
              offset > 0 ? 'INDETERMINATE' : 'VALID',
            );
            assert.equal(result.overall, offset > 0 ? 'INDETERMINATE' : 'VALID');
            if (offset > 0)
              assert.equal(
                result.historicalAuthorization.reason,
                'HISTORICAL_BYTES_NOT_YET_PROVEN',
              );
          });
        await t.test(label + ' cannot backfill history with a later signed status', async () => {
          const laterStatus = writeStatus(H - 1, K + 200);
          const replacement = replace(r.bundle, type, laterStatus);
          assert.deepEqual(
            documentTimestampImprint(format, replacement.objects),
            documentTimestampImprint(format, r.bundle.objects),
          );
          const bytes = c.dcbor(replacement);
          assert.equal(
            createVerifier({ format, trust: { ...r.trust, knowledgeTime: H } }).verify(bytes)
              .overall,
            'VALID',
          );
          const result = verifyPreservedDocument({
            ...options,
            originalBytes: bytes,
            evidenceRecord: await createERS(bytes, { tsa: r.timestamp.issue }),
          });
          assert.equal(result.preservation.proofOfExistenceUpperBound, K);
          assert.equal(result.preservation.overall, 'VALID');
          assert.equal(result.currentAdmissibility.overall, 'VALID');
          assert.equal(result.historicalAuthorization.overall, 'INDETERMINATE');
          assert.equal(result.historicalAuthorization.reason, 'HISTORICAL_BYTES_NOT_YET_PROVEN');
          assert.equal(result.overall, 'INDETERMINATE');
        });
        await t.test(label + ' claimed publication cannot follow its original proof', () => {
          const result = verifyPreservedDocument({
            ...options,
            originalBytes: postdatedBytes,
            evidenceRecord: postdatedRecord,
          });
          assert.equal(result.preservation.overall, 'VALID');
          assert.equal(result.preservation.proofOfExistenceUpperBound, H - 1);
          assert.equal(result.historicalAuthorization.overall, 'INVALID');
          assert.equal(result.historicalAuthorization.reason, 'HISTORICAL_STATUS_PROOF_TIME');
          assert.equal(result.currentAdmissibility.overall, 'VALID');
        });
        for (const [offset, boundary] of [
          [-1, 'before'],
          [0, 'at'],
          [1, 'after'],
        ])
          await t.test(label + ' authority compromise ' + boundary + ' original proof', () => {
            const proofTime = H - 1;
            const result = verifyPreservedDocument({
              ...options,
              evidenceRecord: records.get(-1),
              authorityResolver(query) {
                if (query.role === 'STATUS_AUTHORITY' && query.stateTime >= proofTime + offset)
                  return { overall: 'INVALID', reason: 'AUTHORITY_REVOKED' };
                return r.trust.authorityResolver(query);
              },
            });
            assert.equal(result.preservation.overall, 'VALID');
            assert.equal(result.currentAdmissibility.overall, 'INVALID');
            assert.equal(result.currentAdmissibility.reason, 'AUTHORITY_REVOKED');
            assert.equal(result.historicalAuthorization.overall, offset <= 0 ? 'INVALID' : 'VALID');
            assert.equal(result.overall, 'INVALID');
            if (offset <= 0)
              assert.equal(result.historicalAuthorization.reason, 'AUTHORITY_REVOKED');
          });
        await t.test(
          label + ' known proof-time compromise dominates missing publication-time admission',
          () => {
            const result = verifyPreservedDocument({
              ...options,
              authorityResolver(query) {
                if (query.role === 'STATUS_AUTHORITY')
                  return query.stateTime < H
                    ? { overall: 'INDETERMINATE', reason: 'TEST_PUBLICATION_ADMISSION_MISSING' }
                    : { overall: 'INVALID', reason: 'AUTHORITY_REVOKED' };
                return r.trust.authorityResolver(query);
              },
            });
            assert.equal(result.preservation.overall, 'VALID');
            assert.equal(result.historicalAuthorization.overall, 'INVALID');
            assert.equal(result.historicalAuthorization.reason, 'AUTHORITY_REVOKED');
          },
        );
        for (const overall of ['INVALID', 'INDETERMINATE', 'UNSUPPORTED'])
          await t.test(
            label + ' retains ' + overall + ' TSA knowledge at historical cutoff',
            () => {
              const reason = 'TEST_HISTORICAL_TSA_' + overall;
              const result = verifyPreservedDocument({
                ...options,
                evidenceRecord: records.get(-1),
                preservationPolicy: {
                  ...options.preservationPolicy,
                  resolveTimestamp: () => ({
                    ...r.timestamp.trust,
                    validUntil: H + 60,
                    status: (query) =>
                      query.knowledgeTime >= H
                        ? { overall, reason }
                        : { overall: 'VALID', reason: 'TEST_TSA_AUTHORIZED' },
                  }),
                },
              });
              assert.equal(result.preservation.overall, overall);
              assert.equal(result.historicalAuthorization.overall, overall);
              assert.equal(result.historicalAuthorization.reason, reason);
              assert.equal(result.currentAdmissibility.overall, 'VALID');
            },
          );
        for (const overall of ['INVALID', 'INDETERMINATE', 'UNSUPPORTED'])
          await t.test(
            label + ' retains initial ' + overall + ' TSA status despite later GOOD status',
            () => {
              const reason = 'TEST_INITIAL_TSA_' + overall;
              const result = verifyPreservedDocument({
                ...options,
                evidenceRecord: records.get(-1),
                preservationPolicy: {
                  ...options.preservationPolicy,
                  resolveTimestamp: () => ({
                    ...r.timestamp.trust,
                    validUntil: H + 60,
                    status: (query) =>
                      query.knowledgeTime < H
                        ? { overall, reason }
                        : { overall: 'VALID', reason: 'TEST_TSA_LATER_GOOD' },
                  }),
                },
              });
              assert.equal(result.preservation.overall, 'VALID');
              assert.equal(result.originalProof.overall, overall);
              assert.equal(result.originalProof.reason, reason);
              assert.equal(result.historicalBytesVisibility.overall, overall);
              assert.equal(result.historicalAuthorization.overall, overall);
              assert.equal(result.historicalAuthorization.reason, reason);
              assert.equal(result.currentAdmissibility.overall, 'VALID');
              assert.equal(result.overall, overall);
            },
          );
        await t.test(label + ' invalid initial proof signature remains invalid', () => {
          const broken = Buffer.from(records.get(0));
          broken[broken.length - 1] ^= 1;
          const result = verifyPreservedDocument({ ...options, evidenceRecord: broken });
          assert.equal(result.originalProof.overall, 'INVALID');
          assert.equal(result.originalProof.reason, 'CMS_SIGNATURE');
          assert.equal(result.historicalBytesVisibility.overall, 'INVALID');
          assert.equal(result.historicalAuthorization.overall, 'INVALID');
          assert.equal(result.historicalAuthorization.reason, 'CMS_SIGNATURE');
          assert.equal(result.currentAdmissibility.overall, 'VALID');
          assert.equal(result.overall, 'INVALID');
        });
        await t.test(
          label + ' invalid original mathematics dominate unavailable visibility',
          () => {
            const raw = Buffer.from(r.bundle.objects.find((leaf) => leaf.type === type).payload);
            raw[raw.length - 1] ^= 1;
            const bytes = c.dcbor(replace(r.bundle, type, raw));
            const result = verifyPreservedDocument({
              ...options,
              originalBytes: bytes,
              evidenceRecord: Buffer.alloc(0),
            });
            assert.equal(result.historicalAuthorization.overall, 'INVALID');
            assert.equal(result.currentAdmissibility.overall, 'VALID');
            assert.equal(result.overall, 'INVALID');
          },
        );
        await t.test(
          label + ' later renewal failure retains the authenticated historical view',
          async () => {
            clock = H + 6;
            const renewed = await renewERS(records.get(0), originalBytes, {
              tsa: r.timestamp.issue,
            });
            const broken = Buffer.from(renewed);
            broken[broken.length - 1] ^= 1;
            const result = verifyPreservedDocument({
              ...options,
              currentKnowledgeTime: H + 7,
              evidenceRecord: broken,
            });
            assert.equal(result.preservation.overall, 'INVALID');
            assert.equal(result.historicalAuthorization.overall, 'VALID');
            assert.equal(result.currentAdmissibility.overall, 'VALID');
            assert.equal(result.overall, 'INVALID');
          },
        );
        for (const [absence, evidenceRecord] of [
          ['empty', Buffer.alloc(0)],
          ['null', null],
          ['undefined', undefined],
        ])
          await t.test(
            label + ' ' + absence + ' original proof leaves positive history indeterminate',
            () => {
              const result = verifyPreservedDocument({ ...options, evidenceRecord });
              assert.equal(result.historicalAuthorization.overall, 'INDETERMINATE');
              assert.equal(result.historicalAuthorization.reason, 'HISTORICAL_BYTES_UNPROVEN');
              assert.equal(result.currentAdmissibility.overall, 'VALID');
            },
          );
      },
    });
  });
