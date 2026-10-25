import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal } from './state.mjs';
import { runDemo } from './demo.mjs';
import { runDocumentDemo } from './document-demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { exampleTimestamp } from './example-timestamp.mjs';
import { createERS, renewERS } from './archive.mjs';
import { evidenceLeaf, createEvidencePackage } from './evidence-plan.mjs';
import { verifyPreservedDocument } from './historical-validation.mjs';
import { originalStatusContext, verifyOriginalStatusProof } from './original-status-proof.mjs';

function replaceStatus(bundle, cms) {
  return c.dcbor(
    createEvidencePackage(
      bundle.plan.profile,
      bundle.objects.map((leaf) =>
        leaf.type === 'CertificateStatus' ? evidenceLeaf(leaf.type, cms) : leaf,
      ),
    ),
  );
}

function decision(error, overall, code) {
  return error.overall === overall && error.code === code;
}

test('original CMS status proof derives its identity and preserves historical bounds', async (t) => {
  let clock = 1_800_000_000;
  t.mock.method(Date, 'now', () => clock * 1000);
  await runDemo({
    trustedTime: true,
    activationMode: 'HUMAN_WEBAUTHN',
    onComplete: async (r) => {
      const journal = new Journal();
      try {
        const originalBytes = c.dcbor(r.bundle),
          context = originalStatusContext('CMS', originalBytes, r.trust);
        const S = context.body.publishedAt,
          Ps = S + 1,
          P = S + 3,
          H = P,
          D = H + 3,
          K = H + 6;
        const oldTSA = exampleTimestamp(journal, { clock: () => clock });
        const newTSA = exampleTimestamp(journal, { clock: () => clock });
        const hashValidUntil = { [p.OID.sha512]: K + 1000, [p.OID.sha256]: K + 1000 };
        const signer = p.parseCertificate(context.certificate);
        const protectionTrust = {
          keyDeadlines: { [c.keyID(signer.publicKey).toString('hex')]: K + 1000 },
          algorithmDeadlines: {
            [c.ALG[signer.publicKey.asymmetricKeyType].oid]: K + 1000,
            [signer.algorithm]: K + 1000,
          },
          hashDeadlines: hashValidUntil,
        };
        clock = S;
        const equalInitial = await createERS(context.cms, { tsa: oldTSA.issue });
        clock = Ps;
        const initial = await createERS(context.cms, { tsa: oldTSA.issue });
        clock = P;
        const whole = await createERS(originalBytes, { tsa: r.timestamp.issue });
        clock = P + 1;
        const laterInitial = await createERS(context.cms, { tsa: oldTSA.issue });
        clock = D - 1;
        const timely = await renewERS(initial, context.cms, { tsa: newTSA.issue });
        const equalProof = await renewERS(equalInitial, context.cms, { tsa: newTSA.issue });
        const laterProof = await renewERS(laterInitial, context.cms, { tsa: newTSA.issue });
        const renewals = new Map();
        for (const instant of [D, D + 1]) {
          clock = instant;
          renewals.set(instant, await renewERS(initial, context.cms, { tsa: newTSA.issue }));
        }
        const wrongCMS = r.signStatus({
          ...context.body,
          certificateID: Buffer.alloc(context.body.certificateID.length, 7),
        });
        clock = Ps;
        const transplantedInitial = await createERS(wrongCMS, { tsa: oldTSA.issue });
        const postdatedCMS = r.signStatus({ ...context.body, publishedAt: Ps + 1 });
        const postdatedInitial = await createERS(postdatedCMS, { tsa: oldTSA.issue });
        clock = D - 1;
        const transplanted = await renewERS(transplantedInitial, wrongCMS, { tsa: newTSA.issue });
        const postdatedProof = await renewERS(postdatedInitial, postdatedCMS, {
          tsa: newTSA.issue,
        });
        const policy = (
          status = () => ({ overall: 'VALID', reason: 'SYNTHETIC_TSA_ADMITTED' }),
        ) => ({
          hashValidUntil,
          resolveTimestamp(token) {
            const cert = p.verifyCMS(token, { expectedContentType: p.OID.tstInfo }).certificate;
            const entry = c.equal(cert, oldTSA.trust.certificate)
              ? { ...oldTSA.trust, validUntil: D }
              : c.equal(cert, newTSA.trust.certificate)
                ? { ...newTSA.trust, validUntil: K + 1000 }
                : undefined;
            return entry && { ...entry, status };
          },
        });
        const selection = { evidenceRecord: timely, preservationPolicy: policy(), protectionTrust };
        const packagePolicy = {
          dataValidUntil: K + 1000,
          hashValidUntil,
          resolveTimestamp: () => ({ ...r.timestamp.trust, validUntil: K + 1000 }),
        };
        function run({ selected = selection, omit = false, options = {}, authority } = {}) {
          const queries = [];
          const resolver = (query) => {
            let result = authority?.(query);
            if (result === undefined)
              result =
                query.role === 'STATUS_AUTHORITY' && query.stateTime >= P
                  ? { overall: 'INVALID', reason: 'AUTHORITY_EXPIRED' }
                  : r.trust.authorityResolver(query);
            queries.push({
              role: query.role,
              stateTime: query.stateTime,
              knowledgeTime: query.knowledgeTime,
              certificate: query.certificate,
              scope: query.scope,
              result,
            });
            return result;
          };
          const input = {
            format: 'CMS',
            originalBytes,
            evidenceRecord: whole,
            historicalTrust: r.trust,
            currentTrust: r.trust,
            preservationPolicy: packagePolicy,
            authorityResolver: resolver,
            historicalKnowledgeTime: H,
            currentKnowledgeTime: K,
            ...options,
          };
          if (!omit) input.originalStatusProof = selected;
          return { result: verifyPreservedDocument(input), queries };
        }
        const base = run({ omit: true }),
          good = run();
        await t.test(
          'omitted selection retains the full-package authority bound and result shape',
          () => {
            assert.equal(base.result.historicalAuthorization.overall, 'INVALID');
            assert.equal(base.result.historicalAuthorization.reason, 'AUTHORITY_EXPIRED');
            assert.equal(base.result.currentAdmissibility.overall, 'VALID');
            assert.equal(Object.hasOwn(base.result, 'originalStatusProof'), false);
            assert.equal(Object.hasOwn(base.result, 'originalStatusAdmission'), false);
            const explicit = run({ selected: undefined, omit: true });
            assert.deepEqual(explicit, base);
            assert.deepEqual(
              base.queries
                .filter((q) => q.role === 'STATUS_AUTHORITY' && q.knowledgeTime === H)
                .map((q) => q.stateTime),
              [S, P, S, P],
            );
          },
        );
        await t.test(
          'protected earlier proof admits retired status authority at S and Ps using H',
          () => {
            assert.equal(good.result.overall, 'VALID');
            assert.equal(good.result.originalStatusProof.proofOfExistenceUpperBound, Ps);
            assert.deepEqual(good.result.currentAdmissibility, base.result.currentAdmissibility);
            assert.deepEqual(good.result.preservation, base.result.preservation);
            assert.ok(good.result.originalStatusAdmission.length > 0);
            for (const admission of good.result.originalStatusAdmission)
              assert.deepEqual([admission.S, admission.B, admission.H], [S, Ps, H]);
            assert.deepEqual(
              good.queries
                .filter((q) => q.role === 'STATUS_AUTHORITY' && q.knowledgeTime === H)
                .map((q) => q.stateTime),
              [S, Ps, S, Ps],
            );
            for (const query of good.queries.filter(
              (q) => q.role === 'STATUS_AUTHORITY' && q.knowledgeTime === H,
            )) {
              assert.deepEqual(query.certificate, context.certificate);
              assert.deepEqual(query.scope, context.scope);
            }
          },
        );
        await t.test('publication and historical proof cutoff equality are admitted', () => {
          const exactPublication = run({
            selected: { ...selection, evidenceRecord: equalProof },
          }).result;
          assert.equal(exactPublication.overall, 'VALID');
          assert.ok(exactPublication.originalStatusAdmission.every((a) => a.S === S && a.B === S));
          assert.equal(
            verifyOriginalStatusProof(
              context,
              { ...selection, evidenceRecord: laterProof },
              P + 1,
              K,
            ).proofOfExistenceUpperBound,
            P + 1,
          );
        });
        await t.test('a later selected proof retains the earlier complete-package bound', () => {
          const { result } = run({
            selected: { ...selection, evidenceRecord: laterProof },
            options: { historicalKnowledgeTime: P + 2 },
          });
          assert.equal(result.originalStatusProof.overall, 'VALID');
          assert.equal(result.originalStatusProof.proofOfExistenceUpperBound, P + 1);
          assert.equal(result.historicalAuthorization.reason, 'AUTHORITY_EXPIRED');
          assert.ok(result.originalStatusAdmission.every((a) => a.B === P));
        });
        for (const [label, selected, overall, reason] of [
          [
            'missing proof',
            { ...selection, evidenceRecord: null },
            'INDETERMINATE',
            'ORIGINAL_STATUS_EVIDENCE_UNAVAILABLE',
          ],
          [
            'empty proof',
            { ...selection, evidenceRecord: Buffer.alloc(0) },
            'INVALID',
            'ORIGINAL_STATUS_PROOF',
          ],
          [
            'missing preservation policy',
            { ...selection, preservationPolicy: null },
            'INDETERMINATE',
            'ORIGINAL_STATUS_PROOF_POLICY',
          ],
          [
            'missing protection policy',
            { ...selection, protectionTrust: undefined },
            'INDETERMINATE',
            'ORG_PROTECTION_DEADLINE_MISSING',
          ],
          [
            'null protection policy',
            { ...selection, protectionTrust: null },
            'INDETERMINATE',
            'ORG_PROTECTION_DEADLINE_MISSING',
          ],
          [
            'empty protection policy',
            { ...selection, protectionTrust: {} },
            'INDETERMINATE',
            'ORG_PROTECTION_DEADLINE_MISSING',
          ],
          [
            'unrenewed expired proof',
            { ...selection, evidenceRecord: initial },
            'INVALID',
            'ERS_FINAL_PROTECTION_EXPIRED',
          ],
          [
            'transplanted proof of another CMS',
            { ...selection, evidenceRecord: transplanted },
            'INVALID',
            'TSA_REQUEST_BINDING',
          ],
          ['array selection', [], 'INVALID', 'ORIGINAL_STATUS_SELECTION'],
          ['malformed explicit selection', null, 'INVALID', 'ORIGINAL_STATUS_SELECTION'],
          [
            'caller supplied scope',
            { ...selection, scope: context.scope },
            'INVALID',
            'ORIGINAL_STATUS_SELECTION',
          ],
        ])
          await t.test(label + ' cannot silently select another proof', () => {
            const { result, queries } = run({ selected });
            assert.equal(result.originalStatusProof.overall, overall);
            assert.equal(result.originalStatusProof.reason, reason);
            assert.equal(result.historicalAuthorization.overall, overall);
            assert.equal(result.historicalAuthorization.reason, reason);
            assert.ok(result.originalStatusAdmission.length > 0);
            assert.ok(result.originalStatusAdmission.every((a) => a.B === null));
            assert.ok(
              queries.some(
                (q) => q.role === 'STATUS_AUTHORITY' && q.stateTime === S && q.knowledgeTime === H,
              ),
            );
            assert.deepEqual(result.currentAdmissibility, good.result.currentAdmissibility);
          });
        for (const instant of [D, D + 1])
          await t.test(
            'renewal at ' +
              (instant === D ? 'the deadline' : 'after the deadline') +
              ' is rejected',
            () => {
              const { result } = run({
                selected: { ...selection, evidenceRecord: renewals.get(instant) },
              });
              assert.equal(result.originalStatusProof.overall, 'INVALID');
              assert.equal(result.originalStatusProof.reason, 'ERS_RENEWAL_LATE');
            },
          );
        for (const reason of ['AUTHORITY_ROLE', 'AUTHORITY_SCOPE', 'AUTHORITY_REVOKED'])
          await t.test(reason + ' remains invalid with unavailable supplemental proof', () => {
            const { result, queries } = run({
              selected: { ...selection, evidenceRecord: null },
              authority: (q) =>
                q.role === 'STATUS_AUTHORITY' ? { overall: 'INVALID', reason } : undefined,
            });
            assert.equal(result.historicalAuthorization.overall, 'INVALID');
            assert.equal(result.historicalAuthorization.reason, reason);
            assert.ok(
              result.originalStatusAdmission.every(
                (a) =>
                  a.B === null &&
                  a.proof.overall === 'INDETERMINATE' &&
                  a.authority.reason === reason,
              ),
            );
            assert.ok(
              queries.some(
                (q) => q.role === 'STATUS_AUTHORITY' && q.stateTime === S && q.knowledgeTime === H,
              ),
            );
          });
        await t.test(
          'unknown authority and unavailable proof remain distinct indeterminate outcomes',
          () => {
            const { result } = run({
              selected: { ...selection, evidenceRecord: null },
              authority: (q) =>
                q.role === 'STATUS_AUTHORITY'
                  ? { overall: 'INDETERMINATE', reason: 'AUTHORITY_MISSING' }
                  : undefined,
            });
            assert.equal(result.historicalAuthorization.overall, 'INDETERMINATE');
            assert.ok(
              result.originalStatusAdmission.every(
                (a) =>
                  a.authority.reason === 'AUTHORITY_MISSING' &&
                  a.proof.reason === 'ORIGINAL_STATUS_EVIDENCE_UNAVAILABLE',
              ),
            );
          },
        );
        await t.test('a malformed upper-bound authority decision cannot be admitted', () => {
          const { result } = run({
            authority: (q) =>
              q.role === 'STATUS_AUTHORITY' && q.stateTime === Ps && q.knowledgeTime === H
                ? { overall: 'VALID' }
                : undefined,
          });
          assert.equal(result.historicalAuthorization.overall, 'INDETERMINATE');
          assert.equal(result.historicalAuthorization.reason, 'AUTHORITY_DECISION_MISSING');
          assert.ok(
            result.originalStatusAdmission.every((a) => a.authority.overall === 'INDETERMINATE'),
          );
        });
        for (const [name, options, reason] of [
          ['missing complete proof', { evidenceRecord: null }, 'HISTORICAL_BYTES_UNPROVEN'],
          [
            'complete proof after H',
            { historicalKnowledgeTime: P - 1 },
            'HISTORICAL_BYTES_NOT_YET_PROVEN',
          ],
        ])
          await t.test(name + ' is not repaired by a valid supplemental proof', () => {
            const { result } = run({ options });
            assert.equal(result.originalStatusProof.overall, 'VALID');
            assert.equal(result.historicalBytesVisibility.overall, 'INDETERMINATE');
            assert.equal(result.historicalBytesVisibility.reason, reason);
            assert.ok(result.originalStatusAdmission.every((a) => a.B === null));
          });
        await t.test('rejected complete-package TSA under H prevents constructing B', () => {
          const Hlater = H + 1;
          const { result, queries } = run({
            options: {
              historicalKnowledgeTime: Hlater,
              preservationPolicy: {
                ...packagePolicy,
                resolveTimestamp: () => ({
                  ...r.timestamp.trust,
                  validUntil: K + 1000,
                  status: ({ knowledgeTime }) =>
                    knowledgeTime === Hlater
                      ? { overall: 'INVALID', reason: 'AUTHORITY_REVOKED' }
                      : { overall: 'VALID', reason: 'SYNTHETIC_TSA_ADMITTED' },
                }),
              },
            },
          });
          assert.equal(result.originalProof.overall, 'VALID');
          assert.equal(result.historicalBytesVisibility.reason, 'AUTHORITY_REVOKED');
          assert.ok(result.originalStatusAdmission.every((a) => a.B === null));
          assert.ok(
            queries.some(
              (q) =>
                q.role === 'STATUS_AUTHORITY' && q.stateTime === S && q.knowledgeTime === Hlater,
            ),
          );
        });
        await t.test('initial supplemental TSA needs H coverage while renewal stays at K', () => {
          const calls = [];
          const { result } = run({
            selected: {
              ...selection,
              preservationPolicy: policy((query) => {
                calls.push(query);
                return query.stateTime === Ps && query.knowledgeTime === H
                  ? { overall: 'INDETERMINATE', reason: 'AUTHORITY_STATUS_STALE' }
                  : { overall: 'VALID', reason: 'SYNTHETIC_TSA_ADMITTED' };
              }),
            },
          });
          assert.equal(result.originalStatusProof.reason, 'AUTHORITY_STATUS_STALE');
          assert.equal(result.historicalAuthorization.overall, 'INDETERMINATE');
          assert.ok(result.originalStatusAdmission.every((a) => a.B === null));
          assert.deepEqual(
            calls.map((q) => [q.stateTime, q.knowledgeTime]),
            [
              [Ps, Ps],
              [Ps, K],
              [D - 1, K],
              [Ps, H],
            ],
          );
        });
        await t.test('proof after H does not query a future TSA state with H knowledge', () => {
          const calls = [];
          const { result } = run({
            selected: {
              ...selection,
              evidenceRecord: laterProof,
              preservationPolicy: policy((q) => {
                calls.push(q);
                return { overall: 'VALID', reason: 'SYNTHETIC_TSA_ADMITTED' };
              }),
            },
          });
          assert.equal(result.originalStatusProof.reason, 'ORIGINAL_STATUS_PROOF_NOT_YET_VISIBLE');
          assert.ok(calls.every((q) => q.knowledgeTime >= q.stateTime));
          assert.ok(result.originalStatusAdmission.every((a) => a.B === null));
        });
        await t.test(
          'direct proof check rejects publication after the authenticated CMS bound',
          () => {
            const changed = originalStatusContext(
              'CMS',
              replaceStatus(r.bundle, postdatedCMS),
              r.trust,
            );
            assert.throws(
              () =>
                verifyOriginalStatusProof(
                  changed,
                  { ...selection, evidenceRecord: postdatedProof },
                  H,
                  K,
                ),
              (error) => error.code === 'ORIGINAL_STATUS_PROOF_TIME',
            );
          },
        );
        await t.test('derived context rejects a valid CMS signed for another target', () => {
          assert.throws(
            () => originalStatusContext('CMS', replaceStatus(r.bundle, wrongCMS), r.trust),
            (error) => decision(error, 'INVALID', 'ORIGINAL_STATUS_TARGET'),
          );
        });
        for (const type of ['CertificateStatus', 'Certificate', 'SIM']) {
          await t.test('missing original ' + type + ' is unavailable context', () => {
            const incomplete = {
              ...r.bundle,
              objects: r.bundle.objects.filter((o) => o.type !== type),
            };
            assert.throws(
              () => originalStatusContext('CMS', c.dcbor(incomplete), r.trust),
              (error) => decision(error, 'INDETERMINATE', 'ORIGINAL_STATUS_MISSING_' + type),
            );
          });
          await t.test('duplicate original ' + type + ' is malformed context', () => {
            const duplicate = {
              ...r.bundle,
              objects: [...r.bundle.objects, r.bundle.objects.find((o) => o.type === type)],
            };
            assert.throws(
              () => originalStatusContext('CMS', c.dcbor(duplicate), r.trust),
              (error) => decision(error, 'INVALID', 'ORIGINAL_STATUS_SINGLE_' + type),
            );
          });
        }
        await t.test(
          'direct context binds signer and query scope without caller declarations',
          () => {
            assert.equal(
              context.matches(
                {
                  role: 'STATUS_AUTHORITY',
                  stateTime: S,
                  knowledgeTime: H,
                  certificate: context.certificate,
                  scope: context.scope,
                },
                H,
              ),
              true,
            );
            for (const change of [
              { stateTime: S + 1 },
              { knowledgeTime: H + 1 },
              { role: 'RECEIPT_AUTHORITY' },
              { certificate: oldTSA.trust.certificate },
              { scope: { ...context.scope, profileID: 'OTHER' } },
            ])
              assert.equal(
                context.matches(
                  {
                    role: 'STATUS_AUTHORITY',
                    stateTime: S,
                    knowledgeTime: H,
                    certificate: context.certificate,
                    scope: context.scope,
                    ...change,
                  },
                  H,
                ),
                false,
              );
            assert.throws(() =>
              originalStatusContext('CMS', originalBytes, {
                ...r.trust,
                statusCertificate: oldTSA.trust.certificate,
              }),
            );
          },
        );
        for (const [name, cms, current, reason] of [
          [
            'stale current status',
            r.signStatus({ ...context.body, nextUpdate: H }),
            'INDETERMINATE',
            'ECP_STATUS_STALE',
          ],
          ['current target mismatch', wrongCMS, 'INVALID', 'ECP_STATUS_BINDING'],
        ])
          await t.test(name + ' stays separate from admitted historical proof', () => {
            const { result } = run({ options: { currentBytes: replaceStatus(r.bundle, cms) } });
            assert.equal(result.historicalAuthorization.overall, 'VALID');
            assert.equal(result.currentAdmissibility.overall, current);
            assert.equal(result.currentAdmissibility.reason, reason);
          });
      } finally {
        journal.close();
      }
    },
  });
});

test('native mdoc keeps its valid document decisions when CMS proof selection is unsupported', async (t) => {
  let clock = 1_800_100_000;
  t.mock.method(Date, 'now', () => clock * 1000);
  await runFoundationDemo({
    trustedTime: true,
    activationMode: 'HUMAN_WEBAUTHN',
    onComplete: async (r) => {
      const bytes = c.dcbor(r.bundle),
        H = clock + 2,
        K = H + 2;
      clock = H;
      const record = await createERS(bytes, { tsa: r.timestamp.issue });
      const options = {
        format: 'MDOC',
        originalBytes: bytes,
        evidenceRecord: record,
        historicalTrust: r.trust,
        currentTrust: r.trust,
        authorityResolver: r.trust.authorityResolver,
        historicalKnowledgeTime: H,
        currentKnowledgeTime: K,
        preservationPolicy: {
          dataValidUntil: K + 100,
          hashValidUntil: { [p.OID.sha512]: K + 100 },
          resolveTimestamp: () => ({ ...r.timestamp.trust, validUntil: K + 100 }),
        },
      };
      const standard = verifyPreservedDocument(options);
      assert.equal(standard.overall, 'VALID');
      for (const [selection, overall, reason] of [
        [{}, 'UNSUPPORTED', 'ORIGINAL_STATUS_CMS_ONLY'],
        [null, 'INVALID', 'ORIGINAL_STATUS_SELECTION'],
      ]) {
        const result = verifyPreservedDocument({ ...options, originalStatusProof: selection });
        assert.equal(result.overall, overall);
        assert.deepEqual(result.originalStatusProof, { overall, reason });
        assert.deepEqual(result.originalStatusAdmission, []);
        for (const key of [
          'preservation',
          'originalProof',
          'historicalBytesVisibility',
          'historicalAuthorization',
          'currentAdmissibility',
        ])
          assert.deepEqual(result[key], standard[key]);
      }
      assert.deepEqual(
        verifyPreservedDocument({ ...options, originalStatusProof: undefined }),
        standard,
      );
    },
  });
});

test('organization status context is explicitly outside the selected single-status proof capability', async (t) => {
  let clock = 1_800_200_000;
  t.mock.method(Date, 'now', () => clock * 1000);
  await runDocumentDemo({
    trustedTime: true,
    activationMode: 'HUMAN_WEBAUTHN',
    onComplete: async (r) => {
      const bytes = c.dcbor(r.bundle),
        H = clock + 2,
        K = H + 2;
      clock = H;
      const record = await createERS(bytes, { tsa: r.timestamp.issue });
      const options = {
        format: 'CMS',
        originalBytes: bytes,
        evidenceRecord: record,
        historicalTrust: r.trust,
        currentTrust: r.trust,
        authorityResolver: r.trust.authorityResolver,
        historicalKnowledgeTime: H,
        currentKnowledgeTime: K,
        preservationPolicy: {
          dataValidUntil: K + 100,
          hashValidUntil: { [p.OID.sha512]: K + 100 },
          resolveTimestamp: () => ({ ...r.timestamp.trust, validUntil: K + 100 }),
        },
      };
      const standard = verifyPreservedDocument(options);
      assert.equal(standard.overall, 'VALID');
      const result = verifyPreservedDocument({ ...options, originalStatusProof: {} });
      assert.equal(result.overall, 'UNSUPPORTED');
      assert.deepEqual(result.originalStatusProof, {
        overall: 'UNSUPPORTED',
        reason: 'ORIGINAL_STATUS_SINGLE_STATUS_ONLY',
      });
      assert.deepEqual(result.originalStatusAdmission, []);
      for (const key of [
        'preservation',
        'originalProof',
        'historicalBytesVisibility',
        'historicalAuthorization',
        'currentAdmissibility',
      ])
        assert.deepEqual(result[key], standard[key]);
    },
  });
});
