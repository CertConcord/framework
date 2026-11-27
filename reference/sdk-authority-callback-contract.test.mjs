import test from 'node:test';
import assert from 'node:assert/strict';
import { dcbor } from './core.mjs';
import { runDemo } from './demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { createVerifier } from './sdk/index.mjs';

for (const format of ['CMS', 'MDOC'])
  test(format + ' signed evidence does not accept failed external authority policy', async () => {
    const fixture = format === 'CMS' ? await runDemo() : await runFoundationDemo();
    const bytes = dcbor(fixture.bundle);
    const trust = fixture.trust;
    const selectedDomain = Buffer.from(trust.trustDomainID);
    const selectedAuthority = trust.authorityResolver;
    assert.equal(createVerifier({ format, trust }).verify(bytes).overall, 'VALID');

    const cases = [
      [
        'wrong tenant',
        (query) => {
          if (!query.scope?.trustDomainID?.equals(selectedDomain)) return selectedAuthority(query);
          return { overall: 'INVALID', reason: 'AUTHORITY_TENANT_MISMATCH' };
        },
        'INVALID',
      ],
      [
        'stale authenticated source',
        () => ({ overall: 'INDETERMINATE', reason: 'AUTHORITY_STATUS_STALE' }),
        'INDETERMINATE',
      ],
      [
        'known later compromise',
        () => ({ overall: 'INVALID', reason: 'AUTHORITY_REVOKED' }),
        'INVALID',
      ],
      [
        'unavailable source',
        () => {
          throw Error('source unavailable');
        },
        'NON_VALID',
      ],
      [
        'asynchronous source',
        () => Promise.resolve({ overall: 'VALID', reason: 'AUTHORITY_ADMITTED' }),
        'NON_VALID',
      ],
    ];
    for (const [name, authorityResolver, expected] of cases) {
      const result = createVerifier({ format, trust: { ...trust, authorityResolver } }).verify(
        bytes,
      );
      if (expected === 'NON_VALID') assert.notEqual(result.overall, 'VALID', name);
      else assert.equal(result.overall, expected, name + ': ' + result.reason);
    }

    const rotated = createVerifier({
      format,
      trust: {
        ...trust,
        authorityResolver: () => ({ overall: 'INVALID', reason: 'AUTHORITY_ROTATED' }),
      },
    });
    assert.equal(rotated.verify(bytes).overall, 'INVALID');
    assert.equal(createVerifier({ format, trust }).verify(bytes).overall, 'VALID');
  });

for (const format of ['CMS', 'MDOC'])
  test(
    format + ' authority callback cannot rewrite selected trust during one evaluation',
    async () => {
      const fixture = format === 'CMS' ? await runDemo() : await runFoundationDemo();
      const bytes = dcbor(fixture.bundle);
      const selectedDomain = Buffer.from(fixture.trust.trustDomainID);
      const selectedAuthority = fixture.trust.authorityResolver;
      let changed = 0;
      let queries = 0;
      const verifier = createVerifier({
        format,
        trust: {
          ...fixture.trust,
          authorityResolver: (query) => {
            queries++;
            assert.deepEqual(query.scope.trustDomainID, selectedDomain);
            if (!changed && query.role === 'RECEIPT_AUTHORITY') {
              query.scope.trustDomainID.fill(0);
              changed++;
              return selectedAuthority({
                ...query,
                scope: { ...query.scope, trustDomainID: Buffer.from(selectedDomain) },
              });
            }
            return selectedAuthority(query);
          },
        },
      });
      const first = verifier.verify(bytes);
      assert.equal(changed, 1, format + ' must exercise the callback mutation');
      assert(queries > 1, format + ' must exercise later authority queries');
      assert.equal(first.overall, 'VALID', format + ': ' + first.reason);
      assert.equal(verifier.verify(bytes).overall, 'VALID');
      assert.deepEqual(fixture.trust.trustDomainID, selectedDomain);
    },
  );
