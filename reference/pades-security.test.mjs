import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import {
  O,
  epoch,
  padesFixture,
  independentApproval,
  independentTimestamp,
  independentDSS,
  pdfSignatures,
  replaceCMS,
  loadPAdES,
  absentCapability,
  decision,
  expectOverall,
  attr,
  cmsView,
} from './pades-fixtures.mjs';
import { rewriteCMS } from './cades-fixtures.mjs';

const api = await loadPAdES(),
  selected = { skip: !api && absentCapability };
let f, original;
before(() => {
  if (!api) return;
  f = padesFixture();
  const b = independentApproval(f).pdf;
  const t = independentTimestamp(f, b).pdf;
  const lt = independentDSS(t, f.material());
  const lta = independentTimestamp(f, lt, { at: epoch + 30 }).pdf;
  original = { b, t, lt, lta };
});
after(() => f?.close());
const verify = async (pdf, level, overall, changes) =>
  expectOverall(await decision(api, f, pdf, level, changes), overall);
const badSignature = (raw) => {
  const signature = Buffer.from(cmsView(raw).signature);
  signature[signature.length - 1] ^= 1;
  return rewriteCMS(raw, { signature });
};

for (const oid of [O.contentType, O.messageDigest, O.ess]) {
  test(
    `missing mandatory signed CMS attribute ${oid} is incomplete evidence`,
    selected,
    async () => {
      const signed = cmsView(pdfSignatures(original.b)[0].cms)
        .signed.filter((a) => c.oidText(a.children[0]) !== oid)
        .map((a) => a.raw);
      const pdf = independentApproval(f, { cmsOptions: { signed } }).pdf;
      // Only contentType and ESS can be transplanted; the digest must belong to this exact PDF.
      if (oid !== O.messageDigest) {
        const current = pdfSignatures(pdf)[0],
          [a, b, d, e] = current.byteRange;
        const digest = attr(
          O.messageDigest,
          c.octet(c.sha256(Buffer.concat([pdf.subarray(a, a + b), pdf.subarray(d, d + e)]))),
        );
        const corrected = signed
          .filter((value) => c.oidText(c.parseDER(value).children[0]) !== O.messageDigest)
          .concat(digest);
        const resigned = replaceCMS(pdf, 0, (raw) =>
          rewriteCMS(raw, {
            signed: corrected,
            signature: c.sign(c.set(...corrected), f.signer.privateKey),
          }),
        );
        await verify(resigned, 'B', 'INDETERMINATE');
      } else await verify(pdf, 'B', 'INDETERMINATE');
    },
  );
  test(`duplicate signed CMS attribute ${oid} is ambiguous`, selected, async () => {
    const extra = cmsView(pdfSignatures(original.b)[0].cms).signed.find(
      (a) => c.oidText(a.children[0]) === oid,
    ).raw;
    await verify(
      independentApproval(f, { cmsOptions: { additionalSigned: [extra] } }).pdf,
      'B',
      'INVALID',
    );
  });
}

for (const [name, additionalSigned, unsigned] of [
  ['CMS signing-time', [attr(O.signingTime, c.der(23, Buffer.from('270115080010Z')))], []],
  [
    'CMS algorithm protection',
    [attr('1.2.840.113549.1.9.52', c.seq(c.seq(c.oid(O.sha256)), c.der(0xa1, c.oid(O.es256))))],
    [],
  ],
  ['CAdES ATSv3', [], [attr(O.archiveTimestamp, c.seq())]],
  ['CAdES ATS hash index', [], [attr(O.index, c.seq())]],
])
  test(`published PAdES baseline forbids ${name}`, selected, async () => {
    await verify(
      independentApproval(f, { cmsOptions: { additionalSigned, unsigned } }).pdf,
      'B',
      'INVALID',
    );
  });

for (const id of [
  '0.4.0.19122.1.1',
  '1.2.840.113549.1.9.16.2.20',
  '1.2.840.113549.1.9.16.2.15',
  '1.2.840.113549.1.9.16.2.16',
])
  test(`permitted unselected PAdES signed semantics ${id} is explicit`, selected, async () => {
    await verify(
      independentApproval(f, { cmsOptions: { additionalSigned: [attr(id, c.seq())] } }).pdf,
      'B',
      'UNSUPPORTED',
    );
  });
test(
  'unselected CMS signature-timestamp route is not silently treated as the document timestamp route',
  selected,
  async () => {
    const token = f.token({
      hashOID: O.sha256,
      imprint: Buffer.alloc(32),
      nonce: 8n,
      policy: O.policy,
    });
    await verify(
      independentApproval(f, { cmsOptions: { unsigned: [attr(O.signatureTimestamp, token)] } }).pdf,
      'T',
      'UNSUPPORTED',
    );
  },
);
test('embedded CMS eContent violates the detached PDF binding', selected, async () => {
  await verify(independentApproval(f, { cmsOptions: { embedded: true } }).pdf, 'B', 'INVALID');
});
test(
  'known bad signature wins over an unselected signed attribute and missing status',
  selected,
  async () => {
    const pdf = independentApproval(f, {
      cmsOptions: { additionalSigned: [attr('1.3.6.1.4.1.55555.91.999', c.seq())] },
    }).pdf;
    await verify(replaceCMS(pdf, 0, badSignature), 'B', 'INVALID', {
      policy: f.policy({ currentMaterial: { certificates: [], crls: [] } }),
    });
  },
);

for (const [name, certs] of [
  ['signer', () => [f.root.der]],
  ['embedded root', () => [f.signer.der]],
])
  test(
    `missing ${name} is not supplied by external currentMaterial for B closure`,
    selected,
    async () => {
      await verify(
        independentApproval(f, { cmsOptions: { certificates: certs() } }).pdf,
        'B',
        'INDETERMINATE',
      );
    },
  );
test('a substituted embedded root does not build the selected signer path', selected, async () => {
  const other = f.certificate('Unrelated root');
  await verify(
    independentApproval(f, { cmsOptions: { certificates: [f.signer.der, other.der] } }).pdf,
    'B',
    'INDETERMINATE',
    { policy: f.policy({ currentMaterial: { certificates: [other.der], crls: [] } }) },
  );
});
test('external material does not create embedded LT closure', selected, async () => {
  await verify(original.t, 'LT', 'INDETERMINATE');
});
test('a PDF M self-claim does not establish historical signer existence', selected, async () => {
  await verify(original.b, 'B', 'INDETERMINATE', {
    validationTime: epoch + 200,
    knowledgeTime: epoch + 200,
  });
  await verify(replaceCMS(original.b, 0, badSignature), 'B', 'INVALID', {
    validationTime: epoch + 200,
    knowledgeTime: epoch + 200,
  });
});

for (const [name, roleChanges] of [
  ['root ISSUER', { root: ['STATUS_AUTHORITY'] }],
  ['root STATUS_AUTHORITY', { root: ['ISSUER'] }],
  ['TSA TIMESTAMP_AUTHORITY', { tsa: ['ISSUER'] }],
])
  test(`mathematical signature cannot infer ${name} role`, selected, async () => {
    await verify(original.lta, 'LTA', 'INVALID', {
      policy: f.policy({ authorityResolver: f.authorities({ roles: roleChanges }) }),
    });
  });
for (const key of ['root', 'tsa'])
  test(`wrong ${key} authority scope is rejected`, selected, async () => {
    await verify(original.lta, 'LTA', 'INVALID', {
      policy: f.policy({
        authorityResolver: f.authorities({
          scopes: { [key]: { ...f.scope, issuerID: 'different-issuer' } },
        }),
      }),
    });
  });
test('unknown authority is uncertainty rather than inferred raw-key trust', selected, async () => {
  await verify(original.lta, 'LTA', 'INDETERMINATE', {
    policy: f.policy({ authorityResolver: f.authorities({ missing: [f.tsa] }) }),
  });
});

for (const [name, options, expected] of [
  ['stale', { thisUpdate: epoch - 100, nextUpdate: epoch + 5 }, 'INDETERMINATE'],
  ['future', { thisUpdate: epoch + 50, nextUpdate: epoch + 1000 }, 'INDETERMINATE'],
  [
    'known revoked and stale',
    { thisUpdate: epoch - 100, nextUpdate: epoch + 5, entries: [{ revokedAt: epoch }] },
    'INVALID',
  ],
])
  test(`${name} CRL retains its typed result`, selected, async () => {
    await verify(original.b, 'B', expected, {
      policy: f.policy({ currentMaterial: f.material(f.crl(options)) }),
    });
  });
test('missing CRL cannot grant B under the selected policy', selected, async () => {
  await verify(original.b, 'B', 'INDETERMINATE', {
    policy: f.policy({ currentMaterial: { certificates: f.material().certificates, crls: [] } }),
  });
});
test(
  'conflicting authenticated CRLs do not select the more convenient status',
  selected,
  async () => {
    const good = f.crl({ number: 7 }),
      revoked = f.crl({ number: 7, entries: [{ revokedAt: epoch }] });
    await verify(original.b, 'B', 'INVALID', {
      policy: f.policy({
        currentMaterial: { certificates: f.material().certificates, crls: [good, revoked] },
      }),
    });
  },
);

test(
  'actual knowledgeTime cannot hide later known compromise applying to the first timestamp',
  selected,
  async () => {
    const authorityResolver = f.authorities({
      states: {
        tsa: ({ authorityID, scope, knowledgeTime }) => ({
          authorityID,
          trustDomainID: scope.trustDomainID,
          scope: 'AUTHORITY',
          status: knowledgeTime < epoch + 35 ? 'GOOD' : 'REVOKED',
          publishedAt: knowledgeTime < epoch + 35 ? epoch : epoch + 35,
          nextUpdate: epoch + 1000,
          ...(knowledgeTime < epoch + 35
            ? {}
            : { effectiveTime: epoch + 35, compromiseStart: epoch + 15 }),
        }),
      },
    });
    await verify(original.lta, 'LTA', 'INVALID', {
      policy: f.policy({ authorityResolver }),
      validationTime: epoch + 30,
      knowledgeTime: epoch + 40,
    });
  },
);

for (const [name, key, pdf, level] of [
  ['unprotected approval', 'signer', 'b', 'B'],
  ['newest initial timestamp', 'tsa', 't', 'T'],
  ['newest preservation timestamp', 'tsa', 'lta', 'LTA'],
])
  test(`${name} must remain authentic at actual knowledgeTime`, selected, async () => {
    const policy = f.policy();
    policy.keyDeadlines[c.keyID(f[key].publicKey).toString('hex')] = epoch + 100;
    await verify(original[pdf], level, 'INVALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 200,
    });
  });

test(
  'a timely later document timestamp may protect an earlier validationTime',
  selected,
  async () => {
    const renewed = independentTimestamp(f, original.lta, {
      at: epoch + 80,
      tokenOptions: { authority: f.successor },
    }).pdf;
    const policy = f.policy();
    policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')] = epoch + 100;
    await verify(renewed, 'LTA', 'VALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 200,
    });
  },
);
test(
  'the first timestamp after historical validationTime does not prove existence by that time',
  selected,
  async () => {
    const late = independentTimestamp(f, original.b, { at: epoch + 50 }).pdf;
    await verify(late, 'T', 'INDETERMINATE', {
      validationTime: epoch + 40,
      knowledgeTime: epoch + 90,
    });
  },
);
for (const [name, at, accuracy] of [
  ['equal exclusive cutoff', 50, 0],
  ['after cutoff', 51, 0],
  ['accuracy reaches cutoff', 49, 1],
])
  test(`renewal ${name} cannot repair lost protection`, selected, async () => {
    const renewed = independentTimestamp(f, original.lta, {
      at: epoch + at,
      tokenOptions: { authority: f.successor, accuracy },
    }).pdf;
    const policy = f.policy();
    policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')] = epoch + 50;
    await verify(renewed, 'LTA', 'INVALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 90,
    });
  });
test(
  'SHA512 document imprint does not extend the newest TSA SHA256 CMS signature',
  selected,
  async () => {
    const renewed = independentTimestamp(f, original.lta, {
      at: epoch + 45,
      hashOID: O.sha512,
      tokenOptions: { authority: f.successor },
    }).pdf;
    const policy = f.policy();
    policy.hashDeadlines[O.sha256] = epoch + 50;
    await verify(renewed, 'LTA', 'INVALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 90,
    });
  },
);

test(
  'current DSS appended after the last timestamp has no retroactive coverage',
  selected,
  async () => {
    const extra = f.crl({ number: 2, thisUpdate: epoch + 35 });
    const added = independentDSS(original.lta, {
      certificates: f.material().certificates,
      crls: [...f.material().crls, extra],
    });
    await verify(added, 'LT', 'VALID');
    await verify(added, 'LTA', 'INDETERMINATE');
  },
);
test(
  'a timestamp before DSS cannot supply historical POE for that later validation material',
  selected,
  async () => {
    const after = independentDSS(original.t, f.material());
    const policy = f.policy({
      currentMaterial: f.material(
        f.crl({ number: 2, thisUpdate: epoch + 150, nextUpdate: epoch + 1000 }),
      ),
    });
    await verify(after, 'LT', 'INDETERMINATE', {
      policy,
      validationTime: epoch + 200,
      knowledgeTime: epoch + 200,
    });
  },
);
test(
  'a current authenticated successor can protect exact earlier DSS despite ordinary certificate expiry',
  selected,
  async () => {
    const renewed = independentTimestamp(f, original.lta, {
      at: epoch + 80,
      tokenOptions: { authority: f.successor },
    }).pdf;
    const policy = f.policy({
      currentMaterial: f.material(
        f.crl({ number: 2, thisUpdate: epoch + 150, nextUpdate: epoch + 1000 }),
      ),
    });
    await verify(renewed, 'LTA', 'VALID', {
      policy,
      validationTime: epoch + 200,
      knowledgeTime: epoch + 200,
    });
  },
);

for (const [name, tokenOptions] of [
  ['wrong imprint', { imprint: Buffer.alloc(32, 9) }],
  ['wrong nonce', { nonce: 999n }],
  ['wrong policy', { policy: '1.3.6.1.4.1.55555.91.99' }],
  ['wrong hash', { hashOID: O.sha512, imprint: Buffer.alloc(64, 9) }],
])
  test(`finish rejects an authentically signed timestamp with ${name}`, selected, async () => {
    const p = await api.preparePAdESAugmentation(original.b, {
      targetLevel: 'T',
      validationMaterial: { certificates: [], crls: [] },
      timestampRequestOptions: { hashOID: O.sha256, policy: O.policy, nonce: 63n },
      policy: f.policy(),
      signatureBytes: 8192,
    });
    const token = f.token(p.requestDER, { genTime: epoch + 20, ...tokenOptions });
    await assert.rejects(
      p.finish(token, { validationTime: epoch + 20, knowledgeTime: epoch + 20 }),
      (error) => error.overall === 'INVALID',
    );
  });
test(
  'finish requires explicit current times and rejects a token whose accuracy interval is not yet known',
  selected,
  async () => {
    const p = await api.preparePAdESAugmentation(original.b, {
      targetLevel: 'T',
      validationMaterial: { certificates: [], crls: [] },
      timestampRequestOptions: { hashOID: O.sha256, policy: O.policy },
      policy: f.policy(),
      signatureBytes: 8192,
    });
    const token = f.token(p.requestDER, { genTime: epoch + 20, accuracy: 1 });
    await assert.rejects(p.finish(token));
    await assert.rejects(
      p.finish(token, { validationTime: epoch + 20, knowledgeTime: epoch + 20 }),
      (error) => error.overall === 'INDETERMINATE',
    );
  },
);
