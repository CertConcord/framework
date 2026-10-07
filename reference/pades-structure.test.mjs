import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import {
  epoch,
  padesFixture,
  independentApproval,
  independentTimestamp,
  independentDSS,
  appendRevision,
  fixtureState,
  pdfSignatures,
  replaceCMS,
  loadPAdES,
  absentCapability,
  decision,
  expectOverall,
  cmsView,
} from './pades-fixtures.mjs';
import { rewriteCMS } from './cades-fixtures.mjs';

const api = await loadPAdES(),
  selected = { skip: !api && absentCapability };
let f, b;
before(() => {
  if (api) {
    f = padesFixture();
    b = independentApproval(f).pdf;
  }
});
after(() => f?.close());
const verify = async (pdf, overall = 'INVALID', level = 'B', changes) =>
  expectOverall(await decision(api, f, pdf, level, changes), overall);

for (const [name, transformByteRange] of [
  ['additional excluded byte', ([a, b, d, e]) => [a, b - 1, d, e]],
  ['only hex digits excluded', ([a, b, d, e]) => [a, b + 1, d - 1, e + 1]],
  ['missing prefix', ([a, b, d, e]) => [a + 1, b - 1, d, e]],
  ['unsigned end-of-revision byte', ([a, b, d, e]) => [a, b, d, e - 1]],
  ['negative offset', ([a, b, d, e]) => [-1, b, d, e]],
  ['non-integer length', ([a, b, d, e]) => [a, b - 0.5, d, e]],
])
  test(`an independently signed ${name} ByteRange is rejected`, selected, async () => {
    await verify(independentApproval(f, { transformByteRange }).pdf);
  });

for (const [name, extra] of [
  ['Type decoded-name duplicate', '/Ty#70e /Sig'],
  ['SubFilter decoded-name duplicate', '/Sub#46ilter /ETSI.CAdES.detached'],
  ['M decoded-name duplicate', '/#4d (D:20270115080010Z)'],
  ['ByteRange decoded-name duplicate', '/Byte#52ange [0 1 2 3]'],
  ['Contents decoded-name duplicate', '/Cont#65nts <00>'],
])
  test(`${name} cannot resolve by object parser preference`, selected, async () => {
    await verify(independentApproval(f, { extra }).pdf);
  });

test('approval M malformed date is a signed structural violation', selected, async () => {
  await verify(
    independentApproval(f, {
      dictionary: (body) => body.replace('D:20270115080010Z', 'D:20279999080010Z'),
    }).pdf,
  );
});
test('approval M cannot be an indirect value', selected, async () => {
  await verify(
    independentApproval(f, { dictionary: (body) => body.replace(/\/M\s*\([^)]*\)/, '/M 5 0 R') })
      .pdf,
  );
});
test(
  'missing mandatory approval M is incomplete evidence and does not hide bad mathematics',
  selected,
  async () => {
    const pdf = independentApproval(f, { omitM: true }).pdf;
    await verify(pdf, 'INDETERMINATE');
    const invalid = replaceCMS(pdf, 0, (raw) => {
      const signature = Buffer.from(cmsView(raw).signature);
      signature[signature.length - 1] ^= 1;
      return rewriteCMS(raw, { signature });
    });
    await verify(invalid, 'INVALID');
  },
);
test(
  'a document timestamp cannot introduce a duplicate fully qualified field name',
  selected,
  async () => {
    await verify(independentTimestamp(f, b, { fieldName: 'Approval' }).pdf, 'INVALID', 'T');
  },
);
test('wrong PDF signature SubFilter is an explicit unsupported capability', selected, async () => {
  await verify(independentApproval(f, { subFilter: 'adbe.pkcs7.detached' }).pdf, 'UNSUPPORTED');
});

for (const key of ['Cert', 'Reference', 'Changes', 'R', 'Prop_AuthTime', 'Prop_AuthType'])
  test(`document timestamp dictionary forbids ${key}`, selected, async () => {
    await verify(independentTimestamp(f, b, { extra: `/${key} 0` }).pdf, 'INVALID', 'T');
  });
test('document timestamp dictionary V must be zero', selected, async () => {
  await verify(
    independentTimestamp(f, b, { dictionary: (body) => body.replace('/V 0', '/V 1') }).pdf,
    'INVALID',
    'T',
  );
});
test(
  'document timestamp M is SHOULD NOT and is not a fabricated MUST violation',
  selected,
  async () => {
    const pdf = independentTimestamp(f, b, { extra: '/M (D:20000101000000Z)' }).pdf;
    const result = await decision(api, f, pdf, 'T');
    expectOverall(result, 'VALID');
    assert.equal(result.stateTime, epoch + 20, 'the PDF M self-claim is not timestamp POE');
  },
);
test('a real TSA signature over the wrong PDF imprint is invalid', selected, async () => {
  await verify(
    independentTimestamp(f, b, { tokenOptions: { imprint: Buffer.alloc(32, 0x77) } }).pdf,
    'INVALID',
    'T',
  );
});

for (const [name, mutate] of [
  [
    'nonzero CMS padding',
    (pdf, sig) => {
      const at = sig.contentsAt + sig.cms.length * 2;
      pdf.write('01', at, 'ascii');
    },
  ],
  [
    'second DER object in CMS padding',
    (pdf, sig) => {
      pdf.write('0500', sig.contentsAt + sig.cms.length * 2, 'ascii');
    },
  ],
  [
    'non-hex Contents character',
    (pdf, sig) => {
      pdf[sig.contentsAt + sig.cms.length * 2] = 0x67;
    },
  ],
])
  test(`${name} cannot be hidden in the excluded Contents span`, selected, async () => {
    const pdf = Buffer.from(b),
      sig = pdfSignatures(pdf)[0];
    mutate(pdf, sig);
    await verify(pdf);
  });
test('zero CMS padding remains accepted and is outside the signed content', selected, async () => {
  const sig = pdfSignatures(b)[0];
  assert(sig.padding.length > 0 && sig.padding.every((value) => value === 0));
  await verify(b, 'VALID');
});

test(
  'the complete original PDF prefix is mandatory when originalPDF is supplied',
  selected,
  async () => {
    const t = independentTimestamp(f, b).pdf,
      wrong = Buffer.from(b);
    wrong[20] ^= 1;
    await verify(t, 'INVALID', 'T', { originalPDF: wrong });
    await verify(t, 'VALID', 'T', { originalPDF: b });
  },
);
test(
  'a mathematically good approval cannot authorize a later page-content revision',
  selected,
  async () => {
    const content = 'BT /F1 12 Tf 40 120 Td (Substituted document) Tj ET\n';
    const changed = appendRevision(b, [
      { number: 5, body: `<< /Length ${content.length} >>\nstream\n${content}endstream` },
    ]);
    await verify(changed);
  },
);
test(
  'a timestamp cannot legitimize an earlier unauthorized page modification',
  selected,
  async () => {
    const changed = appendRevision(b, [
      {
        number: 3,
        body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 400] /Resources << >> /Contents 5 0 R >>',
      },
    ]);
    await verify(independentTimestamp(f, changed).pdf, 'INVALID', 'T');
  },
);
test(
  'a later catalog cannot hide a previous signature by deleting its field',
  selected,
  async () => {
    const state = fixtureState(b),
      catalog = state.objects.get(state.root).body.replace(/\/AcroForm\s+\d+\s+\d+\s+R/, '');
    await verify(appendRevision(b, [{ number: state.root, body: catalog }]));
  },
);
test(
  'a later signature dictionary cannot replace the original even with identical DER',
  selected,
  async () => {
    const sig = pdfSignatures(b)[0];
    await verify(appendRevision(b, [{ number: sig.objectNumber, body: sig.body }]));
  },
);
test('the field V reference must refer to the actual signature dictionary', selected, async () => {
  const state = fixtureState(b),
    field = [...state.objects.values()].find((entry) => /\/FT\s*\/Sig\b/.test(entry.body));
  await verify(
    appendRevision(b, [
      { number: field.number, body: field.body.replace(/\/V\s+\d+\s+\d+\s+R/, '/V 5 0 R') },
    ]),
  );
});
test('an additional approval signature is recognized but not selected', selected, async () => {
  const second = independentApproval(f, { pdf: b, fieldName: 'Second approval' }).pdf;
  await verify(second, 'UNSUPPORTED');
});
test(
  'bad mathematics is still invalid when an additional approval signature is unselected',
  selected,
  async () => {
    const second = independentApproval(f, { pdf: b, fieldName: 'Second approval' }).pdf;
    const corrupt = replaceCMS(second, 1, (raw) => {
      const signature = Buffer.from(cmsView(raw).signature);
      signature[signature.length - 1] ^= 1;
      return rewriteCMS(raw, { signature });
    });
    const result = await decision(api, f, corrupt);
    expectOverall(result, 'INVALID');
    assert.equal(result.reason, 'CADES_SIGNATURE_INVALID');
  },
);

for (const [name, options] of [
  ['xref object offset', { offsetDelta: 1 }],
  ['broken Prev chain', { prev: 1 }],
  ['non-catalog Root', { root: '3 0 R' }],
  ['too-small Size', { size: 2 }],
])
  test(`${name} is not repaired by a tolerant parser`, selected, async () => {
    const state = fixtureState(b);
    await verify(appendRevision(b, [{ number: state.size, body: '<< >>' }], options));
  });

test('DSS certificate and CRL values must be indirect DER streams', selected, async () => {
  await verify(
    independentDSS(independentTimestamp(f, b).pdf, f.material(), { direct: true }),
    'INVALID',
    'LT',
  );
});
test('DSS duplicate decoded Certs name is ambiguous', selected, async () => {
  await verify(
    independentDSS(independentTimestamp(f, b).pdf, f.material(), { dictionary: '/Ce#72ts []' }),
    'INVALID',
    'LT',
  );
});
for (const [name, dictionary] of [
  ['OCSP material', '/OCSPs []'],
  ['VRI semantics', '/VRI << >>'],
])
  test(`DSS ${name} is recognized but unselected`, selected, async () => {
    await verify(
      independentDSS(independentTimestamp(f, b).pdf, f.material(), { dictionary }),
      'UNSUPPORTED',
      'LT',
    );
  });

for (const [name, extra] of [
  ['active JavaScript', '/OpenAction << /S /JavaScript /JS (app.alert) >>'],
  ['external URI action', '/OpenAction << /S /URI /URI (https://example.invalid/) >>'],
  [
    'unknown extension semantics',
    '/Extensions << /ACME << /BaseVersion /1.7 /ExtensionLevel 1 >> >>',
  ],
])
  test(`${name} is rejected at preparation without executing it`, selected, async () => {
    const state = fixtureState(f.pdf),
      body = state.objects.get(state.root).body.replace(/>>\s*$/, `${extra} >>`);
    const pdf = appendRevision(f.pdf, [{ number: state.root, body }]);
    await assert.rejects(
      api.preparePAdESSignature(pdf, {
        certificate: f.signer.der,
        certificates: [f.root.der],
        signingTime: epoch + 10,
      }),
      (error) => error.overall === 'UNSUPPORTED',
    );
  });
test(
  'undersized signature reservation fails without truncating DER or mutating the caller input',
  selected,
  async () => {
    const input = Buffer.from(f.pdf);
    await assert.rejects(async () => {
      const p = await api.preparePAdESSignature(input, {
        certificate: f.signer.der,
        certificates: [f.root.der],
        signingTime: epoch + 10,
        signatureBytes: 32,
      });
      await p.finish(c.sign(p.tbs, f.signer.privateKey));
    });
    assert.deepEqual(input, f.pdf);
  },
);
