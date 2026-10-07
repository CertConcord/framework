import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import * as c from './core.mjs';
import {
  epoch,
  padesFixture,
  independentApproval,
  independentTimestamp,
  independentDSS,
  appendRevision,
  fixtureState,
  replaceCMS,
  cmsView,
  loadPAdES,
  absentCapability,
  decision,
  expectOverall,
} from './pades-fixtures.mjs';
import { rewriteCMS } from './cades-fixtures.mjs';

const api = await loadPAdES(),
  selected = { skip: !api && absentCapability };
let f, b, t;
before(() => {
  if (api) {
    f = padesFixture();
    b = independentApproval(f).pdf;
    t = independentTimestamp(f, b).pdf;
  }
});
after(() => f?.close());
const rejectPreparation = async (pdf) =>
  assert.rejects(
    api.preparePAdESSignature(pdf, {
      certificate: f.signer.der,
      certificates: [f.root.der],
      signingTime: epoch + 10,
    }),
    (error) => error.overall === 'UNSUPPORTED',
  );

function xrefStream(pdf, hybrid = false) {
  const state = fixtureState(pdf),
    number = state.size,
    offset = pdf.length + 1;
  const data = Buffer.alloc(7);
  data[0] = 1;
  data.writeUInt32BE(offset, 1);
  const body = Buffer.concat([
    Buffer.from(
      `<< /Type /XRef /Size ${number + 1} /Root ${state.root} 0 R /Prev ${state.xref} /W [1 4 2] /Index [${number} 1] /Length ${data.length} >>\nstream\n`,
    ),
    data,
    Buffer.from('\nendstream'),
  ]);
  if (hybrid) return appendRevision(pdf, [{ number, body }], { trailer: `/XRefStm ${offset}` });
  return Buffer.concat([
    pdf,
    Buffer.from(`\n${number} 0 obj\n`),
    body,
    Buffer.from(`\nendobj\nstartxref\n${offset}\n%%EOF\n`),
  ]);
}
for (const hybrid of [false, true])
  test(
    `${hybrid ? 'hybrid' : 'stream'} cross-reference capability is explicit`,
    selected,
    async () => {
      await rejectPreparation(xrefStream(f.pdf, hybrid));
    },
  );
test(
  'a declared Standard Security Handler is recognized as unselected encryption',
  selected,
  async () => {
    const state = fixtureState(f.pdf),
      id = state.size;
    const pdf = appendRevision(
      f.pdf,
      [
        {
          number: id,
          body: `<< /Filter /Standard /V 1 /R 2 /O <${'00'.repeat(32)}> /U <${'00'.repeat(32)}> /P -4 >>`,
        },
      ],
      { trailer: `/Encrypt ${id} 0 R /ID [<${'11'.repeat(16)}> <${'11'.repeat(16)}>]` },
    );
    await rejectPreparation(pdf);
  },
);
test('dynamic XFA is rejected as a capability before creation', selected, async () => {
  const state = fixtureState(f.pdf),
    form = state.size,
    xml = state.size + 1;
  const packet = Buffer.from(
    '<?xml version="1.0"?><xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"/>',
  );
  const root = state.objects.get(state.root).body.replace(/>>\s*$/, `/AcroForm ${form} 0 R >>`);
  const pdf = appendRevision(f.pdf, [
    { number: form, body: `<< /Fields [] /XFA ${xml} 0 R >>` },
    {
      number: xml,
      body: Buffer.concat([
        Buffer.from(`<< /Length ${packet.length} >>\nstream\n`),
        packet,
        Buffer.from('\nendstream'),
      ]),
    },
    { number: state.root, body: root },
  ]);
  await rejectPreparation(pdf);
});
for (const method of ['DocMDP', 'FieldMDP'])
  test(`${method} transforms are explicit unsupported semantics`, selected, async () => {
    const params = method === 'DocMDP' ? '/P 2 /V /1.2' : '/Action /All /V /1.2';
    const pdf = independentApproval(f, {
      extra: `/Reference [<< /Type /SigRef /TransformMethod /${method} /TransformParams << /Type /TransformParams ${params} >> >>]`,
    }).pdf;
    expectOverall(await decision(api, f, pdf), 'UNSUPPORTED');
  });
for (const [name, value] of [
  ['year-only precision', 'D:2027'],
  ['numeric timezone', "D:20270115040010-04'00'"],
])
  test(`legal unselected PDF date ${name} is not malformed`, selected, async () => {
    const pdf = independentApproval(f, {
      dictionary: (body) => body.replace(/\/M\s*\([^)]*\)/, `/M (${value})`),
    }).pdf;
    expectOverall(await decision(api, f, pdf), 'UNSUPPORTED');
  });

for (const key of ['certificates', 'crls'])
  test(`DSS ${key} must contain its advertised ASN.1 type even when unused`, selected, async () => {
    const material = f.material();
    material[key].push(c.seq(c.integer(5)));
    expectOverall(await decision(api, f, independentDSS(t, material), 'LT'), 'INVALID');
  });
test(
  'a valid unused certificate does not become an inferred authority or malformed object',
  selected,
  async () => {
    const extra = f.certificate('PAdES unused but valid certificate');
    const material = f.material();
    material.certificates.push(extra.der);
    expectOverall(await decision(api, f, independentDSS(t, material), 'LT'), 'VALID');
  },
);
for (const [name, index] of [
  ['approval', 0],
  ['document timestamp', 1],
])
  for (const corrupt of [false, true])
    test(
      `one PDF ${name} CMS cannot contain two SignerInfo values (${corrupt ? 'bad math precedence' : 'valid math'})`,
      selected,
      async () => {
        const pdf = replaceCMS(index ? t : b, index, (raw) => {
          const view = cmsView(raw),
            fields = view.fields.map((n) => n.raw),
            signature = Buffer.from(view.signature);
          if (corrupt) {
            signature[signature.length - 1] ^= 1;
            fields[5] = c.octet(signature);
          }
          return rewriteCMS(raw, { signers: [view.signer.raw, c.seq(...fields)] });
        });
        const result = await decision(api, f, pdf, index ? 'T' : 'B');
        expectOverall(result, 'INVALID');
        assert.equal(result.reason, corrupt ? 'CADES_SIGNATURE_INVALID' : 'PADES_MULTIPLE_SIGNERS');
      },
    );

test('bounded Flate DSS streams preserve exact DER material', selected, async () => {
  const material = f.material(),
    compressed = Object.fromEntries(
      Object.entries(material).map(([key, values]) => [
        key,
        values.map((value) => deflateSync(value)),
      ]),
    );
  expectOverall(
    await decision(
      api,
      f,
      independentDSS(t, compressed, { streamOptions: '/Filter /FlateDecode' }),
      'LT',
    ),
    'VALID',
  );
});
test(
  'a Flate expansion beyond the declared decoded-material bound is contained',
  selected,
  async () => {
    const expanded = c.seq(c.octet(Buffer.alloc(16 * 1024 * 1024)));
    const bomb = independentDSS(
      t,
      { certificates: [deflateSync(expanded)], crls: [] },
      { streamOptions: '/Filter /FlateDecode' },
    );
    const result = await decision(api, f, bomb, 'LT');
    assert.notEqual(result.overall, 'VALID');
    assert(['PADES_DSS_FLATE', 'PADES_MATERIAL_LIMIT'].includes(result.reason), result.reason);
  },
);
test('worker transport rejects a callback in structural options', selected, async () => {
  const io = await import('./pades-io.mjs');
  await assert.rejects(
    io.preparePAdESContainer(f.pdf, {
      kind: 'SIGNATURE',
      signingTime: epoch + 10,
      fieldName: () => 'callback',
    }),
    { code: 'PADES_WORKER_OPTIONS' },
  );
});
test('input-size bound is enforced before parsing', selected, async () => {
  const result = await decision(api, f, Buffer.alloc(64 * 1024 * 1024 + 1));
  expectOverall(result, 'UNSUPPORTED');
  assert.equal(result.reason, 'PADES_SIZE_LIMIT');
});
test('deep nested PDF objects are bounded rather than recursively accepted', selected, async () => {
  const state = fixtureState(f.pdf),
    body = state.objects
      .get(state.root)
      .body.replace(/>>\s*$/, `/Nested ${'['.repeat(80)} 0 ${']'.repeat(80)} >>`);
  await rejectPreparation(appendRevision(f.pdf, [{ number: state.root, body }]));
});
test(
  'authority callback views cannot mutate the retained policy or future query identities',
  selected,
  async () => {
    const actual = f.authorities(),
      queries = [];
    const policy = f.policy({
      authorityResolver: (query) => {
        const result = actual(query);
        queries.push({
          role: query.role,
          certificate: Buffer.from(query.certificate),
          domain: Buffer.from(query.scope.trustDomainID),
        });
        query.certificate.fill(0);
        query.scope.trustDomainID.fill(0);
        return result;
      },
    });
    expectOverall(await decision(api, f, t, 'T', { policy }), 'VALID');
    assert(queries.length > 2);
    assert(
      queries.every((query) => query.domain.equals(f.domain) && query.certificate[0] === 0x30),
    );
    assert(policy.scope.trustDomainID.equals(f.domain));
  },
);
