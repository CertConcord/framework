import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import {
  padesFixture, independentApproval, plainPDF, appendRevision, decision, loadPAdES,
} from './pades-fixtures.mjs';

const api = await loadPAdES();
let fixture;
before(() => { fixture = padesFixture(); });
after(() => fixture?.close());

const shading = '<< /ShadingType 2 /ColorSpace /DeviceRGB /Coords [0 0 100 0] ' +
  '/Function << /FunctionType 2 /Domain [0 1] /C0 [1 0 0] /C1 [0 0 1] /N 1 >> ' +
  '/Extend [true true] >>';
const formStream = '40 50 100 80 re f\n';
const meshData = Buffer.from([
  0, 10, 10, 255, 0, 0,
  0, 200, 10, 0, 255, 0,
  0, 100, 200, 0, 0, 255,
]);
const mesh = {
  kind: 'Shading', name: 'Mesh1', content: '/Mesh1 sh\n',
  objects: [{ number: 6, body: `<< /ShadingType 4 /ColorSpace /DeviceRGB ` +
    `/BitsPerCoordinate 8 /BitsPerComponent 8 /BitsPerFlag 8 ` +
    `/Decode [0 255 0 255 0 1 0 1 0 1] /Length ${meshData.length} >>\n` +
    `stream\n${meshData.toString('latin1')}\nendstream` }],
};
const cases = [
  {
    kind: 'ExtGState', name: 'GS1', content: 'q /GS1 gs 0 0 0 rg 40 50 100 80 re f Q\n',
    objects: [{ number: 6, body: '<< /ca 0 >>' }],
  },
  {
    kind: 'Shading', name: 'Sh1', content: '/Sh1 sh\n',
    objects: [{ number: 6, body: shading }],
  },
  {
    kind: 'Pattern', name: 'P1', content: '/Pattern cs /P1 scn 40 50 100 80 re f\n',
    objects: [
      { number: 6, body: '<< /Type /Pattern /PatternType 2 /Shading 7 0 R >>' },
      { number: 7, body: shading },
    ],
  },
  {
    kind: 'XObject', name: 'Fm1', content: 'q /Fm1 Do Q\n',
    objects: [{ number: 6, body: `<< /Type /XObject /Subtype /Form /BBox [0 0 300 200] ` +
      `/Resources << >> /Length ${Buffer.byteLength(formStream)} >>\nstream\n${formStream}endstream` }],
  },
];

const page = (row, value, inherited = false, categoryValue) =>
  `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] ` +
  `${inherited ? '' : `/Resources << /${row.kind} ${categoryValue ?? `<< ${value === undefined ? '' : `/${row.name} ${value}`} >>`} >> `}` +
  `/Contents 5 0 R >>`;
const document = (row, value, content = row.content,
  { objects = row.objects, inherited = false, categoryValue } = {}) => appendRevision(
  plainPDF(),
  [
    ...(inherited ? [{ number: 2, body: `<< /Type /Pages /Kids [3 0 R] /Count 1 ` +
      `/Resources << /${row.kind} << /${row.name} ${value} >> >> >>` }] : []),
    { number: 3, body: page(row, value, inherited, categoryValue) },
    { number: 5, body: `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}endstream` },
    ...objects,
  ],
);
const verify = async pdf => decision(api, fixture, independentApproval(fixture, { pdf }).pdf);

for (const row of cases) {
  test(`signed ${row.kind} content binds a typed resource and rejects null member`, async () => {
    const positive = await verify(document(row, '6 0 R'));
    assert.equal(positive.overall, 'VALID', JSON.stringify(positive));
    assert.equal(positive.reason, 'PADES_VALID');
    const negative = await verify(document(row, 'null'));
    assert.equal(negative.overall, 'INVALID', JSON.stringify(negative));
    assert.equal(negative.reason, 'PADES_PAGE_RESOURCE_MEMBER');
  });
}

test('unreferenced null resource members are equivalent to omission', async () => {
  for (const row of cases) {
    const actual = await verify(document(row, 'null', 'q Q\n'));
    assert.equal(actual.overall, 'VALID', `${row.kind}: ${JSON.stringify(actual)}`);
    assert.equal(actual.reason, 'PADES_VALID');
  }
});

for (const row of cases) {
  test(`signed ${row.kind} resolves inherited resources and rejects missing or mistyped members`, async () => {
    const inherited = await verify(document(row, '6 0 R', row.content, { inherited: true }));
    assert.equal(inherited.overall, 'VALID', JSON.stringify(inherited));
    const missing = await verify(document(row, undefined));
    assert.equal(missing.overall, 'INVALID', JSON.stringify(missing));
    assert.equal(missing.reason, 'PADES_PAGE_RESOURCE_MEMBER');
    const wrongType = await verify(document(row, '6 0 R', row.content,
      { objects: [{ number: 6, body: '42' }] }));
    assert.equal(wrongType.overall, 'INVALID', JSON.stringify(wrongType));
    assert.equal(wrongType.reason, 'PADES_PAGE_RESOURCE_MEMBER');
  });
}

test('signed indirect null resolves as absent only when unreferenced', async () => {
  for (const row of cases) {
    const objects = [{ number: 6, body: 'null' }];
    const referenced = await verify(document(row, '6 0 R', row.content, { objects }));
    assert.equal(referenced.overall, 'INVALID', `${row.kind}: ${JSON.stringify(referenced)}`);
    assert.equal(referenced.reason, 'PADES_PAGE_RESOURCE_MEMBER');
    const unused = await verify(document(row, '6 0 R', 'q Q\n', { objects }));
    assert.equal(unused.overall, 'VALID', `${row.kind}: ${JSON.stringify(unused)}`);
  }
});

test('signed undefined resource references fail when used and are omitted when unused', async () => {
  for (const row of cases) {
    const referenced = await verify(document(row, '99 0 R'));
    assert.equal(referenced.overall, 'INVALID', `${row.kind}: ${JSON.stringify(referenced)}`);
    assert.equal(referenced.reason, 'PADES_PAGE_RESOURCE_MEMBER');
    const unused = await verify(document(row, '99 0 R', 'q Q\n'));
    assert.equal(unused.overall, 'VALID', `${row.kind}: ${JSON.stringify(unused)}`);
  }
});

test('undefined resource subdictionary is omitted until referenced by signed content', async () => {
  for (const row of cases) {
    const options = { categoryValue: '99 0 R' };
    const referenced = await verify(document(row, '6 0 R', row.content, options));
    assert.equal(referenced.overall, 'INVALID', `${row.kind}: ${JSON.stringify(referenced)}`);
    assert.equal(referenced.reason, 'PADES_PAGE_RESOURCE_MEMBER');
    const unused = await verify(document(row, '6 0 R', 'q Q\n', options));
    assert.equal(unused.overall, 'VALID', `${row.kind}: ${JSON.stringify(unused)}`);
  }
});

test('stroking pattern SCN binds the selected Pattern resource', async () => {
  const pattern = cases.find(row => row.kind === 'Pattern');
  const content = '/Pattern CS /P1 SCN 40 50 100 80 re f\n';
  const positive = await verify(document(pattern, '6 0 R', content));
  assert.equal(positive.overall, 'VALID', JSON.stringify(positive));
  const negative = await verify(document(pattern, 'null', content));
  assert.equal(negative.overall, 'INVALID', JSON.stringify(negative));
  assert.equal(negative.reason, 'PADES_PAGE_RESOURCE_MEMBER');
});

test('signed type 4 mesh shading stream is a valid referenced member', async () => {
  const positive = await verify(document(mesh, '6 0 R'));
  assert.equal(positive.overall, 'VALID', JSON.stringify(positive));
  assert.equal(positive.reason, 'PADES_VALID');
  const negative = await verify(document(mesh, 'null'));
  assert.equal(negative.overall, 'INVALID', JSON.stringify(negative));
  assert.equal(negative.reason, 'PADES_PAGE_RESOURCE_MEMBER');
});
