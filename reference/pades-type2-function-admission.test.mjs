import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import {
  padesFixture, independentApproval, decision, loadPAdES,
} from './pades-fixtures.mjs';
import { axialType2Document as document, standardType2Function as standard } from
  './pades-type2-function-fixture.mjs';

const api = await loadPAdES();
let fixture;
before(() => { fixture = padesFixture(); });
after(() => fixture?.close());

const verify = async pdf => decision(api, fixture, independentApproval(fixture, { pdf }).pdf);
const expect = async (pdf, overall, reason) => {
  const actual = await verify(pdf);
  assert.equal(actual.overall, overall, JSON.stringify(actual));
  assert.equal(actual.reason, reason);
};

test('signed axial Type 2 shading admits a three-output function', async () => {
  await expect(document(), 'VALID', 'PADES_VALID');
  await expect(document({}, { functionValue: '7 0 R',
    objects: [{ number: 7, body: `<< ${Object.entries(standard)
      .map(([key, value]) => `/${key} ${value}`).join(' ')} >>` }] }),
  'VALID', 'PADES_VALID');
});

for (const [title, entries, reason] of [
  ['FunctionType boolean', { FunctionType: 'true' }, 'PADES_TYPE2_FUNCTION_TYPE'],
  ['C0 boolean component', { C0: '[true 0 0]' }, 'PADES_TYPE2_FUNCTION_C0'],
  ['N boolean', { N: 'true' }, 'PADES_TYPE2_FUNCTION_N'],
  ['C1 two components for DeviceRGB', { C1: '[0 1]' }, 'PADES_TYPE2_FUNCTION_C1'],
  ['Domain one bound', { Domain: '[0]' }, 'PADES_TYPE2_FUNCTION_DOMAIN'],
  ['Range reversed red bounds', { Range: '[1 0 0 1 0 1]' }, 'PADES_TYPE2_FUNCTION_RANGE'],
  ['negative N with zero in Domain', { N: '-1' }, 'PADES_TYPE2_FUNCTION_DOMAIN'],
]) {
  test(`signed axial Type 2 shading rejects ${title}`, async () => {
    await expect(document(entries), 'INVALID', reason);
  });
}

test('Type 2 defaults and negative exponent retain valid domain boundaries', async () => {
  await expect(document({ C0: undefined, C1: undefined, Range: undefined },
    { colorSpace: '/DeviceGray' }), 'VALID', 'PADES_VALID');
  await expect(document({ N: '-1', Domain: '[1 2]' }, { shadingDomain: '[1 2]' }),
    'VALID', 'PADES_VALID');
  await expect(document({ N: '0.5' }), 'VALID', 'PADES_VALID');
  await expect(document({ N: '0.5', Domain: '[-1 1]' }),
    'INVALID', 'PADES_TYPE2_FUNCTION_DOMAIN');
});

test('unreferenced malformed shading function remains outside signed page content', async () => {
  await expect(document({ FunctionType: 'true' }, { content: 'q Q\n' }),
    'VALID', 'PADES_VALID');
});

test('non-Type-2 functions and arrays are explicit capability limits', async () => {
  await expect(document({ FunctionType: '4' }),
    'UNSUPPORTED', 'PADES_SHADING_FUNCTION_UNSUPPORTED');
  await expect(document({}, { functionValue: '[<< /FunctionType 2 /Domain [0 1] /N 1 >>]' }),
    'UNSUPPORTED', 'PADES_SHADING_FUNCTION_UNSUPPORTED');
});

test('two-output functions and effective complex device defaults remain explicit capability limits', async () => {
  await expect(document({ C0: '[0 0]', C1: '[1 1]', Range: '[0 1 0 1]' },
    { colorSpace: '[/DeviceN [/A /B] /DeviceRGB << /A 0 /B 1 >>]' }),
  'UNSUPPORTED', 'PADES_SHADING_COLORSPACE_UNSUPPORTED');
  await expect(document({}, { colorResources:
    '/ColorSpace << /DefaultRGB [/CalRGB << /WhitePoint [1 1 1] >>] >>' }),
  'UNSUPPORTED', 'PADES_SHADING_COLORSPACE_UNSUPPORTED');
});

test('source integer, ordered domain and range cardinality are required', async () => {
  await expect(document({ FunctionType: '2.0' }), 'INVALID', 'PADES_TYPE2_FUNCTION_TYPE');
  await expect(document({ Domain: '[1 0]' }), 'INVALID', 'PADES_TYPE2_FUNCTION_DOMAIN');
  await expect(document({ Range: '[0 1]' }), 'INVALID', 'PADES_TYPE2_FUNCTION_RANGE');
});

test('optional null entries are omissions, including through indirect references', async () => {
  await expect(document({ C0: 'null', C1: 'null', Range: 'null' },
    { colorSpace: '/DeviceGray' }), 'VALID', 'PADES_VALID');
  await expect(document({ C0: '7 0 R', C1: '8 0 R', Range: '9 0 R' },
    { colorSpace: '/DeviceGray', objects: [
      { number: 7, body: 'null' }, { number: 8, body: 'null' },
      { number: 9, body: 'null' },
    ] }), 'VALID', 'PADES_VALID');
  await expect(document({ Domain: 'null' }), 'INVALID', 'PADES_TYPE2_FUNCTION_DOMAIN');
  await expect(document({ Domain: '7 0 R' },
    { objects: [{ number: 7, body: 'null' }] }),
  'INVALID', 'PADES_TYPE2_FUNCTION_DOMAIN');
});

test('function domain covers the effective axial shading domain', async () => {
  await expect(document({ Domain: '[-1 2]' }), 'VALID', 'PADES_VALID');
  await expect(document({ Domain: '[0.25 0.75]' }),
    'INVALID', 'PADES_TYPE2_FUNCTION_DOMAIN');
  await expect(document({ Domain: '[1 2]' }, { shadingDomain: '[1 2]' }),
    'VALID', 'PADES_VALID');
  await expect(document({ Domain: '[1.5 2]' }, { shadingDomain: '[1 2]' }),
    'INVALID', 'PADES_TYPE2_FUNCTION_DOMAIN');
  await expect(document({}, { shadingDomain: 'null' }), 'VALID', 'PADES_VALID');
  await expect(document({}, { shadingDomain: '7 0 R',
    objects: [{ number: 7, body: 'null' }] }), 'VALID', 'PADES_VALID');
  await expect(document({}, { shadingDomain: '[1 0]' }),
    'INVALID', 'PADES_SHADING_DOMAIN');
});

test('axial shading is a dictionary with source integer ShadingType 2', async () => {
  await expect(document({}, { shadingStream: true }), 'INVALID', 'PADES_SHADING_TYPE');
  await expect(document({}, { shadingType: '2.0' }), 'INVALID', 'PADES_SHADING_TYPE');
  await expect(document({}, { shadingType: '7 0 R',
    objects: [{ number: 7, body: '2' }] }), 'VALID', 'PADES_VALID');
});
