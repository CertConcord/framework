import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { deflateSync } from 'node:zlib';
import {
  padesFixture, independentApproval, plainPDF, appendRevision, decision, loadPAdES,
} from './pades-fixtures.mjs';

const api = await loadPAdES();
let fixture;
before(() => { fixture = padesFixture(); });
after(() => fixture?.close());

const imageEntries = {
  Type: '/XObject', Subtype: '/Image', Width: '1', Height: '1',
  ColorSpace: '/DeviceRGB', BitsPerComponent: '8',
};
const content = 'q 100 0 0 50 40 50 cm /Im1 Do Q\n';
const document = (entries = {}, {
  pageContent = content, resourceColorSpace = '', pixels = '\0\0\0', objects = [],
} = {}) => {
  const image = { ...imageEntries, ...entries };
  const dictionary = Object.entries(image).filter(([, value]) => value !== undefined)
    .map(([key, value]) => `/${key} ${value}`).join(' ');
  return appendRevision(plainPDF(), [
    { number: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] ' +
      `/Resources << /XObject << /Im1 6 0 R >> ${resourceColorSpace} >> /Contents 5 0 R >>` },
    { number: 5, body: `<< /Length ${Buffer.byteLength(pageContent)} >>\nstream\n${pageContent}endstream` },
    { number: 6, body: `<< ${dictionary} /Length ${Buffer.byteLength(pixels, 'latin1')} >>\n` +
      `stream\n${pixels}endstream` },
    ...objects,
  ]);
};
const verify = async pdf => decision(api, fixture, independentApproval(fixture, { pdf }).pdf);

const cases = [
  ['Width', '[]', 'PADES_IMAGE_WIDTH', 'INVALID'],
  ['Height', '[]', 'PADES_IMAGE_HEIGHT', 'INVALID'],
  ['ColorSpace', '/Bogus', 'PADES_IMAGE_COLORSPACE', 'INVALID'],
  ['Filter', '/BogusDecode', 'PADES_IMAGE_FILTER_UNSUPPORTED', 'UNSUPPORTED'],
  ['Decode', '[true 1 0 1 0 1]', 'PADES_IMAGE_DECODE', 'INVALID'],
  ['BitsPerComponent', 'true', 'PADES_IMAGE_BITS_PER_COMPONENT', 'INVALID'],
];
for (const [key, malformed, reason, overall] of cases) {
  test(`signed image XObject ${key} admits valid control and rejects selected malformed value`, async () => {
    const positive = await verify(document());
    assert.equal(positive.overall, 'VALID', JSON.stringify(positive));
    assert.equal(positive.reason, 'PADES_VALID');
    const negative = await verify(document({ [key]: malformed }));
    assert.equal(negative.overall, overall, JSON.stringify(negative));
    assert.equal(negative.reason, reason);
  });
}

test('signed image ColorSpace name resolves through the current page resource dictionary', async () => {
  const actual = await verify(document({ ColorSpace: '/CS1' },
    { resourceColorSpace: '/ColorSpace << /CS1 /DeviceRGB >>' }));
  assert.equal(actual.overall, 'VALID', JSON.stringify(actual));
  assert.equal(actual.reason, 'PADES_VALID');
});

test('unreferenced malformed image dictionary remains outside selected page content', async () => {
  const actual = await verify(document({ Width: '[]' }, { pageContent: 'q Q\n' }));
  assert.equal(actual.overall, 'VALID', JSON.stringify(actual));
});

test('one-bit image mask may omit ColorSpace and BitsPerComponent', async () => {
  const actual = await verify(document({ ImageMask: 'true', ColorSpace: undefined,
    BitsPerComponent: undefined }, { pixels: '\0' }));
  assert.equal(actual.overall, 'VALID', JSON.stringify(actual));
});

test('signed dimensions require positive source integers, including through indirect values', async () => {
  for (const [key, value] of [['Width', '0'], ['Height', '-1'], ['Width', '1.0']]) {
    const actual = await verify(document({ [key]: value }));
    assert.equal(actual.overall, 'INVALID', `${key} ${value}: ${JSON.stringify(actual)}`);
    assert.equal(actual.reason, `PADES_IMAGE_${key.toUpperCase()}`);
  }
  const positive = await verify(document({ Width: '7 0 R' },
    { objects: [{ number: 7, body: '1' }] }));
  assert.equal(positive.overall, 'VALID', JSON.stringify(positive));
  const negative = await verify(document({ Width: '7 0 R' },
    { objects: [{ number: 7, body: '[]' }] }));
  assert.equal(negative.overall, 'INVALID', JSON.stringify(negative));
  assert.equal(negative.reason, 'PADES_IMAGE_WIDTH');
});

test('signed non-mask image requires a resolved ColorSpace', async () => {
  for (const value of [undefined, 'null', '99 0 R']) {
    const actual = await verify(document({ ColorSpace: value }));
    assert.equal(actual.overall, 'INVALID', `${value}: ${JSON.stringify(actual)}`);
    assert.equal(actual.reason, value === '99 0 R' ? 'PADES_DANGLING_REFERENCE'
      : 'PADES_IMAGE_COLORSPACE');
  }
});

test('signed numeric Decode has the device colour component count', async () => {
  const positive = await verify(document({ Decode: '[0 1 0 1 0 1]' }));
  assert.equal(positive.overall, 'VALID', JSON.stringify(positive));
  for (const value of ['[0 1]', 'true', '[0 1 0 1 0 false]']) {
    const actual = await verify(document({ Decode: value }));
    assert.equal(actual.overall, 'INVALID', `${value}: ${JSON.stringify(actual)}`);
    assert.equal(actual.reason, 'PADES_IMAGE_DECODE');
  }
  const gray = await verify(document({ ColorSpace: '/DeviceGray', Decode: '[0 1]' },
    { pixels: '\0' }));
  assert.equal(gray.overall, 'VALID', JSON.stringify(gray));
});

test('signed mask exceptions preserve one-bit controls and reject forbidden fields', async () => {
  const positive = await verify(document({ ImageMask: 'true', ColorSpace: undefined,
    BitsPerComponent: '1', Decode: '[1 0]' }, { pixels: '\0' }));
  assert.equal(positive.overall, 'VALID', JSON.stringify(positive));
  const color = await verify(document({ ImageMask: 'true' }, { pixels: '\0' }));
  assert.equal(color.overall, 'INVALID', JSON.stringify(color));
  assert.equal(color.reason, 'PADES_IMAGE_COLORSPACE');
  const bits = await verify(document({ ImageMask: 'true', ColorSpace: undefined,
    BitsPerComponent: '2' }, { pixels: '\0' }));
  assert.equal(bits.overall, 'INVALID', JSON.stringify(bits));
  assert.equal(bits.reason, 'PADES_IMAGE_BITS_PER_COMPONENT');
  const decode = await verify(document({ ImageMask: 'true', ColorSpace: undefined,
    BitsPerComponent: undefined, Decode: '[0 0]' }, { pixels: '\0' }));
  assert.equal(decode.overall, 'INVALID', JSON.stringify(decode));
  assert.equal(decode.reason, 'PADES_IMAGE_DECODE');
});

test('standard Flate image filters admit a valid stream while unknown decoders stay unsupported', async () => {
  const compressed = deflateSync(Buffer.from([0, 0, 0])).toString('latin1');
  for (const filter of ['/FlateDecode', '[/FlateDecode]']) {
    const positive = await verify(document({ Filter: filter }, { pixels: compressed }));
    assert.equal(positive.overall, 'VALID', `${filter}: ${JSON.stringify(positive)}`);
  }
  const unknown = await verify(document({ Filter: '[/FlateDecode /BogusDecode]' },
    { pixels: compressed }));
  assert.equal(unknown.overall, 'UNSUPPORTED', JSON.stringify(unknown));
  assert.equal(unknown.reason, 'PADES_IMAGE_FILTER_UNSUPPORTED');
  const wrongType = await verify(document({ Filter: 'true' }));
  assert.equal(wrongType.overall, 'INVALID', JSON.stringify(wrongType));
  assert.equal(wrongType.reason, 'PADES_IMAGE_FILTER');
});

test('complex standard colour spaces are explicit capability limits, not invalid names', async () => {
  const actual = await verify(document({ ColorSpace: '[/CalRGB << /WhitePoint [1 1 1] >>]' }));
  assert.equal(actual.overall, 'UNSUPPORTED', JSON.stringify(actual));
  assert.equal(actual.reason, 'PADES_IMAGE_COLORSPACE_UNSUPPORTED');
});

test('indirect image subtype cannot bypass selected dictionary checks', async () => {
  const options = { objects: [{ number: 7, body: '/Image' }] };
  const positive = await verify(document({ Subtype: '7 0 R' }, options));
  assert.equal(positive.overall, 'VALID', JSON.stringify(positive));
  const negative = await verify(document({ Subtype: '7 0 R', Width: '[]' }, options));
  assert.equal(negative.overall, 'INVALID', JSON.stringify(negative));
  assert.equal(negative.reason, 'PADES_IMAGE_WIDTH');
});

test('referenced image subtype and optional Type remain typed', async () => {
  for (const [entry, reason] of [
    [{ Subtype: undefined }, 'PADES_XOBJECT_SUBTYPE'],
    [{ Subtype: '/Bogus' }, 'PADES_XOBJECT_SUBTYPE'],
    [{ Type: '/Bogus' }, 'PADES_IMAGE_TYPE'],
  ]) {
    const actual = await verify(document(entry));
    assert.equal(actual.overall, 'INVALID', JSON.stringify(actual));
    assert.equal(actual.reason, reason);
  }
});

test('signed image mask type and forbidden Mask member are rejected', async () => {
  const wrongType = await verify(document({ ImageMask: '[true]' }));
  assert.equal(wrongType.overall, 'INVALID', JSON.stringify(wrongType));
  assert.equal(wrongType.reason, 'PADES_IMAGE_MASK');
  const forbidden = await verify(document({ ImageMask: 'true', ColorSpace: undefined,
    BitsPerComponent: undefined, Mask: '[]' }, { pixels: '\0' }));
  assert.equal(forbidden.overall, 'INVALID', JSON.stringify(forbidden));
  assert.equal(forbidden.reason, 'PADES_IMAGE_MASK');
});

test('unfiltered image samples bind declared dimensions and component count', async () => {
  const invalid = await verify(document({ Width: '2' }));
  assert.equal(invalid.overall, 'INVALID', JSON.stringify(invalid));
  assert.equal(invalid.reason, 'PADES_IMAGE_DATA_LENGTH');
  const valid = await verify(document({ Width: '2' }, { pixels: '\0\0\0\0\0\0' }));
  assert.equal(valid.overall, 'VALID', JSON.stringify(valid));
});
