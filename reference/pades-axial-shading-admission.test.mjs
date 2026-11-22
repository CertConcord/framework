import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { padesFixture, independentApproval, decision, loadPAdES } from './pades-fixtures.mjs';
import { axialType2Document as document } from './pades-type2-function-fixture.mjs';

const api = await loadPAdES();
let fixture;
before(() => { fixture = padesFixture(); });
after(() => fixture?.close());

async function expect(options, overall, reason) {
  const signed = independentApproval(fixture, { pdf: document({}, options) }).pdf;
  const actual = await decision(api, fixture, signed);
  assert.equal(actual.overall, overall, JSON.stringify(actual));
  assert.equal(actual.reason, reason);
}

test('signed axial dictionary admits standard direct and indirect entries', async () => {
  await expect({}, 'VALID', 'PADES_VALID');
  await expect({ coords: '7 0 R', extend: '8 0 R', bbox: '9 0 R', objects: [
    { number: 7, body: '[0 0 100 0]' },
    { number: 8, body: '[true false]' },
    { number: 9, body: '[0 0 100 200]' },
  ] }, 'VALID', 'PADES_VALID');
  await expect({ extend: null, bbox: undefined }, 'VALID', 'PADES_VALID');
});

for (const [title, options, reason] of [
  ['boolean shading type', { shadingType: 'true' }, 'PADES_SHADING_TYPE'],
  ['non-integer shading type', { shadingType: '2.0' }, 'PADES_SHADING_TYPE'],
  ['unknown shading type', { shadingType: '8' }, 'PADES_SHADING_TYPE'],
  ['missing axial coordinates', { coords: null }, 'PADES_SHADING_COORDS'],
  ['three axial coordinates', { coords: '[0 0 100]' }, 'PADES_SHADING_COORDS'],
  ['boolean axial coordinate', { coords: '[0 0 true 0]' }, 'PADES_SHADING_COORDS'],
  ['numeric extension member', { extend: '[1 true]' }, 'PADES_SHADING_EXTEND'],
  ['single extension member', { extend: '[true]' }, 'PADES_SHADING_EXTEND'],
  ['three extension members', { extend: '[true true false]' }, 'PADES_SHADING_EXTEND'],
  ['three bounding coordinates', { bbox: '[0 0 100]' }, 'PADES_SHADING_BBOX'],
  ['boolean bounding coordinate', { bbox: '[0 0 true 200]' }, 'PADES_SHADING_BBOX'],
]) {
  test(`signed axial dictionary rejects ${title}`, () => expect(options, 'INVALID', reason));
}

test('optional null extension and bounding box are omissions', async () => {
  await expect({ extend: 'null', bbox: 'null' }, 'VALID', 'PADES_VALID');
  await expect({ extend: '7 0 R', bbox: '8 0 R', objects: [
    { number: 7, body: 'null' }, { number: 8, body: 'null' },
  ] }, 'VALID', 'PADES_VALID');
  await expect({ coords: 'null' }, 'INVALID', 'PADES_SHADING_COORDS');
});

test('unreferenced malformed shading is outside signed page content', () =>
  expect({ shadingType: 'true', content: 'q Q\n' }, 'VALID', 'PADES_VALID'));
