import test, {before, after} from 'node:test';
import assert from 'node:assert/strict';
import {
  padesFixture,
  independentApproval,
  plainPDF,
  decision,
  loadPAdES,
} from './pades-fixtures.mjs';

const api = await loadPAdES();
let fixture;
before(() => { fixture = padesFixture(); });
after(() => fixture?.close());

const base = fragment => `BT /F1 12 Tf 40 120 Td ${fragment} (AB) Tj ET\n`;
const cases = [
  ['Tj whole operand', '(AB) Tj', 'true Tj'],
  ['TJ array element', '[(A) -20 (B)] TJ', '[(A) true (B)] TJ'],
  ['Tm matrix', '1 0 0 1 40 120 Tm', '[1 0 0 1 40 120] Tm'],
  ['Td displacement', '2 3 Td', '[2 3] Td'],
  ['Tr render mode', '0 Tr', '[0] Tr'],
  ['Tz horizontal scaling', '100 Tz', '[100] Tz'],
  ['TL leading', '14 TL T*', '[14] TL T*'],
  ['Tc character spacing', '2 Tc', '[2] Tc'],
  ['Tw word spacing', '2 Tw', '[2] Tw'],
  ['Ts rise', '20 Ts', '[20] Ts'],
  ['Tf font size', '/F1 12 Tf', '/F1 [12] Tf'],
];

for (const [label, positive, negative] of cases) {
  test(`signed page ${label} requires its PDF operand grammar`, async () => {
    for (const [kind, fragment, expectedOverall] of [
      ['positive', positive, 'VALID'],
      ['negative', negative, 'INVALID'],
    ]) {
      const stream = base(fragment);
      const signed = independentApproval(fixture, {pdf: plainPDF({stream})}).pdf;
      const result = await decision(api, fixture, signed);
      assert.equal(result.overall, expectedOverall, `${label} ${kind}: ${JSON.stringify(result)}`);
      if (kind === 'negative') assert.equal(result.reason, 'PADES_TEXT_OPERAND');
    }
  });
}
