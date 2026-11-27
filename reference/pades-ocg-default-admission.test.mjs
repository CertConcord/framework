import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import {
  padesFixture,
  independentApproval,
  plainPDF,
  appendRevision,
  decision,
  loadPAdES,
} from './pades-fixtures.mjs';

const api = await loadPAdES();
let fixture;
before(() => {
  fixture = padesFixture();
});
after(() => fixture?.close());

const ocgPDF = (
  defaultConfig,
  { groups = '[6 0 R]', alternate = '[<< /BaseState /OFF >>]', extra = [] } = {},
) =>
  appendRevision(plainPDF(), [
    {
      number: 1,
      body: `<< /Type /Catalog /Pages 2 0 R /OCProperties << /OCGs ${groups} ${defaultConfig === undefined ? '' : `/D ${defaultConfig}`} /Configs ${alternate} >> >>`,
    },
    { number: 6, body: '<< /Type /OCG /Name (Signed layer) >>' },
    ...extra,
  ]);
const signedDecision = async (pdf, overall, reason) => {
  const signed = independentApproval(fixture, { pdf }).pdf;
  const actual = await decision(api, fixture, signed);
  assert.equal(actual.overall, overall, JSON.stringify(actual));
  assert.equal(actual.reason, reason, JSON.stringify(actual));
};

test('signed default OCG ON with OFF array and alternate OFF is admitted', async () => {
  await signedDecision(ocgPDF('<< /BaseState /ON /OFF [6 0 R] >>'), 'VALID', 'PADES_VALID');
  await signedDecision(ocgPDF('<< /OFF [6 0 R] >>'), 'VALID', 'PADES_VALID');
  await signedDecision(
    ocgPDF('7 0 R', { extra: [{ number: 7, body: '<< /BaseState /ON /OFF [6 0 R] >>' }] }),
    'VALID',
    'PADES_VALID',
  );
  await signedDecision(
    ocgPDF('<< /BaseState null /Intent /View /OFF [6 0 R] >>'),
    'VALID',
    'PADES_VALID',
  );
});

test('signed default OCG OFF must be an array of listed groups', async () => {
  await signedDecision(
    ocgPDF('<< /BaseState /ON /OFF true >>'),
    'INVALID',
    'PADES_OCG_DEFAULT_OFF',
  );
  await signedDecision(
    ocgPDF('<< /BaseState /ON /OFF [true] >>'),
    'INVALID',
    'PADES_OCG_DEFAULT_OFF',
  );
  await signedDecision(
    ocgPDF('<< /BaseState /ON /OFF [7 0 R] >>', {
      extra: [{ number: 7, body: '<< /Type /OCG /Name (Unlisted) >>' }],
    }),
    'INVALID',
    'PADES_OCG_DEFAULT_OFF',
  );
});

test('signed default OCG BaseState when supplied shall be ON', async () => {
  await signedDecision(ocgPDF('<< /BaseState /OFF >>'), 'INVALID', 'PADES_OCG_DEFAULT_BASE_STATE');
  await signedDecision(
    ocgPDF('<< /BaseState /Unchanged >>'),
    'INVALID',
    'PADES_OCG_DEFAULT_BASE_STATE',
  );
  await signedDecision(ocgPDF('<< /BaseState true >>'), 'INVALID', 'PADES_OCG_DEFAULT_BASE_STATE');
});

test('signed OCG properties require listed groups and a default configuration', async () => {
  await signedDecision(ocgPDF(undefined), 'INVALID', 'PADES_OCG_DEFAULT');
  await signedDecision(ocgPDF('true'), 'INVALID', 'PADES_OCG_DEFAULT');
  await signedDecision(
    ocgPDF('<< /BaseState /ON >>', { groups: 'true' }),
    'INVALID',
    'PADES_OCG_GROUPS',
  );
  await signedDecision(
    ocgPDF('<< /BaseState /ON >>', { groups: '[true]' }),
    'INVALID',
    'PADES_OCG_GROUPS',
  );
  await signedDecision(
    appendRevision(plainPDF(), [
      { number: 1, body: '<< /Type /Catalog /Pages 2 0 R /OCProperties true >>' },
    ]),
    'INVALID',
    'PADES_OCG_PROPERTIES',
  );
});

test('signed default OCG ON array uses the same listed group type', async () => {
  await signedDecision(ocgPDF('<< /BaseState /ON /ON [6 0 R] >>'), 'VALID', 'PADES_VALID');
  await signedDecision(
    ocgPDF('<< /BaseState /ON /ON [true] >>'),
    'INVALID',
    'PADES_OCG_DEFAULT_ON',
  );
});

test('signed default OCG intent remains View when supplied', async () => {
  await signedDecision(ocgPDF('<< /Intent /View >>'), 'VALID', 'PADES_VALID');
  await signedDecision(ocgPDF('<< /Intent /Design >>'), 'INVALID', 'PADES_OCG_DEFAULT_INTENT');
});
