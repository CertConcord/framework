import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { verify } from 'node:crypto';
import * as c from './core.mjs';
import {
  padesFixture,
  independentApproval,
  loadPAdES,
  absentCapability,
  decision,
  expectOverall,
  cmsView,
  replaceCMS,
} from './pades-fixtures.mjs';
import { rewriteCMS } from './cades-fixtures.mjs';

const api = await loadPAdES(),
  selected = { skip: !api && absentCapability };
let f;
before(() => {
  if (api) f = padesFixture();
});
after(() => f?.close());
function serialized(options) {
  const value = independentApproval(f, options),
    view = cmsView(value.cms);
  assert(
    verify(
      'sha256',
      c.set(...view.signed.map((node) => node.raw)),
      f.signer.publicKey,
      view.signature,
    ),
  );
  const digest = view.signed.find((node) => c.oidText(node.children[0]) === '1.2.840.113549.1.9.4')
    .children[1].children[0].value;
  assert.deepEqual(digest, c.sha256(value.content));
  return value.pdf;
}

for (const [name, separator] of [
  ['SP', ' '],
  ['HT', '\t'],
  ['LF', '\n'],
  ['CR', '\r'],
  ['FF', '\f'],
  ['NUL', '\0'],
  ['multiple spaces', '  '],
  ['terminated comments', ' % separator\n'],
])
  test(
    `legal PDF object header ${name} has exact xref offsets and valid signature`,
    selected,
    async () => {
      const pdf = serialized({
        objectHeader: (number, generation) =>
          number === 1
            ? `${number}${separator}${generation}${separator}obj`
            : `${number} ${generation} obj`,
      });
      expectOverall(await decision(api, f, pdf), 'VALID');
    },
  );
for (const target of ['object', 'xref'])
  for (const terminated of [false, true])
    test(
      `${target} offset ${terminated ? 'after a terminated' : 'inside an unterminated'} comment has normative lexical boundaries`,
      selected,
      async () => {
        const prefix = '% ignored prefix' + (terminated ? '\n' : ' ');
        const pdf = serialized(
          target === 'object'
            ? { objectPrefix: (number) => (number === 1 ? prefix : '') }
            : { xrefPrefix: prefix },
        );
        expectOverall(await decision(api, f, pdf), terminated ? 'VALID' : 'INVALID');
      },
    );
test('vertical tab is not one of the six PDF whitespace bytes', selected, async () => {
  const pdf = serialized({
    objectHeader: (number, generation) =>
      number === 1 ? `${number}\v${generation}\vobj` : `${number} ${generation} obj`,
  });
  expectOverall(await decision(api, f, pdf), 'INVALID');
});

test(
  'augmentation preparation preserves known bad mathematics before rejecting extra approval signers',
  selected,
  async () => {
    const first = independentApproval(f).pdf,
      second = independentApproval(f, { pdf: first, fieldName: 'Second approval' }).pdf;
    const bad = replaceCMS(second, 1, (raw) => {
      const signature = Buffer.from(cmsView(raw).signature);
      signature[signature.length - 1] ^= 1;
      return rewriteCMS(raw, { signature });
    });
    await assert.rejects(
      api.preparePAdESAugmentation(bad, { targetLevel: 'T', policy: f.policy() }),
      { code: 'CADES_SIGNATURE_INVALID', overall: 'INVALID' },
    );
  },
);
