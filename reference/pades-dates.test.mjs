import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { verify } from 'node:crypto';
import * as c from './core.mjs';
import {
  epoch,
  padesFixture,
  independentApproval,
  cmsView,
  loadPAdES,
  absentCapability,
  decision,
  expectOverall,
} from './pades-fixtures.mjs';

const api = await loadPAdES(),
  selected = { skip: !api && absentCapability };
let f;
before(() => {
  if (api) f = padesFixture();
});
after(() => f?.close());

// ISO 32000-1 section 7.9.4: omitted trailing fields are permitted, but every
// supplied field must be in range. The quote after offset minutes is optional.
for (const [name, value, expected] of [
  ['complete UTC', 'D:20270115080010Z', 'VALID'],
  ['positive offset', "D:20270115093010+01'30", 'VALID'],
  ['negative offset', "D:20270115063010-01'30", 'VALID'],
  ['positive offset with final quote', "D:20270115093010+01'30'", 'VALID'],
  ['negative offset with final quote', "D:20270115063010-01'30'", 'VALID'],
  ['year precision', 'D:2027', 'UNSUPPORTED'],
  ['month precision', 'D:202701', 'UNSUPPORTED'],
  ['valid leap day precision', 'D:20280229', 'UNSUPPORTED'],
  ['complete local time without timezone', 'D:20270115080010', 'UNSUPPORTED'],
  ['valid date before the selected epoch', 'D:19691231235959Z', 'UNSUPPORTED'],
  ['zero partial month', 'D:202700', 'INVALID'],
  ['out-of-range partial month', 'D:202713', 'INVALID'],
  ['zero partial day', 'D:20270100', 'INVALID'],
  ['impossible partial day', 'D:20270230', 'INVALID'],
  ['non-leap partial day', 'D:20270229', 'INVALID'],
  ['out-of-range partial hour', 'D:2027010124', 'INVALID'],
  ['out-of-range partial minute', 'D:202701010060', 'INVALID'],
  ['out-of-range local second', 'D:20270101000060', 'INVALID'],
  ['impossible full date', 'D:20270230080010Z', 'INVALID'],
  ['out-of-range offset hour', "D:20270115080010+24'00", 'INVALID'],
  ['out-of-range offset minute', "D:20270115080010+00'60", 'INVALID'],
])
  test(`signed PDF date ${name} has a typed decision`, selected, async () => {
    const signed = independentApproval(f, {
      dictionary: (body) => body.replace(/\/M\s*\([^)]*\)/, `/M (${value})`),
    });
    const view = cmsView(signed.cms);
    assert(
      verify(
        'sha256',
        c.set(...view.signed.map((node) => node.raw)),
        f.signer.publicKey,
        view.signature,
      ),
    );
    const digest = view.signed.find(
      (node) => c.oidText(node.children[0]) === '1.2.840.113549.1.9.4',
    ).children[1].children[0].value;
    assert.deepEqual(digest, c.sha256(signed.content));
    expectOverall(await decision(api, f, signed.pdf), expected);
    if (expected === 'VALID') {
      const io = await import('./pades-io.mjs');
      const inspection = await io.inspectPAdESContainer(signed.pdf);
      assert.equal(inspection.signatures[0].signingTime, epoch + 10);
    }
  });
