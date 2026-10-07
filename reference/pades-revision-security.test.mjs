import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  padesFixture,
  independentApproval,
  independentTimestamp,
  independentDSS,
  appendRevision,
  fixtureState,
  loadPAdES,
  absentCapability,
  decision,
  expectOverall,
} from './pades-fixtures.mjs';

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

for (const array of [false, true])
  test(
    `an existing signed page cannot be reclassified as a DSS ${array ? 'Certs array' : 'dictionary'}`,
    selected,
    async () => {
      const state = fixtureState(b),
        dss = array ? state.size : 3;
      const catalog = state.objects.get(state.root).body.replace(/>>\s*$/, `/DSS ${dss} 0 R >>`);
      const changed = appendRevision(b, [
        { number: 3, body: array ? '[ ]' : '<< /Type /DSS /Certs [] /CRLs [] >>' },
        ...(array ? [{ number: dss, body: '<< /Type /DSS /Certs 3 0 R /CRLs [] >>' }] : []),
        { number: state.root, body: catalog },
      ]);
      assert.deepEqual(changed.subarray(0, b.length), b);
      expectOverall(await decision(api, f, changed), 'INVALID');
    },
  );

test(
  'a previously signed AcroForm cannot change role to DSS behind a replacement form',
  selected,
  async () => {
    const state = fixtureState(b),
      root = state.objects.get(state.root).body;
    const form = Number(/\/AcroForm\s+(\d+)\s+0\s+R/.exec(root)[1]);
    const newForm = state.size,
      originalForm = state.objects.get(form).body;
    const catalog = root
      .replace(/\/AcroForm\s+\d+\s+0\s+R/, `/AcroForm ${newForm} 0 R`)
      .replace(/>>\s*$/, `/DSS ${form} 0 R >>`);
    const changed = appendRevision(b, [
      { number: form, body: '<< /Type /DSS /Certs [] /CRLs [] >>' },
      { number: newForm, body: originalForm },
      { number: state.root, body: catalog },
    ]);
    expectOverall(await decision(api, f, changed), 'INVALID');
  },
);

test(
  'arbitrary unreachable objects cannot be appended under the preservation policy',
  selected,
  async () => {
    const state = fixtureState(b),
      changed = appendRevision(b, [
        { number: state.size, body: '<< /UnapprovedMetadata (different document) >>' },
      ]);
    expectOverall(await decision(api, f, changed), 'INVALID');
  },
);

for (const kind of ['xref offset', 'Prev', 'Root', 'Size'])
  test(`otherwise permitted DSS revision cannot repair a bad ${kind}`, selected, async () => {
    const good = independentDSS(independentTimestamp(f, b).pdf, f.material());
    expectOverall(await decision(api, f, good, 'LT'), 'VALID');
    const source = good.toString('binary'),
      start = source.lastIndexOf('\nxref\n'),
      head = source.slice(0, start);
    let tail = source.slice(start);
    if (kind === 'xref offset')
      tail = tail.replace(
        /(\n)(\d{10})( \d{5} n)/,
        (_, before, number, after) => before + String(Number(number) + 1).padStart(10, '0') + after,
      );
    if (kind === 'Prev')
      tail = tail.replace(
        /(\/Prev\s+)(\d+)/,
        (_, before, number) => before + '1'.padEnd(number.length, ' '),
      );
    if (kind === 'Root') tail = tail.replace('/Root 1 0 R', '/Root 3 0 R');
    if (kind === 'Size')
      tail = tail.replace(
        /(\/Size\s+)(\d+)/,
        (_, before, number) => before + '2'.padEnd(number.length, ' '),
      );
    const bad = Buffer.from(head + tail, 'binary');
    assert.equal(bad.length, good.length);
    assert(!bad.equals(good));
    expectOverall(await decision(api, f, bad, 'LT'), 'INVALID');
  });
