import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync } from 'node:fs';
import { verify } from 'node:crypto';
import { PDFDocument } from 'pdf-lib';
import * as c from './core.mjs';
import {
  O,
  epoch,
  padesFixture,
  plainPDF,
  pdfSignatures,
  independentApproval,
  independentTimestamp,
  loadPAdES,
  absentCapability,
  decision,
  expectOverall,
  cmsView,
  hash,
} from './pades-fixtures.mjs';
import { requestFields } from './cades-fixtures.mjs';

const api = await loadPAdES();
const selected = { skip: !api && absentCapability };
let f;
before(() => {
  f = padesFixture();
});
after(() => f?.close());

test('selected PAdES preservation API is present (new-feature availability gate)', () => {
  assert(api, absentCapability);
  for (const name of ['preparePAdESSignature', 'preparePAdESAugmentation', 'verifyPAdES'])
    assert.equal(typeof api[name], 'function', name);
});

test('independent PDF and CMS fixture has a real page and OpenSSL-verified detached signature', async () => {
  const value = independentApproval(f);
  for (const pdf of [plainPDF(), value.pdf])
    assert.equal((await PDFDocument.load(pdf)).getPageCount(), 1);
  const view = cmsView(value.cms);
  assert(
    verify('sha256', c.set(...view.signed.map((n) => n.raw)), f.signer.publicKey, view.signature),
  );
  writeFileSync(f.file('pades-fixture.cms'), value.cms);
  writeFileSync(f.file('pades-fixture.content'), value.content);
  f.run(
    'cms',
    '-verify',
    '-binary',
    '-inform',
    'DER',
    '-in',
    f.file('pades-fixture.cms'),
    '-content',
    f.file('pades-fixture.content'),
    '-noverify',
    '-out',
    f.file('pades-fixture.output'),
  );
  assert.deepEqual(readFileSync(f.file('pades-fixture.output')), value.content);
  assert.deepEqual(pdfSignatures(value.pdf)[0].cms, value.cms);
});

test('independent document timestamp hashes the complete ByteRange and has a real TSA signature', () => {
  const b = independentApproval(f).pdf,
    t = independentTimestamp(f, b),
    view = cmsView(t.token);
  assert(
    verify('sha256', c.set(...view.signed.map((n) => n.raw)), f.tsa.publicKey, view.signature),
  );
  assert.deepEqual(pdfSignatures(t.pdf)[1].cms, t.token);
  const info = c.parseDER(view.embeddedContent);
  assert.deepEqual(info.children[2].children[1].value, hash(t.content));
  assert.deepEqual(t.pdf.subarray(0, b.length), b);
});

test(
  'independently generated selected approval and document timestamp are accepted',
  selected,
  async () => {
    const b = independentApproval(f).pdf,
      t = independentTimestamp(f, b).pdf;
    expectOverall(await decision(api, f, b), 'VALID');
    expectOverall(await decision(api, f, t, 'T'), 'VALID');
  },
);

test(
  'selected PAdES B/T/LT/LTA lifecycle preserves every previous revision and approval CMS byte',
  selected,
  async () => {
    const values = await f.lifecycle(api),
      original = Buffer.from(values.b),
      approval = pdfSignatures(values.b)[0].cms;
    let previous = f.pdf;
    for (const [key, level] of [
      ['b', 'B'],
      ['t', 'T'],
      ['lt', 'LT'],
      ['lta', 'LTA'],
    ]) {
      const pdf = values[key],
        result = await decision(api, f, pdf, level, { originalPDF: original });
      expectOverall(result, 'VALID');
      assert.equal(result.requestedLevel, level);
      assert.equal(result.verifiedLevel, level);
      assert.deepEqual(pdf.subarray(0, previous.length), previous);
      assert.deepEqual(pdfSignatures(pdf)[0].cms, approval);
      previous = pdf;
    }
    assert.deepEqual(values.b, original);
  },
);

test(
  'PAdES CMS contains exactly selected signed attributes and PDF carries the self-claimed M date',
  selected,
  async () => {
    const pdf = await f.sign(api),
      sig = pdfSignatures(pdf)[0],
      v = cmsView(sig.cms);
    assert.deepEqual(
      v.signed.map((n) => c.oidText(n.children[0])).sort(),
      [O.contentType, O.messageDigest, O.ess].sort(),
    );
    assert.equal(v.unsigned.length, 0);
    assert.equal(v.embeddedContent, undefined);
    assert.match(sig.body, /\/Type\s*\/Sig\b/);
    assert.match(sig.body, /\/SubFilter\s*\/ETSI\.CAdES\.detached\b/);
    assert.match(sig.body, /\/M\s*\(D:20270115080010Z\)/);
    assert.match(
      pdf.toString('binary'),
      /\/ADBE\s*<<\s*\/BaseVersion\s*\/1\.7\s*\/ExtensionLevel\s+8\s*>>/,
    );
  },
);

for (const hashOID of [O.sha256, O.sha512])
  test(
    `document timestamp request independently matches complete PDF ByteRange (${hashOID})`,
    selected,
    async () => {
      const b = await f.sign(api),
        p = await api.preparePAdESAugmentation(b, {
          targetLevel: 'T',
          validationMaterial: { certificates: [], crls: [] },
          timestampRequestOptions: { hashOID, policy: O.policy, nonce: 42n },
          policy: f.policy(),
          signatureBytes: 8192,
        });
      const q = requestFields(p.requestDER);
      assert.equal(q.hashOID, hashOID);
      assert.deepEqual(q.imprint, p.imprint);
      const pdf = await p.finish(f.token(p.requestDER, { genTime: epoch + 20 }), {
        validationTime: epoch + 20,
        knowledgeTime: epoch + 20,
      });
      const sig = pdfSignatures(pdf).at(-1),
        [start, length, tail, tailLength] = sig.byteRange;
      const content = Buffer.concat([
        pdf.subarray(start, start + length),
        pdf.subarray(tail, tail + tailLength),
      ]);
      assert.deepEqual(q.imprint, hash(content, hashOID));
      assert.notDeepEqual(q.imprint, hash(pdfSignatures(b)[0].cms, hashOID));
      assert.equal(start, 0);
      assert.equal(tail + tailLength, pdf.length);
      assert.equal(length, sig.contentsAt - 1);
      assert.equal(tail, sig.contentsAt + 2 * sig.signatureBytes + 1);
      assert.equal(pdf[length], 0x3c);
      assert.equal(pdf[tail - 1], 0x3e);
      expectOverall(await decision(api, f, pdf, 'T'), 'VALID');
    },
  );

test('LT adds validation material without asking for a timestamp token', selected, async () => {
  const b = await f.sign(api),
    t = (await f.augment(api, b, 'T', { at: epoch + 20 })).pdf;
  const p = await api.preparePAdESAugmentation(t, {
    targetLevel: 'LT',
    validationMaterial: f.material(),
    policy: f.policy(),
  });
  assert.equal(p.requestDER, undefined);
  assert.equal(p.imprint, undefined);
  const lt = await p.finish(undefined, { validationTime: epoch + 25, knowledgeTime: epoch + 25 });
  assert.equal(pdfSignatures(lt).length, 2);
  assert.deepEqual(lt.subarray(0, t.length), t);
  expectOverall(await decision(api, f, lt, 'LT'), 'VALID');
});

test(
  'timely document timestamp succession preserves expired signer and first TSA certificates',
  selected,
  async () => {
    const { b, lta } = await f.lifecycle(api),
      policy = f.policy();
    policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')] = epoch + 100;
    const renewed = (
      await f.augment(api, lta, 'LTA', { at: epoch + 80, authority: f.successor, policy })
    ).pdf;
    expectOverall(
      await decision(api, f, renewed, 'LTA', {
        originalPDF: b,
        policy,
        validationTime: epoch + 200,
        knowledgeTime: epoch + 200,
      }),
      'VALID',
    );
    assert.deepEqual(renewed.subarray(0, lta.length), lta);
  },
);

test(
  'offline preserved PAdES keeps actual knowledgeTime in every authority query',
  selected,
  async () => {
    const { lta } = await f.lifecycle(api),
      queries = [],
      resolver = f.authorities();
    const policy = f.policy({
      authorityResolver: (query) => {
        queries.push(query);
        return resolver(query);
      },
    });
    const oldFetch = globalThis.fetch;
    let requests = 0;
    globalThis.fetch = () => {
      requests++;
      throw Error('offline fixture');
    };
    try {
      expectOverall(
        await decision(api, f, lta, 'LTA', {
          validationTime: epoch + 40,
          knowledgeTime: epoch + 90,
          policy,
        }),
        'VALID',
      );
    } finally {
      globalThis.fetch = oldFetch;
    }
    assert.equal(requests, 0);
    assert(queries.length > 0);
    assert(queries.every((q) => q.knowledgeTime === epoch + 90));
    for (const role of ['ISSUER', 'STATUS_AUTHORITY', 'TIMESTAMP_AUTHORITY'])
      assert(
        queries.some((q) => q.role === role),
        role,
      );
  },
);

test(
  'creation snapshots input PDF, certificate arrays and exported signing views before async work',
  selected,
  async () => {
    const input = Buffer.from(f.pdf),
      certificate = Buffer.from(f.signer.der),
      roots = [Buffer.from(f.root.der)];
    const pending = api.preparePAdESSignature(input, {
      certificate,
      certificates: roots,
      signingTime: epoch + 10,
      signatureBytes: 8192,
    });
    input.fill(0);
    certificate.fill(0);
    roots[0].fill(0);
    roots.length = 0;
    const prepared = await pending,
      tbs = Buffer.from(prepared.tbs);
    assert(Buffer.isBuffer(prepared.contentHash));
    assert.equal(prepared.contentHash.length, 32);
    assert.equal(prepared.byteRange.length, 4);
    const signature = c.sign(tbs, f.signer.privateKey);
    prepared.tbs.fill(0);
    prepared.contentHash.fill(0);
    try {
      prepared.byteRange[0] = 9;
    } catch (error) {
      assert(error instanceof TypeError);
    }
    const finishing = prepared.finish(signature);
    signature.fill(0);
    const pdf = await finishing;
    assert.deepEqual(pdf.subarray(0, f.pdf.length), f.pdf);
    expectOverall(await decision(api, f, pdf), 'VALID');
  },
);

test(
  'augmentation and asynchronous finish snapshot nested bytes and the replacement policy',
  selected,
  async () => {
    const original = await f.sign(api),
      input = Buffer.from(original),
      material = f.material(),
      policy = f.policy();
    const pending = api.preparePAdESAugmentation(input, {
      targetLevel: 'T',
      validationMaterial: material,
      timestampRequestOptions: { hashOID: O.sha256, policy: O.policy, nonce: 55n },
      policy,
      signatureBytes: 8192,
    });
    input.fill(0);
    material.certificates[0].fill(0);
    material.crls[0].fill(0);
    policy.scope.trustDomainID = Buffer.alloc(32);
    const p = await pending,
      token = f.token(p.requestDER, { genTime: epoch + 20 }),
      replacement = f.policy();
    const finishing = p.finish(token, {
      validationTime: epoch + 20,
      knowledgeTime: epoch + 20,
      policy: replacement,
    });
    token.fill(0);
    replacement.trustedRoots[0] = Buffer.alloc(1);
    replacement.keyDeadlines = {};
    const pdf = await finishing;
    expectOverall(await decision(api, f, pdf, 'T', { originalPDF: original }), 'VALID');
  },
);

test(
  'verification snapshots bytes and nested policy before entering its worker',
  selected,
  async () => {
    const original = await f.sign(api),
      input = Buffer.from(original),
      policy = f.policy();
    const pending = decision(api, f, input, 'B', { originalPDF: Buffer.from(original), policy });
    input.fill(0);
    policy.trustedRoots.length = 0;
    policy.keyDeadlines = {};
    expectOverall(await pending, 'VALID');
  },
);
