import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import {
  O,
  epoch,
  fixture,
  cmsView,
  hash,
  independentIndex,
  independentArchiveImprint,
  unsignedValues,
  requestFields,
  loadCAdES,
  absentCapability,
  decision,
  expectOverall,
} from './cades-fixtures.mjs';

const api = await loadCAdES();
const selected = { skip: !api && absentCapability };
let f;
before(() => {
  if (api) f = fixture();
});
after(() => f?.close());
test('selected CAdES preservation API is present (new-feature availability gate)', () => {
  assert(api, absentCapability);
  for (const name of ['prepareCAdESSignature', 'prepareCAdESAugmentation', 'verifyCAdES'])
    assert.equal(typeof api[name], 'function', name);
});

for (const detached of [true, false])
  test(
    `CAdES selected lifecycle preserves signed bytes (${detached ? 'detached' : 'attached'})`,
    selected,
    () => {
      const values = f.lifecycle(api, { detached }),
        original = Buffer.from(values.b),
        baseline = cmsView(values.b);
      for (const [key, minimumLevel] of [
        ['b', 'B'],
        ['t', 'T'],
        ['lt', 'LT'],
        ['lta', 'LTA'],
      ]) {
        const result = decision(api, f, values[key], minimumLevel, { originalCMS: original });
        expectOverall(result, 'VALID');
        assert.equal(result.requestedLevel, minimumLevel);
        assert.equal(result.verifiedLevel, minimumLevel);
        const view = cmsView(values[key]);
        assert.deepEqual(
          view.fields.slice(0, 6).map((n) => n.raw),
          baseline.fields.slice(0, 6).map((n) => n.raw),
        );
        assert(view.certificates.some((n) => n.raw.equals(f.signer.der)));
        if (!detached) assert.deepEqual(view.embeddedContent, f.content);
      }
      assert.deepEqual(values.b, original);
    },
  );

test('CAdES mandatory signed signing-time is established by initial signing', selected, () => {
  const b = f.baseCMS(api),
    attributes = cmsView(b).signed;
  for (const id of [O.contentType, O.messageDigest, O.signingTime, O.ess])
    assert.equal(attributes.filter((a) => c.oidText(a.children[0]) === id).length, 1, id);
});

test(
  'signature timestamp request hashes raw signature octets and excludes the OCTET STRING tag and length',
  selected,
  () => {
    const b = f.baseCMS(api),
      prepared = api.prepareCAdESAugmentation(b, {
        content: f.content,
        targetLevel: 'T',
        timestampRequestOptions: { hashOID: O.sha256, policy: O.policy, nonce: 42n },
        policy: f.policy(),
        validationTime: epoch + 20,
        knowledgeTime: epoch + 20,
      });
    const q = requestFields(prepared.requestDER),
      v = cmsView(b);
    assert.deepEqual(q.imprint, hash(v.signature));
    assert.notDeepEqual(q.imprint, hash(v.fields[5].raw));
    assert.notDeepEqual(q.imprint, hash(f.content));
  },
);

for (const hashOID of [O.sha256, O.sha512])
  test(
    `ATSv3 request independently matches exact coverage and index (${hashOID})`,
    selected,
    () => {
      const { lt } = f.lifecycle(api);
      const prepared = api.prepareCAdESAugmentation(lt, {
        content: f.content,
        targetLevel: 'LTA',
        validationMaterial: f.material(),
        timestampRequestOptions: { hashOID, policy: O.policy, nonce: 43n },
        policy: f.policy(),
        validationTime: epoch + 30,
        knowledgeTime: epoch + 30,
      });
      const index = independentIndex(lt, hashOID),
        q = requestFields(prepared.requestDER);
      assert.equal(q.hashOID, hashOID);
      assert.deepEqual(q.imprint, independentArchiveImprint(lt, f.content, index, hashOID));
      const lta = prepared.finish(f.token(prepared.requestDER, { genTime: epoch + 30 }), {
        validationTime: epoch + 30,
        knowledgeTime: epoch + 30,
      });
      expectOverall(decision(api, f, lta, 'LTA'), 'VALID');
      assert.equal(unsignedValues(lta, O.index).length, 0, 'index belongs inside the ATS token');
      const token = unsignedValues(lta, O.archiveTimestamp)[0];
      assert.deepEqual(unsignedValues(token, O.index), [index]);
    },
  );

test(
  'timely TSA succession preserves expired document and prior TSA certificates',
  selected,
  () => {
    const { b, lta } = f.lifecycle(api);
    const policy = f.policy();
    policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')] = epoch + 100;
    const renewed = f.augment(api, lta, 'LTA', {
      at: epoch + 80,
      authority: f.successor,
      policy,
    }).cms;
    expectOverall(
      decision(api, f, renewed, 'LTA', {
        originalCMS: b,
        policy,
        validationTime: epoch + 200,
        knowledgeTime: epoch + 200,
      }),
      'VALID',
    );
    const attrs = cmsView(renewed).unsigned.filter(
      (a) => c.oidText(a.children[0]) === O.archiveTimestamp,
    );
    assert.equal(attrs.length, 2);
    assert(attrs.every((a) => a.children[1].children.length === 1));
  },
);

test(
  'historical material remains offline and authority queries retain actual knowledge time',
  selected,
  () => {
    const { lta } = f.lifecycle(api),
      queries = [],
      expectedKnowledge = epoch + 90;
    const resolver = f.authorities(),
      policy = f.policy({
        authorityResolver: (q) => {
          queries.push(q);
          return resolver(q);
        },
      });
    const previousFetch = globalThis.fetch;
    let networkCalls = 0;
    globalThis.fetch = () => {
      networkCalls++;
      throw Error('issuer and TSA services are closed');
    };
    try {
      expectOverall(
        decision(api, f, lta, 'LTA', {
          policy,
          knowledgeTime: expectedKnowledge,
          validationTime: expectedKnowledge,
        }),
        'VALID',
      );
    } finally {
      globalThis.fetch = previousFetch;
    }
    assert.equal(networkCalls, 0);
    assert(queries.length > 0);
    assert(queries.every((q) => q.knowledgeTime === expectedKnowledge));
    assert(queries.every((q) => q.scope.trustDomainID.equals(f.domain)));
    for (const role of ['ISSUER', 'STATUS_AUTHORITY', 'TIMESTAMP_AUTHORITY'])
      assert(
        queries.some((q) => q.role === role),
        role,
      );
  },
);

test('prepare signature owns byte inputs after returning the signing input', selected, () => {
  const content = Buffer.from(f.content),
    certificate = Buffer.from(f.signer.der);
  const prepared = api.prepareCAdESSignature({
    content,
    certificate,
    certificates: [f.root.der],
    detached: true,
    signingTime: epoch + 10,
  });
  const signature = c.sign(prepared.tbs, f.signer.privateKey);
  content.fill(0);
  certificate.fill(0);
  const cms = prepared.finish(signature);
  expectOverall(decision(api, f, cms), 'VALID');
});

test('augmentation owns original bytes and nested validation-material buffers', selected, () => {
  const original = f.baseCMS(api),
    copy = Buffer.from(original),
    material = f.material();
  const prepared = api.prepareCAdESAugmentation(copy, {
    content: f.content,
    targetLevel: 'T',
    validationMaterial: material,
    timestampRequestOptions: { hashOID: O.sha256, policy: O.policy },
    policy: f.policy(),
    validationTime: epoch + 20,
    knowledgeTime: epoch + 20,
  });
  const token = f.token(prepared.requestDER);
  copy.fill(0);
  material.certificates[0].fill(0);
  material.crls[0].fill(0);
  const augmented = prepared.finish(token, {
    validationTime: epoch + 20,
    knowledgeTime: epoch + 20,
  });
  expectOverall(decision(api, f, augmented, 'T', { originalCMS: original }), 'VALID');
});
