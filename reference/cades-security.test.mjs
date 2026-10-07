import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import {
  O,
  epoch,
  fixture,
  attr,
  cmsView,
  hash,
  rewriteCMS,
  resign,
  unsignedValues,
  replaceUnsigned,
  independentIndex,
  independentArchiveInput,
  independentArchiveImprint,
  requestFields,
  loadCAdES,
  absentCapability,
  decision,
  expectOverall,
} from './cades-fixtures.mjs';
const api = await loadCAdES(),
  selected = { skip: !api && absentCapability };
let f, original;
before(() => {
  if (api) {
    f = fixture();
    original = f.lifecycle(api);
  }
});
after(() => f?.close());
const verify = (cms, level, expected, changes) =>
  expectOverall(decision(api, f, cms, level, changes), expected);
const signedAttributes = () => cmsView(original.b).signed.map((n) => n.raw);
const attrOID = (raw) => c.oidText(c.parseDER(raw).children[0]);
const attachT = (token, cms = original.b) => replaceUnsigned(cms, O.signatureTimestamp, [token]);
const requestT = () => ({
  hashOID: O.sha256,
  imprint: hash(cmsView(original.b).signature),
  policy: O.policy,
  nonce: 51n,
});

for (const [source, requested] of [
  ['b', 'T'],
  ['t', 'LT'],
  ['lt', 'LTA'],
])
  test(`missing ${requested} evidence cannot silently downgrade to ${source}`, selected, () =>
    verify(original[source], requested, 'INDETERMINATE'),
  );

for (const id of [O.contentType, O.messageDigest, O.signingTime, O.ess]) {
  test(`missing signed attribute ${id} is not repairable by augmentation`, selected, () => {
    const cms = resign(
      original.b,
      signedAttributes().filter((a) => attrOID(a) !== id),
      f.signer.privateKey,
    );
    verify(cms, 'B', 'INDETERMINATE');
  });
  test(`duplicate signed attribute ${id} is rejected even with a valid signature`, selected, () => {
    const attributes = signedAttributes(),
      duplicate = attributes.find((a) => attrOID(a) === id);
    verify(resign(original.b, [...attributes, duplicate], f.signer.privateKey), 'B', 'INVALID');
  });
  test(`multiple values for signed attribute ${id} are not first-value selected`, selected, () => {
    const attributes = signedAttributes().map((a) =>
      attrOID(a) === id ? attr(id, ...Array(2).fill(c.parseDER(a).children[1].children[0].raw)) : a,
    );
    verify(resign(original.b, attributes, f.signer.privateKey), 'B', 'INVALID');
  });
}

test('valid signature with wrong signing-time ASN.1 type is INVALID', selected, () => {
  verify(
    resign(
      original.b,
      signedAttributes().map((a) =>
        attrOID(a) === O.signingTime ? attr(O.signingTime, c.integer(epoch + 10)) : a,
      ),
      f.signer.privateKey,
    ),
    'B',
    'INVALID',
  );
});
test(
  'content substitution is INVALID even when required higher-level evidence is missing',
  selected,
  () => {
    verify(original.b, 'LTA', 'INVALID', { content: Buffer.from('substituted document') });
  },
);
test('originalCMS guard rejects a different otherwise valid original signature', selected, () => {
  const other = f.baseCMS(api, { signingTime: epoch + 11 });
  verify(original.lta, 'LTA', 'INVALID', { originalCMS: other });
});
test(
  'same signer key in a different certificate cannot replace the ESS-bound bytes',
  selected,
  () => {
    const replacement = f.certificate('CAdES Document Renewal', { issuer: f.root, key: f.signer });
    const certificates = cmsView(original.b).certificates.map((n) =>
      n.raw.equals(f.signer.der) ? replacement.der : n.raw,
    );
    verify(rewriteCMS(original.b, { certificates }), 'B', 'INVALID');
  },
);

for (const [name, omitted] of [
  ['signer', 'signer'],
  ['root', 'root'],
  ['TSA', 'tsa'],
])
  test(
    `external current material does not replace missing embedded LT ${name} certificate`,
    selected,
    () => {
      const cms = rewriteCMS(original.lt, {
        certificates: cmsView(original.lt)
          .certificates.filter((n) => !n.raw.equals(f[omitted].der))
          .map((n) => n.raw),
      });
      verify(cms, 'LT', 'INDETERMINATE');
    },
  );
test('external fresh CRL does not replace absent root SignedData.crls for LT', selected, () => {
  verify(rewriteCMS(original.lt, { crls: [] }), 'LT', 'INDETERMINATE');
});
test('embedded self-signed certificates are not relying-party trust anchors', selected, () => {
  verify(original.lta, 'LTA', 'INDETERMINATE', { policy: f.policy({ trustedRoots: [] }) });
});
test('a same-named foreign-root CRL is a known invalid binding', selected, () => {
  const foreign = f.certificate('CAdES Root');
  const badCRL = f.crl({ issuer: foreign });
  verify(rewriteCMS(original.lt, { crls: [badCRL] }), 'LT', 'INVALID', {
    policy: f.policy({ currentMaterial: f.material(badCRL) }),
  });
});

for (const [label, oid] of [
  ['certificate-values', '1.2.840.113549.1.9.16.2.23'],
  ['revocation-values', '1.2.840.113549.1.9.16.2.24'],
  ['complete-certificate-refs', '1.2.840.113549.1.9.16.2.21'],
  ['complete-revocation-refs', '1.2.840.113549.1.9.16.2.22'],
  ['legacy archive timestamp', '1.2.840.113549.1.9.16.2.27'],
  ['archive timestamp v2', '1.2.840.113549.1.9.16.2.48'],
  ['counter-signature', '1.2.840.113549.1.9.6'],
])
  test(`unselected ${label} route is explicit UNSUPPORTED`, selected, () => {
    const value = oid === '1.2.840.113549.1.9.6' ? cmsView(original.b).signer.raw : c.seq();
    const cms = rewriteCMS(original.b, { unsigned: [attr(oid, value)] });
    verify(cms, 'B', 'UNSUPPORTED');
    verify(cms, 'B', 'INVALID', { content: Buffer.from('known invalid content') });
  });
test('multiple valid SignerInfo records are explicitly unsupported', selected, () => {
  verify(
    rewriteCMS(original.b, {
      signers: [cmsView(original.b).signer.raw, cmsView(original.b).signer.raw],
    }),
    'B',
    'UNSUPPORTED',
  );
});
test('delta CRLs are not silently interpreted as complete CRLs', selected, () => {
  const delta = f.crl({ extensions: [p.extension('2.5.29.27', c.integer(0), true)] });
  verify(rewriteCMS(original.lt, { crls: [delta] }), 'LT', 'UNSUPPORTED', {
    policy: f.policy({ currentMaterial: f.material(delta) }),
  });
});
test('indirect CRLs are explicitly unsupported', selected, () => {
  const indirect = f.crl({
    extensions: [p.extension('2.5.29.28', c.seq(c.der(0x84, Buffer.from([0xff]))), true)],
  });
  verify(rewriteCMS(original.lt, { crls: [indirect] }), 'LT', 'UNSUPPORTED', {
    policy: f.policy({ currentMaterial: f.material(indirect) }),
  });
});

for (const [name, options, expected] of [
  ['stale GOOD', { thisUpdate: epoch - 100, nextUpdate: epoch + 5 }, 'INDETERMINATE'],
  ['future publication', { thisUpdate: epoch + 50, nextUpdate: epoch + 100 }, 'INDETERMINATE'],
  [
    'known revoked despite stale CRL',
    { thisUpdate: epoch - 100, nextUpdate: epoch + 5, entries: [{ revokedAt: epoch, reason: 1 }] },
    'INVALID',
  ],
])
  test(`B validation treats ${name} honestly`, selected, () => {
    verify(original.b, 'B', expected, {
      policy: f.policy({ currentMaterial: f.material(f.crl(options)) }),
    });
  });
test('bad CRL signature outranks stale status', selected, () => {
  const crl = f.crl({ thisUpdate: epoch - 100, nextUpdate: epoch + 5 });
  crl[crl.length - 1] ^= 1;
  verify(original.b, 'B', 'INVALID', { policy: f.policy({ currentMaterial: f.material(crl) }) });
});
test('same-number authenticated CRL fork is not arbitrarily selected', selected, () => {
  const good = f.crl({ number: 5 }),
    revoked = f.crl({ number: 5, entries: [{ revokedAt: epoch }] });
  verify(original.b, 'B', 'INVALID', {
    policy: f.policy({
      currentMaterial: { certificates: f.material().certificates, crls: [good, revoked] },
    }),
  });
});

for (const name of ['content', 'signature TLV', 'signedAttrs'])
  test(`valid TSA token over ${name} is the wrong signature timestamp coverage`, selected, () => {
    const v = cmsView(original.b),
      wrong =
        name === 'content'
          ? f.content
          : name === 'signature TLV'
            ? v.fields[5].raw
            : v.fields[3].raw;
    verify(attachT(f.token(requestT(), { imprint: hash(wrong) })), 'T', 'INVALID');
  });
test('signature timestamp at signer expiration cannot establish timely proof', selected, () => {
  verify(
    attachT(f.token(requestT(), { authority: f.successor, genTime: f.signer.cert.notAfter })),
    'T',
    'INVALID',
    { validationTime: epoch + 150, knowledgeTime: epoch + 150 },
  );
});
test('timestamp accuracy interval crossing TSA expiration is rejected', selected, () => {
  verify(attachT(f.token(requestT(), { genTime: epoch + 99, accuracy: 2 })), 'T', 'INVALID', {
    validationTime: epoch + 110,
    knowledgeTime: epoch + 110,
  });
});
test('absent timestamp accuracy is unknown rather than zero', selected, () => {
  verify(attachT(f.token(requestT(), { accuracy: null })), 'T', 'INDETERMINATE');
});
for (const [label, changes] of [
  ['wrong nonce', { nonce: 999n }],
  ['wrong policy', { policy: '1.3.6.1.4.1.55555.91.9' }],
  ['wrong imprint', { imprint: Buffer.alloc(32, 1) }],
])
  test(`augmentation finish binds the pending timestamp request (${label})`, selected, () => {
    const options = {
      content: f.content,
      targetLevel: 'T',
      timestampRequestOptions: { hashOID: O.sha256, policy: O.policy, nonce: 42n },
      policy: f.policy(),
      validationTime: epoch + 20,
      knowledgeTime: epoch + 20,
    };
    const good = api.prepareCAdESAugmentation(original.b, options);
    assert(
      Buffer.isBuffer(
        good.finish(f.token(good.requestDER), {
          validationTime: epoch + 20,
          knowledgeTime: epoch + 20,
        }),
      ),
    );
    const bad = api.prepareCAdESAugmentation(original.b, options);
    assert.throws(() =>
      bad.finish(f.token(bad.requestDER, changes), {
        validationTime: epoch + 20,
        knowledgeTime: epoch + 20,
      }),
    );
  });

for (const [label, options] of [
  ['wrong EKU', { eku: 'serverAuth' }],
  ['noncritical EKU', { ekuCritical: false }],
])
  test(`TSA ${label} cannot timestamp a document`, selected, () => {
    const authority = f.certificate(`TSA ${label}`, { issuer: f.root, tsa: true, ...options });
    verify(attachT(f.token(requestT(), { authority })), 'T', 'INVALID');
  });
for (const [label, settings, expected] of [
  ['wrong root role', { roles: { root: ['REGISTRATION_AUTHORITY'] } }, 'INVALID'],
  ['wrong TSA role', { roles: { tsa: ['STATUS_AUTHORITY'] } }, 'INVALID'],
  [
    'wrong issuer scope',
    { scopes: { root: { trustDomainID: Buffer.alloc(32, 0x91), issuerID: 'another-issuer' } } },
    'INVALID',
  ],
  ['missing TSA appointment', { missing: null }, 'INDETERMINATE'],
])
  test(`CAdES authority selection rejects ${label}`, selected, () => {
    if (settings.missing === null) settings.missing = [f.tsa];
    verify(original.t, 'T', expected, {
      policy: f.policy({ authorityResolver: f.authorities(settings) }),
    });
  });

test(
  'external knowledge is not lowered to hide a later learned applicable TSA compromise',
  selected,
  () => {
    const resolver = f.authorities({
      states: {
        tsa: ({ authorityID, trustDomainID, knowledgeTime }) => ({
          authorityID,
          trustDomainID,
          scope: 'AUTHORITY',
          status: knowledgeTime < epoch + 35 ? 'GOOD' : 'REVOKED',
          publishedAt: knowledgeTime < epoch + 35 ? epoch : epoch + 35,
          nextUpdate: epoch + 1000,
          ...(knowledgeTime < epoch + 35
            ? {}
            : { effectiveTime: epoch + 35, compromiseStart: epoch + 15 }),
        }),
      },
    });
    const policy = f.policy({ authorityResolver: resolver });
    verify(original.t, 'T', 'VALID', {
      policy,
      validationTime: epoch + 30,
      knowledgeTime: epoch + 30,
    });
    verify(original.t, 'T', 'INVALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 40,
    });
  },
);

test('old CRL bytes cannot be reused historically without ATS protection', selected, () => {
  const old = f.crl({ nextUpdate: epoch + 28 }),
    policy = f.policy({ currentMaterial: f.material(old) });
  verify(rewriteCMS(original.lt, { crls: [old] }), 'LT', 'INDETERMINATE', { policy });
});
test(
  'latest ATS still requires fresh current status after retained coverage expires',
  selected,
  () => {
    verify(original.lta, 'LTA', 'INDETERMINATE', {
      policy: f.policy({ currentMaterial: undefined }),
      validationTime: epoch + 2000,
      knowledgeTime: epoch + 2000,
    });
  },
);

for (const corruption of ['whole CMS', 'field order', 'content raw bytes', 'signature value only'])
  test(`authentic ATS over wrong ${corruption} coverage is INVALID`, selected, () => {
    const index = independentIndex(original.lt),
      v = cmsView(original.lt);
    const correct = independentArchiveInput(original.lt, f.content, index);
    const wrong =
      corruption === 'whole CMS'
        ? original.lt
        : corruption === 'field order'
          ? Buffer.concat([
              hash(f.content),
              v.contentType.raw,
              ...v.fields.slice(0, 6).map((n) => n.raw),
              index,
            ])
          : corruption === 'content raw bytes'
            ? Buffer.concat([
                v.contentType.raw,
                f.content,
                ...v.fields.slice(0, 6).map((n) => n.raw),
                index,
              ])
            : Buffer.concat([
                v.contentType.raw,
                hash(f.content),
                ...v.fields.slice(0, 5).map((n) => n.raw),
                v.signature,
                index,
              ]);
    assert.notDeepEqual(wrong, correct);
    let token = f.token(
      { hashOID: O.sha256, imprint: hash(wrong), policy: O.policy, nonce: 74n },
      { genTime: epoch + 30 },
    );
    token = replaceUnsigned(token, O.index, [index]);
    verify(replaceUnsigned(original.lt, O.archiveTimestamp, [token]), 'LTA', 'INVALID');
  });
test(
  'ATS index cannot omit a preexisting CRL even with a correct signature on the reduced index',
  selected,
  () => {
    const parts = c.parseDER(independentIndex(original.lt)).children.map((n) => n.raw);
    parts[2] = c.seq();
    const index = c.seq(...parts),
      imprint = independentArchiveImprint(original.lt, f.content, index);
    const token = replaceUnsigned(
      f.token(
        { hashOID: O.sha256, imprint, policy: O.policy, nonce: 75n },
        { genTime: epoch + 30 },
      ),
      O.index,
      [index],
    );
    verify(replaceUnsigned(original.lt, O.archiveTimestamp, [token]), 'LTA', 'INVALID');
  },
);
test(
  'ATS index belongs inside the corresponding token and cannot be supplied at document level',
  selected,
  () => {
    const token = unsignedValues(original.lta, O.archiveTimestamp)[0],
      index = unsignedValues(token, O.index)[0];
    const wrongToken = replaceUnsigned(token, O.index, []);
    const wrong = replaceUnsigned(
      replaceUnsigned(original.lt, O.archiveTimestamp, [wrongToken]),
      O.index,
      [index],
    );
    verify(wrong, 'LTA', 'INVALID');
  },
);
test('absent inner ATS index is missing evidence, not an inferred archive proof', selected, () => {
  const token = unsignedValues(original.lta, O.archiveTimestamp)[0];
  verify(
    replaceUnsigned(original.lt, O.archiveTimestamp, [replaceUnsigned(token, O.index, [])]),
    'LTA',
    'INDETERMINATE',
  );
});
test('duplicate ATS index attributes are ambiguous even when byte-identical', selected, () => {
  const token = unsignedValues(original.lta, O.archiveTimestamp)[0],
    index = unsignedValues(token, O.index)[0];
  const wrong = rewriteCMS(token, { unsigned: [attr(O.index, index), attr(O.index, index)] });
  verify(replaceUnsigned(original.lt, O.archiveTimestamp, [wrong]), 'LTA', 'INVALID');
});
test(
  'removing exact indexed material is INVALID even when fresh external replacement exists',
  selected,
  () => {
    const replacement = f.crl({ number: 2 });
    verify(rewriteCMS(original.lta, { crls: [replacement] }), 'LTA', 'INVALID', {
      policy: f.policy({ currentMaterial: f.material(replacement) }),
    });
  },
);
test(
  'new validation material may be added before renewal without invalidating the older index',
  selected,
  () => {
    const extra = f.crl({ number: 2, thisUpdate: epoch + 50, nextUpdate: epoch + 1000 });
    const renewed = f.augment(api, original.lta, 'LTA', {
      at: epoch + 60,
      authority: f.successor,
      validationMaterial: {
        certificates: f.material().certificates,
        crls: [...cmsView(original.lta).crls.map((n) => n.raw), extra],
      },
    }).cms;
    verify(renewed, 'LTA', 'VALID', { validationTime: epoch + 70, knowledgeTime: epoch + 70 });
  },
);

for (const offset of [50, 51])
  test(
    `renewal at/after exclusive prior TSA key deadline (${offset}) cannot repair protection`,
    selected,
    () => {
      // Create cryptographically correct bytes under a broad acquisition policy, then
      // apply the externally authenticated, later-known risk cutoff at verification.
      const renewed = f.augment(api, original.lta, 'LTA', {
        at: epoch + offset,
        authority: f.successor,
      }).cms;
      const policy = f.policy();
      policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')] = epoch + 50;
      verify(renewed, 'LTA', 'INVALID', {
        policy,
        validationTime: epoch + 80,
        knowledgeTime: epoch + 80,
      });
    },
  );
test('accuracy upper bound equal to a protection deadline is too late', selected, () => {
  const renewed = f.augment(api, original.lta, 'LTA', {
    at: epoch + 49,
    accuracy: 1,
    authority: f.successor,
  }).cms;
  const policy = f.policy();
  policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')] = epoch + 50;
  verify(renewed, 'LTA', 'INVALID', {
    policy,
    validationTime: epoch + 80,
    knowledgeTime: epoch + 80,
  });
});
test(
  'SHA512 archive imprint does not rescue the latest TSA SHA256 CMS after SHA256 retirement',
  selected,
  () => {
    const renewed = f.augment(api, original.lta, 'LTA', {
      at: epoch + 60,
      authority: f.successor,
      hashOID: O.sha512,
    }).cms;
    const policy = f.policy();
    policy.hashDeadlines[O.sha256] = epoch + 70;
    verify(renewed, 'LTA', 'INVALID', {
      policy,
      validationTime: epoch + 80,
      knowledgeTime: epoch + 80,
    });
  },
);
test(
  'missing finite key protection cutoff is not silently replaced with Infinity',
  selected,
  () => {
    const policy = f.policy();
    delete policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')];
    verify(original.lta, 'LTA', 'INDETERMINATE', { policy });
  },
);
test('trailing or truncated DER is a typed INVALID result', selected, () => {
  verify(Buffer.concat([original.b, Buffer.from([0])]), 'B', 'INVALID');
  verify(original.b.subarray(0, original.b.length - 1), 'B', 'INVALID');
});
