import test, { before, after } from 'node:test';
import { createHash } from 'node:crypto';
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
  replaceUnsigned,
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
const requestT = () => ({
  hashOID: O.sha256,
  imprint: hash(cmsView(original.b).signature),
  policy: O.policy,
  nonce: 151n,
});
const attachT = (token) => replaceUnsigned(original.b, O.signatureTimestamp, [token]);

test(
  'historical validation cannot authenticate an uncovered timestamp after current TSA key protection ends',
  selected,
  () => {
    const policy = f.policy();
    policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')] = epoch + 50;
    verify(original.t, 'T', 'VALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 40,
    });
    verify(original.t, 'T', 'INVALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 200,
    });
  },
);
test(
  'historical B validation cannot authenticate an unprotected document signature after current signer key cutoff',
  selected,
  () => {
    const policy = f.policy();
    policy.keyDeadlines[c.keyID(f.signer.publicKey).toString('hex')] = epoch + 50;
    verify(original.b, 'B', 'VALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 40,
    });
    verify(original.b, 'B', 'INVALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 200,
    });
    verify(original.t, 'T', 'VALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 200,
    });
  },
);
test(
  'a timely later archive may authenticate proof for an earlier validationTime',
  selected,
  () => {
    const policy = f.policy();
    policy.keyDeadlines[c.keyID(f.tsa.publicKey).toString('hex')] = epoch + 100;
    const renewed = f.augment(api, original.lta, 'LTA', {
      at: epoch + 80,
      authority: f.successor,
    }).cms;
    verify(renewed, 'T', 'VALID', {
      policy,
      validationTime: epoch + 40,
      knowledgeTime: epoch + 200,
    });
  },
);
test(
  'signature timestamp after the historical validationTime cannot establish earlier existence',
  selected,
  () => {
    verify(original.t, 'T', 'INDETERMINATE', {
      validationTime: epoch + 19,
      knowledgeTime: epoch + 200,
    });
  },
);

test('valid ES256 TSA with SHA384 message imprint is recognized but unsupported', selected, () => {
  const token = f.token(requestT(), {
    hashOID: '2.16.840.1.101.3.4.2.2',
    imprint: createHash('sha384').update(cmsView(original.b).signature).digest(),
  });
  verify(attachT(token), 'T', 'UNSUPPORTED');
});
test('invalid TSA signature outranks an unsupported SHA384 message imprint', selected, () => {
  const token = f.token(requestT(), {
    hashOID: '2.16.840.1.101.3.4.2.2',
    imprint: createHash('sha384').update(cmsView(original.b).signature).digest(),
  });
  const signature = Buffer.from(cmsView(token).signature);
  signature[signature.length - 1] ^= 1;
  verify(attachT(rewriteCMS(token, { signature })), 'T', 'INVALID');
});

test('B after ordinary signer expiry without historical proof is INDETERMINATE', selected, () => {
  verify(original.b, 'B', 'INDETERMINATE', {
    validationTime: epoch + 200,
    knowledgeTime: epoch + 200,
  });
});
test('B before certificate notBefore without historical proof is INDETERMINATE', selected, () => {
  const future = f.certificate('Future Document', {
    issuer: f.root,
    notBefore: epoch + 80,
    notAfter: epoch + 500,
  });
  const prepared = api.prepareCAdESSignature({
    content: f.content,
    certificate: future.der,
    certificates: [f.root.der],
    detached: true,
    signingTime: epoch + 10,
  });
  const cms = prepared.finish(c.sign(prepared.tbs, future.privateKey)),
    policy = f.policy();
  policy.keyDeadlines[c.keyID(future.publicKey).toString('hex')] = epoch + 10000;
  verify(cms, 'B', 'INDETERMINATE', { policy });
});
test('expired B uncertainty cannot hide an invalid signature', selected, () => {
  const signature = Buffer.from(cmsView(original.b).signature);
  signature[signature.length - 1] ^= 1;
  verify(rewriteCMS(original.b, { signature }), 'B', 'INVALID', {
    validationTime: epoch + 200,
    knowledgeTime: epoch + 200,
  });
});
test('expired B uncertainty cannot hide known applicable certificate revocation', selected, () => {
  const status = f.crl({ entries: [{ revokedAt: epoch + 5 }], nextUpdate: epoch + 1000 });
  verify(original.b, 'B', 'INVALID', {
    validationTime: epoch + 200,
    knowledgeTime: epoch + 200,
    policy: f.policy({ currentMaterial: f.material(status) }),
  });
});

for (const variant of [
  'root tag',
  'MessageImprint tag',
  'hashedMessage tag',
  'zero serial',
  'optional field order',
])
  test(`valid TSA CMS signature cannot authenticate malformed TSTInfo ${variant}`, selected, () => {
    const mutateTSTInfo = (raw) => {
      const node = c.parseDER(raw),
        parts = node.children.map((n) => n.raw);
      if (variant === 'root tag') return c.der(0xa0, node.value);
      if (variant === 'MessageImprint tag') parts[2] = c.der(0xa0, node.children[2].value);
      if (variant === 'hashedMessage tag')
        parts[2] = c.seq(
          node.children[2].children[0].raw,
          c.der(0x0c, node.children[2].children[1].value),
        );
      if (variant === 'zero serial') parts[3] = c.integer(0);
      if (variant === 'optional field order') [parts[5], parts[6]] = [parts[6], parts[5]];
      return c.seq(...parts);
    };
    verify(attachT(f.token(requestT(), { mutateTSTInfo })), 'T', 'INVALID');
  });
test(
  'recognized TSTInfo extensions are explicitly unsupported in the selected timestamp subset',
  selected,
  () => {
    const token = f.token(requestT(), {
      mutateTSTInfo: (raw) =>
        c.seq(
          ...c.parseDER(raw).children.map((n) => n.raw),
          c.der(
            0xa1,
            p.extension('1.3.6.1.4.1.55555.91.98', c.octet(Buffer.from('opaque extension'))),
          ),
        ),
    });
    verify(attachT(token), 'T', 'UNSUPPORTED');
  },
);

test(
  'originalCMS guard preserves individual unsigned values while allowing a new value in the same Attribute',
  selected,
  () => {
    const id = '1.3.6.1.4.1.55555.91.99',
      a = c.octet(Buffer.from('retained A')),
      b = c.octet(Buffer.from('later B'));
    const originalCMS = rewriteCMS(original.b, { unsigned: [attr(id, a)] });
    const added = rewriteCMS(originalCMS, { unsigned: [attr(id, a, b)] });
    verify(added, 'B', 'VALID', { originalCMS });
    verify(rewriteCMS(originalCMS, { unsigned: [attr(id, b)] }), 'B', 'INVALID', { originalCMS });
  },
);
test(
  'archive index retains an old unsigned value after another value is added to its Attribute',
  selected,
  () => {
    const id = '1.3.6.1.4.1.55555.91.99',
      a = c.octet(Buffer.from('indexed A')),
      b = c.octet(Buffer.from('unindexed B'));
    const lt = rewriteCMS(original.lt, {
      unsigned: [...cmsView(original.lt).unsigned.map((n) => n.raw), attr(id, a)],
    });
    const archived = f.augment(api, lt, 'LTA', { at: epoch + 30 }).cms;
    const appended = replaceUnsigned(archived, id, [a, b]);
    verify(appended, 'LT', 'VALID', { originalCMS: archived });
    verify(appended, 'LTA', 'INDETERMINATE', { originalCMS: archived });
    verify(replaceUnsigned(archived, id, [b]), 'LT', 'INVALID', { originalCMS: archived });
  },
);
