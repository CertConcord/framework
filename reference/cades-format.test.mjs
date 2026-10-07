import test, { before, after } from 'node:test';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { issueOCSP, ocspRequest } from './revocation.mjs';
import {
  O,
  epoch,
  fixture,
  attr,
  cmsView,
  rewriteCMS,
  resign,
  loadCAdES,
  absentCapability,
  decision,
  expectOverall,
} from './cades-fixtures.mjs';

const api = await loadCAdES(),
  selected = { skip: !api && absentCapability };
let f, base;
before(() => {
  if (api) {
    f = fixture();
    base = f.baseCMS(api);
  }
});
after(() => f?.close());

function attributeCertificate(version) {
  // RFC5652 AttributeCertificateV1 and RFC3281 AttributeCertificateV2 shapes.
  // These are signed, structurally encoded unsupported choices, not a claim of
  // implementing attribute-certificate trust or an authorization profile.
  const names = (name) => c.seq(c.der(0xa4, name));
  const subject = names(f.signer.cert.subject),
    issuer = names(f.root.cert.subject);
  const algorithm = c.seq(c.oid(O.es256));
  const prefix =
    version === 1
      ? [c.der(0xa1, c.parseDER(subject).value), issuer]
      : [c.integer(1), c.seq(c.der(0xa1, c.parseDER(subject).value)), c.der(0xa0, issuer)];
  const info = c.seq(
    ...prefix,
    algorithm,
    c.integer(101),
    c.seq(p.generalizedTime(epoch - 10), p.generalizedTime(epoch + 100)),
    c.seq(attr('1.3.6.1.4.1.55555.91.100', c.der(12, Buffer.from('synthetic role')))),
  );
  return c.der(
    version === 1 ? 0xa1 : 0xa2,
    c.parseDER(c.seq(info, algorithm, c.bit(c.sign(info, f.root.privateKey)))).value,
  );
}

function variant(kind, { wrongVersion = false, badSignature = false } = {}) {
  let cms = base,
    version;
  if (kind === 'OCSP other revocation info') {
    const request = ocspRequest(
      {
        issuer: f.root.cert.subject,
        issuerPublicKey: f.root.publicKey,
        serial: f.signer.cert.serial,
      },
      { nonce: Buffer.alloc(16, 7) },
    );
    const response = issueOCSP(request.raw, {
      issuer: f.root.cert.subject,
      issuerPublicKey: f.root.publicKey,
      privateKey: f.root.privateKey,
      records: new Map([[f.signer.cert.serial.toString(), { status: 'GOOD' }]]),
      thisUpdate: epoch,
      nextUpdate: epoch + 1000,
    });
    const choice = c.der(0xa1, c.parseDER(c.seq(c.oid('1.3.6.1.5.5.7.16.2'), response)).value);
    cms = rewriteCMS(cms, { crls: [choice] });
    version = 5;
  } else if (kind === 'other certificate') {
    const choice = c.der(
      0xa3,
      c.parseDER(
        c.seq(
          c.oid('1.3.6.1.4.1.55555.91.101'),
          c.octet(Buffer.from('unselected certificate format')),
        ),
      ).value,
    );
    cms = rewriteCMS(cms, { certificates: [f.root.der, f.signer.der, choice] });
    version = 5;
  } else if (kind.startsWith('attribute certificate')) {
    const acVersion = kind.endsWith('v1') ? 1 : 2;
    cms = rewriteCMS(cms, {
      certificates: [f.root.der, f.signer.der, attributeCertificate(acVersion)],
    });
    version = acVersion === 1 ? 3 : 4;
  } else if (kind === 'non-id-data content') {
    const type = '1.3.6.1.4.1.55555.91.102';
    cms = rewriteCMS(cms, { contentType: type });
    cms = resign(
      cms,
      cmsView(cms).signed.map((a) =>
        c.oidText(a.children[0]) === O.contentType ? attr(O.contentType, c.oid(type)) : a.raw,
      ),
      f.signer.privateKey,
    );
    version = 3;
  } else version = 3;
  const v = cmsView(cms),
    fields = v.fields.map((n) => n.raw);
  if (kind === 'SKI SignerIdentifier') {
    fields[0] = c.integer(3);
    fields[1] = c.der(0x80, c.parseDER(f.signer.cert.extensions.get('2.5.29.14').value).value);
  }
  if (badSignature) {
    const signature = Buffer.from(v.signature);
    signature[signature.length - 1] ^= 1;
    fields[5] = c.octet(signature);
  }
  const sd = v.sd.children.map((n) => n.raw);
  sd[0] = c.integer(wrongVersion ? 1 : version);
  sd[sd.length - 1] = c.set(c.seq(...fields));
  return c.seq(c.oid(O.signedData), c.der(0xa0, c.seq(...sd)));
}

for (const kind of [
  'OCSP other revocation info',
  'other certificate',
  'attribute certificate v1',
  'attribute certificate v2',
  'SKI SignerIdentifier',
  'non-id-data content',
]) {
  test(`recognized ${kind} with RFC5652-derived version is UNSUPPORTED`, selected, () => {
    expectOverall(decision(api, f, variant(kind)), 'UNSUPPORTED');
  });
  test(`${kind} with an incorrect lower SignedData version is INVALID`, selected, () => {
    expectOverall(decision(api, f, variant(kind, { wrongVersion: true })), 'INVALID');
  });
  test(`available invalid signature outranks recognized ${kind}`, selected, () => {
    expectOverall(decision(api, f, variant(kind, { badSignature: true })), 'INVALID');
  });
}
