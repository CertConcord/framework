import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as a from './archive.mjs';
import { Journal } from './state.mjs';

const namespace = 'urn:ietf:params:xml:ns:ers';
const start = 1800000000;

function fixture(t, { notBefore = start - 10, notAfter = start + 10000 } = {}) {
  const root = c.generate('ml-dsa-87'),
    key = c.generate('ml-dsa-87'),
    journal = new Journal(),
    policy = '1.3.6.1.4.1.32473.90.2',
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        serial: 1,
        issuer: p.name('XMLERS test root'),
        subject: p.name('XMLERS test TSA'),
        profileID: 'CERTCONCORD-TSA-v1',
        notBefore,
        notAfter,
      },
      root.privateKey,
    );
  let clock = start;
  const authority = new a.TimestampAuthority({
    certificate,
    privateKey: key.privateKey,
    policy,
    journal,
    clock: () => clock,
    accuracySeconds: 0,
  });
  t.after(() => journal.close());
  return {
    trust: {
      certificate,
      issuerKey: root.publicKey,
      policy,
      validUntil: notAfter,
      status: () => true,
    },
    clock: (at) => {
      clock = at;
    },
    accuracy: (seconds) => {
      authority.accuracySeconds = seconds;
    },
    tsa: async (imprint, hashOID) =>
      a.tokenFromResponse(authority.issue(a.timestampRequest(imprint, { hashOID, policy }).der)),
  };
}

function qualify(xml, name, uri) {
  return xml
    .replace(
      new RegExp('<' + name + '(?=[ >])'),
      '<selected:' + name + ' xmlns:selected="' + uri + '"',
    )
    .replace('</' + name + '>', '</selected:' + name + '>');
}

for (const name of [
  'ArchiveTimeStampChain',
  'ArchiveTimeStamp',
  'HashTree',
  'Sequence',
  'DigestValue',
]) {
  test(`XMLERS rejects a foreign namespace on ${name}`, async (t) => {
    const f = fixture(t),
      data = Buffer.from('Namespace-bound archive object');
    let record = await a.createXMLERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
    if (['HashTree', 'Sequence', 'DigestValue'].includes(name))
      record = record.replace(
        '<TimeStamp>',
        '<HashTree><Sequence Order="1"><DigestValue>' +
          c.sha256(data).toString('base64') +
          '</DigestValue></Sequence></HashTree><TimeStamp>',
      );
    const trust = { ...f.trust, at: start + 1000 };
    const expected = {
      chains: 1,
      poeUpperBound: start,
      integrity: 'VALID',
      preservation: 'NOT_EVALUATED',
    };
    assert.deepEqual(a.verifyXMLERS(record, data, trust), expected);
    assert.deepEqual(a.verifyXMLERS(qualify(record, name, namespace), data, trust), expected);
    assert.throws(() => a.verifyXMLERS(qualify(record, name, 'urn:foreign:xmlers'), data, trust), {
      code: 'XMLERS_NAMESPACE',
    });
  });
}

test('XMLERS accepts 64 timestamps in a chain and rejects a genuine 65th renewal', async (t) => {
  const f = fixture(t),
    data = Buffer.from('Bounded archive timestamp chain'),
    trust = { ...f.trust, at: start + 1000 };
  let record = await a.createXMLERS(data, { tsa: f.tsa });
  for (let i = 1; i < 64; i++) record = await a.renewXMLERS(record, data, { tsa: f.tsa });
  assert.equal(a.verifyXMLERS(record, data, trust).integrity, 'VALID');
  const extra = await a.renewXMLERS(record, data, { tsa: f.tsa });
  assert.throws(() => a.verifyXMLERS(extra, data, trust), { code: 'XMLERS_STAMP_LIMIT' });
});
