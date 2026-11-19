import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { der, keyID, oid, oidText, parseDER, seq, set, verify } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';
import { verifyCAdES } from './cades.mjs';
import { cmsView, O, epoch } from './cades-fixtures.mjs';

const bytes = readFileSync(new URL('./vectors/cades-ess-sha384.json', import.meta.url));
assert.equal(
  createHash('sha256').update(bytes).digest('hex'),
  '2defc4714b3261e15f68e2ff0c412b108b18d35d005f111049bffb6bfa60b05b',
);
const vectors = JSON.parse(bytes);
assert.equal(vectors.schema, 'certconcord.cades-esscertidv2-sha384.v1');
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
const load = (entry) => {
  const raw = Buffer.from(entry.base64, 'base64');
  assert.equal(raw.length, entry.bytes);
  assert.equal(sha(raw), entry.sha256);
  return raw;
};
const fixture = Object.fromEntries(
  Object.entries(vectors.fixture).map(([name, entry]) => [name, load(entry)]),
);
const signed = Object.fromEntries(
  Object.entries(vectors.signedCMS).map(([name, entry]) => [name, load(entry)]),
);
const essAttribute = Object.fromEntries(
  Object.entries(vectors.signedESSAttributes).map(([name, entry]) => [name, load(entry)]),
);
const sha384 = '2.16.840.1.101.3.4.2.2';
const essOID = '1.2.840.113549.1.9.16.2.47';
const signer = new X509Certificate(fixture.signerCertificate);
const root = new X509Certificate(fixture.rootCertificate);

const policy = (includeSHA384Deadline = true) => {
  const domain = Buffer.alloc(32, 0x91);
  const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
  const status = {
    authorityID: keyID(root.publicKey),
    trustDomainID: domain,
    scope: 'AUTHORITY',
    status: 'GOOD',
    publishedAt: epoch - 100,
    nextUpdate: epoch + 100000,
  };
  const authorityResolver = createAuthorityResolver({
    trustDomainID: domain,
    authorities: [
      {
        mode: 'CERTIFICATE',
        certificate: fixture.rootCertificate,
        knownAt: epoch - 100,
        validFrom: epoch - 100,
        validUntil: epoch + 100000,
        roles: ['ISSUER', 'STATUS_AUTHORITY'],
        scopes: [scope],
        status,
      },
    ],
  });
  return {
    trustedRoots: [fixture.rootCertificate],
    authorityResolver,
    scope,
    algorithmDeadlines: { [O.es256]: epoch + 100000 },
    hashDeadlines: {
      [O.sha256]: epoch + 100000,
      [O.sha512]: epoch + 100000,
      ...(includeSHA384Deadline ? { [sha384]: epoch + 100000 } : {}),
    },
    keyDeadlines: {
      [keyID(signer.publicKey).toString('hex')]: epoch + 100000,
      [keyID(root.publicKey).toString('hex')]: epoch + 100000,
    },
    timestampPolicies: [O.policy],
    currentMaterial: {
      certificates: [fixture.signerCertificate, fixture.rootCertificate],
      crls: [fixture.crl],
    },
  };
};
const checkB = (cms, selectedPolicy = policy()) => {
  const verdict = verifyCAdES(cms, {
    content: fixture.document,
    minimumLevel: 'B',
    validationTime: epoch + 40,
    knowledgeTime: epoch + 40,
    policy: selectedPolicy,
  });
  return {
    overall: verdict.overall,
    reason: verdict.reason,
    verifiedLevel: verdict.verifiedLevel ?? null,
  };
};

test('frozen signed CMS keeps the signer, content and mathematical signature', () => {
  assert(root.verify(root.publicKey));
  assert(signer.verify(root.publicKey));
  const baseline = cmsView(signed.baselineSHA256);
  const correctHash = createHash('sha384').update(fixture.signerCertificate).digest();
  const wrongHash = Buffer.from(correctHash);
  wrongHash[0] ^= 1;
  for (const [name, cms] of Object.entries(signed)) {
    const view = cmsView(cms);
    assert.equal(view.embeddedContent, undefined);
    assert(view.fields[1].raw.equals(baseline.fields[1].raw));
    assert(view.certificates.some((node) => node.raw.equals(fixture.signerCertificate)));
    assert(view.certificates.some((node) => node.raw.equals(fixture.rootCertificate)));
    assert(verify(der(0x31, view.fields[3].value), view.signature, signer.publicKey));
    if (name === 'baselineSHA256') continue;
    const entry = view.signed.find((node) => oidText(node.children[0]) === essOID);
    assert(entry?.raw.equals(essAttribute[name]));
    const id = entry.children[1].children[0].children[0].children[0];
    assert.equal(oidText(id.children[0].children[0]), sha384);
    if (name === 'correctSHA384' || name === 'wrongSHA384')
      assert.equal(id.children[0].children.length, 1); // absent parameters
    else {
      assert.equal(id.children[0].children.length, 2);
      assert.equal(
        id.children[0].children[1].raw.toString('hex'),
        name === 'sha384Null' ? '0500' : '0400',
      );
    }
    assert(id.children[1].value.equals(name === 'wrongSHA384' ? wrongHash : correctHash));
    const attrs = view.signed.map((node) => ({ id: oidText(node.children[0]), raw: node.raw }));
    const original = baseline.signed.map((node) => ({
      id: oidText(node.children[0]),
      raw: node.raw,
    }));
    assert(
      attrs.every(
        (row, index) =>
          row.id === original[index].id &&
          (row.id === essOID || row.raw.equals(original[index].raw)),
      ),
    );
  }
});

test('explicit SHA-384 ESS binding accepts the signer and rejects a signed wrong hash', () => {
  for (const name of ['baselineSHA256', 'correctSHA384', 'wrongSHA384']) {
    const expected = vectors.expected[name];
    assert.deepEqual(checkB(signed[name]), expected, name);
  }
});

test('signed SHA-384 NULL parameters are accepted and malformed parameters rejected', () => {
  for (const name of ['sha384Null', 'sha384MalformedParams'])
    assert.deepEqual(checkB(signed[name]), vectors.expected[name], name);
});

test('SHA-384 ESS acceptance requires its own finite caller deadline', () => {
  const verdict = checkB(signed.correctSHA384, policy(false));
  assert.deepEqual(verdict, {
    overall: 'INDETERMINATE',
    reason: 'CADES_HASH_DEADLINE_MISSING',
    verifiedLevel: null,
  });
});

test('SHA-384 ESS admission does not add SHA-384 SignerInfo digest support', () => {
  const contentInfo = parseDER(signed.correctSHA384);
  const signedData = contentInfo.children[1].children[0];
  const fields = signedData.children.map((node) => node.raw);
  const signerInfo = signedData.children.at(-1).children[0];
  const signerFields = signerInfo.children.map((node) => node.raw);
  signerFields[2] = seq(oid(sha384));
  fields[1] = set(seq(oid(sha384)));
  fields[fields.length - 1] = set(seq(...signerFields));
  const modified = seq(contentInfo.children[0].raw, der(0xa0, seq(...fields)));
  const verdict = inspectAdESSignature(modified, { content: fixture.document, profile: 'CADES' });
  assert.equal(verdict.overall, 'UNSUPPORTED');
  assert.equal(verdict.reason, 'CADES_HASH_UNSUPPORTED');
});

test('other inspection profiles retain their SHA-384 ESS boundary', () => {
  for (const profile of ['PADES', 'SMIME', 'RFC3161']) {
    const verdict = inspectAdESSignature(signed.correctSHA384, {
      content: fixture.document,
      profile,
    });
    assert(
      verdict.failures.some((failure) => failure.reason === 'CADES_HASH_UNSUPPORTED'),
      profile,
    );
  }
});
