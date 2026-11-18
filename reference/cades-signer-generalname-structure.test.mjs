import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyID, oidText, parseDER } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';
import { cmsView } from './cades-fixtures.mjs';

const raw = readFileSync(new URL('./vectors/cades-signer-generalname-structure.json', import.meta.url));
assert.equal(createHash('sha256').update(raw).digest('hex'),
  'b0bcee6070b6745eb54071e30403506816e5a1abef68f53e6e595638fb378383');
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.cades-signer-generalname-structure.v1');
assert.equal(vectors.baseMain, '7bfccab63fe43ec9411bb9302fe6f8444bd8aaad');
const decode = entry => {
  const bytes = Buffer.from(entry.derBase64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  return bytes;
};

for (const [name, variant] of Object.entries(vectors.cases))
  test(`CAdES B admits the signed ${name} control and rejects its structural mutation`, () => {
    const root = decode(variant.fixture.root);
    const document = decode(variant.fixture.document);
    const crl = decode(variant.fixture.crl);
    const rootKey = new X509Certificate(root).publicKey;
    const rootID = keyID(rootKey).toString('hex');
    const domain = Buffer.alloc(32, 0x91);
    const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
    const deadline = vectors.epoch + 100000;
    const authorityResolver = createAuthorityResolver({ trustDomainID: domain,
      authorities: [{ mode: 'CERTIFICATE', certificate: root,
        knownAt: vectors.epoch - 100, validFrom: vectors.epoch - 100, validUntil: deadline,
        roles: ['ISSUER', 'STATUS_AUTHORITY'], scopes: [scope],
        status: { authorityID: Buffer.from(rootID, 'hex'), trustDomainID: domain,
          scope: 'AUTHORITY', status: 'GOOD', publishedAt: vectors.epoch - 100,
          nextUpdate: deadline } }] });
    const positiveTBS = decode(variant.positive.tbs);
    const negativeTBS = decode(variant.negative.tbs);
    assert.equal(positiveTBS.length, negativeTBS.length);
    const changed = [...positiveTBS.keys()].filter(i => positiveTBS[i] !== negativeTBS[i]);
    assert.deepEqual(changed, [variant.tbsDifferenceOffset]);
    assert.equal(positiveTBS[changed[0]], variant.positiveTag);
    assert.equal(negativeTBS[changed[0]], variant.negativeTag);
    for (const [kind, expectedOverall, expectedReason] of [
      ['positive', 'VALID', 'CADES_VALID'],
      ['negative', 'INVALID', variant.negativeReason],
    ]) {
      const certificate = decode(variant[kind].certificate);
      const cms = decode(variant[kind].cms);
      const x509 = new X509Certificate(certificate);
      assert(x509.verify(rootKey), `${name}/${kind} issuer signature`);
      const parsed = parseDER(certificate);
      assert(parsed.children[0].raw.equals(decode(variant[kind].tbs)));
      const extensions = parsed.children[0].children.at(-1).children[0].children;
      assert(extensions.some(ext => oidText(ext.children[0]) === variant.extensionOID));
      const view = cmsView(cms);
      assert(view.certificates.some(cert => cert.raw.equals(certificate)));
      assert(view.certificates.some(cert => cert.raw.equals(root)));
      const signerID = keyID(x509.publicKey).toString('hex');
      const policy = { trustedRoots: [root], authorityResolver, scope,
        algorithmDeadlines: { '1.2.840.10045.4.3.2': deadline },
        hashDeadlines: { '2.16.840.1.101.3.4.2.1': deadline,
          '2.16.840.1.101.3.4.2.3': deadline },
        keyDeadlines: { [signerID]: deadline, [rootID]: deadline },
        timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
        currentMaterial: { certificates: [certificate, root], crls: [crl] } };
      const result = verifyCAdES(cms, { content: document, minimumLevel: 'B',
        validationTime: vectors.epoch + 40, knowledgeTime: vectors.epoch + 40, policy });
      assert.equal(result.overall, expectedOverall, `${name}/${kind}: ${JSON.stringify(result.checks)}`);
      assert.equal(result.reason, expectedReason, `${name}/${kind}: ${JSON.stringify(result.checks)}`);
      if (kind === 'positive') assert.equal(result.verifiedLevel, 'B');
    }
  });
