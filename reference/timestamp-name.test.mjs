import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, X509Certificate, verify } from 'node:crypto';
import { parseDER, der, oidText } from './core.mjs';
import { OID } from './pki.mjs';
import { parseTSTInfo, verifyTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(
    readFileSync(new URL('./vectors/timestamp-name-contract.json', import.meta.url), 'utf8'),
  ),
  bytes = (value) => Buffer.from(value, 'base64'),
  hash = (raw) => createHash('sha256').update(raw).digest('hex'),
  roots = Object.fromEntries(
    Object.entries(vectors.roots).map(([id, raw]) => [
      id,
      createPublicKey({ key: bytes(raw), format: 'der', type: 'spki' }),
    ]),
  ),
  query = {
    ...vectors.query,
    imprint: bytes(vectors.query.imprint),
    nonce: BigInt(vectors.query.nonce),
  };

test('RFC3161 timestamp admission corpus binds exact signed bytes and independent certificate controls', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'rfc3161-tstinfo-admission');
  assert.equal(vectors.cases.length, 42);
  assert.equal(new Set(vectors.cases.map((row) => row.id)).size, 42);
  for (const entry of Object.values(vectors.certificates)) {
    const raw = bytes(entry.raw),
      cert = new X509Certificate(raw);
    assert.equal(hash(raw), entry.sha256);
    assert(cert.verify(roots.issuer));
    assert(!cert.verify(roots.other));
  }
  for (const row of vectors.cases) {
    const raw = bytes(row.raw),
      sd = parseDER(raw).children[1].children[0].children,
      signer = sd.at(-1).children[0].children,
      tbs = der(0x31, signer[3].value),
      cert = new X509Certificate(bytes(vectors.certificates[row.certificate].raw));
    assert.equal(hash(raw), row.sha256, row.id);
    assert.deepEqual(sd[2].children[1].children[0].value, bytes(row.tstInfo), row.id);
    assert.deepEqual(tbs, bytes(row.signedAttributes), row.id);
    assert.deepEqual(signer[5].value, bytes(row.signature), row.id);
    assert.equal(verify(null, tbs, cert.publicKey, signer[5].value), row.signatureValid, row.id);
    assert.equal(row.signatureValid, !row.id.endsWith('signature-tamper'), row.id);
    const digest = signer[3].children.find(
      (attribute) => oidText(attribute.children[0]) === OID.messageDigest,
    ).children[1].children[0].value;
    assert.equal(
      digest.equals(createHash('sha512').update(bytes(row.tstInfo)).digest()),
      !row.id.endsWith('content-tamper'),
      row.id,
    );
  }
  const subject = vectors.cases.find((row) => row.id === 'subject-directory-name'),
    mismatch = vectors.cases.find((row) => row.id === 'different-directory-name');
  assert.deepEqual(
    parseDER(bytes(subject.tstInfo))
      .children.slice(0, 7)
      .map((node) => node.raw),
    parseDER(bytes(mismatch.tstInfo))
      .children.slice(0, 7)
      .map((node) => node.raw),
  );
  const tsaField = parseDER(bytes(subject.tstInfo)).children.at(-1).raw;
  const extra = vectors.cases.find(
      (row) => row.id === 'directory-name-only-in-another-certificate',
    ),
    extraSD = parseDER(bytes(extra.raw)).children[1].children[0].children,
    certSet = extraSD.find((node) => node.tag === 0xa0).children.map((node) => node.raw),
    ess = extraSD
      .at(-1)
      .children[0].children[3].children.find(
        (attribute) => oidText(attribute.children[0]) === OID.ess,
      );
  assert.equal(certSet.length, 2);
  for (const id of ['subject', 'san'])
    assert(certSet.some((raw) => raw.equals(bytes(vectors.certificates[id].raw))));
  assert.deepEqual(
    ess.children[1].children[0].children[0].children[0].children[1].value,
    createHash('sha512').update(bytes(vectors.certificates.subject.raw)).digest(),
  );
  assert.deepEqual(parseTSTInfo(bytes(subject.tstInfo)).tsaName, tsaField);
  assert.equal(
    parseTSTInfo(bytes(vectors.cases.find((row) => row.id === 'absent-name').tstInfo)).tsaName,
    undefined,
  );
  const ordered = parseDER(
    bytes(vectors.cases.find((row) => row.id === 'ordered-optional-fields').tstInfo),
  ).children;
  assert.deepEqual(
    ordered.slice(5).map((node) => node.tag),
    [0x30, 1, 2, 0xa0],
  );
  for (const row of vectors.cases.filter((row) => row.expected.code === 'TST_FIELD_ORDER')) {
    const fields = parseDER(bytes(row.tstInfo)).children;
    assert.deepEqual(
      fields.slice(0, 5).map((node) => node.raw),
      ordered.slice(0, 5).map((node) => node.raw),
    );
    assert.deepEqual(
      fields
        .slice(5)
        .map((node) => node.raw.toString('hex'))
        .sort(),
      ordered
        .slice(5)
        .map((node) => node.raw.toString('hex'))
        .sort(),
    );
    assert.notDeepEqual(
      fields.slice(5).map((node) => node.tag),
      [0x30, 1, 2, 0xa0],
    );
  }
});

for (const profile of ['CERTCONCORD-PQ', 'EXTERNAL-RFC3161'])
  for (const row of vectors.cases)
    test(`RFC3161 timestamp admission ${profile} raw vector: ${row.id}`, () => {
      const expected = row.expected[profile] ?? row.expected,
        operation = () =>
          verifyTimestampToken(bytes(row.raw), {
            ...query,
            certificate: bytes(vectors.certificates[row.certificate].raw),
            issuerKey: roots[row.query?.issuer ?? 'issuer'],
            signatureProfile: profile,
          });
      if (expected.overall === 'VALID') {
        const info = operation();
        assert.equal(info.serial, 1001n);
        assert.equal(info.genTime, query.at - 2);
        assert.equal(info.poeUpperBound, query.at - 1);
        assert.deepEqual(info.imprint, query.imprint);
        assert.equal(info.nonce, query.nonce);
      } else {
        assert.throws(operation, (error) => {
          assert.equal(error.code, expected.code);
          assert.equal(error.overall ?? 'INVALID', expected.overall);
          return true;
        });
      }
    });
