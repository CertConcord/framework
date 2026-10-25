import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { parseDER, seq, integer } from './core.mjs';
import { algID, OID, verifyCMS } from './pki.mjs';
import { parseTSTInfo, renewERS } from './archive.mjs';

const observations = JSON.parse(
  readFileSync(new URL('../tools/ers-bc186/observed.json', import.meta.url)),
);
const diagnostic = observations.find((row) => row.diagnostic);
const hash = (algorithm, bytes) => createHash(algorithm).update(bytes).digest();
const read = (sha, suffix) => {
  const bytes = Buffer.from(
    readFileSync(
      new URL('./vectors/cms-retirement-mtc07-rar2/files/' + sha + suffix, import.meta.url),
      'utf8',
    ),
    'base64',
  );
  assert.equal(hash('sha256', bytes).toString('hex'), sha);
  return bytes;
};
const original = read(
  '09e93450939c93b3dce9daa2ab8f278a357701b46d2d93f0c4fba3c9a0839133',
  '.cbor.b64',
);
const timely = read('148c25cb9fb9c16846eb14ece6bc8927bdf442444d7ff76168b680236b343050', '.der.b64');
const chains = parseDER(timely).children[2].children;
const prefix = (count) =>
  seq(
    integer(1),
    seq(algID(OID.sha256)),
    seq(seq(...chains[0].children.slice(0, count).map((n) => n.raw))),
  );
const tokens = chains.flatMap((chain) => chain.children.map((stamp) => stamp.children.at(-1).raw));

test('BC 1.86 observations bind exact original, ERS prefixes and mutation bytes', () => {
  const initial = read(
    '456167c872b5e60e7ed55e199924cf460bea3dd4fb6e91cca80c8f009b219040',
    '.der.b64',
  );
  const late = read('6a3851994afc0cf36df9ae9668c7ed04b54426fe47deec89d148cfb4086b3230', '.der.b64');
  assert.equal(original.length, 114435);
  assert.equal(timely.length, 37979);
  assert.deepEqual(prefix(1), initial);
  const corrupt = Buffer.from(timely),
    changed = Buffer.from(original);
  corrupt[corrupt.length - 1] ^= 1;
  changed[changed.length - 1] ^= 1;
  const inputs = [
    [original, initial],
    [original, prefix(2)],
    [original, timely],
    [original, late],
    [original, corrupt],
    [changed, initial],
    [original, timely.subarray(0, -1)],
    [changed, timely],
  ];
  for (let i = 0; i < inputs.length; i++) {
    assert.equal(hash('sha256', inputs[i][0]).toString('hex'), observations[i].dataSHA256);
    assert.equal(hash('sha256', inputs[i][1]).toString('hex'), observations[i].recordSHA256);
  }
  const changedTokens = parseDER(corrupt).children[2].children.flatMap((chain) =>
    chain.children.map((stamp) => stamp.children.at(-1).raw),
  );
  assert.deepEqual(changedTokens.slice(0, 2), tokens.slice(0, 2));
  assert.throws(() => verifyCMS(changedTokens[2], { expectedContentType: OID.tstInfo }));
});

test('fixed ERS imprint distinguishes binary sorting from BC data-then-chain order', () => {
  const dataHash = hash('sha512', original);
  const chainHash = hash('sha512', seq(chains[0].raw));
  const sorted = hash('sha512', Buffer.concat([dataHash, chainHash].sort(Buffer.compare)));
  const ordered = hash('sha512', Buffer.concat([dataHash, chainHash]));
  assert.equal(dataHash.toString('hex'), diagnostic.dataSHA512);
  assert.equal(chainHash.toString('hex'), diagnostic.previousSequenceSHA512);
  assert.equal(sorted.toString('hex'), diagnostic.sortedPairSHA512);
  assert.equal(ordered.toString('hex'), diagnostic.dataThenChainSHA512);
  assert.equal(ordered.toString('hex'), diagnostic.bcERSByteDataHash);
  assert.notDeepEqual(sorted, ordered);
  const verified = tokens.map((token) =>
    parseTSTInfo(verifyCMS(token, { expectedContentType: OID.tstInfo }).content),
  );
  assert.equal(verified.length, 3);
  assert.equal(verified[2].imprint.toString('hex'), diagnostic.observedImprint);
  assert.equal(verified[2].imprint.toString('hex'), sorted.toString('hex'));
  assert.notEqual(hash('sha512', chains[0].raw).toString('hex'), diagnostic.previousSequenceSHA512);
});

test('fixed hash renewal retains the selected sorted construction and exact archived bytes', async () => {
  let requests = 0;
  const renewed = await renewERS(prefix(2), original, {
    hashRenewal: true,
    hashOID: OID.sha512,
    tsa: async (imprint, hashOID) => {
      requests++;
      assert.equal(hashOID, OID.sha512);
      assert.equal(imprint.toString('hex'), diagnostic.sortedPairSHA512);
      assert.notEqual(imprint.toString('hex'), diagnostic.bcERSByteDataHash);
      return tokens[2];
    },
  });
  assert.equal(requests, 1);
  assert.deepEqual(renewed, timely);
});

test('recorded BC regression keeps three failed positive presence expectations visible', () => {
  const cases = observations.filter((row) => row.case);
  assert.equal(cases.length, 8);
  assert.deepEqual(
    cases.filter((row) => !row.compatibilityExpectationMatched).map((row) => row.case),
    ['timely-hash-renewal', 'late-hash-renewal', 'corrupt-final-signature'],
  );
  for (const row of cases) {
    assert.equal(
      row.compatibilityExpectationMatched,
      row.presence === row.expectedPresence &&
        row.validTokenSignatures === row.expectedValidTokenSignatures,
    );
  }
  assert.equal(observations.at(-1).compatibilityExpectationsMatched, 5);
  assert.equal(observations.at(-1).completeTrustEstablished, false);
});
