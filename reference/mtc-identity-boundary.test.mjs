import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as m from './mtc.mjs';
import { Journal } from './state.mjs';
import { MTCIssuer } from './issuance.mjs';
import { RegistrationAuthority, createCSR } from './enrollment.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';

const corpus = JSON.parse(
  readFileSync(new URL('./vectors/mtc-identity-boundaries.json', import.meta.url)),
);
const b = (hex) => Buffer.from(hex, 'hex');
const publicKeys = Object.fromEntries(
  Object.entries(corpus.publicKeys).map(([id, hex]) => [
    id,
    createPublicKey({ key: b(hex), type: 'spki', format: 'der' }),
  ]),
);
const sizedID = (pen, length) => String(pen) + '.1'.repeat(length - 3);
const caID = '32473.1',
  memberID = '32474.1',
  overlong = sizedID(32474, 33);
const policyHash = Buffer.alloc(64, 1),
  rtmHash = Buffer.alloc(64, 2);
const error = { code: 'TRUST_ANCHOR_ID' };
function options(f, row = {}) {
  const result = {
    caID: f.caID,
    caPublicKey: publicKeys[row.wrongCA ? 'wrong' : 'ca'],
    members: [
      {
        id: f.memberID,
        publicKey: publicKeys[row.wrongMember ? 'wrong' : 'mirror'],
        operatorID: 'synthetic-mirror',
      },
    ],
    threshold: row.threshold ?? 1,
    policyHash,
    rtmHash,
    membershipEpoch: 1,
    at: corpus.at,
    profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
  };
  if (row.extraMemberID)
    result.members.push({
      id: row.extraMemberID,
      publicKey: publicKeys.unknown,
      operatorID: 'unused',
    });
  if (row.additionalValidMember)
    result.members.push({ id: '32476.1', publicKey: publicKeys.unknown, operatorID: 'unused' });
  if (row.cache)
    result.trustedSubtrees = [
      {
        caID: f.caID,
        logNumber: f.logNumber,
        start: 0,
        end: 1,
        membershipEpoch: row.wrongScope ? 2 : 1,
        mode: 'LIVE',
        policyHash,
        rtmHash,
        validFrom: corpus.at - 1,
        expiresAt: row.expired ? corpus.at : corpus.at + 1,
        root: row.wrongRoot ? Buffer.alloc(32, 7) : b(f.rootHex),
      },
    ];
  return result;
}

test('MTC identity: raw signatures, transcripts and certificate commitments are independently fixed', () => {
  for (const f of corpus.fixtures) {
    const cert = p.parseCertificate(b(f.certificateHex)),
      proof = m.decodeProof(cert.signature);
    assert.deepEqual(cert.tbs, b(f.tbsHex));
    assert.deepEqual(cert.signature, b(f.proofHex));
    assert.equal(cert.serial, BigInt(f.logNumber) << 48n);
    assert.deepEqual(m.logEntryFromTBS(cert.tbs), b(f.entryHex));
    assert.deepEqual(c.sha256(Buffer.concat([Buffer.from([0]), b(f.entryHex)])), b(f.rootHex));
    assert.deepEqual(m.encodeProof(proof), b(f.proofHex));
    for (const s of f.signatures) {
      const actual = proof.signatures.find((v) => v.cosignerID === s.id);
      assert(actual);
      assert.deepEqual(actual.signature, b(s.signatureHex));
      assert(verify(null, b(s.transcriptHex), publicKeys[s.key], actual.signature));
      assert.deepEqual(m.anchorBytes(s.id), b(s.contentHex));
    }
  }
});
for (const row of corpus.cases)
  test('MTC identity: raw ' + row.id, () => {
    const f = corpus.fixtures.find((v) => v.id === row.fixture),
      raw = b(f.certificateHex),
      before = Buffer.from(raw),
      config = options(f, row);
    let cacheLookups = 0;
    if (row.cache && row.expected === 'TRUST_ANCHOR_ID')
      config.trustedSubtrees.find = () => {
        cacheLookups++;
        throw new Error('CACHE_LOOKUP_REACHED');
      };
    if (['STANDALONE', 'LANDMARK'].includes(row.expected)) {
      const result = m.verifyMTC(raw, config);
      assert.equal(result.mode, row.expected);
      assert.deepEqual(result.root, b(f.rootHex));
      assert.deepEqual(result.certificate.tbs, b(f.tbsHex));
      if (result.mode === 'STANDALONE')
        assert.deepEqual(
          result.verifiedCosigners.map((v) => v.id),
          [f.memberID],
        );
    } else assert.throws(() => m.verifyMTC(raw, config), { code: row.expected });
    assert.equal(cacheLookups, 0);
    assert.deepEqual(raw, before);
  });

for (const length of [1, 31, 32])
  test('MTC identity: typed content boundary ' + length, () => {
    const id = Array(length).fill('1').join('.'),
      value = p.trustAnchorID(id);
    assert.deepEqual(value, Buffer.alloc(length, 1));
    assert.equal(c.oid(id, true).length, length + 2);
    assert.deepEqual(c.parseDER(p.anchorName(id)).children[0].children[0].children[1].value, value);
  });
test('MTC identity: multi-byte arbitrary precision component uses content length', () => {
  const arc = (1n << 217n).toString(),
    expected = Buffer.from([0x81, ...Array(30).fill(0x80), 0]);
  assert.deepEqual(p.trustAnchorID(arc), expected);
  assert.equal(c.oid(arc, true).length, 34);
  assert.throws(() => p.trustAnchorID((1n << 224n).toString()), error);
});
test('MTC identity: generic relative OID retains a thirty-three-byte value', () => {
  const raw = c.oid(overlong, true),
    node = c.parseDER(raw);
  assert.equal(node.value.length, 33);
  assert.equal(c.oidText(node), overlong);
  assert.throws(() => p.trustAnchorID(overlong), error);
  assert.throws(() => p.anchorName(overlong), error);
});
for (const [name, id] of [
  ['empty', ''],
  ['empty-component', '1..2'],
  ['leading-zero', '01.2'],
  ['plus', '+1'],
  ['whitespace', ' 1'],
  ['trailing-newline', '1\n'],
  ['hexadecimal', '0x10'],
  ['negative', '-1'],
  ['unicode', '１'],
  ['nonstring', 1],
])
  test('MTC identity: rejects noncanonical text ' + name, () =>
    assert.throws(() => p.trustAnchorID(id), error),
  );
for (const [length, logNumber, accepted] of [
  [30, 1, true],
  [31, 1, false],
  [29, 128, true],
  [30, 128, false],
])
  test(`MTC identity: derived log ca${length} log${logNumber}`, () => {
    const id = sizedID(32473, length),
      origin = id + '.0.' + logNumber;
    assert.equal(c.parseDER(c.oid(origin, true)).value.length, accepted ? 32 : 33);
    if (accepted) assert.equal(m.mtcLogID(id, logNumber), origin);
    else assert.throws(() => m.mtcLogID(id, logNumber), error);
  });
for (const logNumber of [0, 65536, 1.5, '1'])
  test('MTC identity: invalid log number ' + JSON.stringify(logNumber), () =>
    assert.throws(() => m.mtcLogID(caID, logNumber), { code: 'MTC_SERIAL' }),
  );
test('MTC identity: last log number fits a short identity', () =>
  assert.equal(m.mtcLogID(caID, 65535), caID + '.0.65535'));
test('MTC identity: canonical transcript and TBS preserve fixed bytes', () => {
  const f = corpus.fixtures.find((v) => v.id === 'short'),
    s = f.signatures[0];
  assert.deepEqual(
    m.cosignedMessage({
      cosignerID: s.id,
      caID: f.caID,
      logNumber: 1,
      start: 0,
      end: 1,
      root: b(f.rootHex),
    }),
    b(s.transcriptHex),
  );
  const tbs = m.createMTCTBS(
    {
      publicKey: publicKeys.holder,
      subject: p.name('Synthetic MTC identity boundary'),
      notBefore: corpus.at - 60,
      notAfter: corpus.at + 60,
      profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
    },
    { caID: f.caID, logNumber: 1, index: 0 },
  );
  assert.deepEqual(tbs, b(f.tbsHex));
});
for (const [label, changes] of [
  ['cosigner', { cosignerID: overlong }],
  ['CA', { caID: overlong }],
  ['derived-log', { caID: sizedID(32473, 31) }],
])
  test('MTC identity: transcript rejects ' + label, () =>
    assert.throws(
      () =>
        m.cosignedMessage({
          cosignerID: memberID,
          caID,
          logNumber: 1,
          start: 0,
          end: 1,
          root: Buffer.alloc(32),
          ...changes,
        }),
      error,
    ),
  );
test('MTC identity: TBS construction rejects an overlong derived log', () =>
  assert.throws(
    () =>
      m.createMTCTBS(
        { publicKey: publicKeys.holder, subject: p.name('Synthetic') },
        { caID: sizedID(32473, 31), logNumber: 1, index: 0 },
      ),
    error,
  ));
test('MTC identity: all real signers are checked before any signing key is read', () => {
  const f = corpus.fixtures.find((v) => v.id === 'short');
  let keyReads = 0;
  const first = {
    id: caID,
    get privateKey() {
      keyReads++;
      throw new Error('SIGNING_REACHED');
    },
  };
  assert.throws(
    () =>
      m.issueMTC(b(f.tbsHex), {
        caID,
        logNumber: 1,
        index: 0,
        entries: [b(f.entryHex)],
        cosigners: [first, { id: overlong }],
      }),
    error,
  );
  assert.equal(keyReads, 0);
});
function observedJournal() {
  const calls = [];
  const journal = Object.fromEntries(
    ['get', 'put', 'transaction'].map((method) => [
      method,
      (...args) => {
        calls.push(method);
        if (method === 'transaction') return args[0]();
      },
    ]),
  );
  return { journal, calls };
}
test('MTC identity: Mirror constructor rejects before journal access', () => {
  const { journal, calls } = observedJournal();
  assert.throws(() => new m.Mirror({ journal, id: overlong }), error);
  assert.deepEqual(calls, []);
});
for (const method of ['cosign', 'cosignSubtree'])
  for (const [label, changes] of [
    ['CA', { caID: overlong }],
    ['derived-log', { caID: sizedID(32473, 31) }],
    ['changed-own', {}],
    ['log-zero', { logNumber: 0 }],
  ])
    test(`MTC identity: Mirror ${method} rejects ${label} before store and signing`, () => {
      const { journal, calls } = observedJournal(),
        mirror = new m.Mirror({ journal, id: memberID });
      let keyReads = 0;
      Object.defineProperty(mirror, 'privateKey', {
        get() {
          keyReads++;
          throw new Error('SIGNING_REACHED');
        },
      });
      if (label === 'changed-own') mirror.id = overlong;
      assert.throws(
        () =>
          mirror[method]({
            caID,
            logNumber: 1,
            entries: [Buffer.from('entry')],
            start: 0,
            end: 1,
            ...changes,
          }),
        label === 'log-zero' ? { code: 'MTC_SERIAL' } : error,
      );
      assert.deepEqual(calls, []);
      assert.equal(keyReads, 0);
    });
test('MTC identity: direct Mirror store rejects an overlong origin', () => {
  const { journal, calls } = observedJournal(),
    mirror = new m.Mirror({ journal, id: memberID });
  assert.throws(() => mirror.store(sizedID(32473, 33)), error);
  assert.deepEqual(calls, []);
});
test('MTC identity: boundary Mirror commits a leaf and signs its exact root', (t) => {
  const journal = new Journal();
  t.after(() => journal.close());
  const key = generateKeyPairSync('ed25519'),
    id = sizedID(32474, 32),
    mirror = new m.Mirror({ journal, id, privateKey: key.privateKey }),
    entries = [Buffer.from('one'), Buffer.from('two')];
  for (const result of [
    mirror.cosign({ caID, logNumber: 1, entries }),
    mirror.cosignSubtree({ caID, logNumber: 1, start: 0, end: 2 }),
  ]) {
    assert.equal(result.cosignerID, id);
    assert(
      verify(
        null,
        m.cosignedMessage({
          cosignerID: id,
          caID,
          logNumber: 1,
          start: 0,
          end: 2,
          root: m.treeHash(entries),
        }),
        key.publicKey,
        result.signature,
      ),
    );
  }
  assert.equal(mirror.store(caID + '.0.1').head().size, 2);
  assert.deepEqual(mirror.store(caID + '.0.1').entry(0), entries[0]);
});
function constructorOptions(journal) {
  return {
    journal,
    caID,
    logNumber: 1,
    members: [{ id: memberID }],
    threshold: 1,
    mirrors: [{}],
    issuanceScope: {
      trustDomainID: Buffer.alloc(32, 1),
      issuerID: caID,
      issuerKeyID: Buffer.alloc(64, 2),
      representation: 'MTC',
    },
  };
}
for (const label of ['CA', 'member', 'unused-member', 'derived-log'])
  test('MTC identity: issuer constructor rejects ' + label + ' before journal access', () => {
    const { journal, calls } = observedJournal(),
      config = constructorOptions(journal);
    if (label === 'CA') config.caID = overlong;
    if (label === 'derived-log') config.caID = sizedID(32473, 31);
    if (label === 'member') config.members[0].id = overlong;
    if (label === 'unused-member') config.members.push({ id: overlong });
    assert.throws(() => new MTCIssuer(config), error);
    assert.deepEqual(calls, []);
  });

const issuanceRows = (journal) =>
  journal
    .list('mtc-issuance')
    .map((row) => ({ id: row.id, ...journal.get('mtc-issuance', row.id) }));
async function liveIssuer(t) {
  t.mock.method(Date, 'now', () => corpus.at * 1000);
  const journals = [],
    journal = () => {
      const j = new Journal();
      journals.push(j);
      return j;
    };
  t.after(() => journals.forEach((j) => j.close()));
  const control = (serial) => {
    const key = c.generate('ml-dsa-87'),
      subject = p.name('Synthetic MTC identity authority ' + serial);
    return {
      ...key,
      certificate: p.issueCertificate(
        {
          publicKey: key.publicKey,
          issuer: subject,
          subject,
          serial,
          profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
          notBefore: corpus.at - 60,
          notAfter: corpus.at + 86400,
        },
        key.privateKey,
      ),
    };
  };
  const ra = control(1),
    ca = control(2),
    member = { id: sizedID(32474, 32), operatorID: 'identity-mirror', ...c.generate('ml-dsa-87') },
    scope = {
      trustDomainID: c.random(),
      issuerID: caID,
      issuerKeyID: c.keyID(ca.publicKey),
      representation: 'MTC',
    },
    profileID = 'CERTCONCORD-PERSON-SIGN-v1',
    resolver = exampleAuthorityResolver({
      at: corpus.at,
      trustDomainID: scope.trustDomainID,
      authorities: [
        { certificate: ra.certificate, roles: ['REGISTRATION_AUTHORITY'] },
        { certificate: ca.certificate, roles: ['ISSUER'] },
        {
          mode: 'RAW_KEY',
          publicKeyDER: c.spki(member.publicKey),
          roles: ['COSIGNER'],
          knownAt: corpus.at - 60,
          validFrom: corpus.at - 60,
          validUntil: corpus.at + 86400,
        },
      ],
    }),
    raService = new RegistrationAuthority({
      journal: journal(),
      ...ra,
      approve: async () => ({ approved: true }),
    }),
    key = c.generate('ml-dsa-65'),
    csr = createCSR({ ...key, subject: p.name('Synthetic MTC identity subject') }),
    rar = await raService.authorize({
      csr,
      subjectID: c.random(),
      profileID,
      policyHash,
      identityEvidenceHash: c.random(64),
      issuanceScope: scope,
    }),
    mirror = new m.Mirror({ journal: journal(), id: member.id, privateKey: member.privateKey }),
    issuerJournal = journal(),
    config = {
      journal: issuerJournal,
      raCertificate: ra.certificate,
      caID,
      logNumber: 1,
      privateKey: ca.privateKey,
      policyHash,
      rtmHash,
      membershipEpoch: 1,
      members: [member],
      threshold: 1,
      mirrors: [mirror],
      allowedProfiles: [profileID],
      issuanceScope: scope,
      authorityResolver: resolver,
      issuerCertificate: ca.certificate,
    },
    issuer = new MTCIssuer(config),
    request = { csr, rar },
    certificate = await issuer.issue(request);
  const result = m.verifyMTC(certificate, {
    ...config,
    caPublicKey: ca.publicKey,
    profileID,
    at: corpus.at,
  });
  assert.equal(result.mode, 'STANDALONE');
  assert.deepEqual(
    result.verifiedCosigners.map((v) => v.id),
    [member.id],
  );
  return { issuer, journal: issuerJournal, request, certificate, mirror, config };
}
test('MTC identity: boundary cosigner issuance preserves exact certified replay', async (t) => {
  const f = await liveIssuer(t),
    before = issuanceRows(f.journal),
    root = f.issuer.log.root();
  assert.equal(f.issuer.log.head().size, 1);
  assert.equal(before.length, 1);
  assert.equal(before[0].value.state, 'CERTIFIED');
  assert.deepEqual(await f.issuer.issue(f.request), f.certificate);
  const reopened = new MTCIssuer(f.config);
  assert.deepEqual(await reopened.issue(f.request), f.certificate);
  assert.deepEqual(issuanceRows(f.journal), before);
  assert.deepEqual(reopened.log.root(), root);
  assert.equal(reopened.log.head().size, 1);
});
for (const label of ['CA', 'member', 'derived-log'])
  test('MTC identity: issuer rechecks changed ' + label + ' before durable replay', async (t) => {
    const f = await liveIssuer(t),
      before = issuanceRows(f.journal),
      head = f.issuer.log.head(),
      root = f.issuer.log.root(),
      observed = [];
    const mocks = ['get', 'put', 'transaction'].map((method) =>
      t.mock.method(f.journal, method, (...args) => {
        observed.push(method);
        throw new Error('JOURNAL_REACHED');
      }),
    );
    const signer = t.mock.method(f.mirror, 'cosign', () => {
      observed.push('cosign');
      throw new Error('SIGNING_REACHED');
    });
    if (label === 'CA') f.issuer.caID = overlong;
    if (label === 'member') f.issuer.members[0].id = overlong;
    if (label === 'derived-log') {
      f.issuer.caID = sizedID(32473, 30);
      f.issuer.logNumber = 128;
    }
    await assert.rejects(f.issuer.issue(f.request), error);
    assert.deepEqual(observed, []);
    for (const mock of mocks) mock.mock.restore();
    signer.mock.restore();
    assert.deepEqual(issuanceRows(f.journal), before);
    assert.deepEqual(f.issuer.log.head(), head);
    assert.deepEqual(f.issuer.log.root(), root);
  });
