import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import * as c from './core.mjs';
import { validateCAdESMaterial, validateSmimeMaterial } from './cades-validation.mjs';
import {
  smimeMaterialFixture,
  epoch,
  at,
  SIGNING,
  ENCRYPTION,
  O,
} from './smime-material-fixtures.mjs';

let f;
before(() => {
  f = smimeMaterialFixture();
});
after(() => f?.close());

const summary = (result) =>
  JSON.stringify({ overall: result.overall, reason: result.reason, checks: result.checks });
function overall(result, expected) {
  assert.equal(result.overall, expected, summary(result));
  return result;
}
const checkReason = (result, reason, kind = 'INVALID') =>
  assert(
    result.checks.some((check) => check.overall === kind && check.reason === reason),
    summary(result),
  );
const validate = (leaf = f.signer, changes = {}) => validateSmimeMaterial(f.options(leaf, changes));
const invalidSignature = (der) => {
  const value = Buffer.from(der);
  value[value.length - 1] ^= 1;
  return value;
};

test('mail signing material returns exact current identity and proof dependencies', () => {
  const result = overall(validate(), 'VALID');
  assert.equal(result.reason, 'SMIME_MATERIAL_VALID');
  assert.equal(result.purpose, SIGNING);
  assert.equal(result.stateTime, at);
  assert.equal(result.knowledgeTime, at);
  assert.equal(result.validUntil, epoch + 100000);
  assert.deepEqual(result.identity.certificateHash, c.sha256(f.signer.der));
  assert.deepEqual(result.identity.keyID, c.keyID(f.signer.publicKey));
  assert.deepEqual(result.identity.publicKeyDER, c.spki(f.signer.publicKey));
  assert.deepEqual(
    result.usedCertificates.map((raw) => raw.toString('hex')).sort(),
    [f.signer.der, f.root.der].map((raw) => raw.toString('hex')).sort(),
  );
  assert.deepEqual(result.usedCRLs, [f.defaultCRL]);
  assert.equal(result.currentValidity.leaf.atKnowledgeTime, 'WITHIN');
  assert.equal(result.currentValidity.root.atKnowledgeTime, 'WITHIN');
  assert.deepEqual(result.ordinaryTimeCheckIndexes, []);
  assert.deepEqual(result.knownInvalidCheckIndexes, []);
});

test('RSA3072 recipient subject key is independent of its P256 issuer signature', () => {
  const result = overall(validate(f.recipient, { purpose: ENCRYPTION }), 'VALID');
  assert.equal(result.purpose, ENCRYPTION);
  assert.deepEqual(result.identity.publicKeyDER, c.spki(f.recipient.publicKey));
  assert.equal(f.recipient.cert.algorithm, O.es256);
  assert.equal(f.recipient.publicKey.asymmetricKeyType, 'rsa');
  assert.equal(f.recipient.publicKey.asymmetricKeyDetails.modulusLength, 3072);
});

test('RSA4096 recipient is within the selected mail profile', () => {
  const leaf = f.certificate('RSA4096 Recipient', { key: f.key('rsa', 4096), purpose: ENCRYPTION });
  overall(validate(leaf, { purpose: ENCRYPTION }), 'VALID');
});

for (const critical of [false, true]) {
  test(`explicit emailProtection accepts ${critical ? 'critical' : 'noncritical'} EKU with another well-formed purpose`, () => {
    const leaf = f.certificate(`Mail EKU ${critical}`, {
      key: f.signer,
      eku: 'emailProtection,serverAuth',
      ekuCritical: critical,
    });
    overall(validate(leaf), 'VALID');
  });
}

for (const [name, eku] of [
  ['missing', null],
  ['anyExtendedKeyUsage only', 'anyExtendedKeyUsage'],
  ['TSA only', 'timeStamping'],
]) {
  test(`mail material rejects ${name} emailProtection as a known purpose failure`, () => {
    const leaf = f.certificate(`EKU ${name}`, { key: f.signer, eku });
    const result = overall(validate(leaf), 'INVALID');
    checkReason(result, 'SMIME_EMAIL_PROTECTION_REQUIRED');
  });
}

for (const [name, changes] of [
  ['wrong KU', { ku: 'keyEncipherment' }],
  ['noncritical KU', { kuCritical: false }],
  ['CA signing bits', { ku: 'digitalSignature,keyCertSign,cRLSign' }],
  ['CA leaf', { ca: true, ku: 'digitalSignature,keyCertSign,cRLSign', eku: 'emailProtection' }],
]) {
  test(`mail signing material rejects ${name}`, () => {
    const leaf = f.certificate(`Mail ${name}`, { key: f.signer, ...changes });
    overall(validate(leaf), 'INVALID');
  });
}

test('RSA recipient with digitalSignature but no keyEncipherment cannot be admitted', () => {
  const leaf = f.certificate('RSA Wrong KU', {
    key: f.recipient,
    purpose: ENCRYPTION,
    ku: 'digitalSignature',
  });
  overall(validate(leaf, { purpose: ENCRYPTION }), 'INVALID');
});

test('the two mail purposes cannot substitute for each other', () => {
  overall(validate(f.signer, { purpose: ENCRYPTION }), 'INVALID');
  overall(validate(f.recipient, { purpose: SIGNING }), 'INVALID');
});

test('well-formed RSA2048 recipient remains an unsupported key capability', () => {
  const leaf = f.certificate('RSA2048 Recipient', { key: f.key('rsa', 2048), purpose: ENCRYPTION });
  overall(validate(leaf, { purpose: ENCRYPTION }), 'UNSUPPORTED');
});

test('well-formed P384 signer remains an unsupported key capability', () => {
  const leaf = f.certificate('P384 Sender', { key: f.key('secp384r1') });
  overall(validate(leaf), 'UNSUPPORTED');
});

test('SAN email identity preserves exact typed bytes, duplicate names and source order', () => {
  const names = ['alice@example.test', 'Bob@Example.Test', 'alice@example.test'];
  const leaf = f.certificate('Ordered Mail Names', {
    key: f.signer,
    emails: names,
    otherNames: ['DNS:mail.example.test'],
  });
  const result = overall(validate(leaf), 'VALID');
  const identity = result.identity.certificateNames;
  assert.equal(identity.sanPresent, true);
  assert.equal(identity.preferredSource, 'SAN_RFC822');
  assert.deepEqual(
    identity.rfc822Names.map((name) => name.value),
    names,
  );
  for (let index = 0; index < names.length; index++) {
    assert.deepEqual(identity.rfc822Names[index].valueBytes, Buffer.from(names[index], 'ascii'));
    assert.deepEqual(
      identity.rfc822Names[index].rawDER,
      c.der(0x81, Buffer.from(names[index], 'ascii')),
    );
  }
  assert.equal(identity.otherGeneralNames.length, 1);
  assert.equal(identity.otherGeneralNames[0].tag, 0x82);
  assert.deepEqual(
    identity.otherGeneralNames[0].rawDER,
    c.der(0x82, Buffer.from('mail.example.test')),
  );
});

test('a critical SAN containing only selected mailbox names is processed', () => {
  const leaf = f.certificate('Critical Mail Names', { key: f.signer, sanCritical: true });
  overall(validate(leaf), 'VALID');
});

test('an unselected critical SAN form cannot be ignored beside a selected mailbox', () => {
  const leaf = f.certificate('Critical Other Name', {
    key: f.signer,
    sanCritical: true,
    otherNames: ['DNS:mail.example.test'],
  });
  overall(validate(leaf), 'UNSUPPORTED');
});

test('material with no certificate email name exposes no inferred mailbox', () => {
  const leaf = f.certificate('alice@example.test', { key: f.signer, emails: [] });
  const result = overall(validate(leaf), 'VALID');
  assert.deepEqual(result.identity.certificateNames.rfc822Names, []);
  assert.equal(result.identity.certificateNames.preferredSource, 'NONE');
  assert.equal(result.identity.certificateNames.legacySubjectEmailPresent, false);
  assert.equal(result.mailbox, undefined);
});

test('legacy subject email without a SAN mailbox is unsupported rather than a fallback', () => {
  const leaf = f.certificate('Legacy Mail', {
    key: f.signer,
    emails: [],
    legacyEmail: 'alice@example.test',
  });
  overall(validate(leaf), 'UNSUPPORTED');
});

test('SAN mailbox remains the selected source when legacy subject email is also present', () => {
  const leaf = f.certificate('SAN And Legacy', {
    key: f.signer,
    legacyEmail: 'another@example.test',
  });
  const result = overall(validate(leaf), 'VALID');
  assert.equal(result.identity.certificateNames.preferredSource, 'SAN_RFC822');
  assert.equal(result.identity.certificateNames.legacySubjectEmailPresent, true);
  assert.deepEqual(
    result.identity.certificateNames.rfc822Names.map((entry) => entry.value),
    ['alice@example.test'],
  );
});

test('recognized internationalized mailbox identity is unsupported even in noncritical SAN', () => {
  const leaf = f.certificate('International Mail', {
    key: f.signer,
    emails: [],
    otherNames: ['otherName:1.3.6.1.5.5.7.8.9;UTF8:alice@example.test'],
  });
  overall(validate(leaf), 'UNSUPPORTED');
});

test('empty selected SAN mailbox encoding is invalid despite a valid certificate signature', () => {
  const leaf = f.certificate('Empty Mail Name', {
    key: f.signer,
    sanDER: c.seq(c.der(0x81, Buffer.alloc(0))),
  });
  const result = overall(validate(leaf), 'INVALID');
  checkReason(result, 'SMIME_CERTIFICATE_NAME_ENCODING');
});

test('wrong same-name root cannot authenticate a validly encoded mail certificate', () => {
  const otherRoot = f.certificate('S-MIME Fixture Root', {
    issuer: null,
    ca: true,
    key: f.key(),
    eku: null,
    emails: [],
  });
  const result = overall(
    validate(f.signer, { policy: f.policy(SIGNING, { trustedRoots: [otherRoot.der] }) }),
    'INVALID',
  );
  checkReason(result, 'CADES_CERTIFICATE_SIGNATURE');
});

test('missing explicit root is indeterminate rather than trust in an embedded certificate', () => {
  overall(validate(f.signer, { policy: f.policy(SIGNING, { trustedRoots: [] }) }), 'INDETERMINATE');
});

test('bad certificate signature remains invalid when current revocation material is missing', () => {
  const result = overall(
    validate(f.signer, { certificate: invalidSignature(f.signer.der), crls: [] }),
    'INVALID',
  );
  checkReason(result, 'CADES_CERTIFICATE_SIGNATURE');
});

for (const [name, status] of [
  ['missing', () => []],
  ['stale', () => [f.crl({ nextUpdate: at })]],
  ['not yet known', () => [f.crl({ thisUpdate: at + 1 })]],
]) {
  test(`current mail status is indeterminate when ${name}`, () => {
    overall(validate(f.signer, { crls: status() }), 'INDETERMINATE');
  });
}

test('known authenticated revocation dominates stale status and a later GOOD CRL', () => {
  const revoked = f.crl({ number: 1, nextUpdate: at, entries: [{ revokedAt: epoch + 10 }] });
  const good = f.crl({ number: 2, thisUpdate: epoch + 20 });
  const result = overall(validate(f.signer, { crls: [good, revoked] }), 'INVALID');
  checkReason(result, 'CADES_CERTIFICATE_REVOKED');
});

test('bad CRL signature is not downgraded to stale or missing evidence', () => {
  const result = overall(
    validate(f.signer, { crls: [invalidSignature(f.crl({ nextUpdate: at }))] }),
    'INVALID',
  );
  assert(result.knownInvalidCheckIndexes.length > 0);
});

test('conflicting authenticated CRL contents with one number are indeterminate', () => {
  const first = f.crl({ number: 5 });
  const second = f.crl({ number: 5, thisUpdate: epoch + 1 });
  const result = overall(validate(f.signer, { crls: [first, second] }), 'INDETERMINATE');
  checkReason(result, 'CADES_CRL_CONFLICT', 'INDETERMINATE');
});

test('mail issuer and status roles are independent requirements', () => {
  for (const roles of [['ISSUER'], ['STATUS_AUTHORITY']]) {
    const result = overall(
      validate(f.signer, {
        policy: f.policy(SIGNING, { authorityResolver: f.authorities({ roles }) }),
      }),
      'INVALID',
    );
    checkReason(result, 'AUTHORITY_ROLE');
  }
});

test('material queries preserve actual knowledge time and fixed operation purpose', () => {
  const queries = [];
  const resolver = f.authorities();
  const policy = f.policy(SIGNING, {
    authorityResolver: (query) => {
      queries.push({ ...query, scope: { ...query.scope } });
      return resolver(query);
    },
  });
  overall(validate(f.signer, { policy }), 'VALID');
  assert(queries.some((query) => query.role === 'ISSUER' && query.stateTime === at));
  assert(queries.some((query) => query.role === 'STATUS_AUTHORITY' && query.stateTime === epoch));
  assert(queries.every((query) => query.knowledgeTime === at && query.scope.purpose === SIGNING));
});

test('current mail scope cannot substitute a different purpose or profile', () => {
  overall(validate(f.signer, { policy: f.policy(ENCRYPTION) }), 'INVALID');
  const policy = f.policy();
  policy.scope.profileID = 'different-profile';
  overall(validate(f.signer, { policy }), 'INVALID');
});

for (const [field, value] of [
  ['stateTime', epoch],
  ['evidenceTime', epoch],
  ['signatureEvidenceTime', epoch],
  ['knownCRLs', []],
]) {
  test(`mail material rejects historical override ${field}`, () => {
    overall(validate(f.signer, { [field]: value }), 'INVALID');
  });
}

test('expired leaf time is isolated without granting current material admission', () => {
  const leaf = f.certificate('Expired Sender', { key: f.signer, notAfter: at });
  const result = overall(validate(leaf), 'INVALID');
  assert.equal(result.currentValidity.leaf.atKnowledgeTime, 'EXPIRED');
  assert.equal(result.ordinaryTimeCheckIndexes.length, 1);
  assert.equal(result.checks[result.ordinaryTimeCheckIndexes[0]].reason, 'CADES_CERTIFICATE_TIME');
  assert.deepEqual(result.knownInvalidCheckIndexes, []);
});

test('not-yet-valid leaf remains a known invalid fact and never an ordinary expiry', () => {
  const leaf = f.certificate('Future Sender', { key: f.signer, notBefore: at + 1 });
  const result = overall(validate(leaf), 'INVALID');
  assert.equal(result.currentValidity.leaf.atKnowledgeTime, 'NOT_YET_VALID');
  assert.deepEqual(result.ordinaryTimeCheckIndexes, []);
  assert(
    result.knownInvalidCheckIndexes.some(
      (index) => result.checks[index].reason === 'CADES_CERTIFICATE_TIME',
    ),
  );
});

test('expired root and its current issuer appointment are isolated from status authority', () => {
  const root = f.certificate('Expired Mail Root', {
    issuer: null,
    ca: true,
    eku: null,
    emails: [],
    notAfter: at,
  });
  const leaf = f.certificate('Expired Root Sender', { issuer: root, key: f.signer });
  const policy = f.policy(SIGNING, {
    trustedRoots: [root.der],
    authorityResolver: f.authorities({ authority: root }),
  });
  const result = overall(
    validate(leaf, { certificates: [root.der], crls: [f.crl({ issuer: root })], policy }),
    'INVALID',
  );
  assert.equal(result.currentValidity.root.atKnowledgeTime, 'EXPIRED');
  const ordinary = result.ordinaryTimeCheckIndexes.map((index) => result.checks[index]);
  assert(ordinary.some((check) => check.reason === 'CADES_ROOT_TIME'));
  assert(
    ordinary.some(
      (check) => check.reason === 'AUTHORITY_EXPIRED' && check.authorityRole === 'ISSUER',
    ),
  );
  assert(ordinary.every((check) => check.authorityRole !== 'STATUS_AUTHORITY'));
  assert.deepEqual(result.knownInvalidCheckIndexes, []);
});

test('revocation remains a known invalid fact alongside ordinary leaf expiry', () => {
  const leaf = f.certificate('Expired Revoked Sender', { key: f.signer, notAfter: at });
  const result = overall(
    validate(leaf, { crls: [f.crl({ entries: [{ serial: leaf.cert.serial }] })] }),
    'INVALID',
  );
  assert(result.ordinaryTimeCheckIndexes.length > 0);
  assert(
    result.knownInvalidCheckIndexes.some(
      (index) => result.checks[index].reason === 'CADES_CERTIFICATE_REVOKED',
    ),
  );
});

test('explicit key protection cutoff remains invalid when status is unavailable', () => {
  const policy = f.policy();
  policy.keyDeadlines[c.keyID(f.signer.publicKey).toString('hex')] = at;
  const result = overall(validate(f.signer, { policy, crls: [] }), 'INVALID');
  checkReason(result, 'CADES_KEY_PROTECTION_EXPIRED');
  assert(
    result.knownInvalidCheckIndexes.some(
      (index) => result.checks[index].reason === 'CADES_KEY_PROTECTION_EXPIRED',
    ),
  );
  assert.deepEqual(result.ordinaryTimeCheckIndexes, []);
});

test('missing explicit protection policy is indeterminate', () => {
  const policy = f.policy();
  delete policy.keyDeadlines[c.keyID(f.signer.publicKey).toString('hex')];
  overall(validate(f.signer, { policy }), 'INDETERMINATE');
});

for (const location of [
  'certificates',
  'crls',
  'trustedRoots',
  'currentCertificates',
  'currentCRLs',
]) {
  const inputAt = (size) => {
    const options = f.options();
    const raw = location.toLowerCase().includes('crl') ? f.defaultCRL : f.root.der;
    const values = Array.from({ length: size }, () => Buffer.from(raw));
    if (location === 'certificates' || location === 'crls') options[location] = values;
    else if (location === 'trustedRoots') options.policy.trustedRoots = values;
    else
      options.policy.currentMaterial[location === 'currentCertificates' ? 'certificates' : 'crls'] =
        values;
    return options;
  };
  test(`mail ${location} accepts 32 raw entries and rejects 33 before deduplication`, () => {
    overall(validateSmimeMaterial(inputAt(32)), 'VALID');
    const result = overall(validateSmimeMaterial(inputAt(33)), 'UNSUPPORTED');
    assert.equal(result.reason, 'SMIME_MATERIAL_LIMIT_UNSUPPORTED');
  });
  test(`mail ${location} malformed array, member or sparse hole is invalid rather than a capacity limitation`, () => {
    for (const values of ['not an array', ['not DER bytes'], new Array(1)]) {
      const options = inputAt(1);
      if (location === 'certificates' || location === 'crls') options[location] = values;
      else if (location === 'trustedRoots') options.policy.trustedRoots = values;
      else
        options.policy.currentMaterial[
          location === 'currentCertificates' ? 'certificates' : 'crls'
        ] = values;
      const result = overall(validateSmimeMaterial(options), 'INVALID');
      assert.equal(result.reason, 'SMIME_MATERIAL_INPUT_INVALID');
    }
  });
}

test('returned identity and proof buffers cannot mutate source certificates or later results', () => {
  const before = Buffer.from(f.signer.der);
  const first = overall(validate(), 'VALID');
  first.identity.certificateHash.fill(0);
  first.identity.publicKeyDER.fill(0);
  first.identity.certificateNames.rfc822Names[0].rawDER.fill(0);
  first.identity.certificateNames.rfc822Names[0].valueBytes.fill(0);
  first.usedCertificates[0].fill(0);
  first.usedCRLs[0].fill(0);
  assert.deepEqual(f.signer.der, before);
  const second = overall(validate(), 'VALID');
  assert.deepEqual(second.identity.certificateHash, c.sha256(before));
  assert.deepEqual(second.identity.publicKeyDER, c.spki(f.signer.publicKey));
  assert.deepEqual(
    second.identity.certificateNames.rfc822Names[0].valueBytes,
    Buffer.from('alice@example.test'),
  );
});

test('authority callbacks cannot rewrite snapshotted material inputs', () => {
  const options = f.options();
  const resolver = options.policy.authorityResolver;
  options.policy.authorityResolver = (query) => {
    options.certificate.fill(0);
    options.certificates[0].fill(0);
    options.crls[0].fill(0);
    options.policy.scope.trustDomainID.fill(0);
    return resolver(query);
  };
  overall(validateSmimeMaterial(options), 'VALID');
});

test('mail extension does not broaden the legacy document and TSA purposes', () => {
  for (const purpose of ['SIGNER', 'TSA']) {
    const input = f.options();
    const result = validateCAdESMaterial({ ...input, purpose, stateTime: at });
    assert.notEqual(result.overall, 'VALID', summary(result));
  }
  const doc = f.certificate('Legacy Document Control', { key: f.signer, eku: null, emails: [] });
  const docInput = f.options(doc);
  const docResult = validateCAdESMaterial({ ...docInput, purpose: 'SIGNER', stateTime: at });
  overall(docResult, 'VALID');
  assert.equal(docResult.reason, 'CADES_MATERIAL_VALID');
});

test('ordinary selected mail certificates and current full CRL pass OpenSSL purpose validation', () => {
  const crlFile = f.file('mail-current.crl');
  const crlPem = `-----BEGIN X509 CRL-----\n${f.defaultCRL
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END X509 CRL-----\n`;
  writeFileSync(crlFile, crlPem);
  for (const [entry, purpose] of [
    [f.signer, 'smimesign'],
    [f.recipient, 'smimeencrypt'],
  ]) {
    const output = f.run(
      'verify',
      '-CAfile',
      f.root.pemFile,
      '-CRLfile',
      crlFile,
      '-crl_check',
      '-attime',
      String(at),
      '-purpose',
      purpose,
      entry.pemFile,
    );
    assert.match(output, /: OK\s*$/);
  }
});
