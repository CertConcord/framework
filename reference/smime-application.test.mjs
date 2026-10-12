import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { SmimeApplication } from './smime.mjs';
import * as c from './core.mjs';
import {
  smimeMaterialFixture,
  epoch,
  at,
  SIGNING,
  ENCRYPTION,
  O,
} from './smime-material-fixtures.mjs';
import {
  applicationFixture,
  copy,
  entity,
  identity,
  normalization,
  noOutput,
  expectOverall,
  SMIME_OID,
} from './smime-application-fixtures.mjs';

let material;
let alternateSigner;
let alternateRecipient;
let expiredSigner;
let futureSigner;
let unnamedSigner;
let expiredRoot;
let expiredRootSigner;
before(() => {
  material = smimeMaterialFixture();
  alternateSigner = material.certificate('Alternate sender');
  alternateRecipient = material.certificate('Other explicit recipient', {
    purpose: ENCRYPTION,
    key: material.key('rsa'),
    emails: ['carol@example.test'],
  });
  expiredSigner = material.certificate('Expired sender', {
    key: material.signer,
    notAfter: at - 1,
  });
  futureSigner = material.certificate('Future sender', { key: material.signer, notBefore: at + 1 });
  unnamedSigner = material.certificate('Unnamed sender', { key: material.signer, emails: [] });
  expiredRoot = material.certificate('Expired mail root', {
    issuer: null,
    ca: true,
    key: material.root,
    notAfter: at - 1,
  });
  expiredRootSigner = material.certificate('Sender under expired root', { issuer: expiredRoot });
});
after(() => material?.close());

function fixture() {
  const f = applicationFixture(material);
  f.app = new SmimeApplication({ readContext: f.readContext, backend: f.backend });
  return f;
}
function rejected(result) {
  assert.notEqual(result.overall, 'VALID', JSON.stringify(result));
  assert(['INVALID', 'UNSUPPORTED', 'INDETERMINATE'].includes(result.overall));
  noOutput(result);
  return result;
}
function noPrivateAction(f) {
  assert.equal(f.count('sign'), 0);
  assert.equal(f.count('encrypt'), 0);
  assert.equal(f.count('decrypt'), 0);
}
function withdraw(f) {
  f.state.knowledgeTime += 1;
  f.state.mailboxDecision = () => ({ overall: 'INVALID', reason: 'FIXTURE_BINDING_WITHDRAWN' });
}

for (const mode of ['SIGNED', 'SIGNED_AND_ENCRYPTED']) {
  test(`S/MIME application preserves the exact signed entity in ${mode} mode`, async () => {
    const f = fixture();
    const result = expectOverall(await f.app.protectSmimeMessage(f.protectInput(mode)), 'VALID');
    assert.deepEqual(result.canonicalMimeHash, c.sha256(entity));
    assert.deepEqual(result.sender, identity(material.signer, 'alice@example.test'));
    assert.deepEqual(result.protection, { content: mode, outerHeaders: 'UNPROTECTED' });
    assert.deepEqual(result.normalization, normalization());
    assert.equal(result.knowledgeTime, at);
    assert.equal(f.count('sign'), 1);
    assert.equal(f.count('encrypt'), mode === 'SIGNED' ? 0 : 1);
    assert.equal(f.count('decrypt'), 0);
    assert.deepEqual(f.events.find((event) => event.name === 'sign').args.content, entity);
    const processed = expectOverall(
      await f.app.processSmimeMessage({
        ...f.processInput(mode),
        message: result.message,
      }),
      'VALID',
    );
    assert.deepEqual(processed.content.mime, entity);
    assert.deepEqual(processed.content.parts[0].bytes, Buffer.from('Independent message.\r\n'));
    assert.deepEqual(processed.canonicalMimeHash, c.sha256(entity));
    assert.deepEqual(
      processed.authenticatedAuthor,
      identity(material.signer, 'alice@example.test'),
    );
    assert.deepEqual(processed.protection, { content: mode, outerHeaders: 'UNPROTECTED' });
    if (mode === 'SIGNED_AND_ENCRYPTED')
      assert.deepEqual(
        processed.matchedRecipient,
        identity(material.recipient, 'bob@example.test'),
      );
    for (const query of f.queries) {
      assert.equal(query.stateTime, at);
      assert.equal(query.knowledgeTime, at);
      assert.equal(query.scope.purpose, query.purpose);
      assert.equal(query.scope.profileID, 'certconcord-smime-application-v1');
      assert.deepEqual(query.scope.trustDomainID, material.domain);
    }
  });
}

test('S/MIME encryption uses only explicit recipients and preserves the signed carrier', async () => {
  const f = fixture();
  f.state.extraRecipients = [alternateRecipient];
  const input = f.protectInput('SIGNED_AND_ENCRYPTED');
  input.recipients.push({ mailbox: 'carol@example.test', certificate: alternateRecipient.der });
  const result = expectOverall(await f.app.protectSmimeMessage(input), 'VALID');
  assert.deepEqual(result.admittedRecipients, [
    identity(material.recipient, 'bob@example.test'),
    identity(alternateRecipient, 'carol@example.test'),
  ]);
  const encrypted = f.events.find((event) => event.name === 'encrypt').args;
  assert.deepEqual(encrypted.certificates, [material.recipient.der, alternateRecipient.der]);
  const inner = f.carriers.get(encrypted.content.toString('hex'));
  assert.equal(inner.format, 'ENTITY');
  assert.equal(inner.kind, 'SIGNED_DATA');
  assert.deepEqual(inner.outerHeaders, []);
  assert.deepEqual(f.facts(inner.cms).content, entity);
  assert(f.queries.every((query) => query.mailbox !== 'elsewhere@example.test'));
});

for (const [name, mutate] of [
  [
    'mailbox',
    (b) => {
      b.mailbox = 'mallory@example.test';
    },
  ],
  [
    'certificate hash',
    (b) => {
      b.certificateHash[0] ^= 1;
    },
  ],
  [
    'key identifier',
    (b) => {
      b.keyID[0] ^= 1;
    },
  ],
  [
    'purpose',
    (b) => {
      b.purpose = ENCRYPTION;
    },
  ],
  [
    'trust domain',
    (b) => {
      b.scope.trustDomainID[0] ^= 1;
    },
  ],
  [
    'issuer',
    (b) => {
      b.scope.issuerID = 'another-issuer';
    },
  ],
  [
    'representation',
    (b) => {
      b.scope.representation = 'MTC';
    },
  ],
  [
    'profile',
    (b) => {
      b.scope.profileID = 'another-profile';
    },
  ],
  [
    'scope purpose',
    (b) => {
      b.scope.purpose = ENCRYPTION;
    },
  ],
]) {
  test(`S/MIME rejects a mailbox binding that substitutes ${name}`, async () => {
    const f = fixture();
    f.state.mailboxDecision = (_query, result) => {
      mutate(result.binding);
      return result;
    };
    expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'INVALID');
    noPrivateAction(f);
  });
}

for (const [name, mutate] of [
  [
    'future knowledge',
    (b) => {
      b.knownAt = at + 1;
    },
  ],
  [
    'future appointment',
    (b) => {
      b.validFrom = at + 1;
    },
  ],
  [
    'exclusive expiration',
    (b) => {
      b.validUntil = at;
    },
  ],
  [
    'nonintegral time',
    (b) => {
      b.knownAt = at - 0.5;
    },
  ],
  [
    'infinite end',
    (b) => {
      b.validUntil = Infinity;
    },
  ],
  [
    'missing start',
    (b) => {
      delete b.validFrom;
    },
  ],
  [
    'unselected provenance',
    (b) => {
      b.provenance = 'MESSAGE_CERTIFICATE';
    },
  ],
]) {
  test(`S/MIME does not use a mailbox binding with ${name}`, async () => {
    const f = fixture();
    f.state.mailboxDecision = (_query, result) => {
      mutate(result.binding);
      return result;
    };
    rejected(await f.app.protectSmimeMessage(f.protectInput()));
    noPrivateAction(f);
  });
}

test('S/MIME accepts a mailbox appointment exactly at its known and valid start', async () => {
  const f = fixture();
  f.state.mailboxDecision = (_query, result) => {
    Object.assign(result.binding, { knownAt: at, validFrom: at, validUntil: at + 1 });
    return result;
  };
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
  assert.equal(f.count('sign'), 1);
});

for (const decision of ['INDETERMINATE', 'UNSUPPORTED', 'INVALID']) {
  test(`S/MIME preserves a ${decision} mailbox decision without private use`, async () => {
    const f = fixture();
    f.state.mailboxDecision = () => ({ overall: decision, reason: 'FIXTURE_DECISION' });
    expectOverall(await f.app.protectSmimeMessage(f.protectInput()), decision);
    noPrivateAction(f);
  });
}

test('S/MIME external binding does not override a definite SAN mailbox mismatch', async () => {
  const f = fixture();
  const input = f.protectInput();
  input.senderMailbox = 'mallory@example.test';
  f.hooks.after.prepareMimeMessage = (result) => {
    result.headerClaims.fromMailbox = input.senderMailbox;
  };
  expectOverall(await f.app.protectSmimeMessage(input), 'INVALID');
  noPrivateAction(f);
});

test('S/MIME admits a certificate without email names only through the exact external binding', async () => {
  const f = fixture();
  f.state.signer = unnamedSigner;
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
  assert(f.queries.every((query) => query.certificateHash.equals(c.sha256(unnamedSigner.der))));
});

for (const method of ['prepareMimeMessage', 'describeKey']) {
  test(`S/MIME fresh admission after ${method} prevents the next private action`, async () => {
    const f = fixture();
    f.hooks.after[method] = () => withdraw(f);
    const result = expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'INVALID');
    assert.equal(result.effectMayHaveOccurred, false);
    noPrivateAction(f);
  });
}
for (const method of ['sign', 'inspectCMS', 'packageCMS', 'encrypt']) {
  test(`S/MIME withdrawal after ${method} suppresses output and later effects`, async () => {
    const f = fixture();
    f.hooks.after[method] = () => withdraw(f);
    const result = expectOverall(
      await f.app.protectSmimeMessage(f.protectInput('SIGNED_AND_ENCRYPTED')),
      'INVALID',
    );
    assert.equal(result.effectMayHaveOccurred, true);
    assert.equal(f.count('sign'), 1);
    assert.equal(f.count('encrypt'), method === 'encrypt' ? 1 : 0);
    assert.equal(f.count('decrypt'), 0);
  });
}
for (const method of ['parseProtectedMessage', 'describeKey', 'inspectCMS']) {
  test(`S/MIME inbound fresh admission after ${method} precedes decryption`, async () => {
    const f = fixture();
    f.hooks.after[method] = () => withdraw(f);
    const result = expectOverall(
      await f.app.processSmimeMessage(f.processInput('SIGNED_AND_ENCRYPTED')),
      'INVALID',
    );
    assert.equal(result.effectMayHaveOccurred, false);
    noPrivateAction(f);
  });
}
for (const method of ['decrypt', 'inspectVerifiedMime']) {
  test(`S/MIME inbound withdrawal after ${method} keeps decrypted bytes quarantined`, async () => {
    const f = fixture();
    f.hooks.after[method] = () => withdraw(f);
    const result = expectOverall(
      await f.app.processSmimeMessage(f.processInput('SIGNED_AND_ENCRYPTED')),
      'INVALID',
    );
    assert.equal(result.effectMayHaveOccurred, true);
    assert.equal(f.count('decrypt'), 1);
    assert.equal(f.count('sign'), 0);
    assert.equal(f.count('encrypt'), 0);
  });
}

test('S/MIME copied method inputs survive caller mutation during MIME preparation', async () => {
  const f = fixture();
  const input = f.protectInput('SIGNED_AND_ENCRYPTED');
  const originalMessage = Buffer.from(input.message);
  f.hooks.before.prepareMimeMessage = () => {
    input.message.fill(0);
    input.signer.certificate.fill(0);
    input.signer.keyRef = 'recipient';
    input.recipients[0].certificate.fill(0);
    input.recipients[0].mailbox = 'mallory@example.test';
    input.recipients.length = 0;
  };
  const result = expectOverall(await f.app.protectSmimeMessage(input), 'VALID');
  assert.deepEqual(
    f.events.find((event) => event.name === 'prepareMimeMessage').args.message,
    originalMessage,
  );
  assert.deepEqual(result.sender, identity(material.signer, 'alice@example.test'));
  assert.deepEqual(result.admittedRecipients, [identity(material.recipient, 'bob@example.test')]);
  assert.equal(f.count('sign'), 1);
  assert.equal(f.count('encrypt'), 1);
});

test('S/MIME resolver query mutation cannot change the admitted tuple or policy namespace', async () => {
  const f = fixture();
  f.state.mailboxDecision = (query, result) => {
    query.certificateHash.fill(0);
    query.keyID.fill(0);
    query.scope.trustDomainID.fill(0);
    query.scope.issuerID = 'mutated-callback-view';
    return result;
  };
  const result = expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
  assert.deepEqual(result.sender, identity(material.signer, 'alice@example.test'));
  assert.deepEqual(f.policy.scope.trustDomainID, material.domain);
  assert.equal(f.policy.scope.issuerID, 'smime-material-fixture');
});

test('S/MIME snapshots MIME backend return bytes before a later key lookup await', async () => {
  const f = fixture();
  let returned;
  f.hooks.after.prepareMimeMessage = (value) => {
    returned = value;
  };
  f.hooks.before.describeKey = () => {
    returned.mime.fill(0);
    returned.outerHeaders[0].raw.fill(0);
    returned.headerClaims.fromMailbox = 'mallory@example.test';
  };
  const result = expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
  assert.deepEqual(result.canonicalMimeHash, c.sha256(entity));
  assert.deepEqual(f.events.find((event) => event.name === 'sign').args.content, entity);
});

test('S/MIME retains constructor callback and backend method references', async () => {
  const f = applicationFixture(material);
  const settings = { readContext: f.readContext, backend: f.backend };
  const app = new SmimeApplication(settings);
  settings.readContext = () => {
    throw new Error('replacement context');
  };
  f.backend.sign = () => {
    throw new Error('replacement backend');
  };
  expectOverall(await app.protectSmimeMessage(f.protectInput()), 'VALID');
  assert.equal(f.count('sign'), 1);
});

for (const resolver of ['authorityResolver', 'mailboxResolver']) {
  test(`S/MIME rejects replacement of the initially configured ${resolver}`, async () => {
    const f = fixture();
    expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
    const original = f.policy[resolver];
    f.policy[resolver] = (...args) => original(...args);
    rejected(await f.app.protectSmimeMessage(f.protectInput()));
    assert.equal(f.count('sign'), 1);
  });
}

test('S/MIME rejects a described key different from the admitted certificate before signing', async () => {
  const f = fixture();
  f.keys.set('signer', alternateSigner.publicKey);
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'INVALID');
  noPrivateAction(f);
});

test('S/MIME detects a serializer that replaces the completed CMS candidate', async () => {
  const f = fixture();
  f.hooks.after.packageCMS = (result, input) => {
    result.message = f.carrier(
      f.signed(Buffer.from('Other signed body.')),
      'SIGNED_DATA',
      input.format,
    );
  };
  expectOverall(await f.app.protectSmimeMessage(f.protectInput('SIGNED_AND_ENCRYPTED')), 'INVALID');
  assert.equal(f.count('sign'), 1);
  assert.equal(f.count('encrypt'), 0);
});

test('S/MIME incoming byte and recipient inputs are copied before the first await', async () => {
  const f = fixture();
  const input = f.processInput('SIGNED_AND_ENCRYPTED');
  f.hooks.before.parseProtectedMessage = () => {
    input.message.fill(0);
    input.recipient.certificate.fill(0);
    input.recipient.keyRef = 'signer';
    input.recipient.mailbox = 'mallory@example.test';
  };
  const result = expectOverall(await f.app.processSmimeMessage(input), 'VALID');
  assert.deepEqual(result.content.mime, entity);
  assert.deepEqual(result.matchedRecipient, identity(material.recipient, 'bob@example.test'));
  assert.equal(f.count('decrypt'), 1);
});

test('S/MIME rechecks the recipient reported by the actual decrypt operation', async () => {
  const f = fixture();
  f.hooks.after.decrypt = (result) => {
    result.recipient.certificateHash = c.sha256(alternateRecipient.der);
    result.recipient.publicKeyDER = c.spki(alternateRecipient.publicKey);
  };
  expectOverall(await f.app.processSmimeMessage(f.processInput('SIGNED_AND_ENCRYPTED')), 'INVALID');
  assert.equal(f.count('decrypt'), 1);
  assert.equal(f.count('inspectVerifiedMime'), 0);
});

test('S/MIME copies accepted CMS content before a later MIME inspection await', async () => {
  const f = fixture();
  let inspected;
  f.hooks.after.inspectCMS = (result) => {
    if (result.kind === 'SIGNED_DATA') inspected = result;
  };
  f.hooks.before.inspectVerifiedMime = () => {
    inspected.content.fill(0);
  };
  const result = expectOverall(await f.app.processSmimeMessage(f.processInput()), 'VALID');
  assert.deepEqual(result.content.mime, entity);
  assert.deepEqual(result.canonicalMimeHash, c.sha256(entity));
});

for (const name of ['content', 'certificate', 'public key', 'MIME kind']) {
  test(`S/MIME rejects a signed backend candidate with substituted ${name}`, async () => {
    const f = fixture();
    f.hooks.after.sign = (result) => {
      const facts = f.facts(result.cms);
      if (name === 'content') facts.content = Buffer.from('substituted content');
      if (name === 'certificate') {
        facts.certificate = Buffer.from(alternateSigner.der);
        facts.signer.certificateHash = c.sha256(alternateSigner.der);
        facts.signer.publicKeyDER = c.spki(alternateSigner.publicKey);
      }
      if (name === 'public key') facts.signer.publicKeyDER = c.spki(alternateSigner.publicKey);
      if (name === 'MIME kind') facts.kind = 'AUTH_ENVELOPED_DATA';
    };
    expectOverall(
      await f.app.protectSmimeMessage(f.protectInput('SIGNED_AND_ENCRYPTED')),
      'INVALID',
    );
    assert.equal(f.count('sign'), 1);
    assert.equal(f.count('encrypt'), 0);
  });
}

for (const name of ['dropped recipient', 'substituted recipient key', 'extra recipient']) {
  test(`S/MIME rejects an encrypted backend candidate with ${name}`, async () => {
    const f = fixture();
    f.hooks.after.encrypt = (result) => {
      const facts = f.facts(result.cms);
      if (name === 'dropped recipient') facts.recipientMatches = [];
      if (name === 'substituted recipient key')
        facts.recipientMatches[0].publicKeyDER = c.spki(alternateRecipient.publicKey);
      if (name === 'extra recipient') {
        facts.recipients.push({
          ...copy(facts.recipients[0]),
          index: 1,
          identifierDER: c.seq(c.integer(999)),
        });
      }
    };
    expectOverall(
      await f.app.protectSmimeMessage(f.protectInput('SIGNED_AND_ENCRYPTED')),
      'INVALID',
    );
    assert.equal(f.count('sign'), 1);
    assert.equal(f.count('encrypt'), 1);
  });
}

for (const method of ['sign', 'encrypt', 'decrypt']) {
  test(`S/MIME does not repeat ${method} or release output after an ambiguous backend failure`, async () => {
    const f = fixture();
    f.hooks.before[method] = () => {
      throw new Error('backend unavailable after invocation');
    };
    const result = expectOverall(
      await (method === 'decrypt'
        ? f.app.processSmimeMessage(f.processInput('SIGNED_AND_ENCRYPTED'))
        : f.app.protectSmimeMessage(f.protectInput('SIGNED_AND_ENCRYPTED'))),
      'INDETERMINATE',
    );
    assert.equal(result.effectMayHaveOccurred, true);
    assert.equal(f.count(method), 1);
    if (method === 'sign') assert.equal(f.count('encrypt'), 0);
    if (method === 'decrypt') assert.equal(f.count('inspectVerifiedMime'), 0);
  });
}

test('S/MIME a second explicit call is a new attempt and rechecks current admission', async () => {
  const f = fixture();
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
  assert.equal(f.count('sign'), 2);
  withdraw(f);
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'INVALID');
  assert.equal(f.count('sign'), 2);
});

for (const [actual, required] of [
  ['SIGNED', 'SIGNED_AND_ENCRYPTED'],
  ['SIGNED_AND_ENCRYPTED', 'SIGNED'],
]) {
  test(`S/MIME ${actual} cannot satisfy the exact ${required} requirement`, async () => {
    const f = fixture();
    const input = f.processInput(actual);
    input.requiredProtection = required;
    expectOverall(await f.app.processSmimeMessage(input), 'INVALID');
    assert.equal(f.count('decrypt'), 0);
    assert.equal(f.count('inspectVerifiedMime'), 0);
  });
}

test('S/MIME incoming ordinary signer expiration is uncertainty without historical proof', async () => {
  const f = fixture();
  f.state.signer = expiredSigner;
  expectOverall(await f.app.processSmimeMessage(f.processInput()), 'INDETERMINATE');
  noPrivateAction(f);
  assert.equal(f.count('inspectVerifiedMime'), 0);
});
test('S/MIME ordinary expired signer is never used for live signing', async () => {
  const f = fixture();
  f.state.signer = expiredSigner;
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'INVALID');
  noPrivateAction(f);
});
test('S/MIME a not-yet-valid incoming signer remains INVALID', async () => {
  const f = fixture();
  f.state.signer = futureSigner;
  expectOverall(await f.app.processSmimeMessage(f.processInput()), 'INVALID');
  assert.equal(f.count('inspectVerifiedMime'), 0);
});
test('S/MIME known incoming revocation stays INVALID even with expired validity', async () => {
  const f = fixture();
  f.state.signer = expiredSigner;
  f.policy.currentMaterial.crls = [
    material.crl({ entries: [{ serial: expiredSigner.cert.serial }] }),
  ];
  expectOverall(await f.app.processSmimeMessage(f.processInput()), 'INVALID');
  assert.equal(f.count('inspectVerifiedMime'), 0);
});

function expiredRootFixture() {
  const f = applicationFixture(material);
  f.state.signer = expiredRootSigner;
  f.policy.trustedRoots = [Buffer.from(expiredRoot.der)];
  f.policy.authorityResolver = material.authorities({ authority: expiredRoot });
  f.policy.currentMaterial = {
    certificates: [Buffer.from(expiredRoot.der)],
    crls: [material.crl({ issuer: expiredRoot })],
  };
  f.app = new SmimeApplication({ readContext: f.readContext, backend: f.backend });
  return f;
}

test('S/MIME incoming ordinary root expiration alone is uncertainty without historical proof', async () => {
  const f = expiredRootFixture();
  expectOverall(await f.app.processSmimeMessage(f.processInput()), 'INDETERMINATE');
  noPrivateAction(f);
  assert.equal(f.count('inspectVerifiedMime'), 0);
});
for (const cause of ['root key cutoff', 'hash cutoff', 'bad signature']) {
  test(`S/MIME ordinary expired root cannot downgrade known ${cause}`, async () => {
    const f = expiredRootFixture();
    if (cause === 'root key cutoff')
      f.policy.keyDeadlines[c.keyID(expiredRoot.publicKey).toString('hex')] = at;
    if (cause === 'hash cutoff') f.policy.hashDeadlines[O.sha256] = at;
    if (cause === 'bad signature')
      f.hooks.after.inspectCMS = (result) => {
        Object.assign(result, {
          overall: 'INVALID',
          reason: 'SMIME_SIGNATURE_INVALID',
          checks: [{ overall: 'INVALID', reason: 'SMIME_SIGNATURE_INVALID' }],
        });
      };
    expectOverall(await f.app.processSmimeMessage(f.processInput()), 'INVALID');
    noPrivateAction(f);
    assert.equal(f.count('inspectVerifiedMime'), 0);
  });
}
test('S/MIME safely available bad math dominates missing current validation material', async () => {
  const f = fixture();
  f.policy.currentMaterial.crls = [];
  f.hooks.after.inspectCMS = (result) => {
    Object.assign(result, {
      overall: 'INVALID',
      reason: 'SMIME_SIGNATURE_INVALID',
      checks: [{ overall: 'INVALID', reason: 'SMIME_SIGNATURE_INVALID' }],
    });
  };
  const result = expectOverall(await f.app.processSmimeMessage(f.processInput()), 'INVALID');
  assert.equal(result.reason, 'SMIME_SIGNATURE_INVALID');
  assert.equal(f.count('inspectVerifiedMime'), 0);
});

for (const deadline of ['signature algorithm', 'hash', 'signer key', 'OAEP', 'GCM']) {
  test(`S/MIME enforces the exclusive ${deadline} protection cutoff at actual knowledge`, async () => {
    const f = fixture();
    if (deadline === 'signature algorithm') f.policy.algorithmDeadlines[O.es256] = at;
    if (deadline === 'hash') f.policy.hashDeadlines[O.sha256] = at;
    if (deadline === 'signer key')
      f.policy.keyDeadlines[c.keyID(material.signer.publicKey).toString('hex')] = at;
    if (deadline === 'OAEP') f.policy.algorithmDeadlines[SMIME_OID.oaep] = at;
    if (deadline === 'GCM') f.policy.algorithmDeadlines[SMIME_OID.aes256GCM] = at;
    expectOverall(
      await f.app.protectSmimeMessage(f.protectInput('SIGNED_AND_ENCRYPTED')),
      'INVALID',
    );
    assert.equal(f.count('encrypt'), 0);
    if (!['OAEP', 'GCM'].includes(deadline)) assert.equal(f.count('sign'), 0);
  });
}

test('S/MIME an unavailable current context does not reuse an earlier GOOD decision', async () => {
  const f = fixture();
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
  f.state.contextOverride = () => {
    throw new Error('configuration unavailable');
  };
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'INDETERMINATE');
  assert.equal(f.count('sign'), 1);
});
test('S/MIME unavailable current context cannot mask safely available incoming bad math', async () => {
  const f = fixture();
  const input = f.processInput();
  f.state.contextOverride = () => {
    throw new Error('configuration unavailable');
  };
  f.hooks.after.inspectCMS = (result) => {
    Object.assign(result, {
      overall: 'INVALID',
      reason: 'SMIME_SIGNATURE_INVALID',
      checks: [{ overall: 'INVALID', reason: 'SMIME_SIGNATURE_INVALID' }],
    });
  };
  const result = expectOverall(await f.app.processSmimeMessage(input), 'INVALID');
  assert.equal(result.reason, 'SMIME_SIGNATURE_INVALID');
  assert.equal(f.count('inspectVerifiedMime'), 0);
  noPrivateAction(f);
});
test('S/MIME constructor rejects an unavailable initial context with a typed error', () => {
  const f = applicationFixture(material);
  assert.throws(
    () =>
      new SmimeApplication({
        backend: f.backend,
        readContext() {
          throw new Error('configuration unavailable');
        },
      }),
    (error) => {
      assert.equal(error.overall, 'INDETERMINATE');
      assert.equal(typeof error.code, 'string');
      return true;
    },
  );
  noPrivateAction(f);
});
test('S/MIME rejects a thenable context without executing a private operation', async () => {
  const f = fixture();
  f.state.contextOverride = (context) => Promise.resolve(context);
  rejected(await f.app.protectSmimeMessage(f.protectInput()));
  noPrivateAction(f);
});
test('S/MIME rejects a thenable mailbox decision without executing a private operation', async () => {
  const f = fixture();
  f.state.mailboxDecision = (_query, result) => Promise.resolve(result);
  rejected(await f.app.protectSmimeMessage(f.protectInput()));
  noPrivateAction(f);
});
test('S/MIME knowledge cannot roll back within an application instance', async () => {
  const f = fixture();
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
  f.state.knowledgeTime -= 1;
  rejected(await f.app.protectSmimeMessage(f.protectInput()));
  assert.equal(f.count('sign'), 1);
});
for (const field of ['trust domain', 'issuer', 'trusted roots']) {
  test(`S/MIME does not change the fixed ${field} namespace between operations`, async () => {
    const f = fixture();
    expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'VALID');
    if (field === 'trust domain') f.policy.scope.trustDomainID[0] ^= 1;
    if (field === 'issuer') f.policy.scope.issuerID = 'different-issuer';
    if (field === 'trusted roots') f.policy.trustedRoots = [alternateSigner.der];
    rejected(await f.app.protectSmimeMessage(f.protectInput()));
    assert.equal(f.count('sign'), 1);
  });
}
for (const field of ['knowledgeTime', 'policy', 'roots', 'readContext']) {
  test(`S/MIME rejects the message-facing ${field} override`, async () => {
    const f = fixture();
    const input = f.protectInput();
    input[field] = field === 'knowledgeTime' ? epoch : f.policy;
    expectOverall(await f.app.protectSmimeMessage(input), 'INVALID');
    noPrivateAction(f);
  });
}

for (const invalidMode of ['', 'ENCRYPTED', 'signed']) {
  test(`S/MIME rejects unselected protection mode ${JSON.stringify(invalidMode)}`, async () => {
    const f = fixture();
    rejected(await f.app.protectSmimeMessage({ ...f.protectInput(), mode: invalidMode }));
    noPrivateAction(f);
  });
}
test('S/MIME encrypted mode needs at least one explicit recipient', async () => {
  const f = fixture();
  const input = f.protectInput('SIGNED_AND_ENCRYPTED');
  input.recipients = [];
  rejected(await f.app.protectSmimeMessage(input));
  noPrivateAction(f);
});
test('S/MIME duplicate recipient keys do not become multiple admitted destinations', async () => {
  const f = fixture();
  const input = f.protectInput('SIGNED_AND_ENCRYPTED');
  input.recipients.push(copy(input.recipients[0]));
  rejected(await f.app.protectSmimeMessage(input));
  noPrivateAction(f);
});
test('S/MIME rejects more than 32 explicit recipients before crypto', async () => {
  const f = fixture();
  const input = f.protectInput('SIGNED_AND_ENCRYPTED');
  input.recipients = Array.from({ length: 33 }, () => copy(input.recipients[0]));
  rejected(await f.app.protectSmimeMessage(input));
  noPrivateAction(f);
});
test('S/MIME rejects a MIME result beyond the canonical entity byte bound', async () => {
  const f = fixture();
  f.hooks.after.prepareMimeMessage = (result) => {
    result.mime = Buffer.alloc(16777217, 0x41);
  };
  expectOverall(await f.app.protectSmimeMessage(f.protectInput()), 'UNSUPPORTED');
  noPrivateAction(f);
});

for (const depth of [16, 17]) {
  test(`S/MIME decoded result enforces depth ${depth} with root at one before content release`, async () => {
    const f = fixture();
    f.hooks.after.inspectVerifiedMime = (result) => {
      const leaf = result.tree[0];
      result.tree = Array.from({ length: depth }, (_, index) => ({
        ...copy(leaf),
        path: Array(index).fill(0),
        mediaType: index === depth - 1 ? 'text/plain' : 'multipart/mixed',
        children: index === depth - 1 ? 0 : 1,
      }));
      result.parts[0].path = Array(depth - 1).fill(0);
    };
    const result = expectOverall(
      await f.app.processSmimeMessage(f.processInput()),
      depth === 16 ? 'VALID' : 'UNSUPPORTED',
    );
    if (depth === 16) {
      assert.deepEqual(result.content.mime, entity);
      assert.deepEqual(result.content.parts[0].path, Array(15).fill(0));
    }
    noPrivateAction(f);
  });
}
