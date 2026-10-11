import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import * as c from './core.mjs';
import { at, epoch, SIGNING, ENCRYPTION, O } from './smime-material-fixtures.mjs';

export const SMIME_OID = Object.freeze({
  data: '1.2.840.113549.1.7.1',
  signed: '1.2.840.113549.1.7.2',
  authenticatedEnvelope: '1.2.840.113549.1.9.16.1.23',
  oaep: '1.2.840.113549.1.1.7',
  mgf1: '1.2.840.113549.1.1.8',
  pSpecified: '1.2.840.113549.1.1.9',
  aes256GCM: '2.16.840.1.101.3.4.1.46',
});
export const entity = Buffer.from(
  'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n' +
    'SW5kZXBlbmRlbnQgbWVzc2FnZS4NCg==\r\n',
);
export const ordinaryMessage = Buffer.from(
  'From: Alice <alice@example.test>\r\nTo: Unselected <elsewhere@example.test>\r\n' +
    'Subject: Fixture message\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nIndependent message.\r\n',
);

export function copy(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(copy);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, copy(entry)]));
  return value;
}
export const publicKeyDER = (certificate) => c.spki(new X509Certificate(certificate).publicKey);
export const identity = (leaf, mailbox) => ({
  mailbox,
  certificateHash: c.sha256(leaf.der),
  keyID: c.keyID(leaf.publicKey),
});
export const claims = (mailbox = 'alice@example.test') => ({
  fromMailbox: mailbox,
  senderMailbox: null,
});
export const outerHeaders = () => [
  {
    name: 'from',
    value: 'Alice <alice@example.test>',
    raw: Buffer.from('From: Alice <alice@example.test>\r\n'),
  },
  {
    name: 'to',
    value: 'Unselected <elsewhere@example.test>',
    raw: Buffer.from('To: Unselected <elsewhere@example.test>\r\n'),
  },
  { name: 'subject', value: 'Fixture message', raw: Buffer.from('Subject: Fixture message\r\n') },
];
export const normalization = () => ({
  textParts: 1,
  lineEndingsChanged: false,
  charsetsChanged: false,
  transferEncodingsChanged: true,
  originalMessageHash: c.sha256(ordinaryMessage),
});

export function noOutput(result) {
  for (const field of ['message', 'authenticatedAuthor', 'content', 'parts', 'plaintext'])
    assert.equal(Object.hasOwn(result, field), false, `Failure must not expose ${field}`);
}
export function expectOverall(result, expected) {
  assert.equal(
    result.overall,
    expected,
    JSON.stringify({ overall: result.overall, reason: result.reason, checks: result.checks }),
  );
  if (expected !== 'VALID') noOutput(result);
  return result;
}
export function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

// This double tests only the application contract. Its CMS identifiers are
// opaque handles; real cryptography and serialization have separate tests.
export function applicationFixture(material) {
  const state = {
    knowledgeTime: at,
    signer: material.signer,
    recipient: material.recipient,
    mailboxDecision: null,
    contextOverride: null,
  };
  const events = [];
  const queries = [];
  const contexts = [];
  const hooks = { before: {}, after: {} };
  const records = new Map();
  const carriers = new Map();
  const keys = new Map([
    ['signer', material.signer.publicKey],
    ['recipient', material.recipient.publicKey],
  ]);
  let sequence = 0;
  const token = (type) => Buffer.from(`${type}:${++sequence}:independent-fixture`);
  const identifier = (leaf) => c.seq(leaf.cert.issuer, c.integer(leaf.cert.serial));
  const oaep = c.seq(
    c.der(0xa0, c.seq(c.oid(O.sha256), c.der(5, Buffer.alloc(0)))),
    c.der(0xa1, c.seq(c.oid(SMIME_OID.mgf1), c.seq(c.oid(O.sha256), c.der(5, Buffer.alloc(0))))),
    c.der(0xa2, c.seq(c.oid(SMIME_OID.pSpecified), c.octet(Buffer.alloc(0)))),
  );
  const signed = (content = entity, leaf = state.signer) => {
    const cms = token('signed');
    records.set(cms.toString('hex'), {
      facts: {
        overall: 'VALID',
        reason: 'SMIME_CMS_VALID',
        checks: [],
        kind: 'SIGNED_DATA',
        contentTypeOID: SMIME_OID.signed,
        content: Buffer.from(content),
        certificate: Buffer.from(leaf.der),
        certificates: [Buffer.from(leaf.der), Buffer.from(material.root.der)],
        crls: [],
        signer: {
          identifierDER: identifier(leaf),
          certificateHash: c.sha256(leaf.der),
          publicKeyDER: c.spki(leaf.publicKey),
          hashOID: O.sha256,
          signatureOID: O.es256,
          claimedSigningTime: epoch + 10,
          signedAttributeOIDs: [
            '1.2.840.113549.1.9.3',
            '1.2.840.113549.1.9.4',
            '1.2.840.113549.1.9.5',
            '1.2.840.113549.1.9.16.2.47',
          ],
        },
        recipients: [],
        recipientMatches: [],
      },
    });
    return cms;
  };
  const envelope = (content, recipients = [state.recipient]) => {
    const cms = token('envelope');
    records.set(cms.toString('hex'), {
      content: Buffer.from(content),
      facts: {
        overall: 'VALID',
        reason: 'SMIME_CMS_VALID',
        checks: [],
        kind: 'AUTH_ENVELOPED_DATA',
        contentTypeOID: SMIME_OID.authenticatedEnvelope,
        certificates: [],
        crls: [],
        recipients: recipients.map((leaf, index) => ({
          index,
          recipientInfoDER: c.seq(c.integer(index)),
          identifierDER: identifier(leaf),
          keyEncryptionOID: SMIME_OID.oaep,
          keyEncryptionParametersDER: Buffer.from(oaep),
          encryptedKey: Buffer.alloc(384, index + 1),
        })),
        recipientMatches: recipients.map((leaf, index) => ({
          index,
          identifierDER: identifier(leaf),
          certificateHash: c.sha256(leaf.der),
          publicKeyDER: c.spki(leaf.publicKey),
        })),
        encryption: {
          contentTypeOID: SMIME_OID.data,
          algorithmOID: SMIME_OID.aes256GCM,
          nonce: Buffer.alloc(12, 0x25),
          tagLength: 16,
          authenticatedAttributesPresent: false,
        },
      },
    });
    return cms;
  };
  const carrier = (cms, kind, format = 'MESSAGE', headers = outerHeaders()) => {
    const message = token('carrier');
    carriers.set(message.toString('hex'), {
      cms: Buffer.from(cms),
      kind,
      format,
      outerHeaders: format === 'MESSAGE' ? copy(headers) : [],
      headerClaims: format === 'MESSAGE' ? claims() : { fromMailbox: null, senderMailbox: null },
    });
    return message;
  };
  const facts = (cms) => records.get(cms.toString('hex'))?.facts;
  const invoke = async (name, args, operation) => {
    events.push({ name, args: copy(args) });
    if (hooks.before[name]) await hooks.before[name](args);
    const result = operation(args);
    if (hooks.after[name]) await hooks.after[name](result, args);
    return result;
  };
  const backend = {
    normalizeMailbox({ mailbox }) {
      assert.equal(typeof mailbox, 'string');
      const match = /^([^@\s]+)@([A-Za-z0-9.-]+)$/.exec(mailbox);
      if (!match)
        throw Object.assign(new Error('mailbox'), {
          overall: 'INVALID',
          code: 'SMIME_MAILBOX_INVALID',
        });
      return { mailbox: `${match[1]}@${match[2].toLowerCase()}` };
    },
    prepareMimeMessage(args) {
      return invoke('prepareMimeMessage', args, () => ({
        mime: Buffer.from(entity),
        outerHeaders: outerHeaders(),
        headerClaims: claims(),
        normalization: normalization(),
      }));
    },
    parseProtectedMessage(args) {
      return invoke('parseProtectedMessage', args, ({ message, format }) => {
        const value = carriers.get(message.toString('hex'));
        assert(value, 'Fixture carrier exists');
        assert.equal(value.format, format, 'MESSAGE/ENTITY boundary');
        const result = copy(value);
        delete result.format;
        return result;
      });
    },
    packageCMS(args) {
      return invoke('packageCMS', args, ({ cms, kind, format, outerHeaders: headers }) => ({
        message: carrier(cms, kind, format, headers),
      }));
    },
    inspectVerifiedMime(args) {
      return invoke('inspectVerifiedMime', args, () => ({
        tree: [
          {
            path: [],
            mediaType: 'text/plain',
            charset: 'utf-8',
            disposition: null,
            filename: null,
            contentID: null,
            children: 0,
          },
        ],
        parts: [
          {
            path: [],
            mediaType: 'text/plain',
            charset: 'utf-8',
            disposition: null,
            filename: null,
            contentID: null,
            bytes: Buffer.from('Independent message.\r\n'),
          },
        ],
      }));
    },
    describeKey(args) {
      return invoke('describeKey', args, ({ keyRef }) => ({
        publicKeyDER: c.spki(keys.get(keyRef)),
      }));
    },
    sign(args) {
      return invoke('sign', args, ({ content }) => ({ cms: signed(content) }));
    },
    inspectCMS(args) {
      return invoke('inspectCMS', args, ({ cms }) => {
        const result = facts(cms);
        assert(result, 'Fixture CMS exists');
        return copy(result);
      });
    },
    encrypt(args) {
      return invoke('encrypt', args, ({ content, certificates }) => ({
        cms: envelope(
          content,
          certificates.map((certificate) => {
            const leaf = [
              state.recipient,
              material.recipient,
              ...(state.extraRecipients ?? []),
            ].find((candidate) => candidate.der.equals(certificate));
            assert(leaf, 'Fixture recipient is registered');
            return leaf;
          }),
        ),
      }));
    },
    decrypt(args) {
      return invoke('decrypt', args, ({ cms, certificate }) => {
        const record = records.get(cms.toString('hex'));
        const match = record.facts.recipientMatches.find((item) =>
          item.certificateHash.equals(c.sha256(certificate)),
        );
        assert(match, 'Fixture recipient matches');
        return { content: Buffer.from(record.content), recipient: copy(match) };
      });
    },
  };
  const binding = (query) => ({
    mailbox: query.mailbox,
    purpose: query.purpose,
    certificateHash: Buffer.from(query.certificateHash),
    keyID: Buffer.from(query.keyID),
    scope: copy(query.scope),
    knownAt: epoch - 1000,
    validFrom: epoch - 1000,
    validUntil: epoch + 100000,
    provenance: 'TRUSTED_CONFIGURATION',
  });
  const mailboxResolver = (query) => {
    queries.push(copy(query));
    const result = { overall: 'VALID', reason: 'FIXTURE_BINDING_VALID', binding: binding(query) };
    return state.mailboxDecision ? state.mailboxDecision(query, result) : result;
  };
  const policy = material.policy(SIGNING, {
    scope: material.scope('SMIME_APPLICATION'),
    mailboxResolver,
    algorithmDeadlines: {
      [O.es256]: epoch + 100000,
      [SMIME_OID.oaep]: epoch + 100000,
      [SMIME_OID.aes256GCM]: epoch + 100000,
    },
    currentMaterial: {
      certificates: [Buffer.from(material.root.der)],
      crls: [Buffer.from(material.defaultCRL)],
    },
  });
  const readContext = () => {
    const value = { knowledgeTime: state.knowledgeTime, policy };
    contexts.push(state.knowledgeTime);
    return state.contextOverride ? state.contextOverride(value) : value;
  };
  const protectInput = (mode = 'SIGNED') => ({
    message: Buffer.from(ordinaryMessage),
    mode,
    senderMailbox: 'alice@example.test',
    signer: { certificate: Buffer.from(state.signer.der), keyRef: 'signer' },
    recipients:
      mode === 'SIGNED_AND_ENCRYPTED'
        ? [{ mailbox: 'bob@example.test', certificate: Buffer.from(state.recipient.der) }]
        : [],
  });
  const incoming = (mode = 'SIGNED', leaf = state.signer) => {
    const cms = signed(entity, leaf);
    if (mode === 'SIGNED') return carrier(cms, 'SIGNED_DATA');
    const inner = carrier(cms, 'SIGNED_DATA', 'ENTITY');
    return carrier(envelope(inner), 'AUTH_ENVELOPED_DATA');
  };
  const processInput = (mode = 'SIGNED') => ({
    message: incoming(mode),
    requiredProtection: mode,
    expectedSenderMailbox: 'alice@example.test',
    ...(mode === 'SIGNED_AND_ENCRYPTED'
      ? {
          recipient: {
            mailbox: 'bob@example.test',
            certificate: Buffer.from(state.recipient.der),
            keyRef: 'recipient',
          },
        }
      : {}),
  });
  const count = (name) => events.filter((event) => event.name === name).length;
  return {
    state,
    events,
    queries,
    contexts,
    hooks,
    records,
    carriers,
    keys,
    backend,
    policy,
    readContext,
    binding,
    facts,
    signed,
    envelope,
    carrier,
    incoming,
    protectInput,
    processInput,
    count,
  };
}
