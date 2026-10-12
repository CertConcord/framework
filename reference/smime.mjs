import { ProtocolError, dcbor, equal, integer, keyID, seq, sha256 } from './core.mjs';
import { types } from 'node:util';
import { parseCertificate } from './pki.mjs';
import { validateSmimeMaterial } from './cades-validation.mjs';

const PROFILE = 'certconcord-smime-application-v1';
const SIGNING = 'SMIME_SIGNING';
const RECIPIENT = 'SMIME_RECIPIENT_ENCRYPTION';
const MODES = ['SIGNED', 'SIGNED_AND_ENCRYPTED'];
const OUTCOMES = ['INVALID', 'UNSUPPORTED', 'INDETERMINATE', 'VALID'];
const OID = {
  data: '1.2.840.113549.1.7.1',
  signed: '1.2.840.113549.1.7.2',
  enveloped: '1.2.840.113549.1.9.16.1.23',
  sha256: '2.16.840.1.101.3.4.2.1',
  es256: '1.2.840.10045.4.3.2',
  oaep: '1.2.840.113549.1.1.7',
  gcm: '2.16.840.1.101.3.4.1.46',
};
const MAX_INPUT = 32 * 1024 * 1024;
const MAX_MIME = 16 * 1024 * 1024;
const STOP = Symbol('unaccepted');
const METHODS = [
  'normalizeMailbox',
  'prepareMimeMessage',
  'parseProtectedMessage',
  'packageCMS',
  'inspectVerifiedMime',
  'describeKey',
  'sign',
  'inspectCMS',
  'encrypt',
  'decrypt',
];

function failure(code, overall = 'INVALID') {
  const error = new ProtocolError(code);
  error.overall = overall;
  return error;
}
function check(condition, code, overall = 'INVALID') {
  if (!condition) throw failure(code, overall);
}
const instant = (value) => Number.isSafeInteger(value) && value >= 0;
const plain = (value) =>
  value !== null &&
  typeof value === 'object' &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));
function fields(value, allowed, required = []) {
  check(plain(value), 'SMIME_OPTIONS_REQUIRED');
  check(
    Object.keys(value).every((key) => allowed.includes(key)),
    'SMIME_UNKNOWN_OPTION',
  );
  check(
    required.every((key) => Object.hasOwn(value, key)),
    'SMIME_OPTION_REQUIRED',
  );
}
function bytes(value, maximum = MAX_INPUT, empty = false) {
  check(Buffer.isBuffer(value), 'SMIME_BYTES_REQUIRED');
  check(empty || value.length > 0, 'SMIME_EMPTY_BYTES');
  check(value.length <= maximum, 'SMIME_BYTE_LIMIT', 'UNSUPPORTED');
  return Buffer.from(value);
}
function byteList(value, maximum = 32) {
  check(Array.isArray(value), 'SMIME_MATERIAL_INPUT_INVALID');
  check(value.length <= maximum, 'SMIME_MATERIAL_LIMIT_UNSUPPORTED', 'UNSUPPORTED');
  let total = 0;
  return Array.from(value, (raw) => {
    check(Buffer.isBuffer(raw), 'SMIME_MATERIAL_INPUT_INVALID');
    total += raw.length;
    check(total <= MAX_INPUT, 'SMIME_MATERIAL_LIMIT_UNSUPPORTED', 'UNSUPPORTED');
    return bytes(raw);
  });
}
function label(value) {
  check(typeof value === 'string' && value.length > 0 && value.length <= 1024, 'SMIME_KEY_REF');
  return value;
}

// A rejected native Promise is still an unavailable synchronous dependency.
// Observe its rejection without awaiting it or invoking an arbitrary thenable.
function synchronous(value, code) {
  if (types.isPromise(value)) {
    Promise.prototype.then.call(value, undefined, () => {});
    throw failure(code, 'INDETERMINATE');
  }
  check(!value?.then, code, 'INDETERMINATE');
  return value;
}

// Callbacks and backend workers receive only detached views. A bounded snapshot
// also prevents a returned object graph from bypassing the selected byte limits.
function snapshot(value, budget = { bytes: 0, nodes: 0 }, depth = 0, ancestors = new Set()) {
  check(depth <= 40 && ++budget.nodes <= 50000, 'SMIME_RESULT_LIMIT', 'UNSUPPORTED');
  if (Buffer.isBuffer(value)) {
    budget.bytes += value.length;
    check(budget.bytes <= 128 * 1024 * 1024, 'SMIME_RESULT_LIMIT', 'UNSUPPORTED');
    return Buffer.from(value);
  }
  if (
    value === null ||
    value === undefined ||
    ['number', 'boolean', 'bigint'].includes(typeof value)
  )
    return value;
  if (typeof value === 'string') {
    budget.bytes += Buffer.byteLength(value);
    check(budget.bytes <= 128 * 1024 * 1024, 'SMIME_RESULT_LIMIT', 'UNSUPPORTED');
    return value;
  }
  check(Array.isArray(value) || plain(value), 'SMIME_RESULT_SHAPE');
  check(!ancestors.has(value), 'SMIME_RESULT_SHAPE');
  ancestors.add(value);
  const copied = Array.isArray(value)
    ? Array.from(value, (item) => snapshot(item, budget, depth + 1, ancestors))
    : Object.fromEntries(
        Object.entries(value).map(([name, item]) => [
          name,
          snapshot(item, budget, depth + 1, ancestors),
        ]),
      );
  ancestors.delete(value);
  return copied;
}
function errorCheck(error, fallback = 'SMIME_VALIDATION_FAILED', overall = 'INVALID') {
  return {
    overall: OUTCOMES.slice(0, 3).includes(error?.overall) ? error.overall : overall,
    reason: typeof error?.code === 'string' ? error.code : fallback,
  };
}
function add(run, value, stage) {
  check(value && OUTCOMES.includes(value.overall), 'SMIME_RESULT_SHAPE');
  const complete = typeof value.reason === 'string' && value.reason.length > 0;
  // Missing decision metadata cannot establish acceptance or erase a known failure.
  run.checks.push({
    overall: !complete && value.overall === 'VALID' ? 'INDETERMINATE' : value.overall,
    reason: complete ? value.reason : 'SMIME_DECISION_INCOMPLETE',
    stage,
  });
}
function collect(run, stage, operation) {
  try {
    return operation();
  } catch (error) {
    add(run, errorCheck(error), stage);
    return undefined;
  }
}
function aggregate(checks) {
  return OUTCOMES.slice(0, 3)
    .map((overall) => checks.find((entry) => entry.overall === overall))
    .find(Boolean);
}
function requireAccepted(run) {
  if (aggregate(run.checks)) throw STOP;
}
function result(run, details = {}) {
  const rejected = aggregate(run.checks);
  return Object.freeze(
    snapshot({
      ...(rejected ? {} : details),
      overall: rejected?.overall ?? 'VALID',
      reason: rejected?.reason ?? 'SMIME_VALID',
      knowledgeTime: run.knowledgeTime,
      ...(rejected ? { effectMayHaveOccurred: run.effectMayHaveOccurred } : {}),
      checks: run.checks,
    }),
  );
}
function scopeFor(scope, purpose) {
  return { ...scope, trustDomainID: Buffer.from(scope.trustDomainID), purpose };
}
function publicIdentity(credential) {
  return {
    mailbox: credential.mailbox,
    certificateHash: Buffer.from(credential.identity.certificateHash),
    keyID: Buffer.from(credential.identity.keyID),
  };
}
function certificateFacts(raw) {
  const certificate = parseCertificate(raw);
  return {
    certificateHash: sha256(raw),
    keyID: keyID(certificate.publicKey),
    publicKeyDER: Buffer.from(certificate.spki),
    identifierDER: seq(certificate.issuer, integer(certificate.serial)),
  };
}
function deadlineMap(value) {
  if (value === undefined) return {};
  check(plain(value) && Object.keys(value).length <= 1024, 'SMIME_PROTECTION_POLICY');
  const copied = Object.fromEntries(Object.entries(value));
  check(
    Object.values(copied).every((n) => instant(n)),
    'SMIME_PROTECTION_POLICY',
  );
  return copied;
}
function contextShape(raw) {
  fields(raw, ['knowledgeTime', 'policy'], ['knowledgeTime', 'policy']);
  check(instant(raw.knowledgeTime), 'SMIME_KNOWLEDGE_TIME', 'INDETERMINATE');
  const input = raw.policy;
  fields(
    input,
    [
      'scope',
      'trustedRoots',
      'authorityResolver',
      'mailboxResolver',
      'currentMaterial',
      'algorithmDeadlines',
      'hashDeadlines',
      'keyDeadlines',
    ],
    ['scope', 'trustedRoots'],
  );
  const scope = snapshot(input.scope);
  fields(scope, ['trustDomainID', 'issuerID', 'representation', 'profileID', 'purpose']);
  check(
    Buffer.isBuffer(scope.trustDomainID) &&
      scope.trustDomainID.length === 32 &&
      typeof scope.issuerID === 'string' &&
      scope.issuerID.length > 0 &&
      scope.issuerID.length <= 1024 &&
      scope.representation === 'X509' &&
      scope.profileID === PROFILE &&
      scope.purpose === 'SMIME_APPLICATION',
    'SMIME_AUTHORITY_SCOPE',
  );
  const trustedRoots = byteList(input.trustedRoots);
  check(trustedRoots.length > 0, 'SMIME_TRUST_ROOTS_REQUIRED', 'INDETERMINATE');
  check(
    typeof input.authorityResolver === 'function' && typeof input.mailboxResolver === 'function',
    'SMIME_RESOLVERS_REQUIRED',
    'INDETERMINATE',
  );
  const current = input.currentMaterial ?? {};
  fields(current, ['certificates', 'crls']);
  const policy = {
    scope,
    trustedRoots,
    authorityResolver: input.authorityResolver,
    mailboxResolver: input.mailboxResolver,
    currentMaterial: {
      certificates: byteList(current.certificates ?? []),
      crls: byteList(current.crls ?? []),
    },
    algorithmDeadlines: deadlineMap(input.algorithmDeadlines),
    hashDeadlines: deadlineMap(input.hashDeadlines),
    keyDeadlines: deadlineMap(input.keyDeadlines),
  };
  return {
    knowledgeTime: raw.knowledgeTime,
    policy,
    binding: sha256(
      dcbor({
        scope,
        trustedRoots: [...new Set(trustedRoots.map((der) => der.toString('hex')))].sort(),
      }),
    ),
  };
}
function validateHeaders(headers) {
  check(Array.isArray(headers), 'SMIME_HEADERS_REQUIRED');
  check(headers.length <= 128, 'SMIME_HEADER_LIMIT', 'UNSUPPORTED');
  let length = 0;
  for (const header of headers) {
    fields(header, ['name', 'value', 'raw'], ['name', 'value', 'raw']);
    check(
      typeof header.name === 'string' &&
        /^[!#$%&'*+\-.^_`|~0-9a-z]+$/.test(header.name) &&
        typeof header.value === 'string' &&
        Buffer.isBuffer(header.raw),
      'SMIME_HEADER_SHAPE',
    );
    length += header.raw.length;
  }
  check(length <= 65536, 'SMIME_HEADER_LIMIT', 'UNSUPPORTED');
}

/** Current-use local S/MIME transformations. This class has no delivery or replay service. */
export class SmimeApplication {
  #read;
  #backend;
  #binding;
  #authority;
  #mailboxResolver;
  #last;

  constructor(options) {
    fields(options, ['readContext', 'backend'], ['readContext', 'backend']);
    check(typeof options.readContext === 'function', 'SMIME_CONTEXT_REQUIRED');
    check(options.backend && typeof options.backend === 'object', 'SMIME_BACKEND_REQUIRED');
    this.#read = options.readContext;
    this.#backend = Object.fromEntries(
      METHODS.map((name) => {
        const method = options.backend[name];
        check(typeof method === 'function', 'SMIME_BACKEND_METHOD_REQUIRED');
        return [name, method.bind(options.backend)];
      }),
    );
    const initial = this.#readContext();
    this.#binding = initial.binding;
    this.#authority = initial.policy.authorityResolver;
    this.#mailboxResolver = initial.policy.mailboxResolver;
  }

  #readContext() {
    let value;
    try {
      const raw = synchronous(this.#read(), 'SMIME_CONTEXT_UNAVAILABLE');
      check(raw, 'SMIME_CONTEXT_UNAVAILABLE', 'INDETERMINATE');
      value = contextShape(raw);
    } catch (error) {
      if (error?.overall) throw error;
      throw failure('SMIME_CONTEXT_UNAVAILABLE', 'INDETERMINATE');
    }
    check(
      this.#last === undefined || value.knowledgeTime >= this.#last,
      'SMIME_KNOWLEDGE_TIME_ROLLBACK',
      'INDETERMINATE',
    );
    this.#last = value.knowledgeTime;
    check(
      !this.#binding ||
        (equal(this.#binding, value.binding) &&
          this.#authority === value.policy.authorityResolver &&
          this.#mailboxResolver === value.policy.mailboxResolver),
      'SMIME_CONTEXT_BINDING',
    );
    return value;
  }

  #mailbox(value) {
    check(typeof value === 'string' && value.length > 0, 'SMIME_MAILBOX_REQUIRED');
    check(value.length <= 1024, 'SMIME_MAILBOX_LIMIT', 'UNSUPPORTED');
    let normalized;
    try {
      normalized = synchronous(
        this.#backend.normalizeMailbox({ mailbox: value }),
        'SMIME_BACKEND_UNAVAILABLE',
      );
      normalized = snapshot(normalized);
    } catch (error) {
      if (error?.overall) throw error;
      throw failure('SMIME_BACKEND_UNAVAILABLE', 'INDETERMINATE');
    }
    check(
      typeof normalized?.mailbox === 'string' &&
        normalized.mailbox.length > 0 &&
        normalized.mailbox.length <= 1024,
      'SMIME_MAILBOX_RESULT',
    );
    return normalized.mailbox;
  }

  async #invoke(name, input) {
    try {
      return snapshot(await this.#backend[name](snapshot(input)));
    } catch (error) {
      if (
        Object.hasOwn(error ?? {}, 'code') &&
        Object.hasOwn(error ?? {}, 'overall') &&
        OUTCOMES.slice(0, 3).includes(error.overall)
      )
        throw failure(error.code, error.overall);
      throw failure('SMIME_BACKEND_UNAVAILABLE', 'INDETERMINATE');
    }
  }

  #credential(mailbox, certificate, purpose, details = {}) {
    return {
      mailbox,
      certificate: bytes(certificate),
      purpose,
      certificates: [],
      crls: [],
      ...details,
    };
  }

  #bindMailbox(credential, identity, policy, knowledgeTime) {
    for (const name of identity.certificateNames.rfc822Names) this.#mailbox(name.value);
    check(
      identity.certificateNames.rfc822Names.length === 0 ||
        identity.certificateNames.rfc822Names.some(
          (name) => this.#mailbox(name.value) === credential.mailbox,
        ),
      'SMIME_CERTIFICATE_MAILBOX_MISMATCH',
    );
    const scope = scopeFor(policy.scope, credential.purpose);
    const expected = {
      mailbox: credential.mailbox,
      purpose: credential.purpose,
      certificateHash: Buffer.from(identity.certificateHash),
      keyID: Buffer.from(identity.keyID),
      scope,
    };
    let decision;
    try {
      const raw = synchronous(
        this.#mailboxResolver(snapshot({ ...expected, stateTime: knowledgeTime, knowledgeTime })),
        'SMIME_MAILBOX_DECISION_MISSING',
      );
      decision = snapshot(raw);
    } catch (error) {
      if (error?.overall) throw error;
      throw failure('SMIME_MAILBOX_UNAVAILABLE', 'INDETERMINATE');
    }
    check(
      decision && OUTCOMES.includes(decision.overall),
      'SMIME_MAILBOX_DECISION_MISSING',
      'INDETERMINATE',
    );
    if (decision.overall !== 'VALID')
      throw failure(
        typeof decision.reason === 'string' ? decision.reason : 'SMIME_MAILBOX_NOT_ADMITTED',
        decision.overall,
      );
    const binding = decision.binding;
    check(plain(binding), 'SMIME_MAILBOX_BINDING_MISSING', 'INDETERMINATE');
    check(
      [
        'mailbox',
        'purpose',
        'certificateHash',
        'keyID',
        'scope',
        'knownAt',
        'validFrom',
        'validUntil',
        'provenance',
      ].every((name) => Object.hasOwn(binding, name)),
      'SMIME_MAILBOX_BINDING_MISSING',
      'INDETERMINATE',
    );
    fields(
      binding,
      [
        'mailbox',
        'purpose',
        'certificateHash',
        'keyID',
        'scope',
        'knownAt',
        'validFrom',
        'validUntil',
        'provenance',
      ],
      [
        'mailbox',
        'purpose',
        'certificateHash',
        'keyID',
        'scope',
        'knownAt',
        'validFrom',
        'validUntil',
        'provenance',
      ],
    );
    check(
      binding.mailbox === expected.mailbox &&
        binding.purpose === expected.purpose &&
        equal(binding.certificateHash, expected.certificateHash) &&
        equal(binding.keyID, expected.keyID) &&
        equal(dcbor(binding.scope), dcbor(expected.scope)),
      'SMIME_MAILBOX_BINDING_MISMATCH',
    );
    check(
      binding.provenance === 'TRUSTED_CONFIGURATION',
      'SMIME_MAILBOX_PROVENANCE_UNSUPPORTED',
      'UNSUPPORTED',
    );
    check(
      [binding.knownAt, binding.validFrom, binding.validUntil].every(instant) &&
        binding.validUntil > binding.validFrom,
      'SMIME_MAILBOX_BINDING_TIME',
    );
    check(binding.knownAt <= knowledgeTime, 'SMIME_MAILBOX_NOT_YET_KNOWN', 'INDETERMINATE');
    check(
      binding.validFrom <= knowledgeTime && knowledgeTime < binding.validUntil,
      'SMIME_MAILBOX_BINDING_TIME',
    );
  }

  #refresh(run, credentials, mode, stage) {
    run.started = true;
    const context = collect(run, stage, () => this.#readContext());
    if (!context) return;
    run.knowledgeTime = context.knowledgeTime;
    if (mode === 'SIGNED_AND_ENCRYPTED') {
      for (const oid of [OID.oaep, OID.gcm])
        collect(run, stage, () => {
          const cutoff = context.policy.algorithmDeadlines[oid];
          check(instant(cutoff), 'SMIME_ENCRYPTION_DEADLINE_REQUIRED', 'INDETERMINATE');
          check(context.knowledgeTime < cutoff, 'SMIME_ENCRYPTION_PROTECTION_EXPIRED');
        });
    }
    for (const credential of credentials) {
      const material = collect(run, stage, () =>
        validateSmimeMaterial({
          certificate: Buffer.from(credential.certificate),
          certificates: credential.certificates.map((raw) => Buffer.from(raw)),
          crls: credential.crls.map((raw) => Buffer.from(raw)),
          purpose: credential.purpose,
          knowledgeTime: context.knowledgeTime,
          policy: {
            ...context.policy,
            scope: scopeFor(context.policy.scope, credential.purpose),
            authorityResolver: (query) =>
              synchronous(this.#authority(query), 'SMIME_AUTHORITY_UNAVAILABLE'),
          },
        }),
      );
      if (!material) continue;
      credential.material = material;
      for (const [index, entry] of material.checks.entries()) {
        const expired =
          credential.incomingSigner && material.ordinaryTimeCheckIndexes.includes(index);
        add(
          run,
          expired ? { overall: 'INDETERMINATE', reason: 'SMIME_SIGNER_VALIDITY_UNPROVEN' } : entry,
          stage,
        );
        if (expired) run.checks.at(-1).originalReason = entry.reason;
      }
      if (material.checks.length === 0) add(run, material, stage);
      if (!material.identity) continue;
      credential.identity = material.identity;
      if (credential.expectedPublicKeyDER)
        collect(run, stage, () =>
          check(
            equal(credential.expectedPublicKeyDER, material.identity.publicKeyDER),
            'SMIME_PRIVATE_KEY_BINDING',
          ),
        );
      collect(run, stage, () =>
        this.#bindMailbox(credential, material.identity, context.policy, context.knowledgeTime),
      );
    }
  }

  #headers(run, headers, claims, expected, stage, { outbound = false, entity = false } = {}) {
    collect(run, stage, () => {
      validateHeaders(headers);
      fields(claims, ['fromMailbox', 'senderMailbox'], ['fromMailbox', 'senderMailbox']);
      if (entity) {
        check(
          headers.length === 0 && claims.fromMailbox === null && claims.senderMailbox === null,
          'SMIME_INNER_OUTER_HEADERS',
        );
        return;
      }
      check(
        this.#mailbox(claims.fromMailbox) === expected &&
          (claims.senderMailbox === null || this.#mailbox(claims.senderMailbox) === expected),
        'SMIME_HEADER_MAILBOX_MISMATCH',
      );
      if (outbound)
        check(
          !headers.some((header) => header.name === 'bcc' && header.value.trim().length > 0),
          'SMIME_BCC_UNSUPPORTED',
          'UNSUPPORTED',
        );
    });
  }

  #inspection(run, inspected, expectedKind, stage, nested = false) {
    collect(run, stage, () => {
      check(plain(inspected) && OUTCOMES.includes(inspected.overall), 'SMIME_CMS_RESULT');
      check(Array.isArray(inspected.checks) && inspected.checks.length <= 2048, 'SMIME_CMS_RESULT');
      for (const entry of inspected.checks) add(run, entry, stage);
      add(run, inspected, stage);
    });
    collect(run, stage, () => {
      if (!['SIGNED_DATA', 'AUTH_ENVELOPED_DATA'].includes(inspected.kind)) {
        check(inspected.overall !== 'VALID', 'SMIME_CMS_RESULT');
        return;
      }
      if (nested && inspected.kind === 'AUTH_ENVELOPED_DATA')
        throw failure('SMIME_CMS_NESTING_UNSUPPORTED', 'UNSUPPORTED');
      check(
        inspected.kind === expectedKind &&
          inspected.contentTypeOID ===
            (expectedKind === 'SIGNED_DATA' ? OID.signed : OID.enveloped),
        'SMIME_CMS_LAYER_MISMATCH',
      );
    });
  }

  #signed(run, inspected, mailbox, stage, expected) {
    return collect(run, stage, () => {
      if (!inspected.certificate || !inspected.content || !inspected.signer) {
        check(inspected.overall !== 'VALID', 'SMIME_CMS_RESULT');
        return undefined;
      }
      const certificate = bytes(inspected.certificate),
        content = bytes(inspected.content, MAX_MIME, true),
        certificates = byteList(inspected.certificates),
        crls = byteList(inspected.crls),
        facts = certificateFacts(certificate),
        signer = inspected.signer;
      check(
        certificates.some((raw) => equal(raw, certificate)),
        'SMIME_SIGNER_NOT_EMBEDDED',
      );
      check(
        equal(facts.certificateHash, signer.certificateHash) &&
          equal(facts.publicKeyDER, signer.publicKeyDER) &&
          equal(facts.identifierDER, signer.identifierDER),
        'SMIME_SIGNER_BINDING',
      );
      check(
        signer.hashOID === OID.sha256 && signer.signatureOID === OID.es256,
        'SMIME_SIGNATURE_SUITE_UNSUPPORTED',
        'UNSUPPORTED',
      );
      if (expected)
        check(
          equal(certificate, expected.certificate) && equal(content, expected.content),
          'SMIME_SIGNED_OUTPUT_BINDING',
        );
      return this.#credential(mailbox, certificate, SIGNING, {
        certificates,
        crls,
        incomingSigner: !expected,
        content,
      });
    });
  }

  #envelope(run, inspected, credentials, stage, exactSet) {
    return collect(run, stage, () => {
      const infos = inspected.recipients,
        matches = inspected.recipientMatches,
        encryption = inspected.encryption;
      if (
        (!Array.isArray(infos) || infos.length === 0 || !encryption) &&
        inspected.overall !== 'VALID'
      )
        return undefined;
      check(Array.isArray(infos) && Array.isArray(matches), 'SMIME_CMS_RESULT');
      check(infos.length > 0 && infos.length <= 32, 'SMIME_RECIPIENT_LIMIT', 'UNSUPPORTED');
      check(matches.length <= 32, 'SMIME_RECIPIENT_LIMIT', 'UNSUPPORTED');
      check(
        encryption?.contentTypeOID === OID.data &&
          encryption.algorithmOID === OID.gcm &&
          Buffer.isBuffer(encryption.nonce) &&
          encryption.nonce.length === 12 &&
          encryption.tagLength === 16 &&
          encryption.authenticatedAttributesPresent === false,
        'SMIME_ENCRYPTION_SUITE_UNSUPPORTED',
        'UNSUPPORTED',
      );
      const indexes = new Set(),
        identifiers = new Set();
      for (const info of infos) {
        check(
          Number.isSafeInteger(info.index) &&
            info.index >= 0 &&
            info.index < infos.length &&
            Buffer.isBuffer(info.identifierDER) &&
            Buffer.isBuffer(info.recipientInfoDER) &&
            Buffer.isBuffer(info.encryptedKey) &&
            info.encryptedKey.length > 0 &&
            Buffer.isBuffer(info.keyEncryptionParametersDER),
          'SMIME_RECIPIENT_INFO',
        );
        check(
          info.keyEncryptionOID === OID.oaep,
          'SMIME_RECIPIENT_SUITE_UNSUPPORTED',
          'UNSUPPORTED',
        );
        check(
          !indexes.has(info.index) && !identifiers.has(info.identifierDER.toString('hex')),
          'SMIME_DUPLICATE_RECIPIENT',
        );
        indexes.add(info.index);
        identifiers.add(info.identifierDER.toString('hex'));
      }
      const selected = credentials.map((credential) => {
        const facts = certificateFacts(credential.certificate);
        const candidates = matches.filter((match) =>
          equal(match.certificateHash, facts.certificateHash),
        );
        check(candidates.length === 1, 'SMIME_RECIPIENT_MATCH');
        const match = candidates[0],
          info = infos.find((entry) => entry.index === match.index);
        check(
          info &&
            equal(match.publicKeyDER, facts.publicKeyDER) &&
            equal(match.identifierDER, facts.identifierDER) &&
            equal(info.identifierDER, facts.identifierDER),
          'SMIME_RECIPIENT_BINDING',
        );
        return snapshot(match);
      });
      if (exactSet)
        check(
          matches.length === credentials.length &&
            infos.length === credentials.length &&
            new Set(selected.map((entry) => entry.index)).size === credentials.length,
          'SMIME_RECIPIENT_SET_MISMATCH',
        );
      return selected;
    });
  }

  #catch(run, error, credentials, mode) {
    if (error !== STOP) {
      add(run, errorCheck(error), 'operation');
      if (run.started)
        collect(run, 'failure-context', () =>
          this.#refresh(run, credentials, mode, 'failure-context'),
        );
    }
    return result(run);
  }

  async protectSmimeMessage(options) {
    const run = { checks: [], knowledgeTime: null, effectMayHaveOccurred: false, started: false };
    const credentials = [];
    let mode;
    try {
      fields(
        options,
        ['message', 'mode', 'senderMailbox', 'signer', 'recipients'],
        ['message', 'mode', 'senderMailbox', 'signer'],
      );
      const message = bytes(options.message);
      mode = options.mode;
      check(MODES.includes(mode), 'SMIME_PROTECTION_UNSUPPORTED', 'UNSUPPORTED');
      fields(options.signer, ['certificate', 'keyRef'], ['certificate', 'keyRef']);
      const senderInput = {
        certificate: bytes(options.signer.certificate),
        keyRef: label(options.signer.keyRef),
      };
      const recipientInputs = options.recipients ?? [];
      check(Array.isArray(recipientInputs), 'SMIME_RECIPIENTS_REQUIRED');
      check(recipientInputs.length <= 32, 'SMIME_RECIPIENT_LIMIT', 'UNSUPPORTED');
      const copiedRecipients = Array.from(recipientInputs, (entry) => {
        fields(entry, ['mailbox', 'certificate'], ['mailbox', 'certificate']);
        return { mailbox: entry.mailbox, certificate: bytes(entry.certificate) };
      });
      const mailbox = this.#mailbox(options.senderMailbox);
      const sender = this.#credential(mailbox, senderInput.certificate, SIGNING, {
        keyRef: senderInput.keyRef,
      });
      const recipients = copiedRecipients.map((entry) =>
        this.#credential(this.#mailbox(entry.mailbox), entry.certificate, RECIPIENT),
      );
      credentials.push(sender, ...recipients);
      check(
        mode === 'SIGNED' ? recipients.length === 0 : recipients.length > 0,
        'SMIME_RECIPIENT_MODE',
      );
      const recipientKeys = recipients.map((entry) =>
        certificateFacts(entry.certificate).keyID.toString('hex'),
      );
      check(new Set(recipientKeys).size === recipientKeys.length, 'SMIME_DUPLICATE_RECIPIENT_KEY');
      this.#refresh(run, credentials, mode, 'prepare-admission');
      const prepared = await this.#invoke('prepareMimeMessage', { message });
      this.#refresh(run, credentials, mode, 'prepared-admission');
      const mime = bytes(prepared.mime, MAX_MIME, true);
      this.#headers(
        run,
        prepared.outerHeaders,
        prepared.headerClaims,
        mailbox,
        'prepared-headers',
        { outbound: true },
      );
      const normalization = prepared.normalization;
      collect(run, 'normalization', () => {
        fields(
          normalization,
          [
            'textParts',
            'lineEndingsChanged',
            'charsetsChanged',
            'transferEncodingsChanged',
            'originalMessageHash',
          ],
          [
            'textParts',
            'lineEndingsChanged',
            'charsetsChanged',
            'transferEncodingsChanged',
            'originalMessageHash',
          ],
        );
        check(
          ['textParts', 'lineEndingsChanged', 'charsetsChanged', 'transferEncodingsChanged'].every(
            (name) => instant(normalization[name]),
          ) && equal(normalization.originalMessageHash, sha256(message)),
          'SMIME_NORMALIZATION_BINDING',
        );
      });
      requireAccepted(run);
      const described = await this.#invoke('describeKey', { keyRef: sender.keyRef });
      sender.expectedPublicKeyDER = bytes(described.publicKeyDER);
      this.#refresh(run, credentials, mode, 'sign-admission');
      requireAccepted(run);
      run.effectMayHaveOccurred = true;
      const signed = await this.#invoke('sign', {
        content: mime,
        certificate: sender.certificate,
        certificates: sender.material.usedCertificates.filter(
          (raw) => !equal(raw, sender.certificate),
        ),
        keyRef: sender.keyRef,
        expectedPublicKeyDER: sender.expectedPublicKeyDER,
      });
      this.#refresh(run, credentials, mode, 'signed-admission');
      let cms = bytes(signed.cms),
        kind = 'SIGNED_DATA';
      const inspected = await this.#invoke('inspectCMS', { cms });
      this.#refresh(run, credentials, mode, 'signed-inspection-admission');
      this.#inspection(run, inspected, 'SIGNED_DATA', 'signed-inspection');
      const signedCredential = this.#signed(run, inspected, mailbox, 'signed-binding', {
        certificate: sender.certificate,
        content: mime,
      });
      if (signedCredential) {
        sender.certificates = signedCredential.certificates;
        sender.crls = signedCredential.crls;
        this.#refresh(run, credentials, mode, 'signed-material-admission');
      }
      requireAccepted(run);
      if (mode === 'SIGNED_AND_ENCRYPTED') {
        const carrier = await this.#invoke('packageCMS', { cms, kind, format: 'ENTITY' });
        this.#refresh(run, credentials, mode, 'inner-packaging-admission');
        const entity = bytes(carrier.message);
        const reread = await this.#invoke('parseProtectedMessage', {
          message: entity,
          format: 'ENTITY',
        });
        this.#refresh(run, credentials, mode, 'inner-carrier-admission');
        collect(run, 'inner-carrier-binding', () =>
          check(reread.kind === kind && equal(reread.cms, cms), 'SMIME_CARRIER_BINDING'),
        );
        this.#headers(
          run,
          reread.outerHeaders,
          reread.headerClaims,
          mailbox,
          'inner-carrier-headers',
          { entity: true },
        );
        requireAccepted(run);
        const encrypted = await this.#invoke('encrypt', {
          content: entity,
          certificates: recipients.map((entry) => entry.certificate),
        });
        this.#refresh(run, credentials, mode, 'encrypted-admission');
        cms = bytes(encrypted.cms);
        kind = 'AUTH_ENVELOPED_DATA';
        const inspectedEnvelope = await this.#invoke('inspectCMS', {
          cms,
          recipientCertificates: recipients.map((entry) => entry.certificate),
        });
        this.#refresh(run, credentials, mode, 'envelope-inspection-admission');
        this.#inspection(run, inspectedEnvelope, kind, 'envelope-inspection');
        this.#envelope(run, inspectedEnvelope, recipients, 'envelope-binding', true);
        requireAccepted(run);
      }
      const packaged = await this.#invoke('packageCMS', {
        cms,
        kind,
        format: 'MESSAGE',
        outerHeaders: prepared.outerHeaders,
      });
      this.#refresh(run, credentials, mode, 'packaging-admission');
      const output = bytes(packaged.message);
      const reread = await this.#invoke('parseProtectedMessage', {
        message: output,
        format: 'MESSAGE',
      });
      this.#refresh(run, credentials, mode, 'release-admission');
      collect(run, 'carrier-binding', () =>
        check(reread.kind === kind && equal(reread.cms, cms), 'SMIME_CARRIER_BINDING'),
      );
      this.#headers(run, reread.outerHeaders, reread.headerClaims, mailbox, 'carrier-headers', {
        outbound: true,
      });
      requireAccepted(run);
      return result(run, {
        message: output,
        canonicalMimeHash: sha256(mime),
        sender: publicIdentity(sender),
        admittedRecipients: recipients.map(publicIdentity),
        protection: { content: mode, outerHeaders: 'UNPROTECTED' },
        normalization,
      });
    } catch (error) {
      return this.#catch(run, error, credentials, mode);
    }
  }

  async processSmimeMessage(options) {
    const run = { checks: [], knowledgeTime: null, effectMayHaveOccurred: false, started: false };
    const credentials = [];
    let mode;
    try {
      fields(
        options,
        ['message', 'requiredProtection', 'expectedSenderMailbox', 'recipient'],
        ['message', 'requiredProtection', 'expectedSenderMailbox'],
      );
      const message = bytes(options.message);
      mode = options.requiredProtection;
      check(MODES.includes(mode), 'SMIME_PROTECTION_UNSUPPORTED', 'UNSUPPORTED');
      let recipientInput;
      if (options.recipient !== undefined) {
        fields(
          options.recipient,
          ['mailbox', 'certificate', 'keyRef'],
          ['mailbox', 'certificate', 'keyRef'],
        );
        recipientInput = {
          mailbox: options.recipient.mailbox,
          certificate: bytes(options.recipient.certificate),
          keyRef: label(options.recipient.keyRef),
        };
      }
      const expectedMailbox = this.#mailbox(options.expectedSenderMailbox);
      const recipient =
        recipientInput &&
        this.#credential(
          this.#mailbox(recipientInput.mailbox),
          recipientInput.certificate,
          RECIPIENT,
          { keyRef: recipientInput.keyRef },
        );
      if (recipient) credentials.push(recipient);
      this.#refresh(run, credentials, mode, 'receive-admission');
      const parsed = await this.#invoke('parseProtectedMessage', { message, format: 'MESSAGE' });
      this.#refresh(run, credentials, mode, 'parsed-admission');
      this.#headers(
        run,
        parsed.outerHeaders,
        parsed.headerClaims,
        expectedMailbox,
        'outer-headers',
      );
      const outerCMS = bytes(parsed.cms);
      let inspected = await this.#invoke('inspectCMS', {
        cms: outerCMS,
        ...(recipient ? { recipientCertificates: [recipient.certificate] } : {}),
      });
      this.#refresh(run, credentials, mode, 'outer-inspection-admission');
      const expectedKind = mode === 'SIGNED' ? 'SIGNED_DATA' : 'AUTH_ENVELOPED_DATA';
      this.#inspection(run, inspected, expectedKind, 'outer-inspection');
      collect(run, 'protection-mode', () => {
        check(parsed.kind === inspected.kind, 'SMIME_CARRIER_BINDING');
        check(
          mode === 'SIGNED' ? recipient === undefined : recipient !== undefined,
          'SMIME_RECIPIENT_MODE',
        );
      });
      let matchedRecipient;
      if (mode === 'SIGNED_AND_ENCRYPTED' && inspected.kind === 'AUTH_ENVELOPED_DATA') {
        const selected = this.#envelope(
          run,
          inspected,
          recipient ? [recipient] : [],
          'recipient-binding',
          false,
        );
        requireAccepted(run);
        const described = await this.#invoke('describeKey', { keyRef: recipient.keyRef });
        recipient.expectedPublicKeyDER = bytes(described.publicKeyDER);
        this.#refresh(run, credentials, mode, 'decrypt-admission');
        requireAccepted(run);
        run.effectMayHaveOccurred = true;
        const decrypted = await this.#invoke('decrypt', {
          cms: outerCMS,
          certificate: recipient.certificate,
          keyRef: recipient.keyRef,
          expectedPublicKeyDER: recipient.expectedPublicKeyDER,
        });
        this.#refresh(run, credentials, mode, 'decrypted-admission');
        collect(run, 'decryption-binding', () =>
          check(
            equal(dcbor(decrypted.recipient), dcbor(selected[0])),
            'SMIME_DECRYPTED_RECIPIENT_BINDING',
          ),
        );
        const inner = await this.#invoke('parseProtectedMessage', {
          message: bytes(decrypted.content),
          format: 'ENTITY',
        });
        this.#refresh(run, credentials, mode, 'inner-carrier-admission');
        this.#headers(
          run,
          inner.outerHeaders,
          inner.headerClaims,
          expectedMailbox,
          'inner-headers',
          { entity: true },
        );
        inspected = await this.#invoke('inspectCMS', { cms: bytes(inner.cms) });
        this.#refresh(run, credentials, mode, 'inner-inspection-admission');
        this.#inspection(run, inspected, 'SIGNED_DATA', 'inner-inspection', true);
        collect(run, 'inner-layer', () =>
          check(inner.kind === inspected.kind, 'SMIME_CARRIER_BINDING'),
        );
        matchedRecipient = recipient;
      }
      const sender =
        inspected.kind === 'SIGNED_DATA' &&
        this.#signed(run, inspected, expectedMailbox, 'sender-binding');
      if (sender) credentials.push(sender);
      this.#refresh(run, credentials, mode, 'content-admission');
      collect(run, 'sender-required', () => check(sender, 'SMIME_SIGNER_MISSING', 'INDETERMINATE'));
      requireAccepted(run);
      const mime = Buffer.from(sender.content);
      const decoded = await this.#invoke('inspectVerifiedMime', { mime });
      this.#refresh(run, credentials, mode, 'content-release-admission');
      collect(run, 'decoded-content', () => {
        check(Array.isArray(decoded.tree) && Array.isArray(decoded.parts), 'SMIME_MIME_RESULT');
        check(
          decoded.tree.length > 0 &&
            decoded.tree.length <= 128 &&
            decoded.parts.length > 0 &&
            decoded.parts.length <= 128,
          'SMIME_PART_LIMIT',
          'UNSUPPORTED',
        );
        let total = 0;
        for (const part of decoded.parts) {
          fields(
            part,
            ['path', 'mediaType', 'charset', 'disposition', 'filename', 'contentID', 'bytes'],
            ['path', 'mediaType', 'charset', 'disposition', 'filename', 'contentID', 'bytes'],
          );
          check(
            Array.isArray(part.path) &&
              part.path.every(instant) &&
              typeof part.mediaType === 'string' &&
              Buffer.isBuffer(part.bytes),
            'SMIME_MIME_RESULT',
          );
          check(part.path.length <= 15, 'SMIME_DEPTH_LIMIT', 'UNSUPPORTED');
          check(
            ['charset', 'disposition', 'filename', 'contentID'].every(
              (name) => part[name] === null || typeof part[name] === 'string',
            ),
            'SMIME_MIME_RESULT',
          );
          total += part.bytes.length;
        }
        check(total <= MAX_MIME, 'SMIME_DECODED_LIMIT', 'UNSUPPORTED');
      });
      requireAccepted(run);
      return result(run, {
        authenticatedAuthor: publicIdentity(sender),
        ...(matchedRecipient ? { matchedRecipient: publicIdentity(matchedRecipient) } : {}),
        protection: { content: mode, outerHeaders: 'UNPROTECTED' },
        outerHeaders: parsed.outerHeaders,
        canonicalMimeHash: sha256(mime),
        content: { mime, parts: decoded.parts },
      });
    } catch (error) {
      return this.#catch(run, error, credentials, mode);
    }
  }
}
