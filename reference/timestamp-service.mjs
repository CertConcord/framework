import { X509Certificate, createHash, createPublicKey } from 'node:crypto';
import { ProtocolError, parseDER, intValue, equal, dcbor } from './core.mjs';
import { OID } from './pki.mjs';
import {
  parseTimestampRequest,
  parseTimestampResponse,
  encodeTimestampResponse,
  encodeTSTInfo,
} from './timestamp-protocol.mjs';
import { prepareAdESSignature, inspectRFC3161Token, proofProtectionDeadline } from './ades-cms.mjs';
import { validateCAdESMaterial } from './cades-validation.mjs';

const KINDS = ['INVALID', 'UNSUPPORTED', 'INDETERMINATE'];
const MICRO = 1000000n;
const MAX_ACCURACY = 60000000;
const FAILURE_BITS = {
  badAlg: 0,
  badRequest: 2,
  badDataFormat: 5,
  timeNotAvailable: 14,
  unacceptedPolicy: 15,
  unacceptedExtension: 16,
  addInfoNotAvailable: 17,
  systemFailure: 25,
};
const hash = (bytes) => createHash('sha256').update(bytes).digest();
const second = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 253402300799;
const typed = (overall, reason, details = {}) => ({ overall, reason, ...details });
function failure(overall, code) {
  const error = new ProtocolError(code);
  error.overall = overall;
  return error;
}
function check(condition, code, overall = 'INVALID') {
  if (!condition) throw failure(overall, code);
}
function copy(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(copy);
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, item]) => item !== undefined)
        .map(([name, item]) => [name, copy(item)]),
    );
  return value;
}
function fields(value, allowed, required = []) {
  check(value && typeof value === 'object' && !Array.isArray(value), 'TSP_OPTIONS_REQUIRED');
  check(
    Object.keys(value).every((name) => allowed.includes(name)),
    'TSP_UNKNOWN_OPTION',
  );
  check(
    required.every((name) => value[name] !== undefined),
    'TSP_OPTION_REQUIRED',
  );
}
function bytes(value, maximum, name) {
  check(Buffer.isBuffer(value) || value instanceof Uint8Array, `TSP_${name}_REQUIRED`);
  check(value.length > 0 && value.length <= maximum, `TSP_${name}_LIMIT`, 'UNSUPPORTED');
  return Buffer.from(value);
}
function id(value) {
  check(Buffer.isBuffer(value) && value.length === 32, 'TSP_OPERATION_ID');
  return Buffer.from(value);
}
function name(value, label) {
  check(typeof value === 'string' && value.length > 0 && value.length <= 256, `TSP_${label}`);
  return value;
}
function record(error, fallback = 'TSP_VALIDATION_FAILED') {
  return typed(KINDS.includes(error?.overall) ? error.overall : 'INVALID', error?.code ?? fallback);
}
function collect(checks, operation) {
  try {
    return operation();
  } catch (error) {
    checks.push(record(error));
  }
}
function result(checks, details = {}) {
  const selected = KINDS.map((kind) => checks.find((entry) => entry?.overall === kind)).find(
    Boolean,
  );
  return Object.freeze(copy({ ...details, ...(selected ?? typed('VALID', 'TSP_VALID')), checks }));
}
function parseCertificate(certificate) {
  const x509 = new X509Certificate(certificate),
    spki = x509.publicKey.export({ format: 'der', type: 'spki' });
  check(
    x509.publicKey.asymmetricKeyType === 'ec' &&
      x509.publicKey.asymmetricKeyDetails?.namedCurve === 'prime256v1',
    'TSP_SIGNATURE_SUITE_UNSUPPORTED',
    'UNSUPPORTED',
  );
  return { x509, spki };
}
function contextBinding(policy) {
  const scope = policy?.scope;
  check(
    scope &&
      Buffer.isBuffer(scope.trustDomainID) &&
      scope.trustDomainID.length === 32 &&
      typeof scope.issuerID === 'string' &&
      scope.issuerID.length > 0 &&
      scope.representation === 'X509' &&
      scope.purpose === 'TIMESTAMP_APPLICATION',
    'TSP_SCOPE',
  );
  check(
    Array.isArray(policy.trustedRoots) &&
      policy.trustedRoots.length > 0 &&
      policy.trustedRoots.length <= 128 &&
      policy.trustedRoots.every(Buffer.isBuffer),
    'TSP_TRUST_ROOTS',
    'INDETERMINATE',
  );
  return hash(
    dcbor({ scope, trustedRoots: policy.trustedRoots.map((raw) => raw.toString('hex')).sort() }),
  );
}
function contextShape(value) {
  fields(value, ['knowledgeTime', 'policy', 'clockAdmission'], ['knowledgeTime', 'policy']);
  value = copy(value);
  check(second(value.knowledgeTime), 'TSP_KNOWLEDGE_TIME', 'INDETERMINATE');
  const policy = value.policy;
  contextBinding(policy);
  check(
    typeof policy.authorityResolver === 'function',
    'AUTHORITY_RESOLVER_REQUIRED',
    'INDETERMINATE',
  );
  check(
    Array.isArray(policy.timestampPolicies) &&
      policy.timestampPolicies.length > 0 &&
      policy.timestampPolicies.every((entry) => typeof entry === 'string'),
    'TSP_TIMESTAMP_POLICY_REQUIRED',
    'INDETERMINATE',
  );
  check(
    Number.isSafeInteger(policy.maxAccuracyMicros) &&
      policy.maxAccuracyMicros >= 0 &&
      policy.maxAccuracyMicros <= MAX_ACCURACY,
    'TSP_ACCURACY_POLICY_REQUIRED',
    'INDETERMINATE',
  );
  for (const kind of ['certificates', 'crls']) {
    const material = policy.currentMaterial?.[kind] ?? [];
    check(
      Array.isArray(material) && material.length <= 128 && material.every(Buffer.isBuffer),
      'TSP_MATERIAL_LIMIT',
    );
  }
  return value;
}

// Constructor-fixed dependency. Neither message bytes nor call options can
// substitute a historical/future observation for actual current knowledge.
class ContextReader {
  #read;
  #binding;
  #last;
  #journal;
  #namespace;
  constructor(readContext, journal, namespace) {
    check(typeof readContext === 'function', 'TSP_CONTEXT_REQUIRED');
    this.#read = readContext;
    this.#journal = journal;
    this.#namespace = namespace;
  }
  async read() {
    let value;
    try {
      value = contextShape(await this.#read());
    } catch (error) {
      if (error?.overall) throw error;
      throw failure('INDETERMINATE', 'TSP_CONTEXT_UNAVAILABLE');
    }
    const binding = contextBinding(value.policy);
    check(!this.#binding || equal(this.#binding, binding), 'TSP_CONTEXT_BINDING');
    check(
      this.#last === undefined || value.knowledgeTime >= this.#last,
      'TSP_CLOCK_ROLLBACK',
      'INDETERMINATE',
    );
    if (this.#journal)
      this.#journal.transaction(() => {
        const previous = this.#journal.get(this.#namespace, 'context');
        check(!previous || equal(previous.value.binding, binding), 'TSP_CONTEXT_BINDING');
        check(
          !previous || value.knowledgeTime >= previous.value.knowledgeTime,
          'TSP_CLOCK_ROLLBACK',
          'INDETERMINATE',
        );
        this.#journal.put(
          this.#namespace,
          'context',
          { binding, knowledgeTime: value.knowledgeTime },
          previous?.revision ?? -1,
        );
      });
    this.#binding = binding;
    this.#last = value.knowledgeTime;
    return value;
  }
}

function interval(inspected, policy, checks) {
  const info = inspected.info;
  if (!info || !inspected.parsed) return undefined;
  return collect(checks, () => {
    check(second(info.genTime), 'TSP_TIMESTAMP_PRECISION_UNSUPPORTED', 'UNSUPPORTED');
    check(info.serial > 0n && info.serial < 1n << 160n, 'TSP_SERIAL_RANGE', 'UNSUPPORTED');
    const parsed = parseDER(inspected.parsed.content).children;
    check(
      !parsed.slice(5).some((node) => node.tag === 1),
      'TSP_ORDERING_UNSUPPORTED',
      'UNSUPPORTED',
    );
    const accuracy = parsed.slice(5).find((node) => node.tag === 0x30);
    check(accuracy, 'CADES_TIMESTAMP_ACCURACY_MISSING', 'INDETERMINATE');
    let micros = 0n;
    for (const part of accuracy.children) {
      const n = intValue({ tag: 2, value: part.value });
      micros += n * (part.tag === 2 ? MICRO : part.tag === 0x80 ? 1000n : 1n);
    }
    check(micros <= BigInt(MAX_ACCURACY), 'TSP_ACCURACY_RANGE', 'UNSUPPORTED');
    if (policy) check(micros <= BigInt(policy.maxAccuracyMicros), 'TSP_ACCURACY_POLICY');
    const middle = BigInt(info.genTime) * MICRO;
    check(middle >= micros, 'TSP_TIMESTAMP_INTERVAL');
    return {
      lowerMicros: middle - micros,
      upperMicros: middle + micros,
      accuracyMicros: Number(micros),
    };
  });
}
function authorityDecision(policy, certificate, role, stateTime, knowledgeTime) {
  let value;
  try {
    value = copy(
      policy.authorityResolver(
        copy({ certificate, role, scope: policy.scope, stateTime, knowledgeTime }),
      ),
    );
  } catch {
    return typed('INDETERMINATE', 'TSP_AUTHORITY_UNAVAILABLE');
  }
  if (!value || !['VALID', ...KINDS].includes(value.overall))
    return typed('INDETERMINATE', 'AUTHORITY_DECISION_MISSING');
  return {
    ...value,
    authorityRole: role,
    authorityStateTime: stateTime,
    authorityKnowledgeTime: knowledgeTime,
  };
}

function evaluate(requestDER, responseDER, context, prior = []) {
  const checks = [...prior];
  let request, response;
  request = collect(checks, () => parseTimestampRequest(requestDER));
  try {
    response = parseTimestampResponse(responseDER);
  } catch (error) {
    checks.push(record(error));
    response = error.partial && copy(error.partial);
  }
  if (response) checks.push(...response.diagnostics);
  const policy = context?.policy;
  let inspected, span, material, protection;
  if (response?.tokenDER) {
    inspected = inspectRFC3161Token(response.tokenDER, {
      request: request && { ...request, policy: request.policyOID },
      externalCertificates: policy?.currentMaterial?.certificates ?? [],
    });
    checks.push(...inspected.failures);
    const parsed = inspected.parsed;
    if (parsed) {
      for (const attr of [...parsed.signed, ...parsed.unsigned]) {
        if (![OID.contentType, OID.messageDigest, OID.ess].includes(attr.id))
          checks.push(typed('UNSUPPORTED', 'TSP_ATTRIBUTE_UNSUPPORTED'));
      }
      if (request) {
        if (
          request.certReq &&
          inspected.signature?.certificate &&
          !parsed.certificates.some((cert) => equal(cert, inspected.signature.certificate))
        )
          checks.push(typed('INVALID', 'TSP_CERTREQ_BINDING'));
        if (!request.certReq && parsed.certificatesPresent)
          checks.push(typed('INVALID', 'TSP_CERTREQ_BINDING'));
      }
    }
    span = interval(inspected, policy, checks);
    if (request?.nonce !== undefined && inspected.info && inspected.info.nonce !== request.nonce)
      checks.push(typed('INVALID', 'TSP_NONCE_BINDING'));
    if (policy && inspected.info && !policy.timestampPolicies.includes(inspected.info.policy))
      checks.push(typed('INVALID', 'TSP_TIMESTAMP_POLICY'));
    if (policy && inspected.signature) {
      protection = proofProtectionDeadline(inspected.signature, {
        policy,
        imprintHashOID: inspected.info?.hashOID,
      });
      checks.push(...protection.failures);
      if (Number.isFinite(protection.validUntil) && context.knowledgeTime >= protection.validUntil)
        checks.push(typed('INVALID', 'CADES_PROTECTION_GAP'));
    }
    if (span && context && span.upperMicros > BigInt(context.knowledgeTime) * MICRO) {
      checks.push(typed('INDETERMINATE', 'TSP_NOT_YET_OBSERVABLE'));
    }
    if (
      span &&
      context &&
      inspected.signature?.certificate &&
      span.lowerMicros <= BigInt(context.knowledgeTime) * MICRO
    ) {
      // Authority appointments and status event times in the shared resolver are
      // integral seconds. Probe each intersected second, bounded to 121 points,
      // so separated appointments cannot hide a gap between two valid endpoints.
      const first = Number(span.lowerMicros / MICRO),
        last = Math.min(Number(span.upperMicros / MICRO), context.knowledgeTime);
      const points = first === last ? [first] : [first, last];
      for (const stateTime of points) {
        const checked = validateCAdESMaterial({
          certificate: inspected.signature.certificate,
          certificates: (inspected.parsed?.certificates ?? []).filter((raw) => raw[0] === 0x30),
          crls: (inspected.parsed?.crls ?? []).filter((raw) => raw[0] === 0x30),
          knownCRLs: (inspected.parsed?.crls ?? []).filter((raw) => raw[0] === 0x30),
          purpose: 'TSA',
          stateTime,
          knowledgeTime: context.knowledgeTime,
          policy,
        });
        checks.push(copy(checked));
        if (checked.overall === 'VALID') {
          material = checked;
          if (context.knowledgeTime >= checked.validUntil)
            checks.push(typed('INVALID', 'CADES_PROTECTION_GAP'));
        }
      }
      const root = material?.usedCertificates?.find(
        (cert) => !equal(cert, inspected.signature.certificate),
      );
      for (let stateTime = first + 1; stateTime < last; stateTime++) {
        checks.push(
          authorityDecision(
            policy,
            inspected.signature.certificate,
            'TIMESTAMP_AUTHORITY',
            stateTime,
            context.knowledgeTime,
          ),
        );
        if (root)
          checks.push(authorityDecision(policy, root, 'ISSUER', stateTime, context.knowledgeTime));
      }
    }
  } else if (response && [2, 3, 4, 5].includes(response.status)) {
    checks.push(
      typed(
        'INDETERMINATE',
        response.status === 2
          ? 'TSP_REQUEST_REJECTED'
          : response.status === 3
            ? 'TSP_WAITING'
            : 'TSP_NO_TOKEN',
      ),
    );
  }
  return result(checks, {
    requestDER,
    tokenDER: response?.tokenDER,
    nonceBound: request?.nonce !== undefined,
    protocol: response && {
      status: response.status,
      statusStrings: response.statusStrings,
      failureBits: response.failureBits,
    },
    knowledgeTime: context?.knowledgeTime,
    genTime: inspected?.info?.genTime,
    lowerMicros: span?.lowerMicros,
    upperMicros: span?.upperMicros,
    certificate: inspected?.signature?.certificate,
    embeddedCertificates: inspected?.parsed?.certificates,
    usedCertificates: material?.usedCertificates,
    usedCRLs: material?.usedCRLs,
    protectionDeadline: protection?.validUntil,
  });
}

/** Standalone acceptance. The trusted clock/policy dependency is constructor-fixed. */
export class TimestampResponseVerifier {
  #context;
  constructor(options) {
    fields(options, ['readContext'], ['readContext']);
    this.#context = new ContextReader(options.readContext);
  }
  async verify(options) {
    const checks = [];
    let requestDER, responseDER, context;
    try {
      fields(options, ['requestDER', 'responseDER'], ['requestDER', 'responseDER']);
      requestDER = bytes(options.requestDER, 1048576, 'REQUEST');
      responseDER = bytes(options.responseDER, 1048576, 'RESPONSE');
    } catch (error) {
      return result([record(error)]);
    }
    try {
      context = await this.#context.read();
    } catch (error) {
      checks.push(record(error));
    }
    return evaluate(requestDER, responseDER, context, checks);
  }
}

function persistentVerification(value) {
  const out = copy(value);
  for (const field of ['lowerMicros', 'upperMicros'])
    if (out?.[field] !== undefined) out[field] = String(out[field]);
  return out;
}
function restoredVerification(value) {
  const out = copy(value);
  for (const field of ['lowerMicros', 'upperMicros'])
    if (out?.[field] !== undefined) out[field] = BigInt(out[field]);
  return out;
}
function view(record, operationID) {
  if (!record) return undefined;
  const value = record.value ?? record;
  return Object.freeze(
    copy({
      operationID,
      state:
        value.phase === 'COMPLETED'
          ? 'COMPLETED'
          : ['SIGNING', 'DISPATCHED', 'UNKNOWN_EXECUTION'].includes(value.phase)
            ? 'UNKNOWN_EXECUTION'
            : 'PENDING',
      responseDER: value.phase === 'COMPLETED' ? value.responseDER : undefined,
      verification: value.verification && restoredVerification(value.verification),
      reason: value.reason,
    }),
  );
}
class Store {
  constructor(journal, kind, identity) {
    check(
      journal &&
        [
          'get',
          'list',
          'put',
          'transaction',
          'reserve',
          'complete',
          'uncertain',
          'reconcile',
        ].every((method) => typeof journal[method] === 'function'),
      'TSP_JOURNAL_REQUIRED',
    );
    this.journal = journal;
    this.namespace = `timestamp-${kind}/${hash(Buffer.from(name(identity, 'IDENTITY'))).toString('hex')}`;
  }
  key(operationID) {
    return operationID.toString('hex');
  }
  operation(operationID) {
    return `${this.namespace}/${this.key(operationID)}`;
  }
  get(operationID) {
    return this.journal.get(this.namespace, this.key(operationID));
  }
  update(operationID, value, revision) {
    this.journal.put(this.namespace, this.key(operationID), copy(value), revision);
  }
  reserve(operationID, requestDER, metadata = {}) {
    return this.journal.transaction(() => {
      this.journal.reserve(this.operation(operationID), hash(requestDER));
      const current = this.get(operationID);
      if (current) {
        check(equal(current.value.requestDER, requestDER), 'IDEMPOTENCY_CONFLICT');
        return { current, created: false };
      }
      this.update(operationID, { ...metadata, phase: 'REQUESTED', requestDER }, -1);
      return { current: this.get(operationID), created: true };
    });
  }
  complete(operationID, responseDER, verification) {
    try {
      return this.journal.transaction(() => {
        const current = this.get(operationID);
        if (current.value.phase === 'COMPLETED') {
          check(equal(current.value.responseDER, responseDER), 'TSP_RESPONSE_CONFLICT');
          return view(current, operationID);
        }
        this.update(
          operationID,
          {
            ...current.value,
            phase: 'COMPLETED',
            responseDER,
            verification: persistentVerification(verification),
          },
          current.revision,
        );
        this.journal.reconcile(this.operation(operationID), responseDER);
        return view(this.get(operationID), operationID);
      });
    } catch (error) {
      if (error.code === 'TSP_RESPONSE_CONFLICT') throw error;
      // A commit can succeed before its acknowledgement fails. Only an exact
      // durable readback can establish completion after such a failure.
      let current;
      try {
        current = this.get(operationID);
      } catch {}
      if (current?.value.phase === 'COMPLETED') {
        check(equal(current.value.responseDER, responseDER), 'TSP_RESPONSE_CONFLICT');
        return view(current, operationID);
      }
      return this.uncertain(operationID, 'TSP_PERSISTENCE_OUTCOME_UNKNOWN');
    }
  }
  uncertain(operationID, reason) {
    try {
      return this.journal.transaction(() => {
        const current = this.get(operationID);
        if (current && current.value.phase !== 'COMPLETED') {
          this.update(
            operationID,
            { ...current.value, phase: 'UNKNOWN_EXECUTION', reason },
            current.revision,
          );
          this.journal.uncertain(this.operation(operationID));
        }
        return (
          view(this.get(operationID), operationID) ??
          Object.freeze(copy({ operationID, state: 'UNKNOWN_EXECUTION', reason }))
        );
      });
    } catch {
      let current;
      try {
        current = this.get(operationID);
      } catch {}
      if (current?.value.phase === 'COMPLETED') return view(current, operationID);
      return Object.freeze(copy({ operationID, state: 'UNKNOWN_EXECUTION', reason }));
    }
  }
}

function admittedClock(context, reading) {
  const admission = context.clockAdmission;
  check(
    admission && typeof admission === 'object',
    'TSP_CLOCK_ADMISSION_REQUIRED',
    'INDETERMINATE',
  );
  fields(
    admission,
    ['sourceID', 'validFrom', 'validUntil', 'knownAt', 'maxAccuracyMicros', 'policyOID', 'status'],
    ['sourceID', 'validFrom', 'validUntil', 'knownAt', 'maxAccuracyMicros', 'policyOID', 'status'],
  );
  check(
    admission.status === 'ADMITTED' &&
      admission.sourceID === reading.sourceID &&
      second(admission.knownAt) &&
      admission.knownAt <= context.knowledgeTime &&
      second(admission.validFrom) &&
      second(admission.validUntil) &&
      admission.validFrom < admission.validUntil,
    'TSP_CLOCK_NOT_ADMITTED',
    'INDETERMINATE',
  );
  check(
    Number.isSafeInteger(admission.maxAccuracyMicros) &&
      admission.maxAccuracyMicros >= 0 &&
      admission.maxAccuracyMicros <= MAX_ACCURACY &&
      reading.accuracyMicros <= admission.maxAccuracyMicros &&
      reading.accuracyMicros <= context.policy.maxAccuracyMicros,
    'TSP_CLOCK_ACCURACY',
    'INDETERMINATE',
  );
  const middle = BigInt(reading.genTime) * MICRO,
    accuracy = BigInt(reading.accuracyMicros);
  check(
    middle - accuracy >= BigInt(admission.validFrom) * MICRO &&
      middle + accuracy < BigInt(admission.validUntil) * MICRO,
    'TSP_CLOCK_ADMISSION_TIME',
    'INDETERMINATE',
  );
  return admission;
}
function clockReading(value) {
  fields(
    value,
    ['sourceID', 'genTime', 'accuracyMicros', 'synchronized'],
    ['sourceID', 'genTime', 'accuracyMicros', 'synchronized'],
  );
  value = copy(value);
  name(value.sourceID, 'CLOCK_SOURCE');
  check(
    second(value.genTime) &&
      value.synchronized === true &&
      Number.isSafeInteger(value.accuracyMicros) &&
      value.accuracyMicros >= 0 &&
      value.accuracyMicros <= MAX_ACCURACY,
    'TSP_CLOCK_UNAVAILABLE',
    'INDETERMINATE',
  );
  return value;
}

/** Durable selected TSA. An admitted callback is an assumption, not proof of UTC assurance. */
export class TimestampService {
  #store;
  #context;
  #clock;
  #sign;
  #certificate;
  #certificates;
  #policyOID;
  constructor(options) {
    fields(
      options,
      [
        'journal',
        'serviceID',
        'certificate',
        'certificates',
        'signer',
        'policyOID',
        'clock',
        'readContext',
      ],
      ['journal', 'serviceID', 'certificate', 'signer', 'policyOID', 'clock', 'readContext'],
    );
    fields(options.signer, ['publicKeyDER', 'sign'], ['publicKeyDER', 'sign']);
    this.#certificate = bytes(options.certificate, 1048576, 'CERTIFICATE');
    this.#certificates = copy(options.certificates ?? []);
    check(
      Array.isArray(this.#certificates) &&
        this.#certificates.length <= 127 &&
        this.#certificates.every(Buffer.isBuffer),
      'TSP_CERTIFICATES',
    );
    const { spki } = parseCertificate(this.#certificate),
      publicKeyDER = bytes(options.signer.publicKeyDER, 1048576, 'PUBLIC_KEY');
    createPublicKey({ key: publicKeyDER, type: 'spki', format: 'der' });
    check(equal(spki, publicKeyDER), 'TSP_SIGNER_KEY_BINDING');
    check(typeof options.signer.sign === 'function', 'TSP_SIGNER_REQUIRED');
    check(options.clock && typeof options.clock.read === 'function', 'TSP_CLOCK_REQUIRED');
    this.#sign = options.signer.sign.bind(options.signer);
    this.#clock = options.clock.read.bind(options.clock);
    this.#policyOID = name(options.policyOID, 'POLICY_OID');
    this.#store = new Store(options.journal, 'issuer', options.serviceID);
    this.#context = new ContextReader(options.readContext, options.journal, this.#store.namespace);
  }
  result(operationID) {
    operationID = id(operationID);
    return view(this.#store.get(operationID), operationID);
  }
  async issue(options) {
    fields(options, ['operationID', 'requestDER'], ['operationID', 'requestDER']);
    const operationID = id(options.operationID),
      requestDER = bytes(options.requestDER, 1048576, 'REQUEST');
    const reserved = this.#store.reserve(operationID, requestDER, {
      certificate: this.#certificate,
      certificates: this.#certificates,
      policyOID: this.#policyOID,
    });
    if (!reserved.created && reserved.current.value.phase !== 'REQUESTED')
      return view(reserved.current, operationID);
    return this.#prepare(operationID);
  }
  #reject(operationID, bit, error) {
    const responseDER = encodeTimestampResponse({ status: 2, failureBits: [bit] });
    let current;
    try {
      current = this.#store.get(operationID);
    } catch {
      return this.#store.uncertain(operationID, 'TSP_PERSISTENCE_OUTCOME_UNKNOWN');
    }
    const verification = result([record(error)], {
      protocol: { status: 2, statusStrings: [], failureBits: [bit] },
      requestDER: current.value.requestDER,
    });
    return this.#store.complete(operationID, responseDER, verification);
  }
  #pending(operationID, error) {
    return this.#store.journal.transaction(() => {
      const current = this.#store.get(operationID);
      if (current.value.phase !== 'COMPLETED')
        this.#store.update(
          operationID,
          {
            ...current.value,
            reason: error.code,
            verification: persistentVerification(result([record(error)])),
          },
          current.revision,
        );
      return view(this.#store.get(operationID), operationID);
    });
  }
  async #prepare(operationID) {
    let current = this.#store.get(operationID),
      request;
    if (current.value.phase !== 'REQUESTED') return view(current, operationID);
    check(
      equal(current.value.certificate, this.#certificate) &&
        current.value.policyOID === this.#policyOID,
      'TSP_RESERVED_ISSUER_BINDING',
    );
    try {
      request = parseTimestampRequest(current.value.requestDER);
    } catch (error) {
      return this.#reject(operationID, error.failureBit ?? FAILURE_BITS.badDataFormat, error);
    }
    if (request.policyOID !== undefined && request.policyOID !== this.#policyOID)
      return this.#reject(
        operationID,
        FAILURE_BITS.unacceptedPolicy,
        failure('INVALID', 'TSP_TIMESTAMP_POLICY'),
      );
    let context, reading, prepared;
    try {
      context = await this.#context.read();
      reading = clockReading(await this.#clock());
      const admission = admittedClock(context, reading);
      check(
        admission.policyOID === this.#policyOID &&
          context.policy.timestampPolicies.includes(this.#policyOID),
        'TSP_TIMESTAMP_POLICY',
      );
      check(reading.genTime <= context.knowledgeTime, 'TSP_NOT_YET_OBSERVABLE', 'INDETERMINATE');
      const material = validateCAdESMaterial({
        certificate: this.#certificate,
        certificates: this.#certificates,
        purpose: 'TSA',
        stateTime: reading.genTime,
        knowledgeTime: context.knowledgeTime,
        policy: context.policy,
      });
      if (material.overall !== 'VALID') throw failure(material.overall, material.reason);
      const { x509 } = parseCertificate(this.#certificate),
        protection = proofProtectionDeadline(
          { x509, hashOID: OID.sha256, essHash: OID.sha256, signatureOID: '1.2.840.10045.4.3.2' },
          { policy: context.policy, imprintHashOID: request.hashOID },
        );
      if (protection.overall !== 'VALID') throw failure(protection.overall, protection.reason);
      check(
        context.knowledgeTime < protection.validUntil &&
          context.knowledgeTime < material.validUntil,
        'CADES_PROTECTION_GAP',
      );
      const lower = BigInt(reading.genTime) * MICRO - BigInt(reading.accuracyMicros),
        upper = BigInt(reading.genTime) * MICRO + BigInt(reading.accuracyMicros);
      for (const raw of material.usedCertificates) {
        const cert = new X509Certificate(raw),
          from = Math.floor(cert.validFromDate.getTime() / 1000),
          until = Math.floor(cert.validToDate.getTime() / 1000);
        check(
          lower >= BigInt(from) * MICRO && upper < BigInt(until) * MICRO,
          'TSP_CERTIFICATE_INTERVAL',
        );
      }
      check(
        upper < BigInt(protection.validUntil) * MICRO &&
          upper < BigInt(material.validUntil) * MICRO,
        'CADES_PROTECTION_GAP',
      );
      const first = Number(lower / MICRO),
        last = Math.min(Number(upper / MICRO), context.knowledgeTime),
        rootCertificate = material.usedCertificates.find((raw) => !equal(raw, this.#certificate));
      for (const stateTime of new Set([first, last])) {
        const edge = validateCAdESMaterial({
          certificate: this.#certificate,
          certificates: this.#certificates,
          purpose: 'TSA',
          stateTime,
          knowledgeTime: context.knowledgeTime,
          policy: context.policy,
        });
        if (edge.overall !== 'VALID') throw failure(edge.overall, edge.reason);
      }
      for (let stateTime = first; stateTime <= last; stateTime++) {
        for (const [certificate, role] of [
          [this.#certificate, 'TIMESTAMP_AUTHORITY'],
          [rootCertificate, 'ISSUER'],
        ]) {
          const decision = authorityDecision(
            context.policy,
            certificate,
            role,
            stateTime,
            context.knowledgeTime,
          );
          if (decision.overall !== 'VALID') throw failure(decision.overall, decision.reason);
        }
      }
      const created = this.#store.journal.transaction(() => {
        current = this.#store.get(operationID);
        if (current.value.phase !== 'REQUESTED') return false;
        const previousClock = this.#store.journal.get(this.#store.namespace, 'clock');
        check(
          !previousClock ||
            (previousClock.value.sourceID === reading.sourceID &&
              reading.genTime >= previousClock.value.genTime),
          'TSP_CLOCK_ROLLBACK',
          'INDETERMINATE',
        );
        const previousSerial = this.#store.journal.get(this.#store.namespace, 'serial');
        check(
          !previousSerial ||
            (typeof previousSerial.value.value === 'string' &&
              /^[1-9][0-9]{0,48}$/.test(previousSerial.value.value)),
          'TSP_SERIAL_STATE_INCONSISTENT',
          'INDETERMINATE',
        );
        const previousValue = previousSerial ? BigInt(previousSerial.value.value) : 0n,
          serial = previousValue + 1n;
        const existingSerials = new Set();
        let largestSerial = 0n;
        for (const { id: operationKey } of this.#store.journal.list(this.#store.namespace)) {
          if (!/^[a-f0-9]{64}$/.test(operationKey)) continue;
          const record = this.#store.journal.get(this.#store.namespace, operationKey)?.value;
          if (record?.serial === undefined) continue;
          check(
            typeof record.serial === 'string' && /^[1-9][0-9]{0,48}$/.test(record.serial),
            'TSP_SERIAL_STATE_INCONSISTENT',
            'INDETERMINATE',
          );
          const used = BigInt(record.serial);
          check(
            used > 0n && used < serial && !existingSerials.has(record.serial),
            'TSP_SERIAL_STATE_INCONSISTENT',
            'INDETERMINATE',
          );
          existingSerials.add(record.serial);
          if (used > largestSerial) largestSerial = used;
        }
        check(largestSerial === previousValue, 'TSP_SERIAL_STATE_INCONSISTENT', 'INDETERMINATE');
        check(serial < 1n << 160n, 'TSP_SERIAL_EXHAUSTED', 'INDETERMINATE');
        const info = encodeTSTInfo({
          policyOID: this.#policyOID,
          hashOID: request.hashOID,
          imprint: request.imprint,
          serial,
          genTime: reading.genTime,
          accuracyMicros: reading.accuracyMicros,
          nonce: request.nonce,
        });
        prepared = prepareAdESSignature({
          profile: 'RFC3161',
          content: info,
          certificate: this.#certificate,
          certificates: this.#certificates,
          includeCertificates: request.certReq,
        });
        this.#store.journal.put(
          this.#store.namespace,
          'serial',
          { value: serial.toString() },
          previousSerial?.revision ?? -1,
        );
        this.#store.journal.put(
          this.#store.namespace,
          'clock',
          reading,
          previousClock?.revision ?? -1,
        );
        this.#store.update(
          operationID,
          {
            ...current.value,
            phase: 'SIGNING',
            serial: serial.toString(),
            tstInfo: info,
            tbs: prepared.tbs,
            certificate: this.#certificate,
            certificates: this.#certificates,
            certReq: request.certReq,
            clockReading: reading,
            policyOID: this.#policyOID,
            preparedKnowledgeTime: context.knowledgeTime,
          },
          current.revision,
        );
        return true;
      });
      if (!created) return view(this.#store.get(operationID), operationID);
    } catch (error) {
      const latest = this.#store.get(operationID);
      if (latest.value.phase !== 'REQUESTED') return view(latest, operationID);
      if (error.code === 'TSP_NOT_YET_OBSERVABLE') return this.#pending(operationID, error);
      return this.#reject(
        operationID,
        error.code?.startsWith('TSP_CLOCK')
          ? FAILURE_BITS.timeNotAvailable
          : error.overall === 'INDETERMINATE'
            ? FAILURE_BITS.addInfoNotAvailable
            : FAILURE_BITS.badRequest,
        error,
      );
    }
    let signature;
    try {
      const reserved = this.#store.get(operationID).value;
      signature = bytes(
        await this.#sign(Buffer.from(reserved.tbs), {
          operationID: Buffer.from(operationID),
          serial: BigInt(reserved.serial),
          certificateID: hash(reserved.certificate),
        }),
        16384,
        'SIGNATURE',
      );
    } catch {
      return this.#store.uncertain(operationID, 'TSP_SIGNING_OUTCOME_UNKNOWN');
    }
    try {
      this.#attachSignature(operationID, signature);
    } catch (error) {
      if (error?.overall === 'INVALID')
        return this.#reject(operationID, FAILURE_BITS.systemFailure, error);
      return this.#store.uncertain(operationID, 'TSP_PERSISTENCE_OUTCOME_UNKNOWN');
    }
    return this.#release(operationID);
  }
  #attachSignature(operationID, signature) {
    const current = this.#store.get(operationID),
      reserved = current.value;
    check(reserved.tstInfo && reserved.tbs, 'TSP_RESERVATION_MISSING', 'INDETERMINATE');
    const prepared = prepareAdESSignature({
      profile: 'RFC3161',
      content: reserved.tstInfo,
      certificate: reserved.certificate,
      certificates: reserved.certificates,
      includeCertificates: reserved.certReq,
    });
    check(equal(prepared.tbs, reserved.tbs), 'TSP_RESERVED_TBS_BINDING');
    const tokenDER = prepared.finish(signature);
    return this.#store.journal.transaction(() => {
      const latest = this.#store.get(operationID);
      if (latest.value.signature) {
        check(equal(latest.value.signature, signature), 'TSP_SIGNATURE_CONFLICT');
        return;
      }
      check(['SIGNING', 'UNKNOWN_EXECUTION'].includes(latest.value.phase), 'TSP_OPERATION_STATE');
      this.#store.update(
        operationID,
        { ...latest.value, phase: 'SIGNED_PENDING', signature, tokenDER },
        latest.revision,
      );
    });
  }
  async #release(operationID) {
    let reserved;
    try {
      reserved = copy(this.#store.get(operationID).value);
    } catch {
      return this.#store.uncertain(operationID, 'TSP_PERSISTENCE_OUTCOME_UNKNOWN');
    }
    if (reserved.phase === 'COMPLETED') return view(reserved, operationID);
    check(reserved.tokenDER, 'TSP_SIGNATURE_REQUIRED', 'INDETERMINATE');
    let context;
    const checks = [];
    try {
      context = await this.#context.read();
      const admission = admittedClock(context, reserved.clockReading);
      check(admission.policyOID === reserved.policyOID, 'TSP_TIMESTAMP_POLICY');
      // Publishing a newly issued response is a live service action. Historical
      // acceptance of an already issued token is handled by the public verifier;
      // it does not authorize a service whose admission changed while signing.
      checks.push(
        copy(
          validateCAdESMaterial({
            certificate: reserved.certificate,
            certificates: reserved.certificates,
            purpose: 'TSA',
            stateTime: context.knowledgeTime,
            knowledgeTime: context.knowledgeTime,
            policy: context.policy,
          }),
        ),
      );
    } catch (error) {
      checks.push(record(error));
    }
    const responseDER = encodeTimestampResponse({ status: 0, tokenDER: reserved.tokenDER });
    // The issuer knows which certificate signed its reserved candidate even when
    // certReq=false. It remains an external candidate, never an embedded object.
    if (context)
      context.policy.currentMaterial = {
        ...(context.policy.currentMaterial ?? {}),
        certificates: [
          reserved.certificate,
          ...(context.policy.currentMaterial?.certificates ?? []),
        ].filter((cert, index, all) => !all.slice(0, index).some((old) => equal(old, cert))),
      };
    const verification = evaluate(reserved.requestDER, responseDER, context, checks);
    if (verification.overall === 'VALID')
      return this.#store.complete(operationID, responseDER, verification);
    if (['INVALID', 'UNSUPPORTED'].includes(verification.overall))
      return this.#reject(
        operationID,
        FAILURE_BITS.badRequest,
        failure(verification.overall, verification.reason),
      );
    try {
      return this.#store.journal.transaction(() => {
        const current = this.#store.get(operationID);
        if (current.value.phase !== 'COMPLETED')
          this.#store.update(
            operationID,
            {
              ...current.value,
              phase: 'SIGNED_PENDING',
              verification: persistentVerification(verification),
              reason: verification.reason,
            },
            current.revision,
          );
        return view(this.#store.get(operationID), operationID);
      });
    } catch {
      return this.#store.uncertain(operationID, 'TSP_PERSISTENCE_OUTCOME_UNKNOWN');
    }
  }
  async reconcile(options) {
    fields(options, ['operationID', 'signature'], ['operationID']);
    const operationID = id(options.operationID),
      signature =
        options.signature === undefined ? undefined : bytes(options.signature, 16384, 'SIGNATURE');
    const current = this.#store.get(operationID);
    check(current, 'TSP_OPERATION_MISSING', 'INDETERMINATE');
    if (current.value.phase === 'COMPLETED') {
      if (signature !== undefined)
        check(
          current.value.signature && equal(current.value.signature, signature),
          'TSP_SIGNATURE_CONFLICT',
        );
      return view(current, operationID);
    }
    if (current.value.phase === 'REQUESTED') {
      check(signature === undefined, 'TSP_RESERVATION_MISSING');
      // No serial/TBS/signing dispatch exists yet. This explicit reconciliation
      // may perform the initial preparation; it is not a replay of a signed op.
      return this.#prepare(operationID);
    }
    if (signature !== undefined) {
      try {
        this.#attachSignature(operationID, signature);
      } catch (error) {
        if (error.overall === 'INVALID') throw error;
        return this.#store.uncertain(operationID, 'TSP_PERSISTENCE_OUTCOME_UNKNOWN');
      }
    } else if (!current.value.tokenDER) return view(current, operationID);
    return this.#release(operationID);
  }
}

/** Durable exact-request client; uncertain transport never triggers automatic replay. */
export class TimestampClient {
  #store;
  #context;
  #send;
  #delay;
  constructor(options) {
    fields(
      options,
      ['journal', 'clientID', 'send', 'readContext', 'maxResponseDelaySeconds'],
      ['journal', 'clientID', 'send', 'readContext'],
    );
    check(typeof options.send === 'function', 'TSP_TRANSPORT_REQUIRED');
    this.#send = options.send;
    this.#delay = options.maxResponseDelaySeconds ?? 15;
    check(
      Number.isSafeInteger(this.#delay) && this.#delay > 0 && this.#delay <= 86400,
      'TSP_RESPONSE_DELAY_POLICY',
    );
    this.#store = new Store(options.journal, 'client', options.clientID);
    this.#context = new ContextReader(options.readContext, options.journal, this.#store.namespace);
  }
  result(operationID) {
    operationID = id(operationID);
    return view(this.#store.get(operationID), operationID);
  }
  async request(options) {
    fields(options, ['operationID', 'requestDER'], ['operationID', 'requestDER']);
    const operationID = id(options.operationID),
      requestDER = bytes(options.requestDER, 65536, 'REQUEST');
    const request = parseTimestampRequest(requestDER);
    check(request.nonce !== undefined, 'TSP_NONCE_REQUIRED', 'UNSUPPORTED');
    const reserved = this.#store.reserve(operationID, requestDER);
    if (!reserved.created && reserved.current.value.phase !== 'REQUESTED')
      return view(reserved.current, operationID);
    return this.#dispatch(operationID);
  }
  async #dispatch(operationID) {
    const context = await this.#context.read();
    const dispatch = this.#store.journal.transaction(() => {
      const current = this.#store.get(operationID);
      if (current.value.phase !== 'REQUESTED') return false;
      this.#store.update(
        operationID,
        {
          ...current.value,
          phase: 'DISPATCHED',
          sentKnowledgeTime: context.knowledgeTime,
          maxResponseDelaySeconds: this.#delay,
        },
        current.revision,
      );
      return true;
    });
    if (!dispatch) return view(this.#store.get(operationID), operationID);
    let responseDER;
    try {
      responseDER = bytes(
        await this.#send(Buffer.from(this.#store.get(operationID).value.requestDER), {
          operationID: Buffer.from(operationID),
        }),
        1048576,
        'RESPONSE',
      );
    } catch {
      return this.#store.uncertain(operationID, 'TSP_TRANSPORT_OUTCOME_UNKNOWN');
    }
    return this.#accept(operationID, responseDER);
  }
  async #accept(operationID, responseDER) {
    // Retain bytes before any post-receive context callback can fail or mutate.
    let reserved;
    try {
      this.#store.journal.transaction(() => {
        const current = this.#store.get(operationID);
        if (current.value.phase === 'COMPLETED') {
          check(equal(current.value.responseDER, responseDER), 'TSP_RESPONSE_CONFLICT');
          return;
        }
        const changed =
          current.value.candidateResponse && !equal(current.value.candidateResponse, responseDER);
        if (changed) {
          const previous = parseTimestampResponse(current.value.candidateResponse);
          check(previous.status === 3, 'TSP_RESPONSE_CONFLICT');
        }
        this.#store.update(
          operationID,
          {
            ...current.value,
            phase: 'RECEIVED',
            candidateResponse: responseDER,
            receivedKnowledgeTime: changed ? undefined : current.value.receivedKnowledgeTime,
          },
          current.revision,
        );
      });
      reserved = this.#store.get(operationID).value;
    } catch (error) {
      if (error.code === 'TSP_RESPONSE_CONFLICT') throw error;
      return this.#store.uncertain(operationID, 'TSP_PERSISTENCE_OUTCOME_UNKNOWN');
    }
    if (reserved.phase === 'COMPLETED') return view(reserved, operationID);
    let context;
    const checks = [];
    try {
      context = await this.#context.read();
    } catch (error) {
      checks.push(record(error));
    }
    const receipt = reserved.receivedKnowledgeTime ?? context?.knowledgeTime;
    if (
      receipt !== undefined &&
      receipt - reserved.sentKnowledgeTime > reserved.maxResponseDelaySeconds
    )
      checks.push(typed('INDETERMINATE', 'TSP_RESPONSE_DELAY'));
    const verification = evaluate(reserved.requestDER, responseDER, context, checks);
    if (
      verification.upperMicros !== undefined &&
      verification.upperMicros < BigInt(reserved.sentKnowledgeTime) * MICRO
    )
      return this.#store.complete(
        operationID,
        responseDER,
        result([...verification.checks, typed('INVALID', 'TSP_RESPONSE_TIME')], verification),
      );
    const pending =
      verification.overall === 'INDETERMINATE' &&
      (verification.protocol?.status === 3 ||
        !context ||
        verification.reason === 'TSP_NOT_YET_OBSERVABLE');
    if (!pending) return this.#store.complete(operationID, responseDER, verification);
    try {
      return this.#store.journal.transaction(() => {
        const current = this.#store.get(operationID);
        if (current.value.phase !== 'COMPLETED')
          this.#store.update(
            operationID,
            {
              ...current.value,
              receivedKnowledgeTime: receipt,
              verification: persistentVerification(verification),
              reason: verification.reason,
            },
            current.revision,
          );
        return view(this.#store.get(operationID), operationID);
      });
    } catch {
      return this.#store.uncertain(operationID, 'TSP_PERSISTENCE_OUTCOME_UNKNOWN');
    }
  }
  async reconcile(options) {
    fields(options, ['operationID', 'responseDER'], ['operationID', 'responseDER']);
    const operationID = id(options.operationID),
      responseDER = bytes(options.responseDER, 1048576, 'RESPONSE');
    const current = this.#store.get(operationID);
    check(
      current && current.value.sentKnowledgeTime !== undefined,
      'TSP_OPERATION_MISSING',
      'INDETERMINATE',
    );
    if (current.value.phase === 'COMPLETED') {
      check(equal(current.value.responseDER, responseDER), 'TSP_RESPONSE_CONFLICT');
      return view(current, operationID);
    }
    return this.#accept(operationID, responseDER);
  }
}
