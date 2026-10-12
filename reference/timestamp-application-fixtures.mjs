import assert from 'node:assert/strict';
import { writeFileSync, readFileSync } from 'node:fs';
import * as c from './core.mjs';
import { O, epoch, fixture, cmsView, rewriteCMS, resign } from './cades-fixtures.mjs';
import { encodeTimestampRequest, encodeTimestampResponse } from './timestamp-protocol.mjs';

export { O, epoch, cmsView, rewriteCMS, resign };
export const clone = (value) => {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(clone);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clone(item)]));
  return value;
};
export function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
export const operation = (byte) => Buffer.alloc(32, byte);
export const assertVerdict = (result, overall, reason) => {
  assert.equal(result.overall, overall, JSON.stringify(result.checks));
  if (reason) assert.equal(result.reason, reason);
};

// Independent wire fixtures use ordinary OpenSSL CMS production. Only the three
// selected signed attributes are retained, then the exact SET is signed again.
// Accuracy is encoded independently of the application codec under test.
export function applicationFixture() {
  const f = fixture({ signerNotAfter: epoch + 1000, tsaNotAfter: epoch + 1000 });
  const scope = { ...f.scope, purpose: 'TIMESTAMP_APPLICATION' };
  const resolver = (options = {}) =>
    f.authorities({
      ...options,
      scopes: { root: scope, tsa: scope, successor: scope, ...options.scopes },
    });
  const policy = (changes = {}) =>
    f.policy({
      scope: clone(scope),
      authorityResolver: resolver(),
      maxAccuracyMicros: 60000000,
      ...changes,
    });
  const context = (changes = {}) => ({
    knowledgeTime: epoch + 40,
    policy: policy(),
    clockAdmission: {
      sourceID: 'fixture-clock',
      validFrom: epoch - 100,
      validUntil: epoch + 100000,
      knownAt: epoch - 100,
      maxAccuracyMicros: 60000000,
      policyOID: O.policy,
      status: 'ADMITTED',
    },
    ...changes,
  });
  const request = (changes = {}) =>
    encodeTimestampRequest({
      imprint: Buffer.alloc(32, 0x47),
      nonce: 42n,
      policyOID: O.policy,
      ...changes,
    });
  const token = (
    requestDER,
    {
      authority = f.tsa,
      genTime = epoch + 20,
      accuracyMicros = 0,
      includeCertificates,
      extraSigned = [],
      extraInfo = [],
      ...changes
    } = {},
  ) => {
    const fields = c.parseDER(requestDER).children;
    const requested = {
      hashOID: c.oidText(fields[1].children[0].children[0]),
      imprint: fields[1].children[1].value,
      policy: fields.slice(2).find((n) => n.tag === 6),
      nonce: fields.slice(2).find((n) => n.tag === 2),
    };
    requested.policy = requested.policy ? c.oidText(requested.policy) : O.policy;
    requested.nonce = requested.nonce ? c.intValue(requested.nonce) : undefined;
    includeCertificates ??= fields.some((n) => n.tag === 1 && n.value[0] === 255);
    const micros = accuracyMicros === null ? null : BigInt(accuracyMicros);
    const accuracy =
      micros === null
        ? []
        : [
            c.seq(
              ...(micros === 0n || micros >= 1000000n ? [c.integer(micros / 1000000n)] : []),
              ...((micros / 1000n) % 1000n
                ? [c.der(0x80, c.parseDER(c.integer((micros / 1000n) % 1000n)).value)]
                : []),
              ...(micros % 1000n ? [c.der(0x81, c.parseDER(c.integer(micros % 1000n)).value)] : []),
            ),
          ];
    let raw = f.token(requested, {
      authority,
      genTime,
      nonce: requested.nonce === undefined ? null : requested.nonce,
      ...changes,
      mutateTSTInfo: (info) => {
        const nodes = c.parseDER(info).children;
        return c.seq(
          ...nodes.slice(0, 5).map((n) => n.raw),
          ...accuracy,
          ...nodes.slice(6).map((n) => n.raw),
          ...extraInfo,
        );
      },
    });
    const signed = cmsView(raw)
      .signed.filter((n) =>
        [O.contentType, O.messageDigest, O.ess].includes(c.oidText(n.children[0])),
      )
      .map((n) => n.raw);
    raw = resign(raw, [...signed, ...extraSigned], authority.privateKey);
    return includeCertificates ? raw : rewriteCMS(raw, { certificates: [] });
  };
  const response = (requestDER, options = {}) =>
    encodeTimestampResponse({
      status: options.status ?? 0,
      tokenDER: token(requestDER, options),
    });
  const checkOpenSSL = (raw) => {
    writeFileSync(f.file('application-token.der'), raw);
    f.run(
      'cms',
      '-verify',
      '-noverify',
      '-binary',
      '-inform',
      'DER',
      '-in',
      f.file('application-token.der'),
      '-out',
      f.file('application-tstinfo.der'),
    );
    assert.deepEqual(readFileSync(f.file('application-tstinfo.der')), cmsView(raw).embeddedContent);
  };
  return { ...f, scope, resolver, policy, context, request, token, response, checkOpenSSL };
}
