import { X509Certificate, randomUUID } from 'node:crypto';
import { b64u, unb64u, requireThat, spki, equal, now, fields } from './core.mjs';
import { decode as decodeISO } from './cose.mjs';
import { parseCertificate } from './pki.mjs';
import { assessKeyAttestation } from './key-attestation.mjs';

// The authorization callback resolves an authenticated enrollment reservation.
// Its challenge is also the DeviceBindingRegistry challenge for this exact session.
export function appleACMEAttestation({ policy, profiles, authorizeOrder }) {
  requireThat(
    Array.isArray(profiles) && profiles.length > 0 && typeof authorizeOrder === 'function',
    'APPLE_ACME_POLICY',
  );
  return {
    profiles,
    async createChallenge(context) {
      const grant = await authorizeOrder(context);
      requireThat(
        grant &&
          typeof grant.token === 'string' &&
          /^[A-Za-z0-9_-]{43,128}$/.test(grant.token) &&
          grant.expiresAt > now() &&
          grant.expiresAt <= now() + 120,
        'APPLE_ACME_ORDER_AUTHORITY',
      );
      return grant;
    },
    async verify({ response, token, identifier }) {
      requireThat(
        typeof response?.attObj === 'string' && response.attObj.length <= 131072,
        'APPLE_ACME_OBJECT',
      );
      const object = decodeISO(unb64u(response.attObj));
      requireThat(object instanceof Map && object.get('fmt') === 'apple', 'APPLE_ACME_FORMAT');
      const statement = object.get('attStmt'),
        x5c = statement?.get('x5c');
      requireThat(
        statement instanceof Map &&
          Array.isArray(x5c) &&
          x5c.length > 0 &&
          x5c.length <= 6 &&
          x5c.every((x) => Buffer.isBuffer(x)),
        'APPLE_ACME_CHAIN',
      );
      const leaf = parseCertificate(x5c[0]),
        holderPublicKey = new X509Certificate(x5c[0]).publicKey,
        evidence = { format: 'apple-managed-acme', x5c },
        assessment = assessKeyAttestation(evidence, { holderPublicKey, challenge: token, policy });
      // This profile uses an attested serial number or UDID as ClientIdentifier.
      // Arbitrary opaque ClientIdentifier values require a separately registered identifier profile.
      requireThat(
        identifier.type === 'permanent-identifier' &&
          ['1.2.840.113635.100.8.9.1', '1.2.840.113635.100.8.9.2'].some((oid) =>
            equal(leaf.extensions.get(oid)?.value, Buffer.from(identifier.value, 'utf8')),
          ),
        'APPLE_ACME_IDENTIFIER',
      );
      return { attestedSPKI: spki(holderPublicKey), evidence, assessment, nonce: token };
    },
  };
}
export function appleManagedProfile({
  directoryURL,
  clientIdentifier,
  subjectCommonName = 'RRA holder key',
}) {
  const url = new URL(directoryURL);
  requireThat(
    url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      !url.hash &&
      typeof clientIdentifier === 'string' &&
      /^[A-Za-z0-9_.:-]{1,256}$/.test(clientIdentifier) &&
      typeof subjectCommonName === 'string' &&
      subjectCommonName.length > 0 &&
      subjectCommonName.length <= 128,
    'APPLE_MANAGED_PROFILE',
  );
  const identity = randomUUID(),
    configuration = randomUUID();
  const payload = {
    PayloadType: 'com.apple.security.acme',
    PayloadVersion: 1,
    PayloadIdentifier: 'org.certconcord.holder.' + identity,
    PayloadUUID: identity,
    PayloadDisplayName: 'RRA holder key',
    ClientIdentifier: clientIdentifier,
    DirectoryURL: directoryURL,
    Subject: [[['CN', subjectCommonName]]],
    KeyType: 'ECSECPrimeRandom',
    KeySize: 256,
    HardwareBound: true,
    Attest: true,
    KeyIsExtractable: false,
    AllowAllAppsAccess: false,
    UsageFlags: 1,
  };
  const value = {
    PayloadType: 'Configuration',
    PayloadVersion: 1,
    PayloadIdentifier: 'org.certconcord.enrollment.' + configuration,
    PayloadUUID: configuration,
    PayloadDisplayName: 'RRA holder enrollment',
    PayloadContent: [payload],
  };
  const escape = (s) =>
    s.replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[ch],
    );
  const encode = (v) =>
    typeof v === 'boolean'
      ? '<' + v + '/>'
      : typeof v === 'number'
        ? '<integer>' + v + '</integer>'
        : typeof v === 'string'
          ? '<string>' + escape(v) + '</string>'
          : Array.isArray(v)
            ? '<array>' + v.map(encode).join('') + '</array>'
            : '<dict>' +
              Object.entries(v)
                .map(([k, x]) => '<key>' + escape(k) + '</key>' + encode(x))
                .join('') +
              '</dict>';
  return Buffer.from(
    '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">' +
      encode(value) +
      '</plist>\n',
  );
}
export function platformEvidenceFromJSON(value) {
  if (['android-key', 'apple-managed-acme'].includes(value?.format)) {
    fields(value, ['format', 'x5c']);
    requireThat(
      Array.isArray(value.x5c) &&
        value.x5c.length > 0 &&
        value.x5c.length <= 6 &&
        value.x5c.every((x) => typeof x === 'string' && x.length <= 22000),
      'PLATFORM_EVIDENCE_CHAIN',
    );
    return { format: value.format, x5c: value.x5c.map(unb64u) };
  }
  if (value?.format === 'tpm2-certify') {
    fields(value, ['format', 'akID', 'pubArea', 'certInfo', 'signature']);
    requireThat(
      typeof value.akID === 'string' &&
        value.akID.length <= 256 &&
        ['pubArea', 'certInfo', 'signature'].every(
          (k) => typeof value[k] === 'string' && value[k].length <= 88000,
        ),
      'PLATFORM_EVIDENCE_SIZE',
    );
    return {
      format: value.format,
      akID: value.akID,
      pubArea: unb64u(value.pubArea),
      certInfo: unb64u(value.certInfo),
      signature: unb64u(value.signature),
    };
  }
  throw Error('PLATFORM_EVIDENCE_FORMAT');
}
export function platformEvidenceToJSON(value) {
  if (['android-key', 'apple-managed-acme'].includes(value?.format))
    return { format: value.format, x5c: value.x5c.map(b64u) };
  requireThat(value?.format === 'tpm2-certify', 'PLATFORM_EVIDENCE_FORMAT');
  return {
    format: value.format,
    akID: value.akID,
    pubArea: b64u(value.pubArea),
    certInfo: b64u(value.certInfo),
    signature: b64u(value.signature),
  };
}
