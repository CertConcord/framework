import { parentPort, workerData } from 'node:worker_threads';
import { X509Certificate } from 'node:crypto';
import { parseDER, oidText, intValue, der, seq, equal } from './core.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';
import { bytes, check, copy, hash, LIMITS, outcome } from './smime-adapter-common.mjs';

const OID = Object.freeze({
  signed: '1.2.840.113549.1.7.2',
  data: '1.2.840.113549.1.7.1',
  auth: '1.2.840.113549.1.9.16.1.23',
  oaep: '1.2.840.113549.1.1.7',
  mgf: '1.2.840.113549.1.1.8',
  pSpecified: '1.2.840.113549.1.1.9',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  gcm: '2.16.840.1.101.3.4.1.46',
});
function algorithm(node) {
  check(
    node?.tag === 0x30 && node.children.length >= 1 && node.children.length <= 2,
    'SMIME_ALGORITHM_ENCODING',
  );
  return oidText(node.children[0]);
}
function digestAlgorithm(node) {
  const id = algorithm(node);
  check(
    !node.children[1] || equal(node.children[1].raw, Buffer.from('0500', 'hex')),
    'SMIME_HASH_PARAMETERS',
  );
  return id;
}
function certificateIdentity(raw) {
  const root = parseDER(raw),
    cert = new X509Certificate(raw),
    fields = root.children[0].children;
  const shift = fields[0].tag === 0xa0 ? 1 : 0;
  return {
    identifierDER: seq(fields[shift + 2].raw, fields[shift].raw),
    certificateHash: hash(raw),
    publicKeyDER: cert.publicKey.export({ type: 'spki', format: 'der' }),
  };
}
function oaep(node) {
  const id = algorithm(node);
  check(id === OID.oaep, 'SMIME_KEY_TRANSPORT_UNSUPPORTED', 'UNSUPPORTED');
  const params = node.children[1];
  check(params?.tag === 0x30 && params.children.length <= 3, 'SMIME_OAEP_PARAMETERS');
  let previous = -1,
    hashOID = OID.sha1,
    mgfHash = OID.sha1;
  for (const field of params.children) {
    check(
      field.tag >= 0xa0 && field.tag <= 0xa2 && field.tag > previous && field.children.length === 1,
      'SMIME_OAEP_PARAMETERS',
    );
    previous = field.tag;
    const value = field.children[0];
    if (field.tag === 0xa0) hashOID = digestAlgorithm(value);
    if (field.tag === 0xa1) {
      check(algorithm(value) === OID.mgf, 'SMIME_OAEP_MGF_UNSUPPORTED', 'UNSUPPORTED');
      mgfHash = digestAlgorithm(value.children[1]);
    }
    if (field.tag === 0xa2) {
      check(
        algorithm(value) === OID.pSpecified && value.children[1]?.tag === 4,
        'SMIME_OAEP_LABEL',
      );
      check(value.children[1].value.length === 0, 'SMIME_OAEP_LABEL_UNSUPPORTED', 'UNSUPPORTED');
    }
  }
  check(
    hashOID === OID.sha256 && mgfHash === OID.sha256,
    'SMIME_OAEP_HASH_UNSUPPORTED',
    'UNSUPPORTED',
  );
}
function attempt(checks, fn) {
  try {
    return fn();
  } catch (error) {
    checks.push({
      overall: error.overall ?? 'INVALID',
      reason: error.code ?? 'SMIME_CMS_ENCODING',
    });
  }
}
function inspectEnvelope(container, result, recipientCertificates) {
  const checks = result.checks;
  check(container.tag === 0x30, 'SMIME_AUTH_ENVELOPED_ENCODING');
  const fields = container.children;
  check(fields.length >= 4 && fields.length <= 7, 'SMIME_AUTH_ENVELOPED_ENCODING');
  check(intValue(fields[0]) === 0n, 'SMIME_AUTH_ENVELOPED_VERSION');
  let at = 1;
  if (fields[at]?.tag === 0xa0) {
    checks.push({ overall: 'UNSUPPORTED', reason: 'SMIME_ORIGINATOR_INFO_UNSUPPORTED' });
    at++;
  }
  const recipients = fields[at++];
  check(recipients?.tag === 0x31 && recipients.children.length > 0, 'SMIME_RECIPIENT_INFOS');
  check(recipients.children.length <= LIMITS.recipients, 'SMIME_RECIPIENT_LIMIT', 'UNSUPPORTED');
  const seen = new Set();
  for (const [index, entry] of recipients.children.entries()) {
    attempt(checks, () => {
      check([0x30, 0xa1, 0xa2, 0xa3, 0xa4].includes(entry.tag), 'SMIME_RECIPIENT_ENCODING');
      check(entry.tag === 0x30, 'SMIME_RECIPIENT_KIND_UNSUPPORTED', 'UNSUPPORTED');
      check(entry.children.length === 4, 'SMIME_KEY_TRANS_RECIPIENT');
      const [version, rid, keyAlgorithm, encryptedKey] = entry.children;
      check([0x30, 0x80].includes(rid.tag), 'SMIME_RECIPIENT_IDENTIFIER');
      check(intValue(version) === (rid.tag === 0x30 ? 0n : 2n), 'SMIME_RECIPIENT_VERSION');
      check(rid.tag === 0x30, 'SMIME_RECIPIENT_IDENTIFIER_UNSUPPORTED', 'UNSUPPORTED');
      check(
        rid.children.length === 2 && rid.children[0].tag === 0x30 && intValue(rid.children[1]) > 0n,
        'SMIME_RECIPIENT_IDENTIFIER',
      );
      check(encryptedKey.tag === 4 && encryptedKey.value.length > 0, 'SMIME_ENCRYPTED_KEY');
      const identity = rid.raw.toString('hex');
      check(!seen.has(identity), 'SMIME_DUPLICATE_RECIPIENT');
      seen.add(identity);
      const keyEncryptionOID = algorithm(keyAlgorithm);
      result.recipients.push({
        index,
        recipientInfoDER: entry.raw,
        identifierDER: rid.raw,
        keyEncryptionOID,
        keyEncryptionParametersDER: keyAlgorithm.children[1]?.raw ?? Buffer.alloc(0),
        encryptedKey: encryptedKey.value,
      });
      attempt(checks, () => oaep(keyAlgorithm));
      for (const certificate of recipientCertificates) {
        const facts = certificateIdentity(certificate);
        if (equal(facts.identifierDER, rid.raw)) {
          const key = new X509Certificate(certificate).publicKey;
          check(
            key.asymmetricKeyType === 'rsa' &&
              [3072, 4096].includes(key.asymmetricKeyDetails?.modulusLength),
            'SMIME_RECIPIENT_KEY_UNSUPPORTED',
            'UNSUPPORTED',
          );
          check(
            encryptedKey.value.length === key.asymmetricKeyDetails.modulusLength / 8,
            'SMIME_ENCRYPTED_KEY_LENGTH',
          );
          result.recipientMatches.push({ index, ...facts });
        }
      }
    });
  }
  const encrypted = fields[at++];
  check(
    encrypted?.tag === 0x30 && encrypted.children.length >= 2 && encrypted.children.length <= 3,
    'SMIME_ENCRYPTED_CONTENT_INFO',
  );
  const [contentType, encryptionAlgorithm, ciphertext] = encrypted.children;
  const contentTypeOID = oidText(contentType),
    algorithmOID = algorithm(encryptionAlgorithm);
  check(!ciphertext || ciphertext.tag === 0x80, 'SMIME_CIPHERTEXT_ENCODING');
  if (!ciphertext)
    checks.push({ overall: 'UNSUPPORTED', reason: 'SMIME_DETACHED_ENCRYPTION_UNSUPPORTED' });
  let authenticatedAttributesPresent = false;
  if (fields[at]?.tag === 0xa1) {
    parseDER(der(0x31, fields[at++].value));
    authenticatedAttributesPresent = true;
    checks.push({ overall: 'UNSUPPORTED', reason: 'SMIME_AUTHENTICATED_ATTRIBUTES_UNSUPPORTED' });
  }
  const mac = fields[at++];
  check(mac?.tag === 4 && mac.value.length > 0, 'SMIME_AUTH_TAG');
  if (fields[at]?.tag === 0xa2) {
    parseDER(der(0x31, fields[at++].value));
    checks.push({ overall: 'UNSUPPORTED', reason: 'SMIME_UNAUTHENTICATED_ATTRIBUTES_UNSUPPORTED' });
  }
  check(at === fields.length, 'SMIME_AUTH_ENVELOPED_ENCODING');
  if (contentTypeOID !== OID.data)
    checks.push({ overall: 'UNSUPPORTED', reason: 'SMIME_CONTENT_TYPE_UNSUPPORTED' });
  attempt(checks, () => {
    check(algorithmOID === OID.gcm, 'SMIME_CONTENT_ENCRYPTION_UNSUPPORTED', 'UNSUPPORTED');
    const parameters = encryptionAlgorithm.children[1];
    check(
      parameters?.tag === 0x30 &&
        parameters.children.length >= 1 &&
        parameters.children.length <= 2 &&
        parameters.children[0].tag === 4,
      'SMIME_GCM_PARAMETERS',
    );
    const nonce = parameters.children[0].value,
      tagLength = parameters.children[1] ? Number(intValue(parameters.children[1])) : 12;
    check(tagLength >= 12 && tagLength <= 16, 'SMIME_GCM_TAG_LENGTH');
    check(mac.value.length === tagLength, 'SMIME_AUTH_TAG_LENGTH');
    result.encryption = {
      contentTypeOID,
      algorithmOID,
      nonce,
      tagLength,
      authenticatedAttributesPresent,
    };
    check(nonce.length === 12 && tagLength === 16, 'SMIME_GCM_PROFILE_UNSUPPORTED', 'UNSUPPORTED');
  });
}
function inspect(input) {
  const result = {
    checks: [],
    kind: null,
    contentTypeOID: null,
    certificates: [],
    crls: [],
    recipients: [],
    recipientMatches: [],
  };
  attempt(result.checks, () => {
    const cms = bytes(input.cms, LIMITS.cms),
      certificates = input.recipientCertificates ?? [];
    check(
      Array.isArray(certificates) && certificates.length <= LIMITS.recipients,
      'SMIME_CERTIFICATE_LIMIT',
      'UNSUPPORTED',
    );
    const root = parseDER(cms);
    check(
      root.tag === 0x30 &&
        root.children.length === 2 &&
        root.children[1].tag === 0xa0 &&
        root.children[1].children.length === 1,
      'SMIME_CONTENT_INFO',
    );
    result.contentTypeOID = oidText(root.children[0]);
    if (result.contentTypeOID === OID.signed) {
      result.kind = 'SIGNED_DATA';
      const inspected = inspectAdESSignature(cms, { profile: 'SMIME' });
      result.checks.push(...inspected.failures.map(({ overall, reason }) => ({ overall, reason })));
      if (inspected.parsed) {
        const parsed = inspected.parsed,
          signature = inspected.signature;
        check(
          parsed.certificates.length <= LIMITS.certificates &&
            parsed.crls.length <= LIMITS.certificates,
          'SMIME_MATERIAL_LIMIT',
          'UNSUPPORTED',
        );
        result.certificates = parsed.certificates;
        result.crls = parsed.crls;
        if (parsed.content !== undefined) result.content = bytes(parsed.content, LIMITS.content);
        if (signature?.certificate) {
          result.certificate = signature.certificate;
          result.signer = {
            identifierDER: parsed.si[1].raw,
            certificateHash: hash(signature.certificate),
            publicKeyDER: signature.x509.publicKey.export({ type: 'spki', format: 'der' }),
            hashOID: signature.hashOID,
            signatureOID: signature.signatureOID,
            claimedSigningTime: signature.claimedSigningTime ?? null,
            signedAttributeOIDs: parsed.signed.map((attr) => attr.id),
          };
        }
      }
    } else if (result.contentTypeOID === OID.auth) {
      result.kind = 'AUTH_ENVELOPED_DATA';
      inspectEnvelope(root.children[1].children[0], result, certificates);
    } else {
      result.kind = 'OTHER';
      result.checks.push({ overall: 'UNSUPPORTED', reason: 'SMIME_CMS_TYPE_UNSUPPORTED' });
    }
  });
  return { ...result, ...outcome(result.checks) };
}
try {
  check(workerData.action === 'inspect', 'SMIME_WORKER_ACTION');
  parentPort.postMessage({ ok: true, value: inspect(copy(workerData.input)) });
} catch (error) {
  parentPort.postMessage({
    ok: false,
    code: error.code ?? 'SMIME_CMS_ENCODING',
    overall: error.overall ?? 'INVALID',
  });
}
