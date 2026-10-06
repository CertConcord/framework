import { X509Certificate, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import {
  D,
  H,
  sha256,
  keyID,
  equal,
  requireThat,
  now,
  parseDER,
  intValue,
  spki,
  b64u,
} from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { p1363ToDER } from './ecdsa.mjs';
import { parseJSON } from './json.mjs';

export const ANDROID_KEY_OID = '1.3.6.1.4.1.11129.2.1.17';
export const APPLE_NONCE_OID = '1.2.840.113635.100.8.11.1';
const criticalOIDs = new Set(['2.5.29.19', '2.5.29.15', '2.5.29.37']);
const fail = (condition, suffix) => requireThat(condition, 'KEY_ATTESTATION_' + suffix);

// Bounded DER reader for Android's EXPLICIT high-number authorization tags.
export function readAttestationDER(bytes) {
  fail(Buffer.isBuffer(bytes) && bytes.length <= 65536, 'DER_SIZE');
  let p = 0,
    count = 0;
  function read(end, depth) {
    fail(++count <= 4096 && depth <= 16 && p + 2 <= end, 'DER_LIMIT');
    const start = p,
      first = bytes[p++],
      cls = first >> 6,
      constructed = Boolean(first & 32);
    let tag = first & 31;
    if (tag === 31) {
      tag = 0;
      let n = 0,
        octet;
      do {
        fail(p < end && ++n <= 4, 'DER_TAG');
        octet = bytes[p++];
        fail(n !== 1 || (octet & 127) !== 0, 'DER_TAG');
        tag = tag * 128 + (octet & 127);
      } while (octet & 128);
      fail(tag >= 31, 'DER_TAG');
    }
    fail(p < end, 'DER_LENGTH');
    let len = bytes[p++];
    if (len & 128) {
      const n = len & 127;
      fail(n > 0 && n <= 3 && p + n <= end && bytes[p] !== 0, 'DER_LENGTH');
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + bytes[p++];
      fail(len >= 128, 'DER_LENGTH');
    }
    const begin = p,
      stop = p + len;
    fail(stop <= end, 'DER_TRUNCATED');
    let children;
    if (constructed) {
      children = [];
      while (p < stop) children.push(read(stop, depth + 1));
    } else p = stop;
    const value = bytes.subarray(begin, stop);
    if (cls === 0 && [2, 10].includes(tag))
      fail(
        !constructed &&
          value.length > 0 &&
          !(value[0] & 128) &&
          !(value.length > 1 && value[0] === 0 && !(value[1] & 128)),
        'DER_INTEGER',
      );
    if (cls === 0 && tag === 17) {
      fail(constructed, 'DER_SET');
      for (let i = 1; i < children.length; i++)
        fail(Buffer.compare(children[i - 1].raw, children[i].raw) < 0, 'DER_SET');
    }
    return { cls, tag, constructed, value, children, raw: bytes.subarray(start, stop) };
  }
  const out = read(bytes.length, 0);
  fail(p === bytes.length, 'DER_TRAILING');
  return out;
}
const typed = (node, tag) => {
  fail(node?.cls === 0 && node.tag === tag, 'FIELD');
  return node;
};
const number = (node, tag = 2) => {
  const bytes = typed(node, tag).value;
  fail(bytes.length <= 7, 'INTEGER');
  const n = Number(BigInt('0x' + bytes.toString('hex')));
  fail(Number.isSafeInteger(n), 'INTEGER');
  return n;
};
function authorizations(node) {
  typed(node, 16);
  const out = new Map();
  let previous = -1;
  for (const n of node.children) {
    fail(
      n.cls === 2 && n.constructed && n.children.length === 1 && n.tag > previous,
      'AUTHORIZATIONS',
    );
    previous = n.tag;
    out.set(n.tag, n.children[0]);
  }
  return out;
}
const numbers = (node) => typed(node, 17).children.map((n) => number(n));
const octets = (node) => typed(node, 4).value;

export function verifiedChain(x5c, { roots, status }, at) {
  fail(
    Array.isArray(x5c) &&
      x5c.length >= 1 &&
      x5c.length <= 6 &&
      x5c.every((b) => Buffer.isBuffer(b) && b.length <= 16384),
    'CHAIN',
  );
  fail(Array.isArray(roots) && roots.length > 0 && typeof status === 'function', 'TRUST_POLICY');
  const chain = x5c.map((b) => new X509Certificate(b)),
    anchors = roots.map((b) => (b instanceof X509Certificate ? b : new X509Certificate(b)));
  fail(new Set(chain.map((c) => c.fingerprint256)).size === chain.length, 'CHAIN_LOOP');
  let root = anchors.find((r) => equal(r.raw, chain.at(-1).raw));
  if (!root) {
    root = anchors.find((r) => chain.at(-1).checkIssued(r) && chain.at(-1).verify(r.publicKey));
    fail(root, 'UNTRUSTED_ROOT');
    chain.push(root);
  }
  fail(chain.length >= 2, 'SELF_ATTESTED');
  let expiry = Infinity;
  const evidence = [];
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i],
      parsed = parseCertificate(cert.raw);
    fail(parsed.notBefore <= at && parsed.notAfter > at, 'CERTIFICATE_TIME');
    expiry = Math.min(expiry, parsed.notAfter);
    for (const [id, ext] of parsed.extensions)
      fail(!ext.critical || criticalOIDs.has(id), 'CRITICAL_EXTENSION');
    const ku = parsed.extensions.get('2.5.29.15');
    fail(ku, 'KEY_USAGE');
    const bits = parseDER(ku.value);
    fail(bits.tag === 3 && bits.value.length >= 2, 'KEY_USAGE');
    if (i === 0) fail(!cert.ca && bits.value[1] & 128, 'LEAF_USAGE');
    else {
      fail(cert.ca && bits.value[1] & 4, 'CA_USAGE');
      const bc = parsed.extensions.get('2.5.29.19');
      fail(bc?.critical, 'CA_CONSTRAINTS');
      const constraint = parseDER(bc.value),
        path = constraint.children?.find((n) => n.tag === 2);
      if (path) fail(intValue(path) >= BigInt(i - 1), 'PATH_LENGTH');
    }
    if (i + 1 < chain.length)
      fail(
        cert.checkIssued(chain[i + 1]) && cert.verify(chain[i + 1].publicKey),
        'CHAIN_SIGNATURE',
      );
    // Status is fetched or validated by the trusted server adapter, never supplied as a client claim.
    if (i + 1 < chain.length) {
      const s = status(cert, { at, issuer: chain[i + 1] });
      fail(
        s?.status === 'GOOD' &&
          s.checkedAt <= at &&
          at - s.checkedAt <= 86400 &&
          s.nextUpdate > at &&
          Buffer.isBuffer(s.evidenceHash) &&
          s.evidenceHash.length === 64,
        'STATUS',
      );
      evidence.push(s.evidenceHash);
    }
  }
  return {
    chain,
    leaf: parseCertificate(chain[0].raw),
    expiresAt: expiry,
    statusEvidenceHash: H('AttestationStatus', evidence),
    rootHash: sha256(root.raw),
  };
}
function matchesKey(leaf, holderPublicKey) {
  fail(
    holderPublicKey.type === 'public' &&
      holderPublicKey.asymmetricKeyType === 'ec' &&
      holderPublicKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
      equal(leaf.spki, spki(holderPublicKey)),
    'SUBJECT_KEY',
  );
}
export function verifyAndroidKeyAttestation(
  evidence,
  { holderPublicKey, challenge, at = now(), policy },
) {
  const chain = verifiedChain(evidence.x5c, policy, at);
  matchesKey(chain.leaf, holderPublicKey);
  // Only the first attestation extension walking from the trusted root is authoritative.
  // This profile requires that certificate to be the submitted holder leaf.
  const occurrences = chain.chain.map((c) =>
    parseCertificate(c.raw).extensions.has(ANDROID_KEY_OID),
  );
  fail(occurrences[0] && occurrences.slice(1).every((x) => !x), 'ANDROID_EXTENSION_POSITION');
  const kd = readAttestationDER(chain.leaf.extensions.get(ANDROID_KEY_OID).value);
  typed(kd, 16);
  fail(kd.children.length === 8, 'ANDROID_DESCRIPTION');
  const [version, level, mintVersion, mintLevel, nonce, uniqueID, softNode, hardNode] = kd.children,
    soft = authorizations(softNode),
    hard = authorizations(hardNode),
    securityLevel = number(level, 10);
  fail(
    [3, 4, 100, 200, 300, 400, 500].includes(number(version)) && number(mintVersion) >= 3,
    'ANDROID_VERSION',
  );
  fail(
    policy.allowedSecurityLevels?.includes(securityLevel) &&
      [1, 2].includes(securityLevel) &&
      number(mintLevel, 10) === securityLevel,
    'ANDROID_SECURITY_LEVEL',
  );
  fail(
    equal(octets(nonce), Buffer.from(challenge, 'utf8')) && Buffer.byteLength(challenge) <= 128,
    'CHALLENGE',
  );
  octets(uniqueID);
  fail(!soft.has(600) && !hard.has(600) && !soft.has(601) && !hard.has(601), 'ANDROID_APP_SCOPE');
  fail(
    number(hard.get(2)) === 3 &&
      number(hard.get(3)) === 256 &&
      number(hard.get(10)) === 1 &&
      number(hard.get(702)) === 0 &&
      !soft.has(702),
    'ANDROID_KEY_PROPERTIES',
  );
  const purposes = numbers(hard.get(1)),
    digests = numbers(hard.get(5));
  fail(
    purposes.includes(2) &&
      purposes.every((x) => [2, 3].includes(x)) &&
      digests.includes(4) &&
      digests.every((x) => x === 4),
    'ANDROID_PURPOSE',
  );
  const root = typed(hard.get(704), 16).children;
  fail(
    root.length === 4 &&
      octets(root[0]).length > 0 &&
      typed(root[1], 1).value.equals(Buffer.from([255])) &&
      number(root[2], 10) === 0 &&
      octets(root[3]).length === 32,
    'ANDROID_VERIFIED_BOOT',
  );
  fail(
    Number.isSafeInteger(policy.minimumOSPatch) && number(hard.get(706)) >= policy.minimumOSPatch,
    'ANDROID_PATCH',
  );
  for (const [field, floor] of [
    [718, policy.minimumVendorPatch],
    [719, policy.minimumBootPatch],
  ])
    if (floor !== undefined) fail(number(hard.get(field)) >= floor, 'ANDROID_PATCH');
  const app = readAttestationDER(octets(soft.get(709)));
  typed(app, 16);
  fail(app.children.length === 2 && !hard.has(709), 'ANDROID_APPLICATION');
  const packages = typed(app.children[0], 17).children.map((p) => {
      typed(p, 16);
      fail(p.children.length === 2, 'ANDROID_APPLICATION');
      return { name: octets(p.children[0]).toString('utf8'), version: number(p.children[1]) };
    }),
    digestsAllowed = typed(app.children[1], 17).children.map((o) => octets(o).toString('hex'));
  fail(
    packages.length > 0 &&
      packages.every((p) =>
        policy.applications?.some((a) => a.packageName === p.name && p.version >= a.minimumVersion),
      ) &&
      digestsAllowed.length > 0 &&
      digestsAllowed.every((d) => policy.signingCertificateSHA256?.includes(d)),
    'ANDROID_APPLICATION',
  );
  let localUVPolicy = 'UNASSESSED';
  if (policy.requirePerUseAuthentication) {
    fail(
      !soft.has(503) &&
        !hard.has(503) &&
        !soft.has(504) &&
        hard.has(504) &&
        (!hard.has(505) || number(hard.get(505)) === 0) &&
        !soft.has(505),
      'ANDROID_USER_AUTH',
    );
    const authType = number(hard.get(504));
    fail(authType > 0 && (authType & ~policy.allowedUserAuthTypes) === 0, 'ANDROID_USER_AUTH');
    localUVPolicy = 'PER_USE_AUTH_REQUIRED';
  }
  return {
    boundary: securityLevel === 2 ? 'ANDROID_STRONGBOX' : 'ANDROID_TEE',
    localUVPolicy,
    expiresAt: chain.expiresAt,
    trustAnchorHash: chain.rootHash,
    statusEvidenceHash: chain.statusEvidenceHash,
  };
}
export function verifyAppleManagedAttestation(
  evidence,
  { holderPublicKey, challenge, at = now(), policy },
) {
  const chain = verifiedChain(evidence.x5c, policy, at);
  matchesKey(chain.leaf, holderPublicKey);
  fail(
    equal(
      chain.leaf.extensions.get(APPLE_NONCE_OID)?.value,
      sha256(Buffer.from(challenge, 'utf8')),
    ),
    'CHALLENGE',
  );
  fail(
    policy.flow === 'ACME_HARDWARE_BOUND' &&
      Array.isArray(policy.requiredProperties) &&
      policy.requiredProperties.length > 0,
    'APPLE_POLICY',
  );
  // Values are the original extnValue contents from Apple's attestation certificate.
  // Properties and exact accepted encodings are pinned by the operator's platform policy.
  for (const p of policy.requiredProperties) {
    const value = chain.leaf.extensions.get(p.oid)?.value;
    fail(value && p.acceptedValues.some((v) => equal(value, v)), 'APPLE_DEVICE_PROPERTY');
  }
  return {
    boundary: 'APPLE_SECURE_ENCLAVE',
    localUVPolicy: 'UNASSESSED',
    expiresAt: chain.expiresAt,
    trustAnchorHash: chain.rootHash,
    statusEvidenceHash: chain.statusEvidenceHash,
  };
}
class TPMReader {
  constructor(bytes) {
    fail(Buffer.isBuffer(bytes) && bytes.length <= 65536, 'TPM_SIZE');
    this.bytes = bytes;
    this.p = 0;
  }
  take(n) {
    fail(this.p + n <= this.bytes.length, 'TPM_TRUNCATED');
    const out = this.bytes.subarray(this.p, this.p + n);
    this.p += n;
    return out;
  }
  u16() {
    return this.take(2).readUInt16BE();
  }
  u32() {
    return this.take(4).readUInt32BE();
  }
  sized() {
    return this.take(this.u16());
  }
  end() {
    fail(this.p === this.bytes.length, 'TPM_TRAILING');
  }
}
export function verifyTPMCertify(evidence, { holderPublicKey, challenge, at = now(), policy }) {
  // AKs must be independently enrolled with EK credential activation or an audited ceremony.
  // An arbitrary AIK certificate or self-signed AK is never a hardware trust anchor.
  const ak = policy.authorizedAKs?.get(evidence.akID);
  fail(
    ak &&
      ak.status === 'ACTIVE' &&
      ak.notBefore <= at &&
      ak.expiresAt > at &&
      Buffer.isBuffer(ak.enrollmentEvidenceHash) &&
      ak.enrollmentEvidenceHash.length === 64,
    'TPM_AK_TRUST',
  );
  fail(
    ['EK_ACTIVATE_CREDENTIAL', 'AUDITED_HARDWARE_CEREMONY'].includes(ak.enrollmentMethod) &&
      ak.restrictedSigning === true &&
      ak.fixedTPM === true &&
      ak.fixedParent === true &&
      ak.sensitiveDataOrigin === true &&
      typeof policy.akStatus === 'function',
    'TPM_AK_ENROLLMENT',
  );
  const status = policy.akStatus(evidence.akID, { at });
  fail(
    status?.status === 'GOOD' &&
      status.checkedAt <= at &&
      at - status.checkedAt <= 86400 &&
      status.nextUpdate > at &&
      status.evidenceHash?.length === 64,
    'TPM_AK_STATUS',
  );
  const pub = new TPMReader(evidence.pubArea);
  fail(pub.u16() === 0x23 && pub.u16() === 0x0b, 'TPM_KEY_ALGORITHM');
  const attributes = pub.u32(),
    authPolicy = pub.sized();
  fail(
    (attributes & 0x32) === 0x32 && attributes & 0x40000 && !(attributes & 0x30000),
    'TPM_KEY_ATTRIBUTES',
  );
  fail(
    !policy.requiredAuthPolicy || equal(authPolicy, policy.requiredAuthPolicy),
    'TPM_AUTH_POLICY',
  );
  fail(pub.u16() === 0x10, 'TPM_SYMMETRIC');
  const scheme = pub.u16();
  fail(scheme === 0x10 || (scheme === 0x18 && pub.u16() === 0x0b), 'TPM_SCHEME');
  fail(pub.u16() === 3 && pub.u16() === 0x10, 'TPM_CURVE');
  const x = pub.sized(),
    y = pub.sized();
  pub.end();
  fail(x.length === 32 && y.length === 32, 'TPM_POINT');
  const publicKey = createPublicKey({
    format: 'jwk',
    key: { kty: 'EC', crv: 'P-256', x: b64u(x), y: b64u(y) },
  });
  fail(equal(spki(publicKey), spki(holderPublicKey)), 'SUBJECT_KEY');
  const info = new TPMReader(evidence.certInfo);
  fail(info.u32() === 0xff544347 && info.u16() === 0x8017, 'TPM_CERTIFY_TYPE');
  fail(equal(info.sized(), ak.qualifiedName), 'TPM_SIGNER');
  fail(equal(info.sized(), sha256(Buffer.from(challenge, 'utf8'))), 'CHALLENGE');
  info.take(8);
  info.u32();
  info.u32();
  fail(info.take(1)[0] === 1, 'TPM_CLOCK_SAFE');
  info.take(8);
  fail(
    equal(info.sized(), Buffer.concat([Buffer.from([0, 0x0b]), sha256(evidence.pubArea)])),
    'TPM_NAME',
  );
  const qualifiedName = info.sized();
  fail(qualifiedName.length === 34, 'TPM_QUALIFIED_NAME');
  info.end();
  const sig = new TPMReader(evidence.signature),
    alg = sig.u16(),
    hash = sig.u16();
  fail(hash === 0x0b, 'TPM_SIGNATURE_ALGORITHM');
  let signature;
  if (alg === 0x18) {
    fail(
      ak.publicKey.asymmetricKeyType === 'ec' &&
        ak.publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1',
      'TPM_AK_ALGORITHM',
    );
    const r = sig.sized(),
      s = sig.sized();
    fail(r.length > 0 && r.length <= 32 && s.length > 0 && s.length <= 32, 'TPM_SIGNATURE');
    signature = p1363ToDER(
      Buffer.concat([Buffer.alloc(32 - r.length), r, Buffer.alloc(32 - s.length), s]),
    );
  } else {
    fail(
      alg === 0x14 &&
        ak.publicKey.asymmetricKeyType === 'rsa' &&
        ak.publicKey.asymmetricKeyDetails.modulusLength >= 2048,
      'TPM_AK_ALGORITHM',
    );
    signature = sig.sized();
  }
  sig.end();
  fail(cryptoVerify('sha256', evidence.certInfo, ak.publicKey, signature), 'TPM_SIGNATURE');
  return {
    boundary: 'TPM2',
    localUVPolicy: 'UNASSESSED',
    expiresAt: ak.expiresAt,
    trustAnchorHash: sha256(spki(ak.publicKey)),
    statusEvidenceHash: status.evidenceHash,
    enrollmentEvidenceHash: ak.enrollmentEvidenceHash,
  };
}
export function assessKeyAttestation(evidence, options) {
  const { holderPublicKey, policy, allowUnattested = false, at = now() } = options;
  evidence ??= { format: 'none' };
  const fields = {
    none: ['format'],
    'android-key': ['format', 'x5c'],
    'apple-managed-acme': ['format', 'x5c'],
    'tpm2-certify': ['format', 'akID', 'pubArea', 'certInfo', 'signature'],
  };
  fail(
    fields[evidence.format] &&
      Object.keys(evidence).every((k) => fields[evidence.format].includes(k)),
    'UNSUPPORTED_FORMAT',
  );
  const evidenceHash = H('KeyAttestationEvidence', evidence);
  if (evidence.format === 'none') {
    fail(allowUnattested, 'REQUIRED');
    return {
      schemaVersion: 1,
      format: 'none',
      assurance: 'UNATTESTED',
      keyAssurance: 'KAL1',
      boundary: 'UNATTESTED',
      localUVPolicy: 'UNASSESSED',
      holderKeyID: keyID(holderPublicKey),
      evidenceHash,
      verifiedAt: at,
      expiresAt: at + 86400,
    };
  }
  fail(policy?.id && policy.formats?.[evidence.format], 'FORMAT_POLICY');
  const validators = {
      'android-key': verifyAndroidKeyAttestation,
      'apple-managed-acme': verifyAppleManagedAttestation,
      'tpm2-certify': verifyTPMCertify,
    },
    validate = validators[evidence.format];
  fail(validate, 'UNSUPPORTED_FORMAT');
  const result = validate(evidence, { ...options, policy: policy.formats[evidence.format], at });
  return {
    schemaVersion: 1,
    format: evidence.format,
    policyID: policy.id,
    assurance: 'HARDWARE_KEY_VERIFIED',
    keyAssurance: 'KAL2',
    holderKeyID: keyID(holderPublicKey),
    evidenceHash,
    verifiedAt: at,
    ...result,
  };
}
// Android's service is HTTPS authenticated; the client cannot supply its GOOD result.
export async function fetchAndroidRevocationStatus({
  fetchImpl = fetch,
  at = now(),
  lifetime = 3600,
} = {}) {
  fail(lifetime > 0 && lifetime <= 86400, 'STATUS_LIFETIME');
  const response = await fetchImpl('https://android.googleapis.com/attestation/status', {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  fail(
    response.ok && Number(response.headers.get('content-length') ?? 0) <= 1048576,
    'STATUS_DOWNLOAD',
  );
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    fail(size <= 1048576, 'STATUS_SIZE');
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks),
    value = parseJSON(bytes.toString('utf8'));
  fail(
    value.entries && typeof value.entries === 'object' && !Array.isArray(value.entries),
    'STATUS_FORMAT',
  );
  const entries = new Map(
    Object.entries(value.entries).map(([serial, v]) => [
      serial.replace(/^0+/, '').toLowerCase(),
      v,
    ]),
  );
  return (certificate) => ({
    status: entries.has(certificate.serialNumber.replace(/^0+/, '').toLowerCase())
      ? 'REVOKED'
      : 'GOOD',
    checkedAt: at,
    nextUpdate: at + lifetime,
    evidenceHash: H('AndroidRevocationStatus', bytes),
  });
}

// Checks the issuer-authenticated assessment carried by a signer mdoc.
// This validates claim semantics; live raw attestation is checked by DeviceBindingRegistry.
export function validateAdmissionAssessment(a, holderPublicKey, at = now()) {
  fail(
    a?.schemaVersion === 1 &&
      equal(a.holderKeyID, keyID(holderPublicKey)) &&
      Buffer.isBuffer(a.evidenceHash) &&
      a.evidenceHash.length === 64 &&
      Number.isSafeInteger(a.verifiedAt) &&
      Number.isSafeInteger(a.expiresAt) &&
      a.verifiedAt <= at &&
      a.expiresAt > at,
    'ASSESSMENT_BINDING',
  );
  if (a.assurance === 'UNATTESTED') {
    fail(
      a.format === 'none' &&
        a.keyAssurance === 'KAL1' &&
        a.boundary === 'UNATTESTED' &&
        a.localUVPolicy === 'UNASSESSED',
      'ASSESSMENT_ASSURANCE',
    );
  } else {
    const boundaries = {
      'android-key': ['ANDROID_TEE', 'ANDROID_STRONGBOX'],
      'apple-managed-acme': ['APPLE_SECURE_ENCLAVE'],
      'tpm2-certify': ['TPM2'],
    };
    fail(
      a.assurance === 'HARDWARE_KEY_VERIFIED' &&
        a.keyAssurance === 'KAL2' &&
        boundaries[a.format]?.includes(a.boundary) &&
        typeof a.policyID === 'string' &&
        a.policyID.length > 0 &&
        a.policyID.length <= 256 &&
        Buffer.isBuffer(a.trustAnchorHash) &&
        a.trustAnchorHash.length === 32 &&
        Buffer.isBuffer(a.statusEvidenceHash) &&
        a.statusEvidenceHash.length === 64 &&
        ['UNASSESSED', ...(a.format === 'android-key' ? ['PER_USE_AUTH_REQUIRED'] : [])].includes(
          a.localUVPolicy,
        ),
      'ASSESSMENT_ASSURANCE',
    );
    if (a.format === 'tpm2-certify')
      fail(
        Buffer.isBuffer(a.enrollmentEvidenceHash) && a.enrollmentEvidenceHash.length === 64,
        'ASSESSMENT_AK_ENROLLMENT',
      );
  }
  return a;
}
