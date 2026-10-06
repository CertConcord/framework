import { X509Certificate } from 'node:crypto';
import registry from './registry.json' with { type: 'json' };
import {
  ALG,
  requireThat,
  seq,
  set,
  oid,
  octet,
  bit,
  der,
  integer,
  parseDER,
  oidText,
  intValue,
  spki,
  sha256,
  sha512,
  sign,
  verify,
  equal,
  publicFromDER,
  now,
  D,
  H,
} from './core.mjs';

export const OID = {
  data: '1.2.840.113549.1.7.1',
  signed: '1.2.840.113549.1.7.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  sha256: '2.16.840.1.101.3.4.2.1',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  ess: '1.2.840.113549.1.9.16.2.47',
  timestamp: '1.2.840.113549.1.9.16.2.14',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  mtc: '1.3.6.1.4.1.44363.47.0',
  trustAnchorID: '1.3.6.1.4.1.44363.47.3',
  mtcCA: '1.3.6.1.4.1.44363.47.4',
};
export const RRA = Object.fromEntries(registry.entries.map((e) => [e.name, e.oid]));
export const algID = (name) => seq(oid(ALG[name]?.oid ?? name));
export const name = (cn) => seq(set(seq(oid('2.5.4.3'), der(12, Buffer.from(cn)))));
export const anchorName = (caID) => seq(set(seq(oid(OID.trustAnchorID), oid(caID, true))));
export const generalizedTime = (seconds) =>
  der(
    24,
    Buffer.from(
      new Date(seconds * 1000)
        .toISOString()
        .replace(/[-:T]/g, '')
        .replace(/\.\d{3}Z$/, 'Z'),
    ),
  );
export function extension(id, value, critical = false) {
  return seq(oid(id), ...(critical ? [der(1, Buffer.from([255]))] : []), octet(value));
}
export const profiles = Object.freeze({
  'CERTCONCORD-PERSON-PASSKEY-SIGN-v1': {
    ku: 128,
    eku: RRA['id-kp-certconcordDocumentSigning'],
    days: 90,
    kal: 2,
    sal: 1,
  },
  'CERTCONCORD-PERSON-SIGN-v1': { ku: 128, eku: RRA['id-kp-certconcordDocumentSigning'], days: 90, kal: 1, sal: 1 },
  'CERTCONCORD-PERSON-COMMIT-v1': {
    ku: 64,
    eku: RRA['id-kp-certconcordDocumentSigning'],
    days: 90,
    kal: 2,
    sal: 2,
  },
  'CERTCONCORD-ORG-SEAL-v1': { ku: 64, eku: RRA['id-kp-certconcordOrganizationSeal'], days: 90, kal: 2, sal: 1 },
  'CERTCONCORD-SERVICE-SIGN-v1': { ku: 128, eku: RRA['id-kp-certconcordServiceSigning'], days: 30, kal: 1, sal: 1 },
  'CERTCONCORD-EVIDENCE-SIGN-v1': {
    ku: 128,
    eku: RRA['id-kp-certconcordEvidenceSigning'],
    days: 30,
    kal: 1,
    sal: 1,
  },
  'CERTCONCORD-DOC-ENC-v1': { ku: 32, eku: RRA['id-kp-certconcordDocumentEncryption'], days: 90, kal: 1, sal: 0 },
  'CERTCONCORD-TSA-v1': { ku: 128, eku: '1.3.6.1.5.5.7.3.8', days: 30, kal: 1, sal: 0 },
  'CERTCONCORD-MDOC-DS-v1': { ku: 128, eku: '1.0.18013.5.1.2', days: 90, kal: 1, sal: 0 },
  'CERTCONCORD-MDOC-READER-v1': { ku: 128, eku: '1.0.18013.5.1.6', days: 90, kal: 1, sal: 0 },
  'CERTCONCORD-MDOC-PID-DS-ARF14': { ku: 128, eku: '1.3.130.2.0.0.1.2', days: 90, kal: 1, sal: 0 },
  'CERTCONCORD-MDOC-PID-READER-ARF14': { ku: 128, eku: '1.3.130.2.0.0.1.6', days: 90, kal: 1, sal: 0 },
});
export function tbsCertificate({
  publicKey,
  issuer,
  subject,
  serial,
  signatureAlgorithm,
  notBefore = now() - 60,
  notAfter = now() + 86400,
  profileID = 'CERTCONCORD-PERSON-SIGN-v1',
  extraExtensions = [],
  ca = false,
  subjectKeyIdentifier,
}) {
  const p = profiles[profileID];
  requireThat(p || ca, 'UNKNOWN_PROFILE');
  requireThat(
    notAfter > notBefore && (ca || notAfter - notBefore <= p.days * 86400),
    'CERTIFICATE_LIFETIME',
  );
  if (!ca)
    requireThat(
      profileID === 'CERTCONCORD-DOC-ENC-v1'
        ? publicKey.asymmetricKeyType.startsWith('ml-kem-')
        : ['ml-dsa-65', 'ml-dsa-87', 'ec', 'ed25519'].includes(publicKey.asymmetricKeyType),
      'KEY_PURPOSE',
    );
  if (profileID === 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1')
    requireThat(
      publicKey.asymmetricKeyType === 'ec' &&
        publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1',
      'PASSKEY_CERTIFICATE_ALGORITHM',
    );
  const extensions = [
    extension('2.5.29.19', ca ? seq(der(1, Buffer.from([255])), integer(0)) : seq(), true),
    extension(
      '2.5.29.15',
      der(3, Buffer.from(ca ? [1, 6] : p.ku === 128 ? [7, 128] : p.ku === 64 ? [6, 64] : [5, 32])),
      true,
    ),
    extension('2.5.29.14', octet(subjectKeyIdentifier ?? sha256(spki(publicKey)))),
  ];
  if (!ca)
    extensions.push(
      extension(
        '2.5.29.37',
        seq(oid(p.eku)),
        profileID === 'CERTCONCORD-TSA-v1' || profileID.startsWith('CERTCONCORD-MDOC-'),
      ),
    );
  extensions.push(...extraExtensions);
  return seq(
    der(0xa0, integer(2)),
    integer(serial),
    algID(signatureAlgorithm),
    issuer,
    seq(generalizedTime(notBefore), generalizedTime(notAfter)),
    subject,
    spki(publicKey),
    der(0xa3, seq(...extensions)),
  );
}
export function certificateFromTBS(tbs, signatureAlgorithm, signature) {
  return seq(tbs, algID(signatureAlgorithm), bit(signature));
}
export function issueCertificate(options, issuerKey) {
  const algorithm = issuerKey.asymmetricKeyType;
  const tbs = tbsCertificate({ ...options, signatureAlgorithm: algorithm });
  return certificateFromTBS(tbs, algorithm, sign(tbs, issuerKey));
}
export function parseCertificate(raw) {
  const root = parseDER(raw);
  requireThat(root.tag === 48 && root.children?.length === 3, 'CERTIFICATE_STRUCTURE');
  const [tbs, alg, sig] = root.children,
    t = tbs.children;
  requireThat(
    t?.length >= 7 && t[0].tag === 0xa0 && intValue(t[0].children[0]) === 2n,
    'CERTIFICATE_VERSION',
  );
  requireThat(
    equal(alg.raw, t[2].raw) && sig.tag === 3 && sig.value[0] === 0,
    'CERTIFICATE_ALGORITHM',
  );
  const extensions = new Map();
  for (const e of t.find((n) => n.tag === 0xa3)?.children[0].children ?? []) {
    const id = oidText(e.children[0]);
    requireThat(!extensions.has(id), 'DUPLICATE_EXTENSION');
    const critical = e.children.length === 3;
    requireThat(
      !critical || equal(e.children[1].raw, Buffer.from('0101ff', 'hex')),
      'BAD_CRITICAL',
    );
    extensions.set(id, { critical, value: e.children.at(-1).value });
  }
  const time = (n) => {
    let s = n.value.toString('ascii');
    if (n.tag === 23) {
      requireThat(/^\d{12}Z$/.test(s), 'CERTIFICATE_TIME');
      s = (Number(s.slice(0, 2)) >= 50 ? '19' : '20') + s;
    } else requireThat(n.tag === 24 && /^\d{14}Z$/.test(s), 'CERTIFICATE_TIME');
    const seconds =
      Date.parse(
        `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`,
      ) / 1000;
    requireThat(
      Number.isSafeInteger(seconds) && generalizedTime(seconds).equals(der(24, Buffer.from(s))),
      'CERTIFICATE_TIME',
    );
    return seconds;
  };
  return {
    raw: Buffer.from(raw),
    tbs: tbs.raw,
    serial: intValue(t[1]),
    issuer: t[3].raw,
    subject: t[5].raw,
    spki: t[6].raw,
    publicKey: publicFromDER(t[6].raw),
    algorithm: oidText(alg.children[0]),
    algorithmRaw: alg.raw,
    signature: sig.value.subarray(1),
    notBefore: time(t[4].children[0]),
    notAfter: time(t[4].children[1]),
    extensions,
    certificateID: H('CertificateTBS', tbs.raw),
    representationHash: sha512(raw),
  };
}
export function validateCertificate(
  raw,
  issuerKey,
  { at = now(), profileID, allowCA = false } = {},
) {
  const c = parseCertificate(raw);
  requireThat(
    c.algorithm === ALG[issuerKey.asymmetricKeyType]?.oid &&
      equal(c.algorithmRaw, algID(issuerKey.asymmetricKeyType)),
    'CERTIFICATE_ALGORITHM',
  );
  requireThat(verify(c.tbs, c.signature, issuerKey), 'CERTIFICATE_SIGNATURE');
  requireThat(at >= c.notBefore && at < c.notAfter, 'CERTIFICATE_TIME');
  const known = new Set([
    '2.5.29.19',
    '2.5.29.15',
    '2.5.29.14',
    '2.5.29.35',
    '2.5.29.37',
    ...Object.values(RRA),
  ]);
  for (const [id, e] of c.extensions)
    requireThat(!e.critical || known.has(id), 'UNKNOWN_CRITICAL_EXTENSION');
  requireThat(
    allowCA || equal(c.extensions.get('2.5.29.19')?.value ?? Buffer.alloc(0), seq()),
    'CA_NOT_ALLOWED',
  );
  if (profileID) {
    const p = profiles[profileID];
    requireThat(p, 'UNKNOWN_PROFILE');
    if (profileID === 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1')
      requireThat(
        c.publicKey.asymmetricKeyType === 'ec' &&
          c.publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
          c.extensions.get(RRA['id-pe-certconcordPasskeyBinding'])?.critical,
        'PASSKEY_CERTIFICATE_BINDING',
      );
    requireThat(
      equal(c.extensions.get('2.5.29.37')?.value ?? Buffer.alloc(0), seq(oid(p.eku))),
      'CERTIFICATE_EKU',
    );
    requireThat(
      parseDER(c.extensions.get('2.5.29.15').value).value[1] === p.ku,
      'CERTIFICATE_KEY_USAGE',
    );
    if (profileID === 'CERTCONCORD-TSA-v1')
      requireThat(c.extensions.get('2.5.29.37').critical, 'TSA_EKU_NOT_CRITICAL');
  }
  return c;
}
export function attribute(id, value) {
  return seq(oid(id), set(value));
}
function cmsSuite(cert) {
  if (cert.publicKey.asymmetricKeyType === 'ec') {
    requireThat(
      cert.publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
        cert.extensions.get(RRA['id-pe-certconcordPasskeyBinding'])?.critical,
      'CMS_ALGORITHM',
    );
    return { digestOID: OID.sha256, digest: sha256 };
  }
  requireThat(
    ['ml-dsa-65', 'ml-dsa-87'].includes(cert.publicKey.asymmetricKeyType),
    'CMS_ALGORITHM',
  );
  return { digestOID: OID.sha512, digest: sha512 };
}
export function prepareCMS({
  content,
  certificate,
  contentType = OID.data,
  detached = false,
  context,
  simHash,
  policyHash,
  additionalAttributes = [],
}) {
  const cert = parseCertificate(certificate);
  const { digestOID, digest } = cmsSuite(cert);
  const attrs = [
    attribute(OID.contentType, oid(contentType)),
    attribute(OID.messageDigest, octet(digest(content))),
    attribute(OID.ess, seq(seq(seq(algID(OID.sha512), octet(sha512(certificate)))))),
  ];
  if (context)
    attrs.push(attribute(RRA['id-aa-certconcordSignatureContext'], octet(D('SignatureContext', context))));
  if (simHash) attrs.push(attribute(RRA['id-aa-certconcordSigningIntent'], octet(simHash)));
  if (policyHash) attrs.push(attribute(RRA['id-aa-certconcordSignaturePolicy'], octet(policyHash)));
  attrs.push(...additionalAttributes);
  const tbs = set(...attrs),
    a = cert.publicKey.asymmetricKeyType;
  return {
    tbs,
    certificateID: cert.certificateID,
    representationHash: cert.representationHash,
    finish(signature, unsignedAttributes = []) {
      requireThat(verify(tbs, signature, cert.publicKey), 'PROVIDER_SIGNATURE');
      const si = seq(
        integer(1),
        seq(cert.issuer, integer(cert.serial)),
        algID(digestOID),
        der(0xa0, parseDER(tbs).value),
        algID(a),
        octet(signature),
        ...(unsignedAttributes.length
          ? [der(0xa1, parseDER(set(...unsignedAttributes)).value)]
          : []),
      );
      return seq(
        oid(OID.signed),
        der(
          0xa0,
          seq(
            integer(contentType === OID.data ? 1 : 3),
            set(algID(digestOID)),
            seq(oid(contentType), ...(detached ? [] : [der(0xa0, octet(content))])),
            der(0xa0, certificate),
            set(si),
          ),
        ),
      );
    },
  };
}
export function signCMS(options, privateKey) {
  const p = prepareCMS(options);
  return p.finish(sign(p.tbs, privateKey));
}
export function verifyCMS(
  raw,
  {
    content: detachedContent,
    expectedCertificate,
    expectedContentType = OID.data,
    context,
    simHash,
    policyHash,
    issuerKey,
    at = now(),
    profileID,
  } = {},
) {
  const root = parseDER(raw);
  requireThat(
    root.tag === 0x30 &&
      root.children?.length === 2 &&
      root.children[0].tag === 6 &&
      oidText(root.children[0]) === OID.signed &&
      root.children[1].tag === 0xa0 &&
      root.children[1].children?.length === 1 &&
      root.children[1].children[0].tag === 0x30,
    'CMS_CONTENT_TYPE',
  );
  const sd = root.children[1].children[0].children;
  requireThat(
    sd?.length === 5 &&
      sd[1].tag === 0x31 &&
      sd[1].children?.length === 1 &&
      sd[1].children[0].tag === 0x30,
    'CMS_DIGEST',
  );
  const enc = sd[2].children;
  requireThat(sd[2].tag === 0x30 && enc && [1, 2].includes(enc.length), 'CMS_ENCAP_STRUCTURE');
  requireThat(enc[0].tag === 6 && oidText(enc[0]) === expectedContentType, 'CMS_CONTENT_TYPE');
  // The supported profile uses X.509 certificates and issuer-and-serial SignerInfo.
  requireThat(intValue(sd[0]) === (expectedContentType === OID.data ? 1n : 3n), 'CMS_VERSION');
  if (enc[1])
    requireThat(
      enc[1].tag === 0xa0 && enc[1].children?.length === 1 && enc[1].children[0].tag === 4,
      'CMS_ENCAP_STRUCTURE',
    );
  const embedded = enc[1]?.children?.[0]?.value;
  requireThat(embedded !== undefined || detachedContent !== undefined, 'DETACHED_CONTENT_MISSING');
  if (embedded !== undefined && detachedContent !== undefined)
    requireThat(equal(embedded, detachedContent), 'CONTENT_CONFLICT');
  const content = embedded ?? detachedContent;
  requireThat(
    sd[3].tag === 0xa0 &&
      sd[3].children?.length === 1 &&
      sd[3].children[0].tag === 0x30 &&
      sd[4].tag === 0x31 &&
      sd[4].children?.length === 1 &&
      sd[4].children[0].tag === 0x30,
    'CMS_SIGNERS',
  );
  const certificate = sd[3].children[0].raw;
  if (expectedCertificate)
    requireThat(equal(certificate, expectedCertificate), 'CERTIFICATE_REPRESENTATION');
  const cert = issuerKey
    ? validateCertificate(certificate, issuerKey, { at, profileID })
    : parseCertificate(certificate);
  const { digestOID, digest } = cmsSuite(cert);
  requireThat(equal(sd[1].children[0].raw, algID(digestOID)), 'CMS_DIGEST');
  const si = sd[4].children[0].children;
  requireThat(
    si && [6, 7].includes(si.length) && intValue(si[0]) === 1n && (!si[6] || si[6].tag === 0xa1),
    'CMS_SIGNER_STRUCTURE',
  );
  requireThat(
    equal(si[1].raw, seq(cert.issuer, integer(cert.serial))) &&
      equal(si[2].raw, algID(digestOID)) &&
      equal(si[4].raw, algID(cert.publicKey.asymmetricKeyType)),
    'CMS_SIGNER_ID_OR_ALGORITHM',
  );
  requireThat(si[3].tag === 0xa0 && si[5].tag === 4, 'CMS_ATTRS_OR_SIGNATURE');
  const tbs = der(0x31, si[3].value);
  parseDER(tbs);
  const attrs = new Map();
  for (const a of si[3].children) {
    requireThat(
      a.tag === 0x30 &&
        a.children?.length === 2 &&
        a.children[0].tag === 6 &&
        a.children[1].tag === 0x31 &&
        a.children[1].children?.length === 1,
      'CMS_ATTRIBUTE_STRUCTURE',
    );
    const id = oidText(a.children[0]);
    requireThat(!attrs.has(id) && a.children[1].children.length === 1, 'CMS_DUPLICATE_ATTRIBUTE');
    attrs.set(id, a.children[1].children[0]);
  }
  for (const a of si[6]?.children ?? []) {
    requireThat(
      a.tag === 0x30 &&
        a.children?.length === 2 &&
        a.children[0].tag === 6 &&
        a.children[1].tag === 0x31 &&
        a.children[1].children?.length > 0,
      'CMS_UNSIGNED_ATTRIBUTE_STRUCTURE',
    );
    oidText(a.children[0]);
  }
  requireThat(
    attrs.get(OID.contentType)?.tag === 6 &&
      oidText(attrs.get(OID.contentType)) === expectedContentType,
    'CMS_CONTENT_TYPE_ATTRIBUTE',
  );
  requireThat(
    attrs.get(OID.messageDigest)?.tag === 4 &&
      equal(attrs.get(OID.messageDigest).value, digest(content)),
    'CMS_CONTENT_DIGEST',
  );
  requireThat(
    equal(
      attrs.get(OID.ess)?.raw ?? Buffer.alloc(0),
      seq(seq(seq(algID(OID.sha512), octet(sha512(certificate))))),
    ),
    'ESS_CERTIFICATE_BINDING',
  );
  for (const [id, expected] of [
    [RRA['id-aa-certconcordSignatureContext'], context && D('SignatureContext', context)],
    [RRA['id-aa-certconcordSigningIntent'], simHash],
    [RRA['id-aa-certconcordSignaturePolicy'], policyHash],
  ])
    if (expected)
      requireThat(
        attrs.get(id)?.tag === 4 && equal(attrs.get(id).value, expected),
        'CERTCONCORD_SIGNED_BINDING',
      );
  requireThat(verify(tbs, si[5].value, cert.publicKey), 'CMS_SIGNATURE');
  return {
    content,
    certificate,
    cert,
    tbs,
    signature: si[5].value,
    attributes: attrs,
    unsignedAttributes: si[6]?.children ?? [],
    cryptographicValidity: 'VALID',
    trust: issuerKey ? 'ISSUER_SIGNATURE_CHECKED' : 'NOT_EVALUATED',
  };
}

export function nativeCertificate(raw) {
  return new X509Certificate(raw);
}
