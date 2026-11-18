import { X509Certificate, createHash, verify as cryptoVerify, constants } from 'node:crypto';
import {
  parseDER,
  oidText,
  intValue,
  seq,
  oid,
  integer,
  octet,
  der,
  equal,
  requireThat,
} from './core.mjs';
import { OID } from './pki.mjs';

const hashes = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};
const digest = (a, b) => createHash(a).update(b).digest();
function hashAlgorithm(n) {
  const a = n.children;
  requireThat(
    a?.length >= 1 &&
      a.length <= 2 &&
      (!a[1] || equal(a[1].raw, Buffer.from('0500', 'hex'))) &&
      hashes[oidText(a[0])],
    'CMS_DIGEST_ALGORITHM',
  );
  return hashes[oidText(a[0])];
}
function signedDataVersion(sd, contentType, signerVersion) {
  // RFC 5652 section 5.1 assigns the version from the actual certificate,
  // revocation and signer choices, not from the digest or signature result.
  const certificates = sd.find((n) => n.tag === 0xa0)?.children ?? [],
    crls = sd.find((n) => n.tag === 0xa1)?.children ?? [];
  if (certificates.some((n) => n.tag === 0xa3) || crls.some((n) => n.tag === 0xa1)) return 5n;
  if (certificates.some((n) => n.tag === 0xa2)) return 4n;
  if (certificates.some((n) => n.tag === 0xa1) || signerVersion === 3n || contentType !== OID.data)
    return 3n;
  return 1n;
}
export function verifyExternalCMS(raw, { certificate, expectedContentType, content }) {
  const root = parseDER(raw);
  requireThat(
    root.tag === 0x30 &&
      root.children?.length === 2 &&
      root.children[0].tag === 0x06 &&
      root.children[1].tag === 0xa0 &&
      root.children[1].children?.length === 1 &&
      root.children[1].children[0].tag === 0x30,
    'CMS_CONTENT_INFO_STRUCTURE',
  );
  requireThat(oidText(root.children[0]) === OID.signed, 'CMS_TYPE');
  const sd = root.children[1].children[0].children;
  let signerIndex = 3;
  if (sd[signerIndex]?.tag === 0xa0) signerIndex++;
  if (sd[signerIndex]?.tag === 0xa1) signerIndex++;
  requireThat(
    sd.length === signerIndex + 1 && sd[signerIndex].tag === 0x31,
    'CMS_SIGNED_DATA_STRUCTURE',
  );
  const encapContentInfo = sd[2];
  requireThat(
    encapContentInfo?.tag === 0x30 &&
      encapContentInfo.children?.length >= 1 &&
      encapContentInfo.children.length <= 2 &&
      encapContentInfo.children[0].tag === 0x06 &&
      (!encapContentInfo.children[1] ||
        (encapContentInfo.children[1].tag === 0xa0 &&
          encapContentInfo.children[1].children?.length === 1 &&
          encapContentInfo.children[1].children[0].tag === 0x04)),
    'CMS_ENCAP_CONTENT_INFO_STRUCTURE',
  );
  const eci = encapContentInfo.children;
  requireThat(oidText(eci[0]) === expectedContentType, 'CMS_TYPE');
  const embedded = eci[1]?.children[0].value;
  if (embedded && content) requireThat(equal(embedded, content), 'CMS_CONTENT_CONFLICT');
  content = embedded ?? content;
  requireThat(Buffer.isBuffer(content), 'CMS_CONTENT');
  const certSet = sd.find((n) => n.tag === 0xa0);
  requireThat(
    certSet && certSet.children.some((n) => equal(n.raw, certificate)),
    'CMS_CERTIFICATE_PIN',
  );
  const x509 = new X509Certificate(certificate),
    cert = parseDER(certificate).children[0].children,
    shift = cert[0].tag === 0xa0 ? 1 : 0,
    serial = cert[shift],
    issuer = cert[shift + 2],
    sis = sd[signerIndex].children;
  requireThat(sis.length === 1, 'CMS_SIGNER_COUNT');
  const si = sis[0].children;
  requireThat(
    si.length >= 6 &&
      si.length <= 7 &&
      intValue(si[0]) === 1n &&
      equal(si[1].raw, seq(issuer.raw, serial.raw)),
    'CMS_SIGNER',
  );
  requireThat(intValue(sd[0]) === signedDataVersion(sd, expectedContentType, 1n), 'CMS_VERSION');
  const hash = hashAlgorithm(si[2]);
  requireThat(
    sd[1].tag === 0x31 && sd[1].children.some((n) => hashAlgorithm(n) === hash),
    'CMS_DIGEST_SET',
  );
  requireThat(si[3].tag === 0xa0, 'CMS_SIGNED_ATTRS');
  const tbs = der(0x31, si[3].value);
  parseDER(tbs);
  const attrs = new Map();
  for (const a of si[3].children) {
    requireThat(
      a.tag === 0x30 &&
        a.children?.length === 2 &&
        a.children[0].tag === 0x06 &&
        a.children[1].tag === 0x31 &&
        a.children[1].children?.length === 1,
      'CMS_ATTRIBUTE_STRUCTURE',
    );
    const id = oidText(a.children[0]);
    requireThat(!attrs.has(id), 'CMS_DUPLICATE_ATTRIBUTE');
    attrs.set(id, a.children[1].children[0]);
  }
  const contentType = attrs.get(OID.contentType),
    messageDigest = attrs.get(OID.messageDigest);
  requireThat(contentType && messageDigest, 'CMS_CONTENT_DIGEST');
  requireThat(contentType.tag === 0x06 && messageDigest.tag === 0x04, 'CMS_ATTRIBUTE_STRUCTURE');
  requireThat(
    oidText(contentType) === expectedContentType &&
      equal(messageDigest.value, digest(hash, content)),
    'CMS_CONTENT_DIGEST',
  );
  const ess = attrs.get(OID.ess);
  requireThat(ess?.children?.[0]?.children?.length >= 1, 'CMS_ESS_REQUIRED');
  const id = ess.children[0].children[0].children;
  let at = 0,
    essHash = 'sha256';
  if (id[0].tag === 48) essHash = hashAlgorithm(id[at++]);
  requireThat(
    id[at].tag === 4 && equal(id[at++].value, digest(essHash, certificate)),
    'CMS_ESS_CERTIFICATE',
  );
  if (id[at]) {
    const serialBinding = id[at].children;
    requireThat(
      equal(serialBinding[1].raw, serial.raw) &&
        serialBinding[0].children.some(
          (n) => n.tag === 0xa4 && equal(n.children[0].raw, issuer.raw),
        ),
      'CMS_ESS_ISSUER_SERIAL',
    );
  }
  const algorithm = oidText(si[4].children[0]),
    params = si[4].children[1],
    key = x509.publicKey;
  let options = key,
    signatureHash = hash;
  if (algorithm === '1.2.840.113549.1.1.1') {
    requireThat(
      key.asymmetricKeyType === 'rsa' && (!params || equal(params.raw, Buffer.from('0500', 'hex'))),
      'CMS_RSA_PARAMETERS',
    );
    options = { key, padding: constants.RSA_PKCS1_PADDING };
  } else if (algorithm === '1.2.840.113549.1.1.10') {
    requireThat(key.asymmetricKeyType === 'rsa' && params?.tag === 48, 'CMS_PSS_PARAMETERS');
    const p = new Map(params.children.map((n) => [n.tag, n]));
    requireThat(
      p.size === params.children.length && p.has(0xa0) && p.has(0xa1) && p.has(0xa2),
      'CMS_PSS_PARAMETERS',
    );
    const h = hashAlgorithm(p.get(0xa0).children[0]),
      mgf = p.get(0xa1).children[0].children;
    requireThat(
      h === hash &&
        oidText(mgf[0]) === '1.2.840.113549.1.1.8' &&
        hashAlgorithm(mgf[1]) === hash &&
        (!p.has(0xa3) || intValue(p.get(0xa3).children[0]) === 1n),
      'CMS_PSS_HASH',
    );
    const saltLength = Number(intValue(p.get(0xa2).children[0]));
    requireThat(saltLength === digest(hash, Buffer.alloc(0)).length, 'CMS_PSS_SALT');
    options = { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength };
  } else if (
    ['1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4'].includes(algorithm)
  ) {
    requireThat(
      key.asymmetricKeyType === 'ec' &&
        !params &&
        {
          '1.2.840.10045.4.3.2': 'sha256',
          '1.2.840.10045.4.3.3': 'sha384',
          '1.2.840.10045.4.3.4': 'sha512',
        }[algorithm] === hash,
      'CMS_ECDSA_HASH',
    );
  } else if (['2.16.840.1.101.3.4.3.18', '2.16.840.1.101.3.4.3.19'].includes(algorithm)) {
    requireThat(
      key.asymmetricKeyType === (algorithm.endsWith('.18') ? 'ml-dsa-65' : 'ml-dsa-87') &&
        hash === 'sha512' &&
        !params,
      'CMS_MLDSA_PARAMETERS',
    );
    signatureHash = null;
  } else throw Error('CMS_UNSUPPORTED_ALGORITHM');
  requireThat(
    si[5].tag === 4 && cryptoVerify(signatureHash, tbs, options, si[5].value),
    'CMS_SIGNATURE',
  );
  return { content, certificate, x509, tbs, signature: si[5].value };
}
