import { createHash } from 'node:crypto';
import { seq, der, octet, oid, parseDER, spki, requireThat, equal, now } from './core.mjs';
import {
  issueCertificate,
  parseCertificate,
  extension,
  profiles,
  validateCertificate,
} from './pki.mjs';

const ski = (key) =>
  createHash('sha1')
    .update(parseDER(spki(key)).children[1].value.subarray(1))
    .digest();
function roleProfile(certificateProfile, reader) {
  requireThat(
    ['ISO_MDOC', 'EUDI_PID_ARF_1_4'].includes(certificateProfile),
    'MDOC_CERTIFICATE_SUITE',
  );
  return certificateProfile === 'EUDI_PID_ARF_1_4'
    ? reader
      ? 'CERTCONCORD-MDOC-PID-READER-ARF14'
      : 'CERTCONCORD-MDOC-PID-DS-ARF14'
    : reader
      ? 'CERTCONCORD-MDOC-READER-v1'
      : 'CERTCONCORD-MDOC-DS-v1';
}
function distribution(url) {
  requireThat(new URL(url).protocol === 'https:', 'MDOC_CRL_URL');
  return extension('2.5.29.31', seq(seq(der(0xa0, der(0xa0, der(0x86, Buffer.from(url)))))));
}
export function issueIACA({
  publicKey,
  privateKey,
  subject,
  serial,
  issuerAltName,
  crlURL,
  notBefore = now() - 60,
  notAfter = now() + 365 * 86400,
}) {
  requireThat(publicKey.asymmetricKeyType === 'ec', 'MDOC_IACA_ALGORITHM');
  return issueCertificate(
    {
      publicKey,
      subject,
      issuer: subject,
      serial,
      ca: true,
      notBefore,
      notAfter,
      subjectKeyIdentifier: ski(publicKey),
      extraExtensions: [
        extension('2.5.29.35', seq(der(0x80, ski(publicKey)))),
        extension('2.5.29.18', seq(der(0x86, Buffer.from(issuerAltName)))),
        distribution(crlURL),
      ],
    },
    privateKey,
  );
}
export function issueMdocCertificate({
  publicKey,
  subject,
  serial,
  issuerCertificate,
  issuerKey,
  reader = false,
  certificateProfile = 'ISO_MDOC',
  notBefore = now() - 60,
  notAfter = now() + 86400,
}) {
  const issuer = parseCertificate(issuerCertificate);
  requireThat(
    publicKey.asymmetricKeyType === 'ec' &&
      publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
      notBefore >= issuer.notBefore &&
      notAfter <= issuer.notAfter,
    'MDOC_CERTIFICATE_PARAMETERS',
  );
  return issueCertificate(
    {
      publicKey,
      subject,
      serial,
      issuer: issuer.subject,
      profileID: roleProfile(certificateProfile, reader),
      notBefore,
      notAfter,
      subjectKeyIdentifier: ski(publicKey),
      extraExtensions: [
        extension(
          '2.5.29.35',
          seq(der(0x80, parseDER(issuer.extensions.get('2.5.29.14').value).value)),
        ),
        ...['2.5.29.18', '2.5.29.31'].map((id) => {
          requireThat(issuer.extensions.has(id), 'MDOC_IACA_EXTENSIONS');
          return extension(id, issuer.extensions.get(id).value);
        }),
      ],
    },
    issuerKey,
  );
}
export function validateMdocCertificate(
  certificate,
  { issuerKey, reader = false, certificateProfile = 'ISO_MDOC', at = now() } = {},
) {
  const profileID = roleProfile(certificateProfile, reader),
    c = issuerKey
      ? validateCertificate(certificate, issuerKey, { profileID, at })
      : parseCertificate(certificate);
  requireThat(
    c.publicKey.asymmetricKeyType === 'ec' &&
      c.publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
      at >= c.notBefore &&
      at < c.notAfter &&
      equal(c.extensions.get('2.5.29.19')?.value, seq()),
    'MDOC_CERTIFICATE_PROFILE',
  );
  const eku = c.extensions.get('2.5.29.37');
  requireThat(
    eku?.critical &&
      parseDER(eku.value).children.length === 1 &&
      parseDER(eku.value).children[0].raw.equals(oid(profiles[profileID].eku)),
    'MDOC_CERTIFICATE_EKU',
  );
  requireThat(
    c.extensions.get('2.5.29.15')?.critical &&
      equal(parseDER(c.extensions.get('2.5.29.15').value).value, Buffer.from([7, 128])),
    'MDOC_CERTIFICATE_KU',
  );
  for (const id of ['2.5.29.14', '2.5.29.35', '2.5.29.18', '2.5.29.31'])
    requireThat(
      c.extensions.has(id) && !c.extensions.get(id).critical,
      'MDOC_CERTIFICATE_EXTENSION',
    );
  return c;
}
