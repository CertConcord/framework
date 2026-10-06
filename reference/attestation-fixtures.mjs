// Synthetic certificate and TPM structures for protocol tests. All private keys are generated in memory.
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { ANDROID_KEY_OID, APPLE_NONCE_OID } from './key-attestation.mjs';
import { derToP1363 } from './ecdsa.mjs';
export const explicitTag = (tag, value) =>
  tag < 31
    ? c.der(0xa0 + tag, value)
    : Buffer.concat([Buffer.from([0xbf]), c.base128(tag), c.der(0, value).subarray(1)]);
const enumerated = (n) => c.der(10, c.parseDER(c.integer(n)).value);
const status = (_certificate, { at = c.now() } = {}) => ({
  status: 'GOOD',
  checkedAt: at,
  nextUpdate: at + 3600,
  evidenceHash: c.H('SyntheticAttestationStatus', {}),
});
export function syntheticAttestationCA() {
  const key = c.generate('ec'),
    subject = p.name('Synthetic attestation root');
  const certificate = p.issueCertificate(
    { publicKey: key.publicKey, subject, issuer: subject, serial: 1, ca: true },
    key.privateKey,
  );
  return { ...key, certificate, subject };
}
function attestCertificate(authority, publicKey, extensions) {
  return p.issueCertificate(
    {
      publicKey,
      issuer: authority.subject,
      subject: p.name('Synthetic attested key'),
      serial: 2,
      extraExtensions: extensions,
    },
    authority.privateKey,
  );
}
export function androidFixture(
  holderPublicKey,
  challenge,
  changes = {},
  authority = syntheticAttestationCA(),
) {
  const packageName = 'org.certconcord.holder',
    signer = c.sha256(Buffer.from('Synthetic application signing certificate')),
    app = c.seq(
      c.set(c.seq(c.octet(Buffer.from(changes.packageName ?? packageName)), c.integer(1))),
      c.set(c.octet(signer)),
    ),
    hard = new Map([
      [1, c.set(c.integer(2))],
      [2, c.integer(3)],
      [3, c.integer(256)],
      [5, c.set(c.integer(4))],
      [10, c.integer(1)],
      [504, c.integer(2)],
      [702, c.integer(0)],
      [
        704,
        c.seq(
          c.octet(c.random()),
          c.der(1, Buffer.from([changes.locked === false ? 0 : 255])),
          enumerated(changes.bootState ?? 0),
          c.octet(c.random()),
        ),
      ],
      [705, c.integer(170000)],
      [706, c.integer(changes.patch ?? 202610)],
    ]);
  if (changes.noAuth) hard.set(503, c.der(5, Buffer.alloc(0)));
  if (changes.timeout !== undefined) hard.set(505, c.integer(changes.timeout));
  if (changes.origin !== undefined) hard.set(702, c.integer(changes.origin));
  const extension = c.seq(
    c.integer(300),
    enumerated(changes.level ?? 2),
    c.integer(300),
    enumerated(changes.level ?? 2),
    c.octet(Buffer.from(changes.challenge ?? challenge, 'utf8')),
    c.octet(Buffer.alloc(0)),
    c.seq(explicitTag(709, c.octet(app))),
    c.seq(...[...hard].sort((a, b) => a[0] - b[0]).map(([t, v]) => explicitTag(t, v))),
  );
  const leaf = attestCertificate(authority, holderPublicKey, [
    p.extension(ANDROID_KEY_OID, extension),
  ]);
  return {
    evidence: { format: 'android-key', x5c: [leaf, authority.certificate] },
    policy: {
      id: 'synthetic-android-attestation-v1',
      formats: {
        'android-key': {
          roots: [authority.certificate],
          status,
          allowedSecurityLevels: [2],
          minimumOSPatch: 202609,
          applications: [{ packageName, minimumVersion: 1 }],
          signingCertificateSHA256: [signer.toString('hex')],
          requirePerUseAuthentication: true,
          allowedUserAuthTypes: 2,
        },
      },
    },
    authority,
  };
}
export function appleFixture(
  holderPublicKey,
  challenge,
  changes = {},
  authority = syntheticAttestationCA(),
) {
  const osOID = '1.2.840.113635.100.8.10.1',
    os = Buffer.from('synthetic-platform-version');
  const leaf = attestCertificate(authority, holderPublicKey, [
    p.extension(APPLE_NONCE_OID, c.sha256(Buffer.from(changes.challenge ?? challenge))),
    p.extension(osOID, os),
    p.extension('1.2.840.113635.100.8.9.1', Buffer.from(changes.identifier ?? 'SYNTHETIC-SERIAL')),
  ]);
  return {
    evidence: { format: 'apple-managed-acme', x5c: [leaf, authority.certificate] },
    policy: {
      id: 'synthetic-managed-device-v1',
      formats: {
        'apple-managed-acme': {
          roots: [authority.certificate],
          status,
          flow: 'ACME_HARDWARE_BOUND',
          requiredProperties: [{ oid: osOID, acceptedValues: [os] }],
        },
      },
    },
  };
}
const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const sized = (bytes) => Buffer.concat([u16(bytes.length), bytes]);
export function tpmFixture(holderPublicKey, challenge, changes = {}) {
  const ak = c.generate('ec'),
    jwk = holderPublicKey.export({ format: 'jwk' }),
    qualifiedName = Buffer.concat([u16(0x0b), c.random()]),
    pubArea = Buffer.concat([
      u16(0x23),
      u16(0x0b),
      u32(changes.attributes ?? 0x40072),
      sized(Buffer.alloc(0)),
      u16(0x10),
      u16(0x18),
      u16(0x0b),
      u16(3),
      u16(0x10),
      sized(c.unb64u(jwk.x)),
      sized(c.unb64u(jwk.y)),
    ]),
    certInfo = Buffer.concat([
      u32(0xff544347),
      u16(0x8017),
      sized(qualifiedName),
      sized(c.sha256(Buffer.from(changes.challenge ?? challenge))),
      Buffer.alloc(8),
      u32(1),
      u32(0),
      Buffer.from([1]),
      Buffer.alloc(8),
      sized(Buffer.concat([u16(0x0b), c.sha256(pubArea)])),
      sized(Buffer.concat([u16(0x0b), c.random()])),
    ]),
    sig = derToP1363(c.sign(certInfo, ak.privateKey)),
    signature = Buffer.concat([
      u16(0x18),
      u16(0x0b),
      sized(sig.subarray(0, 32)),
      sized(sig.subarray(32)),
    ]),
    authorized = {
      publicKey: ak.publicKey,
      qualifiedName,
      status: 'ACTIVE',
      notBefore: c.now() - 60,
      expiresAt: c.now() + 86400,
      enrollmentMethod: 'AUDITED_HARDWARE_CEREMONY',
      restrictedSigning: true,
      fixedTPM: true,
      fixedParent: true,
      sensitiveDataOrigin: true,
      enrollmentEvidenceHash: c.H('SyntheticAKEnrollment', {}),
    };
  return {
    evidence: { format: 'tpm2-certify', akID: 'synthetic-AK', pubArea, certInfo, signature },
    policy: {
      id: 'synthetic-tpm-certify-v1',
      formats: {
        'tpm2-certify': {
          authorizedAKs: new Map([['synthetic-AK', authorized]]),
          akStatus: status,
        },
      },
    },
  };
}
