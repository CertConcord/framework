import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { createAuthorityResolver } from './authority-history.mjs';

export const epoch = 1800000000;
export const at = epoch + 50;
export const SIGNING = 'SMIME_SIGNING';
export const ENCRYPTION = 'SMIME_RECIPIENT_ENCRYPTION';
export const O = Object.freeze({
  es256: '1.2.840.10045.4.3.2',
  sha256: '2.16.840.1.101.3.4.2.1',
  emailProtection: '1.3.6.1.5.5.7.3.4',
});
const algorithm = (id) => c.seq(c.oid(id));
const stamp = (time) =>
  new Date(time * 1000).toISOString().replace(/[-:]/g, '').replace('.000', '').replace('T', '');

// OpenSSL issues the standard certificates; the CRL emitter shares only DER and
// primitive signing helpers, never the material validator under examination.
export function smimeMaterialFixture() {
  const executable = process.env.OPENSSL_BIN ?? 'openssl';
  const base = resolve(tmpdir());
  const dir = mkdtempSync(join(base, 'certconcord-smime-material-'));
  const file = (name) => join(dir, name);
  const commands = [];
  const all = [];
  let serial = 1;
  let root;
  const run = (...args) => {
    try {
      const output = execFileSync(executable, args, { encoding: 'utf8', stdio: 'pipe' });
      commands.push({ args, status: 0 });
      return output;
    } catch (error) {
      commands.push({ args, status: error.status, stderr: String(error.stderr) });
      throw error;
    }
  };
  const key = (type = 'ec', size = 3072) =>
    type === 'rsa'
      ? generateKeyPairSync('rsa', { modulusLength: size, publicExponent: 65537 })
      : generateKeyPairSync('ec', { namedCurve: type === 'ec' ? 'prime256v1' : type });
  const certificate = (name, options = {}) => {
    const issuer = Object.hasOwn(options, 'issuer') ? options.issuer : root;
    const ca = options.ca ?? !issuer;
    const purpose = options.purpose ?? SIGNING;
    const pair = options.key ?? key();
    const notBefore = options.notBefore ?? epoch - 1000;
    const notAfter = options.notAfter ?? epoch + 10000;
    const prefix = `${serial++}-${name.replace(/[^A-Za-z0-9_-]/g, '-')}`;
    const ku =
      options.ku ??
      (ca ? 'keyCertSign,cRLSign' : purpose === SIGNING ? 'digitalSignature' : 'keyEncipherment');
    const eku = options.eku === undefined ? (ca ? null : 'emailProtection') : options.eku;
    const emails =
      options.emails === undefined ? (ca ? [] : ['alice@example.test']) : options.emails;
    const otherNames = options.otherNames ?? [];
    const extensions = [
      `basicConstraints=critical,CA:${ca ? 'true' : 'false'}`,
      `keyUsage=${options.kuCritical === false ? '' : 'critical,'}${ku}`,
      'subjectKeyIdentifier=hash',
      ...(issuer ? ['authorityKeyIdentifier=keyid:always'] : []),
      ...(eku === null ? [] : [`extendedKeyUsage=${options.ekuCritical ? 'critical,' : ''}${eku}`]),
      ...(options.sanDER
        ? [
            `subjectAltName=${options.sanCritical ? 'critical,' : ''}DER:${options.sanDER.toString('hex').match(/../g).join(':')}`,
          ]
        : emails.length || otherNames.length
          ? [
              `subjectAltName=${options.sanCritical ? 'critical,' : ''}${[...emails.map((email) => `email:${email}`), ...otherNames].join(',')}`,
            ]
          : []),
      ...(options.extraExtensions ?? []),
    ];
    writeFileSync(file(prefix + '.key'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    run(
      'req',
      '-new',
      '-key',
      file(prefix + '.key'),
      '-subj',
      `/CN=${name}${options.legacyEmail ? `/emailAddress=${options.legacyEmail}` : ''}`,
      '-out',
      file(prefix + '.csr'),
    );
    writeFileSync(file(prefix + '.ext'), extensions.join('\n') + '\n');
    run(
      'x509',
      '-req',
      '-in',
      file(prefix + '.csr'),
      ...(issuer
        ? ['-CA', issuer.pemFile, '-CAkey', issuer.keyFile]
        : ['-signkey', file(prefix + '.key')]),
      '-set_serial',
      String(serial),
      '-sha256',
      '-not_before',
      stamp(notBefore),
      '-not_after',
      stamp(notAfter),
      '-extfile',
      file(prefix + '.ext'),
      '-out',
      file(prefix + '.pem'),
    );
    const native = new X509Certificate(readFileSync(file(prefix + '.pem')));
    assert(native.verify(issuer?.publicKey ?? pair.publicKey), 'Fixture certificate signature');
    const entry = {
      ...pair,
      der: Buffer.from(native.raw),
      cert: p.parseCertificate(native.raw),
      keyFile: file(prefix + '.key'),
      pemFile: file(prefix + '.pem'),
      notBefore,
      notAfter,
    };
    all.push(entry);
    return entry;
  };
  root = certificate('S-MIME Fixture Root');
  const signer = certificate('S-MIME Sender');
  const recipient = certificate('S-MIME Recipient', {
    purpose: ENCRYPTION,
    key: key('rsa'),
    emails: ['bob@example.test'],
  });
  const domain = Buffer.alloc(32, 0x6d);
  const scope = (purpose = SIGNING) => ({
    trustDomainID: Buffer.from(domain),
    issuerID: 'smime-material-fixture',
    representation: 'X509',
    profileID: 'certconcord-smime-application-v1',
    purpose,
  });
  const authorities = ({
    authority = root,
    roles = ['ISSUER', 'STATUS_AUTHORITY'],
    status,
    scopes,
  } = {}) =>
    createAuthorityResolver({
      trustDomainID: domain,
      authorities: [
        {
          mode: 'CERTIFICATE',
          certificate: authority.der,
          knownAt: epoch - 1000,
          validFrom: epoch - 1000,
          validUntil: epoch + 100000,
          roles,
          scopes: scopes ?? [scope(SIGNING), scope(ENCRYPTION)],
          status: status ?? {
            authorityID: c.keyID(authority.publicKey),
            trustDomainID: domain,
            scope: 'AUTHORITY',
            status: 'GOOD',
            publishedAt: epoch - 1000,
            nextUpdate: epoch + 100000,
          },
        },
      ],
    });
  const crl = ({
    issuer = root,
    thisUpdate = epoch,
    nextUpdate = epoch + 1000,
    number = 1,
    entries = [],
  } = {}) => {
    const revoked = entries.map((entry) =>
      c.seq(
        c.integer(entry.serial ?? signer.cert.serial),
        p.generalizedTime(entry.revokedAt ?? epoch + 10),
        c.seq(
          p.extension('2.5.29.21', c.der(10, Buffer.from([entry.reason ?? 1]))),
          ...(entry.invalidityDate === undefined
            ? []
            : [p.extension('2.5.29.24', p.generalizedTime(entry.invalidityDate))]),
        ),
      ),
    );
    const tbs = c.seq(
      c.integer(1),
      algorithm(O.es256),
      issuer.cert.subject,
      p.generalizedTime(thisUpdate),
      p.generalizedTime(nextUpdate),
      ...(revoked.length ? [c.seq(...revoked)] : []),
      c.der(
        0xa0,
        c.seq(
          p.extension('2.5.29.20', c.integer(number)),
          p.extension(
            '2.5.29.35',
            c.seq(c.der(0x80, c.parseDER(issuer.cert.extensions.get('2.5.29.14').value).value)),
          ),
        ),
      ),
    );
    return c.seq(tbs, algorithm(O.es256), c.bit(c.sign(tbs, issuer.privateKey)));
  };
  const defaultCRL = crl();
  const policy = (purpose = SIGNING, changes = {}) => ({
    trustedRoots: [Buffer.from(root.der)],
    scope: scope(purpose),
    authorityResolver: authorities(),
    algorithmDeadlines: { [O.es256]: epoch + 100000 },
    hashDeadlines: { [O.sha256]: epoch + 100000 },
    keyDeadlines: Object.fromEntries(
      all.map((entry) => [c.keyID(entry.publicKey).toString('hex'), epoch + 100000]),
    ),
    currentMaterial: { certificates: [], crls: [] },
    ...changes,
  });
  const options = (leaf = signer, changes = {}) => ({
    certificate: Buffer.from(leaf.der),
    certificates: [Buffer.from(root.der)],
    crls: [Buffer.from(defaultCRL)],
    knowledgeTime: at,
    purpose: changes.purpose ?? SIGNING,
    policy: policy(changes.purpose ?? SIGNING),
    ...changes,
  });
  const close = () => {
    assert(resolve(dir).startsWith(base + sep));
    assert(dir.includes('certconcord-smime-material-'));
    rmSync(dir, { recursive: true, force: true });
  };
  return {
    dir,
    file,
    run,
    commands,
    key,
    certificate,
    root,
    signer,
    recipient,
    domain,
    scope,
    authorities,
    crl,
    defaultCRL,
    policy,
    options,
    close,
  };
}
