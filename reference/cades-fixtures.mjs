// Synthetic, offline fixtures. OpenSSL is a parser/primitive differential,
// not a second complete CAdES Baseline implementation.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { parseTimestampRequest } from './timestamp.mjs';

export const O = Object.freeze({
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  ess: '1.2.840.113549.1.9.16.2.47',
  signatureTimestamp: '1.2.840.113549.1.9.16.2.14',
  archiveTimestamp: '0.4.0.1733.2.4',
  index: '0.4.0.19122.1.5',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha512: '2.16.840.1.101.3.4.2.3',
  es256: '1.2.840.10045.4.3.2',
  policy: '1.3.6.1.4.1.55555.91.1',
});
export const epoch = 1800000000;
export const hash = (value, oid = O.sha256) => {
  assert([O.sha256, O.sha512].includes(oid));
  return oid === O.sha256 ? c.sha256(value) : c.sha512(value);
};
export const executable = process.env.OPENSSL_BIN ?? 'openssl';
export const opensslAvailable =
  spawnSync(executable, ['version'], { encoding: 'utf8' }).status === 0;
if (!opensslAvailable && process.env.CERTCONCORD_REQUIRE_OPENSSL === '1')
  throw Error('Required OpenSSL fixture producer is unavailable (environment failure)');
export const pem = (label, bytes) =>
  `-----BEGIN ${label}-----\n${bytes
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END ${label}-----\n`;
const stamp = (at) =>
  new Date(at * 1000).toISOString().replace(/[-:]/g, '').replace('.000', '').replace('T', '');
const utc = (at) => c.der(23, Buffer.from(stamp(at).slice(2)));
const alg = (id) => c.seq(c.oid(id));
export const attr = (id, ...values) => c.seq(c.oid(id), c.set(...values));

// Only ASN.1 framing is shared with production. No CAdES coverage helper is used.
export function cmsView(raw) {
  const root = c.parseDER(raw),
    sd = root.children[1].children[0];
  const signerSet = sd.children.at(-1),
    signer = signerSet.children[0];
  return {
    root,
    sd,
    signerSet,
    signer,
    fields: signer.children,
    certificates: sd.children.find((n) => n.tag === 0xa0)?.children ?? [],
    crls: sd.children.find((n) => n.tag === 0xa1)?.children ?? [],
    unsigned: signer.children.find((n) => n.tag === 0xa1)?.children ?? [],
    signed: signer.children[3].children,
    signature: signer.children[5].value,
    contentType: sd.children[2].children[0],
    embeddedContent: sd.children[2].children[1]?.children[0].value,
  };
}
export function rewriteCMS(
  raw,
  { certificates, crls, signed, unsigned, signature, signers, contentType } = {},
) {
  const v = cmsView(raw),
    fields = v.fields.map((n) => n.raw);
  if (signed) fields[3] = c.der(0xa0, c.parseDER(c.set(...signed)).value);
  if (signature) fields[5] = c.octet(signature);
  fields.splice(6);
  const us = unsigned ?? v.unsigned.map((n) => n.raw);
  if (us.length) fields.push(c.der(0xa1, c.parseDER(c.set(...us)).value));
  const certs = certificates ?? v.certificates.map((n) => n.raw);
  const statuses = crls ?? v.crls.map((n) => n.raw);
  const encap = contentType
    ? c.seq(c.oid(contentType), ...v.sd.children[2].children.slice(1).map((n) => n.raw))
    : v.sd.children[2].raw;
  const sd = c.seq(
    v.sd.children[0].raw,
    v.sd.children[1].raw,
    encap,
    ...(certs.length ? [c.der(0xa0, c.parseDER(c.set(...certs)).value)] : []),
    ...(statuses.length ? [c.der(0xa1, c.parseDER(c.set(...statuses)).value)] : []),
    c.set(...(signers ?? [c.seq(...fields)])),
  );
  return c.seq(v.root.children[0].raw, c.der(0xa0, sd));
}
export function resign(raw, signed, privateKey) {
  return rewriteCMS(raw, { signed, signature: c.sign(c.set(...signed), privateKey) });
}
export function unsignedValues(raw, oid) {
  return cmsView(raw)
    .unsigned.filter((a) => c.oidText(a.children[0]) === oid)
    .flatMap((a) => a.children[1].children.map((n) => n.raw));
}
export function replaceUnsigned(raw, oid, values) {
  return rewriteCMS(raw, {
    unsigned: [
      ...cmsView(raw)
        .unsigned.filter((a) => c.oidText(a.children[0]) !== oid)
        .map((n) => n.raw),
      ...(values.length ? [attr(oid, ...values)] : []),
    ],
  });
}
export function independentIndex(raw, hashOID = O.sha256) {
  const v = cmsView(raw);
  return c.seq(
    alg(hashOID),
    c.seq(...v.certificates.map((n) => c.octet(hash(n.raw, hashOID)))),
    c.seq(...v.crls.map((n) => c.octet(hash(n.raw, hashOID)))),
    c.seq(
      ...v.unsigned.flatMap((a) =>
        a.children[1].children.map((value) =>
          c.octet(hash(Buffer.concat([a.children[0].raw, value.raw]), hashOID)),
        ),
      ),
    ),
  );
}
export function independentArchiveInput(raw, content, index, hashOID = O.sha256) {
  const v = cmsView(raw);
  return Buffer.concat([
    v.contentType.raw,
    hash(content ?? v.embeddedContent, hashOID),
    ...v.fields.slice(0, 6).map((n) => n.raw),
    index,
  ]);
}
export function independentArchiveImprint(raw, content, index, hashOID = O.sha256) {
  return hash(independentArchiveInput(raw, content, index, hashOID), hashOID);
}
export function requestFields(request) {
  return Buffer.isBuffer(request)
    ? parseTimestampRequest(request)
    : request?.der
      ? parseTimestampRequest(request.der)
      : request;
}

export function fixture({ signerNotAfter = epoch + 120, tsaNotAfter = epoch + 100 } = {}) {
  assert(opensslAvailable, 'OpenSSL is required to generate standard synthetic CAdES fixtures');
  const base = resolve(tmpdir()),
    dir = mkdtempSync(join(base, 'certconcord-cades-'));
  const file = (name) => join(dir, name),
    commands = [];
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
  let serial = 1,
    tokenSerial = 1;
  const certificate = (
    name,
    {
      issuer,
      notBefore = epoch - 100,
      notAfter = epoch + 100000,
      tsa = false,
      ekuCritical = true,
      eku = 'timeStamping',
      key,
    } = {},
  ) => {
    key ??= c.generate('ec');
    const prefix = `${name.replace(/[^A-Za-z0-9_-]/g, '-')}-${serial++}`;
    writeFileSync(file(prefix + '.key'), key.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    run(
      'req',
      '-new',
      '-key',
      file(prefix + '.key'),
      '-subj',
      `/CN=${name}`,
      '-out',
      file(prefix + '.csr'),
    );
    writeFileSync(
      file(prefix + '.ext'),
      issuer
        ? `basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n${tsa ? `extendedKeyUsage=${ekuCritical ? 'critical,' : ''}${eku}\n` : ''}`
        : 'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n',
    );
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
    const der = new X509Certificate(readFileSync(file(prefix + '.pem'))).raw;
    return {
      ...key,
      der,
      keyFile: file(prefix + '.key'),
      pemFile: file(prefix + '.pem'),
      cert: p.parseCertificate(der),
    };
  };
  const root = certificate('CAdES Root');
  const signer = certificate('CAdES Document', { issuer: root, notAfter: signerNotAfter });
  const tsa = certificate('CAdES TSA One', { issuer: root, tsa: true, notAfter: tsaNotAfter });
  const successor = certificate('CAdES TSA Two', { issuer: root, tsa: true });
  const content = Buffer.from(
    'Synthetic CAdES preservation document\nExact octets: \x00\xff\r\n',
    'binary',
  );
  const domain = Buffer.alloc(32, 0x91);
  const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
  const all = [root, signer, tsa, successor];
  const authorities = ({ roles = {}, states = {}, scopes = {}, missing = [] } = {}) =>
    createAuthorityResolver({
      trustDomainID: domain,
      authorities: [root, tsa, successor]
        .filter((entry) => !missing.includes(entry))
        .map((entry) => ({
          mode: 'CERTIFICATE',
          certificate: entry.der,
          knownAt: epoch - 100,
          validFrom: epoch - 100,
          validUntil: epoch + 100000,
          roles:
            roles[entry === root ? 'root' : entry === tsa ? 'tsa' : 'successor'] ??
            (entry === root ? ['ISSUER', 'STATUS_AUTHORITY'] : ['TIMESTAMP_AUTHORITY']),
          scopes: [scopes[entry === root ? 'root' : entry === tsa ? 'tsa' : 'successor'] ?? scope],
          status: states[entry === root ? 'root' : entry === tsa ? 'tsa' : 'successor'] ?? {
            authorityID: c.keyID(entry.publicKey),
            trustDomainID: domain,
            scope: 'AUTHORITY',
            status: 'GOOD',
            publishedAt: epoch - 100,
            nextUpdate: epoch + 100000,
          },
        })),
    });
  const crl = ({
    thisUpdate = epoch,
    nextUpdate = epoch + 1000,
    number = 1,
    entries = [],
    issuer = root,
    utcTime = false,
    extensions = [],
  } = {}) => {
    const time = utcTime ? utc : p.generalizedTime;
    const revoked = entries.map((e) =>
      c.seq(
        c.integer(e.serial ?? signer.cert.serial),
        time(e.revokedAt ?? epoch),
        c.seq(
          p.extension('2.5.29.21', c.der(10, Buffer.from([e.reason ?? 1]))),
          ...(e.invalidityDate === undefined
            ? []
            : [p.extension('2.5.29.24', p.generalizedTime(e.invalidityDate))]),
        ),
      ),
    );
    const tbs = c.seq(
      c.integer(1),
      alg(O.es256),
      issuer.cert.subject,
      time(thisUpdate),
      time(nextUpdate),
      ...(revoked.length ? [c.seq(...revoked)] : []),
      c.der(
        0xa0,
        c.seq(
          p.extension('2.5.29.20', c.integer(number)),
          p.extension(
            '2.5.29.35',
            c.seq(c.der(0x80, c.parseDER(issuer.cert.extensions.get('2.5.29.14').value).value)),
          ),
          ...extensions,
        ),
      ),
    );
    return c.seq(tbs, alg(O.es256), c.bit(c.sign(tbs, issuer.privateKey)));
  };
  const opensslCRL = ({ thisUpdate = epoch, nextUpdate = epoch + 1000 } = {}) => {
    writeFileSync(file('ca-index'), '');
    writeFileSync(file('ca-serial'), '01\n');
    writeFileSync(file('ca-number'), '01\n');
    writeFileSync(
      file('ca.cnf'),
      `[ca]\ndefault_ca=local\n[local]\ndatabase=${file('ca-index')}\nserial=${file('ca-serial')}\ncrlnumber=${file('ca-number')}\nprivate_key=${root.keyFile}\ncertificate=${root.pemFile}\ndefault_md=sha256\ndefault_crl_days=1\ncrl_extensions=crl_ext\n[crl_ext]\nauthorityKeyIdentifier=keyid:always\n`,
    );
    run(
      'ca',
      '-gencrl',
      '-config',
      file('ca.cnf'),
      '-crl_lastupdate',
      stamp(thisUpdate),
      '-crl_nextupdate',
      stamp(nextUpdate),
      '-out',
      file('openssl.crl.pem'),
    );
    run('crl', '-in', file('openssl.crl.pem'), '-outform', 'DER', '-out', file('openssl.crl.der'));
    return readFileSync(file('openssl.crl.der'));
  };
  const token = (
    request,
    { authority = tsa, genTime = epoch + 20, accuracy = 0, imprint, hashOID, policy, nonce } = {},
  ) => {
    const q = requestFields(request),
      serial = tokenSerial++;
    const info = c.seq(
      c.integer(1),
      c.oid(policy ?? q.policy ?? O.policy),
      c.seq(alg(hashOID ?? q.hashOID), c.octet(imprint ?? q.imprint)),
      c.integer(serial),
      p.generalizedTime(genTime),
      ...(accuracy === null ? [] : [c.seq(c.integer(accuracy))]),
      ...(nonce === null ? [] : [c.integer(nonce ?? q.nonce ?? 1n)]),
    );
    writeFileSync(file(`info-${serial}.der`), info);
    run(
      'cms',
      '-sign',
      '-cades',
      '-nodetach',
      '-binary',
      '-in',
      file(`info-${serial}.der`),
      '-signer',
      authority.pemFile,
      '-inkey',
      authority.keyFile,
      '-certfile',
      root.pemFile,
      '-outform',
      'DER',
      '-out',
      file(`token-${serial}.der`),
      '-md',
      'sha256',
      '-econtent_type',
      O.tstInfo,
    );
    return readFileSync(file(`token-${serial}.der`));
  };
  const defaultCRL = crl();
  const material = (status = defaultCRL) => ({
    certificates: all.map((entry) => Buffer.from(entry.der)),
    crls: [Buffer.from(status)],
  });
  const policy = (changes = {}) => ({
    trustedRoots: [root.der],
    authorityResolver: authorities(),
    scope,
    algorithmDeadlines: { [O.es256]: epoch + 100000 },
    hashDeadlines: { [O.sha256]: epoch + 100000, [O.sha512]: epoch + 100000 },
    keyDeadlines: Object.fromEntries(
      all.map((entry) => [c.keyID(entry.publicKey).toString('hex'), epoch + 100000]),
    ),
    timestampPolicies: [O.policy],
    currentMaterial: material(),
    ...changes,
  });
  const baseCMS = (
    api,
    { detached = true, signingTime = epoch + 10, additionalSignedAttributes = [], ...rest } = {},
  ) => {
    const prepared = api.prepareCAdESSignature({
      content,
      certificate: signer.der,
      certificates: [root.der],
      detached,
      signingTime,
      additionalSignedAttributes,
      algorithmProfile: 'ES256',
      ...rest,
    });
    return prepared.finish(c.sign(prepared.tbs, signer.privateKey));
  };
  const augment = (
    api,
    cms,
    targetLevel,
    {
      at = epoch + 30,
      policy: selectedPolicy = policy(),
      validationMaterial = targetLevel === 'T' ? { certificates: [], crls: [] } : material(),
      hashOID = O.sha256,
      authority = tsa,
      ...tokenOptions
    } = {},
  ) => {
    const prepared = api.prepareCAdESAugmentation(cms, {
      content,
      targetLevel,
      validationMaterial,
      timestampRequestOptions: { hashOID, policy: O.policy, nonce: BigInt(tokenSerial + 100) },
      policy: selectedPolicy,
      validationTime: at,
      knowledgeTime: at,
    });
    const result = prepared.finish(
      prepared.requestDER
        ? token(prepared.requestDER, { authority, genTime: at, ...tokenOptions })
        : undefined,
      {
        validationTime: at + (tokenOptions.accuracy ?? 0),
        knowledgeTime: at + (tokenOptions.accuracy ?? 0),
        policy: selectedPolicy,
      },
    );
    return { cms: result, prepared };
  };
  const lifecycle = (api, options = {}) => {
    const b = baseCMS(api, options),
      t = augment(api, b, 'T', { at: epoch + 20 }).cms;
    const lt = augment(api, t, 'LT', { at: epoch + 25 }).cms;
    const lta = augment(api, lt, 'LTA', { at: epoch + 30 }).cms;
    return { b, t, lt, lta };
  };
  const close = () => {
    assert(resolve(dir).startsWith(base + sep));
    assert(dir.includes('certconcord-cades-'));
    rmSync(dir, { recursive: true, force: true });
  };
  return {
    dir,
    file,
    run,
    commands,
    root,
    signer,
    tsa,
    successor,
    content,
    domain,
    scope,
    certificate,
    authorities,
    crl,
    opensslCRL,
    token,
    material,
    policy,
    baseCMS,
    augment,
    lifecycle,
    close,
  };
}

export async function loadCAdES() {
  try {
    return await import('./cades.mjs');
  } catch (error) {
    if (
      error.code === 'ERR_MODULE_NOT_FOUND' &&
      error.url === new URL('./cades.mjs', import.meta.url).href
    )
      return undefined;
    throw error;
  }
}
export const absentCapability =
  'Selected new CAdES API is absent at the verified PR8 baseline; this is not an existing semantic failure';
export function decision(api, f, cms, minimumLevel = 'B', changes = {}) {
  return api.verifyCAdES(cms, {
    content: f.content,
    minimumLevel,
    validationTime: epoch + 40,
    knowledgeTime: epoch + 40,
    policy: f.policy(),
    ...changes,
  });
}
export function expectOverall(result, overall) {
  assert.equal(
    result?.overall,
    overall,
    JSON.stringify({
      overall: result?.overall,
      reason: result?.reason,
      requestedLevel: result?.requestedLevel,
      verifiedLevel: result?.verifiedLevel,
      checks: result?.checks?.map(({ overall, reason }) => ({ overall, reason })),
    }),
  );
}
