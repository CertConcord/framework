import { resolveTxt } from 'node:dns/promises';
import { X509Certificate, createPublicKey } from 'node:crypto';
import {
  random,
  b64u,
  unb64u,
  sha256,
  sha512,
  requireThat,
  now,
  equal,
  spki,
  parseDER,
  oidText,
} from './core.mjs';
import { parseJSON } from './json.mjs';
import { signJWS, verifyJWS, decodeJWS, publicJWK, importPublicJWK, thumbprint } from './jose.mjs';
import { requestBytes, endpoint } from './transport.mjs';
import { verifyCSR } from './enrollment.mjs';
import { parseCertificate } from './pki.mjs';
import { decodeCBOR } from './core.mjs';
const idFromURL = (url) => new URL(url).pathname.split('/').at(-1);
function flattened(token) {
  const [p, payload, signature] = token.split('.');
  return { protected: p, payload, signature };
}
function compact(jws) {
  requireThat(
    jws && Object.keys(jws).sort().join(',') === 'payload,protected,signature',
    'ACME_JWS_STRUCTURE',
  );
  return jws.protected + '.' + jws.payload + '.' + jws.signature;
}
export async function verifyDNS01({ identifier, keyAuthorization }) {
  requireThat(
    identifier.type === 'dns' &&
      /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(identifier.value),
    'ACME_DNS_NAME',
  );
  const expected = b64u(sha256(Buffer.from(keyAuthorization))),
    records = await resolveTxt('_acme-challenge.' + identifier.value);
  return records.some((parts) => parts.join('') === expected);
}
export class ACMEClient {
  constructor({ directoryURL, privateKey, allowLoopback = false }) {
    endpoint(directoryURL, { allowLoopback });
    Object.assign(this, { directoryURL, privateKey, allowLoopback });
  }
  async discover() {
    const r = await requestBytes(this.directoryURL, { allowLoopback: this.allowLoopback });
    requireThat(r.status === 200, 'ACME_DIRECTORY');
    this.directory = parseJSON(r.body.toString('utf8'));
    for (const field of ['newNonce', 'newAccount', 'newOrder', 'revokeCert', 'keyChange'])
      requireThat(
        new URL(this.directory[field]).origin === new URL(this.directoryURL).origin,
        'ACME_ENDPOINT_ORIGIN',
      );
    return this.directory;
  }
  async nonce() {
    const r = await requestBytes(this.directory.newNonce, {
      method: 'HEAD',
      allowLoopback: this.allowLoopback,
    });
    const nonce = r.headers.get('replay-nonce');
    requireThat(nonce, 'ACME_NONCE');
    return nonce;
  }
  async post(url, payload, { useJWK = false, key = this.privateKey } = {}) {
    requireThat(new URL(url).origin === new URL(this.directoryURL).origin, 'ACME_ENDPOINT_ORIGIN');
    for (let attempt = 0; attempt < 2; attempt++) {
      const nonce = this.nextNonce ?? (await this.nonce());
      this.nextNonce = undefined;
      const headers = {
        nonce,
        url,
        ...(useJWK ? { jwk: publicJWK(createPublicKey(key)) } : { kid: this.accountURL }),
      };
      const r = await requestBytes(url, {
        method: 'POST',
        headers: { 'content-type': 'application/jose+json' },
        body: JSON.stringify(
          flattened(signJWS(payload === null ? Buffer.alloc(0) : payload, key, headers)),
        ),
        allowLoopback: this.allowLoopback,
      });
      this.nextNonce = r.headers.get('replay-nonce') ?? undefined;
      const json = (r.headers.get('content-type') ?? '').includes('json')
        ? parseJSON(r.body.toString('utf8'))
        : undefined;
      if (r.status >= 400) {
        if (attempt === 0 && json?.type === 'urn:ietf:params:acme:error:badNonce') continue;
        throw Error(json?.type ?? 'ACME_HTTP_' + r.status);
      }
      return { status: r.status, headers: r.headers, json, body: r.body };
    }
    throw Error('ACME_NONCE_RETRY');
  }
  async createAccount({ contact = [], termsOfServiceAgreed = false, externalAccountBinding } = {}) {
    if (!this.directory) await this.discover();
    const r = await this.post(
      this.directory.newAccount,
      {
        contact,
        termsOfServiceAgreed,
        ...(externalAccountBinding ? { externalAccountBinding } : {}),
      },
      { useJWK: true },
    );
    this.accountURL = r.headers.get('location');
    requireThat(this.accountURL, 'ACME_ACCOUNT_LOCATION');
    return r.json;
  }
  async newOrder({ identifiers, profile }) {
    requireThat(profile === undefined || this.directory.profiles?.[profile], 'ACME_PROFILE');
    const r = await this.post(this.directory.newOrder, { identifiers, profile });
    return { ...r.json, url: r.headers.get('location') };
  }
  async complete(
    order,
    {
      csr,
      provisionDNS01,
      attestDevice,
      cleanupDNS01 = async () => {},
      pollMilliseconds = 1000,
      maxPolls = 60,
    },
  ) {
    for (const authURL of order.authorizations) {
      const authorization = (await this.post(authURL, null)).json;
      if (authorization.status === 'valid') continue;
      const ch = authorization.challenges.find(
        (c) => c.type === (attestDevice ? 'device-attest-01' : 'dns-01'),
      );
      requireThat(ch, 'ACME_CHALLENGE_REQUIRED');
      const keyAuthorization =
          ch.token + '.' + thumbprint(publicJWK(createPublicKey(this.privateKey))),
        context = {
          identifier: authorization.identifier,
          token: ch.token,
          keyAuthorization,
          recordName: '_acme-challenge.' + authorization.identifier.value,
          recordValue: b64u(sha256(Buffer.from(keyAuthorization))),
        };
      const response = attestDevice ? await attestDevice(context) : {};
      if (!attestDevice) await provisionDNS01(context);
      try {
        await this.post(ch.url, response);
        let result;
        for (let n = 0; n < maxPolls; n++) {
          result = (await this.post(authURL, null)).json;
          if (['valid', 'invalid', 'expired', 'deactivated', 'revoked'].includes(result.status))
            break;
          await new Promise((r) => setTimeout(r, pollMilliseconds));
        }
        requireThat(result?.status === 'valid', 'ACME_CHALLENGE_NOT_VALID');
      } finally {
        if (!attestDevice) await cleanupDNS01(context);
      }
    }
    const request = typeof csr === 'function' ? await csr() : csr;
    requireThat(
      !equal(verifyCSR(request).spki, spki(createPublicKey(this.privateKey))),
      'urn:ietf:params:acme:error:badCSR',
    );
    const final = await this.post(order.finalize, { csr: b64u(request) });
    let result = final.json;
    for (let i = 0; result.status === 'processing' && i < 20; i++) {
      await new Promise((r) => setTimeout(r, 500));
      result = (await this.post(order.url, null)).json;
    }
    requireThat(result.status === 'valid' && result.certificate, 'ACME_ORDER_NOT_VALID');
    const certificate = await this.post(result.certificate, null);
    return certificate.body;
  }
  async revoke(certificate, reason = 0) {
    return this.post(this.directory.revokeCert, { certificate: b64u(certificate), reason });
  }
  async changeAccountKey(newKey) {
    const inner = flattened(
      signJWS(
        { account: this.accountURL, oldKey: publicJWK(createPublicKey(this.privateKey)) },
        newKey,
        { url: this.directory.keyChange, jwk: publicJWK(createPublicKey(newKey)) },
      ),
    );
    await this.post(this.directory.keyChange, inner);
    this.privateKey = newKey;
  }
}
export class ACMEService {
  constructor({
    baseURL,
    journal,
    profiles,
    authorizeFinalize,
    issue,
    verifyChallenge = verifyDNS01,
    revoke,
    deviceAttestation,
    defaultProfile,
    termsOfService,
  }) {
    requireThat(
      [authorizeFinalize, issue, revoke].every((f) => typeof f === 'function'),
      'ACME_RA_CALLBACKS_REQUIRED',
    );
    requireThat(
      defaultProfile === undefined || profiles.includes(defaultProfile),
      'ACME_DEFAULT_PROFILE',
    );
    requireThat(
      !deviceAttestation ||
        (typeof deviceAttestation.createChallenge === 'function' &&
          typeof deviceAttestation.verify === 'function' &&
          deviceAttestation.profiles.every((p) => profiles.includes(p))),
      'ACME_DEVICE_POLICY',
    );
    Object.assign(this, {
      baseURL,
      journal,
      profiles,
      authorizeFinalize,
      issue,
      verifyChallenge,
      revoke,
      deviceAttestation,
      defaultProfile,
      termsOfService,
    });
  }
  directory() {
    return {
      newNonce: this.baseURL + '/new-nonce',
      newAccount: this.baseURL + '/new-account',
      newOrder: this.baseURL + '/new-order',
      revokeCert: this.baseURL + '/revoke-cert',
      keyChange: this.baseURL + '/key-change',
      profiles: Object.fromEntries(this.profiles.map((p) => [p, this.baseURL + '/profiles/' + p])),
      ...(this.termsOfService ? { meta: { termsOfService: this.termsOfService } } : {}),
    };
  }
  nonce() {
    return this.journal.issueNonce('acme', 300);
  }
  authenticate(url, jws) {
    const token = compact(jws),
      h = decodeJWS(token).header;
    requireThat(h.url === url && h.alg === 'ES256' && !h.crit, 'ACME_PROTECTED_HEADER');
    try {
      this.journal.consumeNonce('acme', h.nonce);
    } catch {
      throw Error('urn:ietf:params:acme:error:badNonce');
    }
    let account, key;
    if (url === this.baseURL + '/new-account') {
      requireThat(h.jwk && !h.kid, 'ACME_ACCOUNT_JWK');
      key = importPublicJWK(h.jwk);
    } else {
      requireThat(h.kid && !h.jwk, 'ACME_ACCOUNT_KID');
      account = this.journal.get('acme-account', h.kid);
      requireThat(account && account.value.status === 'valid', 'ACME_ACCOUNT');
      key = importPublicJWK(account.value.jwk);
    }
    const r = verifyJWS(token, key),
      payload = r.payload.length ? parseJSON(r.payload.toString('utf8')) : null;
    return { payload, key, account, kid: h.kid };
  }
  #accountForKey(key) {
    const target = spki(key);
    for (const { id } of this.journal.list('acme-account')) {
      const row = this.journal.get('acme-account', id);
      if (equal(target, spki(importPublicJWK(row.value.jwk)))) return { id, ...row };
    }
  }
  #changeAccountKey(jws) {
    const url = this.baseURL + '/key-change',
      { payload, account, kid } = this.authenticate(url, jws),
      inner = compact(payload),
      h = decodeJWS(inner).header;
    requireThat(
      h.url === url &&
        h.alg === 'ES256' &&
        h.jwk &&
        !['kid', 'nonce', 'crit'].some((field) => Object.hasOwn(h, field)),
      'ACME_KEY_CHANGE_HEADER',
    );
    const newKey = importPublicJWK(h.jwk),
      q = parseJSON(verifyJWS(inner, newKey).payload.toString('utf8'));
    requireThat(
      q.account === kid &&
        thumbprint(q.oldKey) === thumbprint(account.value.jwk) &&
        thumbprint(h.jwk) !== thumbprint(account.value.jwk),
      'ACME_KEY_CHANGE',
    );
    return this.journal.transaction(() => {
      const existing = this.#accountForKey(newKey),
        headers = { 'replay-nonce': this.nonce() };
      if (existing)
        return {
          status: 409,
          headers: {
            ...headers,
            location: existing.id,
            'content-type': 'application/problem+json',
          },
          json: {
            type: 'urn:ietf:params:acme:error:malformed',
            detail: 'The replacement key is already registered to an account.',
          },
        };
      this.journal.put(
        'acme-account',
        kid,
        { ...account.value, jwk: publicJWK(newKey) },
        account.revision,
      );
      return { status: 200, headers, json: { status: 'valid' } };
    });
  }
  async handle(path, jws) {
    if (path === '/key-change') return this.#changeAccountKey(jws);
    const url = this.baseURL + path,
      { payload: p, key, account, kid } = this.authenticate(url, jws),
      headers = { 'replay-nonce': this.nonce() };
    const result = (json, status = 200, extra = {}) => ({
      status,
      headers: { ...headers, ...extra },
      json,
    });
    if (path === '/new-account') {
      requireThat(
        p && Array.isArray(p.contact ?? []) && !p.externalAccountBinding,
        'ACME_ACCOUNT_POLICY',
      );
      return this.journal.transaction(() => {
        const jwk = publicJWK(key),
          existing = this.#accountForKey(key),
          id = existing?.id ?? this.baseURL + '/account/' + b64u(random()),
          old = existing?.value;
        requireThat(old || !p.onlyReturnExisting, 'urn:ietf:params:acme:error:accountDoesNotExist');
        requireThat(
          old || !this.termsOfService || p.termsOfServiceAgreed === true,
          'ACME_ACCOUNT_POLICY',
        );
        if (!old)
          this.journal.put('acme-account', id, { jwk, contact: p.contact ?? [], status: 'valid' });
        return result(
          {
            status: old?.status ?? 'valid',
            contact: old?.contact ?? p.contact ?? [],
            orders: this.baseURL + '/orders/' + id.split('/').at(-1),
          },
          old ? 200 : 201,
          { location: id },
        );
      });
    }
    if (path.startsWith('/account/')) {
      requireThat(url === kid, 'ACME_ACCOUNT_OWNER');
      if (p !== null) {
        requireThat(
          Object.keys(p).every((k) => ['contact', 'status'].includes(k)) &&
            (!p.status || p.status === 'deactivated') &&
            (!p.contact || Array.isArray(p.contact)),
          'ACME_ACCOUNT_UPDATE',
        );
        this.journal.put('acme-account', kid, { ...account.value, ...p }, account.revision);
      }
      const current = this.journal.get('acme-account', kid).value;
      return result({
        status: current.status,
        contact: current.contact,
        orders: this.baseURL + '/orders/' + kid.split('/').at(-1),
      });
    }
    if (path.startsWith('/orders/')) {
      requireThat(p === null && idFromURL(url) === idFromURL(kid), 'ACME_ACCOUNT_OWNER');
      const orders = this.journal
        .list('acme-order')
        .filter((r) => this.journal.get('acme-order', r.id).value.account === kid)
        .map((r) => this.baseURL + '/order/' + r.id);
      return result({ orders });
    }
    if (path === '/new-order') {
      const profile = p?.profile ?? this.defaultProfile,
        device = this.deviceAttestation?.profiles.includes(profile);
      requireThat(
        p &&
          this.profiles.includes(profile) &&
          Array.isArray(p.identifiers) &&
          p.identifiers.length >= 1 &&
          p.identifiers.length <= (device ? 1 : 10) &&
          p.identifiers.every((i) =>
            device
              ? i.type === 'permanent-identifier' && /^[A-Za-z0-9_.:-]{1,256}$/.test(i.value)
              : i.type === 'dns' && /^[a-z0-9.-]{1,253}$/.test(i.value),
          ) &&
          new Set(p.identifiers.map((i) => i.value)).size === p.identifiers.length,
        'ACME_ORDER',
      );
      const id = b64u(random()),
        order = {
          status: 'pending',
          expires: new Date((now() + 600) * 1000).toISOString(),
          identifiers: p.identifiers,
          profile,
          account: kid,
          authorizations: [],
          finalize: this.baseURL + '/finalize/' + id,
        };
      for (const identifier of p.identifiers) {
        const grant = device
          ? await this.deviceAttestation.createChallenge({
              accountID: kid,
              identifier,
              profileID: profile,
            })
          : { token: b64u(random()), expiresAt: now() + 600 };
        const aid = b64u(random()),
          authURL = this.baseURL + '/authorization/' + aid,
          ch = {
            type: device ? 'device-attest-01' : 'dns-01',
            url: this.baseURL + '/challenge/' + aid,
            token: grant.token,
            status: 'pending',
          };
        this.journal.put('acme-authorization', aid, {
          orderID: id,
          account: kid,
          identifier,
          status: 'pending',
          challenges: [ch],
          expiresAt: grant.expiresAt,
        });
        order.authorizations.push(authURL);
      }
      this.journal.put('acme-order', id, order);
      return result(publicOrder(order), 201, { location: this.baseURL + '/order/' + id });
    }
    const [_, kind, id] = path.split('/');
    if (['authorization', 'challenge'].includes(kind)) {
      const row = this.journal.get('acme-authorization', id),
        a = row?.value;
      requireThat(a && a.account === kid, 'ACME_AUTHORIZATION');
      if (kind === 'authorization') {
        requireThat(p === null, 'ACME_POST_AS_GET');
        return result(publicAuthorization(a));
      }
      requireThat(
        p &&
          a.status === 'pending' &&
          a.expiresAt > now() &&
          (a.challenges[0].type === 'device-attest-01' || Object.keys(p).length === 0),
        'ACME_CHALLENGE_STATE',
      );
      const ch = a.challenges[0],
        keyAuthorization = ch.token + '.' + thumbprint(account.value.jwk),
        context = { identifier: a.identifier, token: ch.token, keyAuthorization, account: kid };
      let attestation;
      if (ch.type === 'device-attest-01') {
        try {
          attestation = await this.deviceAttestation.verify({ ...context, response: p });
          requireThat(
            attestation?.assessment?.assurance === 'HARDWARE_KEY_VERIFIED' &&
              Buffer.isBuffer(attestation.attestedSPKI),
            'ACME_DEVICE_ATTESTATION',
          );
        } catch {
          const error = {
            type: 'urn:ietf:params:acme:error:badAttestationStatement',
            detail: 'Device attestation did not satisfy the enrollment policy.',
          };
          this.journal.put(
            'acme-authorization',
            id,
            { ...a, status: 'invalid', challenges: [{ ...ch, status: 'invalid', error }] },
            row.revision,
          );
          return result(error, 400, { 'content-type': 'application/problem+json' });
        }
      } else requireThat((await this.verifyChallenge(context)) === true, 'ACME_DNS_VALIDATION');
      this.journal.put(
        'acme-authorization',
        id,
        {
          ...a,
          status: 'valid',
          keyAuthorization,
          ...(attestation ? { attestation } : {}),
          challenges: [{ ...ch, status: 'valid' }],
        },
        row.revision,
      );
      return result({ ...ch, status: 'valid' });
    }
    if (['order', 'finalize', 'certificate'].includes(kind)) {
      const row = this.journal.get('acme-order', id),
        order = row?.value;
      requireThat(
        order && order.account === kid && Date.parse(order.expires) > Date.now(),
        'ACME_ORDER_STATE',
      );
      if (kind === 'certificate') {
        requireThat(p === null && order.status === 'valid', 'ACME_CERTIFICATE_STATE');
        return {
          status: 200,
          headers: { ...headers, 'content-type': 'application/pem-certificate-chain' },
          body: Buffer.from(order.certificatePEM),
        };
      }
      const authorizations = order.authorizations.map(
          (url) => this.journal.get('acme-authorization', idFromURL(url)).value,
        ),
        ready = authorizations.every((a) => a.status === 'valid' && a.expiresAt > now()),
        invalid = authorizations.some((a) => a.status === 'invalid' || a.expiresAt <= now());
      if (kind === 'order') {
        requireThat(p === null, 'ACME_POST_AS_GET');
        return result(
          publicOrder({
            ...order,
            status:
              order.status === 'pending'
                ? invalid
                  ? 'invalid'
                  : ready
                    ? 'ready'
                    : order.status
                : order.status,
          }),
        );
      }
      requireThat(
        p?.csr && ready && ['pending', 'ready'].includes(order.status),
        'ACME_FINALIZE_STATE',
      );
      const csr = unb64u(p.csr),
        parsed = verifyCSR(csr),
        extensions = parsed.attributes.get('1.2.840.113549.1.9.14'),
        san = extensions?.children.find((e) => oidText(e.children[0]) === '2.5.29.17'),
        names = san ? parseDER(san.children.at(-1).value).children : [];
      requireThat(!this.#accountForKey(parsed.publicKey), 'urn:ietf:params:acme:error:badCSR');
      const deviceProofs = authorizations.filter((a) => a.attestation).map((a) => a.attestation);
      if (deviceProofs.length)
        requireThat(
          deviceProofs.length === authorizations.length &&
            !san &&
            deviceProofs.every((a) => equal(a.attestedSPKI, parsed.spki)),
          'urn:ietf:params:acme:error:badCSR',
        );
      else
        requireThat(
          names.every((n) => n.tag === 0x82) &&
            names
              .map((n) => n.value.toString('ascii'))
              .sort()
              .join(',') ===
              order.identifiers
                .map((i) => i.value)
                .sort()
                .join(','),
          'ACME_CSR_IDENTIFIERS',
        );
      this.journal.put(
        'acme-order',
        id,
        { ...order, status: 'processing', csrHash: sha512(csr) },
        row.revision,
      );
      const approval = await this.authorizeFinalize({ csr, order, accountID: kid, deviceProofs });
      requireThat(approval, 'ACME_RA_DENIED');
      const certificate = await this.issue({ csr, approval, profile: order.profile }),
        x = new X509Certificate(certificate);
      requireThat(
        x.publicKey.export({ type: 'spki', format: 'der' }).equals(parsed.spki),
        'ACME_CERTIFICATE_KEY',
      );
      const issuedSAN = parseCertificate(certificate).extensions.get('2.5.29.17');
      requireThat(
        deviceProofs.length
          ? !issuedSAN
          : issuedSAN && equal(issuedSAN.value, san.children.at(-1).value),
        'ACME_CERTIFICATE_IDENTIFIERS',
      );
      const certificatePEM = x.toString();
      this.journal.put(
        'acme-order',
        id,
        {
          ...order,
          status: 'valid',
          certificate: this.baseURL + '/certificate/' + id,
          certificatePEM,
          certificateHash: sha512(certificate),
        },
        row.revision + 1,
      );
      return result(
        publicOrder({
          ...order,
          status: 'valid',
          certificate: this.baseURL + '/certificate/' + id,
        }),
      );
    }
    if (path === '/revoke-cert') {
      requireThat(
        p?.certificate &&
          Number.isInteger(p.reason) &&
          p.reason >= 0 &&
          p.reason <= 10 &&
          ![7, 8].includes(p.reason),
        'ACME_REVOCATION',
      );
      const certificate = unb64u(p.certificate),
        owned = this.journal
          .list('acme-order')
          .map((r) => this.journal.get('acme-order', r.id).value);
      requireThat(
        owned.some((o) => {
          return (
            o.account === kid && o.certificateHash && equal(o.certificateHash, sha512(certificate))
          );
        }),
        'ACME_REVOCATION_AUTHORITY',
      );
      await this.revoke({ certificate, reason: p.reason, accountID: kid });
      return result({});
    }
    throw Error('ACME_RESOURCE_NOT_FOUND');
  }
}
function publicOrder(o) {
  const { account, certificatePEM, certificateHash, csrHash, ...publicValue } = o;
  return publicValue;
}
function publicAuthorization(a) {
  const { account, orderID, attestation, keyAuthorization, expiresAt, ...publicValue } = a;
  return publicValue;
}
