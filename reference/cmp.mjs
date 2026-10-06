import {
  seq,
  der,
  integer,
  octet,
  bit,
  oid,
  parseDER,
  intValue,
  oidText,
  sign,
  verify,
  equal,
  random,
  sha256,
  sha512,
  now,
  b64u,
  requireThat,
} from './core.mjs';
import { algID, OID, parseCertificate, generalizedTime, validateCertificate } from './pki.mjs';
import { verifyCSR } from './enrollment.mjs';
import { requestBytes } from './transport.mjs';

const PROFILE = '1.3.6.1.5.5.7.4.21';
const MINUS_ONE = der(2, Buffer.from([255]));
const explicit = (tag, body) => der(0xa0 + tag, body);
const directoryName = (name) => explicit(4, name);

export function protectCMP({
  sender,
  recipient,
  privateKey,
  transactionID = random(),
  senderNonce = random(),
  recipNonce,
  bodyTag,
  body,
  profile,
  messageTime = now(),
}) {
  requireThat(
    transactionID.length === 32 &&
      senderNonce.length === 32 &&
      (!recipNonce || recipNonce.length === 32),
    'CMP_NONCE_LENGTH',
  );
  const header = seq(
    integer(3),
    directoryName(sender),
    directoryName(recipient),
    explicit(0, generalizedTime(messageTime)),
    explicit(1, algID(privateKey.asymmetricKeyType)),
    explicit(4, octet(transactionID)),
    explicit(5, octet(senderNonce)),
    ...(recipNonce ? [explicit(6, octet(recipNonce))] : []),
    ...(profile ? [explicit(8, seq(seq(oid(PROFILE), seq(der(12, Buffer.from(profile))))))] : []),
  );
  const wrappedBody = explicit(bodyTag, body),
    tbs = seq(header, wrappedBody);
  return seq(header, wrappedBody, explicit(0, bit(sign(tbs, privateKey))));
}

export function verifyCMP(
  raw,
  { sender, recipient, publicKey, transactionID, recipNonce, at = now(), maxAge = 120 },
) {
  const root = parseDER(raw);
  requireThat(root.tag === 48 && root.children.length === 3, 'CMP_MESSAGE');
  const [header, body, protection] = root.children,
    h = header.children;
  requireThat(
    h.length >= 7 &&
      intValue(h[0]) === 3n &&
      equal(h[1].raw, directoryName(sender)) &&
      equal(h[2].raw, directoryName(recipient)),
    'CMP_ADDRESS_OR_VERSION',
  );
  const f = new Map();
  let last = -1;
  for (const n of h.slice(3)) {
    requireThat(
      n.tag >= 0xa0 && n.tag <= 0xa8 && n.tag > last && n.children.length === 1,
      'CMP_HEADER',
    );
    last = n.tag;
    f.set(n.tag - 0xa0, n.children[0]);
  }
  requireThat(
    equal(f.get(1)?.raw, algID(publicKey.asymmetricKeyType)) &&
      protection.tag === 0xa0 &&
      protection.children.length === 1 &&
      protection.children[0].tag === 3 &&
      protection.children[0].value[0] === 0,
    'CMP_PROTECTION_ALGORITHM',
  );
  requireThat(
    verify(seq(header.raw, body.raw), protection.children[0].value.subarray(1), publicKey),
    'CMP_SIGNATURE',
  );
  const time = f.get(0)?.value.toString('ascii');
  requireThat(/^\d{14}Z$/.test(time ?? ''), 'CMP_TIME');
  const timestamp =
    Date.parse(
      `${time.slice(0, 4)}-${time.slice(4, 6)}-${time.slice(6, 8)}T${time.slice(8, 10)}:${time.slice(10, 12)}:${time.slice(12, 14)}Z`,
    ) / 1000;
  requireThat(
    Number.isFinite(timestamp) &&
      Math.abs(at - timestamp) <= maxAge &&
      equal(f.get(0).raw, generalizedTime(timestamp)),
    'CMP_TIME',
  );
  const tx = f.get(4)?.value,
    nonce = f.get(5)?.value,
    recipientNonce = f.get(6)?.value;
  requireThat(
    f.get(4)?.tag === 4 && f.get(5)?.tag === 4 && tx.length === 32 && nonce.length === 32,
    'CMP_NONCES',
  );
  if (transactionID) requireThat(equal(tx, transactionID), 'CMP_TRANSACTION');
  if (recipNonce) requireThat(equal(recipientNonce, recipNonce), 'CMP_RECIPIENT_NONCE');
  const info = f.get(8);
  let profile;
  if (info) {
    requireThat(
      info.children.length === 1 && oidText(info.children[0].children[0]) === PROFILE,
      'CMP_GENERAL_INFO',
    );
    const names = info.children[0].children[1].children;
    requireThat(names.length === 1 && names[0].tag === 12, 'CMP_PROFILE');
    profile = names[0].value.toString('utf8');
  }
  requireThat(body.tag >= 0xa0 && body.tag <= 0xba && body.children.length === 1, 'CMP_BODY');
  return {
    bodyTag: body.tag - 0xa0,
    body: body.children[0],
    transactionID: tx,
    senderNonce: nonce,
    recipNonce: recipientNonce,
    profile,
  };
}

// The RRA CMP adapter selects p10cr with pinned signature protection and explicit confirmation.
// Identity approval and issuance remain mandatory independent policy callbacks.
export class CMPService {
  constructor({
    journal,
    privateKey,
    sender,
    clientName,
    clientPublicKey,
    profiles,
    authorize,
    issue,
    rejectCertificate = async () => {
      throw Error('CMP_REJECTION_HANDLER_REQUIRED');
    },
  }) {
    requireThat(
      typeof authorize === 'function' && typeof issue === 'function',
      'CMP_POLICY_REQUIRED',
    );
    Object.assign(this, {
      journal,
      privateKey,
      sender,
      clientName,
      clientPublicKey,
      profiles,
      authorize,
      issue,
      rejectCertificate,
    });
  }
  async handle(raw) {
    const message = verifyCMP(raw, {
        sender: this.clientName,
        recipient: this.sender,
        publicKey: this.clientPublicKey,
      }),
      id = b64u(message.transactionID),
      old = this.journal.get('cmp', id),
      hash = sha512(raw);
    if (old && equal(old.value.lastRequestHash, hash) && old.value.response)
      return old.value.response;
    const reply = (tag, body, nonce = random()) =>
      protectCMP({
        sender: this.sender,
        recipient: this.clientName,
        privateKey: this.privateKey,
        transactionID: message.transactionID,
        senderNonce: nonce,
        recipNonce: message.senderNonce,
        bodyTag: tag,
        body,
      });
    if (message.bodyTag === 4) {
      requireThat(
        !old && !message.recipNonce && this.profiles.includes(message.profile),
        'CMP_INITIAL_STATE',
      );
      const csr = message.body.raw,
        parsed = verifyCSR(csr);
      this.journal.put('cmp', id, {
        state: 'PROCESSING',
        lastRequestHash: hash,
        expiresAt: now() + 300,
      });
      const approval = await this.authorize({
        csr,
        profile: message.profile,
        clientName: this.clientName,
        transactionID: message.transactionID,
      });
      requireThat(approval, 'CMP_RA_DENIED');
      const certificate = await this.issue({ csr, approval, profile: message.profile }),
        issued = parseCertificate(certificate);
      requireThat(
        equal(issued.spki, parsed.spki) && equal(issued.subject, parsed.subject),
        'CMP_ISSUED_BINDING',
      );
      const nonce = random(),
        body = seq(seq(seq(MINUS_ONE, seq(integer(0)), seq(explicit(0, certificate))))),
        response = reply(3, body, nonce);
      this.journal.put(
        'cmp',
        id,
        {
          state: 'AWAITING_CONFIRMATION',
          lastRequestHash: hash,
          response,
          certificate,
          nonce,
          expiresAt: now() + 300,
        },
        0,
      );
      return response;
    }
    requireThat(
      message.bodyTag === 24 &&
        old?.value.state === 'AWAITING_CONFIRMATION' &&
        old.value.expiresAt > now() &&
        equal(message.recipNonce, old.value.nonce),
      'CMP_CONFIRM_STATE',
    );
    const confirmations = message.body.children;
    let accepted = false;
    if (confirmations.length) {
      requireThat(confirmations.length === 1, 'CMP_CONFIRM_COUNT');
      const c = confirmations[0].children;
      requireThat(
        c.length === 3 &&
          c[0].tag === 4 &&
          equal(c[1].raw, MINUS_ONE) &&
          equal(c[2].raw, explicit(0, algID(OID.sha512))) &&
          equal(c[0].value, sha512(old.value.certificate)),
        'CMP_CONFIRM_HASH',
      );
      accepted = true;
    }
    if (!accepted) await this.rejectCertificate(old.value.certificate);
    const response = reply(19, der(5, Buffer.alloc(0)));
    this.journal.put(
      'cmp',
      id,
      { ...old.value, state: accepted ? 'CONFIRMED' : 'REJECTED', lastRequestHash: hash, response },
      old.revision,
    );
    return response;
  }
  async expire() {
    for (const row of this.journal.list('cmp')) {
      const r = this.journal.get('cmp', row.id);
      if (r.value.state === 'AWAITING_CONFIRMATION' && r.value.expiresAt <= now()) {
        await this.rejectCertificate(r.value.certificate);
        this.journal.put('cmp', row.id, { ...r.value, state: 'EXPIRED' }, r.revision);
      }
    }
  }
}

export class CMPClient {
  constructor({
    url,
    privateKey,
    sender,
    recipient,
    serverPublicKey,
    issuerPublicKey,
    allowLoopback = false,
  }) {
    Object.assign(this, {
      url,
      privateKey,
      sender,
      recipient,
      serverPublicKey,
      issuerPublicKey,
      allowLoopback,
    });
  }
  async post(bytes) {
    const r = await requestBytes(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/pkixcmp' },
      body: bytes,
      allowLoopback: this.allowLoopback,
    });
    requireThat(
      r.status === 200 && r.headers.get('content-type')?.split(';')[0] === 'application/pkixcmp',
      'CMP_HTTP',
    );
    return r.body;
  }
  async enroll({ csr, profile }) {
    const transactionID = random(),
      senderNonce = random(),
      request = protectCMP({ ...this, transactionID, senderNonce, bodyTag: 4, body: csr, profile });
    const response = verifyCMP(await this.post(request), {
      sender: this.recipient,
      recipient: this.sender,
      publicKey: this.serverPublicKey,
      transactionID,
      recipNonce: senderNonce,
    });
    requireThat(response.bodyTag === 3, 'CMP_RESPONSE_TYPE');
    requireThat(
      response.body.children.length === 1 && response.body.children[0].children.length === 1,
      'CMP_RESPONSE_COUNT',
    );
    const c = response.body.children[0].children[0].children;
    requireThat(
      c.length === 3 &&
        equal(c[0].raw, MINUS_ONE) &&
        intValue(c[1].children[0]) === 0n &&
        c[2].children.length === 1 &&
        c[2].children[0].tag === 0xa0,
      'CMP_CERTIFICATE_RESPONSE',
    );
    const certificate = c[2].children[0].children[0].raw,
      cert = validateCertificate(certificate, this.issuerPublicKey, { profileID: profile }),
      requested = verifyCSR(csr);
    requireThat(
      equal(cert.spki, requested.spki) && equal(cert.subject, requested.subject),
      'CMP_CERTIFICATE_BINDING',
    );
    const confirmNonce = random(),
      confirmation = protectCMP({
        ...this,
        transactionID,
        senderNonce: confirmNonce,
        recipNonce: response.senderNonce,
        bodyTag: 24,
        body: seq(seq(octet(sha512(certificate)), MINUS_ONE, explicit(0, algID(OID.sha512)))),
      });
    const ack = verifyCMP(await this.post(confirmation), {
      sender: this.recipient,
      recipient: this.sender,
      publicKey: this.serverPublicKey,
      transactionID,
      recipNonce: confirmNonce,
    });
    requireThat(
      ack.bodyTag === 19 && equal(ack.body.raw, der(5, Buffer.alloc(0))),
      'CMP_CONFIRM_ACK',
    );
    return certificate;
  }
}
