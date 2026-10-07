import { mlDsa87KeyID, subtreeInput } from './vendor/tlog-cosignature-ml-dsa/extension.mjs';
import {
  parseCheckpointEnvelope,
  assertCheckpointLogSignature,
  encodeSubtreeRequest,
  parseSubtreeRequest,
  encodeSubtreeResponse,
  parseSubtreeResponse as parseMldsa87SubtreeResponse,
} from './vendor/tlog-cosignature-ml-dsa/transport.mjs';
export { SUBTREE_WIRE_PROFILE } from './vendor/tlog-cosignature-ml-dsa/transport.mjs';
export { parseSubtreeRequest };
import { sign as signCrypto, verify as verifyCrypto, createPublicKey } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { requireThat, sha256, spki, parseDER, equal, now, b64u, H, D } from './core.mjs';
import {
  treeHash,
  leafHash,
  consistencyProof,
  verifyConsistency,
  uint,
  vector,
  cosignedMessage,
  encodeProof,
  inclusionProof,
} from './mtc.mjs';
import { requestBytes, readBody } from './transport.mjs';
import { certificateFromTBS, OID } from './pki.mjs';
import { IndexedMerkleLog } from './storage/merkle.mjs';
const base64 = (b) => b.toString('base64');
function unbase64(s) {
  requireThat(
    typeof s === 'string' &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s),
    'NOTE_BASE64',
  );
  const b = Buffer.from(s, 'base64');
  requireThat(base64(b) === s, 'NOTE_BASE64');
  return b;
}
function decimal(s) {
  requireThat(/^(0|[1-9][0-9]*)$/.test(s), 'NOTE_DECIMAL');
  const n = BigInt(s);
  requireThat(n <= 0x7fffffffffffffffn, 'NOTE_SIZE');
  return n;
}
export function checkpointBody(origin, size, root) {
  requireThat(
    typeof origin === 'string' &&
      /^[\x21-\x2a\x2c-\x7e]{1,255}$/.test(origin) &&
      root.length === 32,
    'NOTE_ORIGIN',
  );
  return `${origin}\n${BigInt(size)}\n${base64(root)}\n`;
}
export function parseCheckpoint(note) {
  return parseCheckpointEnvelope(note);
}
const rawKey = (k) => parseDER(spki(k)).children[1].value.subarray(1);
export function noteKeyID(name, key, scheme) {
  requireThat(!name.includes('\n'), 'NOTE_NAME');
  if (scheme === 'CERTCONCORD-MLDSA87-SUBTREE-v1') return mlDsa87KeyID(name, key);
  const byte =
    scheme === 'ed25519-log'
      ? 1
      : scheme === 'ed25519-cosign'
        ? 4
        : scheme === 'mldsa44-cosign'
          ? 6
          : 0;
  requireThat(byte > 0, 'NOTE_SCHEME');
  return sha256(
    Buffer.concat([Buffer.from(name + '\n'), Buffer.from([byte]), rawKey(key)]),
  ).subarray(0, 4);
}
const subtreeMessage = subtreeInput;

function signingInput(body, signer, timestamp) {
  if (signer.scheme === 'ed25519-log') return Buffer.from(body);
  if (signer.scheme === 'ed25519-cosign')
    return Buffer.from(`cosignature/v1\ntime ${timestamp}\n` + body);
  const [origin, size, root] = body.trimEnd().split('\n');
  return subtreeMessage({
    name: signer.name,
    origin,
    end: BigInt(size),
    root: unbase64(root),
    timestamp,
  });
}
export function noteSignature(body, signer, { timestamp = now() } = {}) {
  const pub = signer.publicKey ?? createPublicKey(signer.privateKey),
    scheme = signer.scheme;
  requireThat(
    pub.asymmetricKeyType ===
      (scheme.startsWith('ed25519')
        ? 'ed25519'
        : scheme === 'mldsa44-cosign'
          ? 'ml-dsa-44'
          : 'ml-dsa-87'),
    'NOTE_KEY_SCHEME',
  );
  const signature = signCrypto(null, signingInput(body, signer, timestamp), signer.privateKey),
    encoded = scheme === 'ed25519-log' ? signature : Buffer.concat([uint(timestamp, 8), signature]);
  return `— ${signer.name} ${base64(Buffer.concat([noteKeyID(signer.name, pub, scheme), encoded]))}\n`;
}
export function verifyNote(note, signer, { maxFutureSkew = 30 } = {}) {
  const expectedType = signer.scheme.startsWith('ed25519')
    ? 'ed25519'
    : signer.scheme === 'mldsa44-cosign'
      ? 'ml-dsa-44'
      : 'ml-dsa-87';
  requireThat(signer.publicKey?.asymmetricKeyType === expectedType, 'NOTE_KEY_SCHEME');
  const cp = parseCheckpoint(note),
    id = noteKeyID(signer.name, signer.publicKey, signer.scheme),
    matches = cp.signatures.filter((s) => s.name === signer.name && equal(s.keyID, id));
  let good = false;
  for (const s of matches) {
    const signatureLength =
      expectedType === 'ed25519' ? 64 : expectedType === 'ml-dsa-44' ? 2420 : 4627;
    if (s.signature.length !== signatureLength + (signer.scheme === 'ed25519-log' ? 0 : 8))
      continue;
    const timestamp = signer.scheme === 'ed25519-log' ? 0 : s.signature.readBigUInt64BE(0),
      sig = signer.scheme === 'ed25519-log' ? s.signature : s.signature.subarray(8);
    if (
      timestamp <= BigInt(now() + maxFutureSkew) &&
      verifyCrypto(null, signingInput(cp.body, signer, timestamp), signer.publicKey, sig)
    )
      good = true;
  }
  requireThat(good, 'NOTE_UNTRUSTED_SIGNATURE');
  return cp;
}
export function verifyPublishedCheckpoint(note, log) {
  assertCheckpointLogSignature(note, {
    name: log.name,
    keyID: noteKeyID(log.name, log.publicKey, log.scheme),
  });
  return verifyNote(note, log);
}
export function checkpointForSubtree(note, signer) {
  const cp = verifyNote(note, signer),
    keyID = noteKeyID(signer.name, signer.publicKey, signer.scheme),
    signature = cp.signatures.find(
      (value) => value.name === signer.name && equal(value.keyID, keyID),
    );
  return (
    cp.body +
    '\n' +
    `— ${signature.name} ${base64(Buffer.concat([signature.keyID, signature.signature]))}\n`
  );
}
export function signedCheckpoint({ origin, entries, signer }) {
  const body = checkpointBody(origin, entries.length, treeHash(entries));
  return body + '\n' + noteSignature(body, signer);
}
export function witnessRequest(oldSize, proof, checkpoint) {
  requireThat(proof.length <= 63 && proof.every((h) => h.length === 32), 'WITNESS_PROOF');
  return `old ${BigInt(oldSize)}\n${proof.map(base64).join('\n')}${proof.length ? '\n' : ''}\n${checkpoint}`;
}
function parseWitnessRequest(body) {
  const i = body.indexOf('\n\n');
  requireThat(i > 0, 'WITNESS_REQUEST');
  const lines = body.slice(0, i).split('\n'),
    old = lines.shift();
  requireThat(old.startsWith('old '), 'WITNESS_OLD');
  const oldSize = decimal(old.slice(4)),
    proof = lines.map(unbase64);
  requireThat(proof.length <= 63 && proof.every((h) => h.length === 32), 'WITNESS_PROOF');
  return { oldSize, proof, note: body.slice(i + 2) };
}
export class TlogWitness {
  constructor({ journal, signer, logs, namespace = 'witness' }) {
    Object.assign(this, { journal, signer, logs, namespace });
  }
  signSubtree({ origin, start, end, root, proof, checkpoint }) {
    requireThat(this.logs.has(origin), 'WITNESS_UNKNOWN_LOG');
    requireThat(!this.signer.scheme.startsWith('ed25519'), 'SUBTREE_SIGNATURE_SCHEME');
    requireThat(parseCheckpoint(checkpoint).signatures.length === 1, 'SUBTREE_ONE_WITNESS');
    const cp = verifyNote(checkpoint, {
      ...this.signer,
      publicKey: this.signer.publicKey ?? createPublicKey(this.signer.privateKey),
    });
    requireThat(cp.origin === origin && end <= cp.size, 'SUBTREE_CONTEXT');
    verifyConsistency({ start, end, size: cp.size, node: root, root: cp.root, proof });
    return {
      root,
      signature: signCrypto(
        null,
        subtreeMessage({ name: this.signer.name, origin, start, end, root, timestamp: 0 }),
        this.signer.privateKey,
      ),
    };
  }
  addCheckpoint(body, { sign = true } = {}) {
    const q = parseWitnessRequest(body),
      cp = parseCheckpoint(q.note),
      log = this.logs.get(cp.origin);
    requireThat(log, 'WITNESS_UNKNOWN_LOG');
    verifyPublishedCheckpoint(q.note, log);
    return this.journal.transaction(() => {
      const r = this.journal.get(this.namespace, cp.origin),
        old = r?.value ?? { size: 0, root: treeHash([]) };
      if (BigInt(old.size) !== q.oldSize)
        return { status: 409, type: 'text/x.tlog.size', body: old.size + '\n' };
      requireThat(cp.size >= q.oldSize, 'WITNESS_ROLLBACK');
      if (q.oldSize === 0n) requireThat(q.proof.length === 0, 'WITNESS_ZERO_PROOF');
      else
        verifyConsistency({
          start: 0,
          end: q.oldSize,
          size: cp.size,
          node: old.root,
          root: cp.root,
          proof: q.proof,
        });
      const cosignature = sign ? noteSignature(cp.body, this.signer) : '';
      this.journal.put(
        this.namespace,
        cp.origin,
        { size: cp.size, root: cp.root, note: q.note, cosignature },
        r?.revision ?? -1,
      );
      return {
        status: 200,
        type: 'text/plain',
        body: cosignature,
      };
    });
  }
}
export async function submitWitness(url, request, { signer, checkpoint, allowLoopback = false }) {
  const r = await requestBytes(url + '/add-checkpoint', {
    method: 'POST',
    body: request,
    headers: { 'content-type': 'text/plain' },
    allowLoopback,
  });
  if (r.status === 409)
    return { status: 'CONFLICT', size: decimal(r.body.toString('utf8').trimEnd()) };
  requireThat(r.status === 200, 'WITNESS_HTTP');
  const combined = checkpoint + r.body.toString('utf8');
  verifyNote(combined, signer);
  return { status: 'SIGNED', checkpoint: combined };
}
export function mirrorUpload(origin, entries, start = 0, { maxPackages = Infinity } = {}) {
  const end = entries.length,
    parts = [vector(Buffer.from(origin), 1), uint(start, 8), uint(end, 8), uint(0, 2)];
  let count = 0;
  for (let i = start; i < end && count++ < maxPackages; ) {
    const begin = Math.floor(i / 256) * 256,
      limit = Math.min(end, begin + 256),
      proof = consistencyProof(entries, begin, limit);
    parts.push(
      ...entries.slice(i, limit).map((e) => vector(e, 2)),
      uint(proof.length, 1),
      ...proof,
    );
    i = limit;
  }
  return Buffer.concat(parts);
}
export function indexedMirrorUpload(origin, store, start, end = store.head().size) {
  const base = Math.floor(start / 256) * 256,
    limit = Math.min(end, base + 256),
    proof = store.consistency(base, limit, end);
  return Buffer.concat([
    vector(Buffer.from(origin), 1),
    uint(start, 8),
    uint(end, 8),
    uint(0, 2),
    ...store.entries(start, limit).map((e) => vector(e, 2)),
    uint(proof.length, 1),
    ...proof,
  ]);
}
export class TlogMirror {
  constructor({ journal, signer, logs, maxEntries = 2 ** 40 }) {
    Object.assign(this, { journal, signer, logs, maxEntries });
    this.pending = new TlogWitness({ journal, signer, logs, namespace: 'mirror-pending' });
  }
  store(origin) {
    requireThat(!this.journal.get('mirror-data', origin)?.value.entries, 'LOG_MIGRATION_REQUIRED');
    return new IndexedMerkleLog(this.journal, 'tlog:' + origin, { maxEntries: this.maxEntries });
  }
  storedSize(origin) {
    return this.store(origin).head().size;
  }
  addCheckpoint(body) {
    const result = this.pending.addCheckpoint(body, { sign: false });
    if (result.status === 200) {
      const cp = parseCheckpoint(parseWitnessRequest(body).note);
      const previous = this.journal.get('mirror-checkpoint-history', cp.origin + ':' + cp.size);
      if (previous)
        requireThat(
          equal(parseCheckpoint(previous.value.note).root, cp.root),
          'MIRROR_CHECKPOINT_FORK',
        );
      else
        this.journal.put('mirror-checkpoint-history', cp.origin + ':' + cp.size, { note: cp.note });
    }
    return result;
  }
  addEntries(input, { gzip = false } = {}) {
    return this.journal.transaction(() => this.appendEntries(input, { gzip }));
  }
  appendEntries(input, { gzip = false } = {}) {
    const b = gzip ? gunzipSync(input, { maxOutputLength: 16 * 1024 * 1024 }) : Buffer.from(input);
    requireThat(b.length <= 16 * 1024 * 1024, 'MIRROR_REQUEST_LIMIT');
    let pos = 0;
    function read(n) {
      requireThat(pos + n <= b.length, 'MIRROR_TRUNCATED');
      return b.subarray(pos, (pos += n));
    }
    const u = (n) => {
        let x = 0n;
        for (const v of read(n)) x = x * 256n + BigInt(v);
        return x;
      },
      origin = read(Number(u(1))).toString('utf8'),
      start = u(8),
      end = u(8),
      ticket = read(Number(u(2)));
    requireThat(
      ticket.length === 0 &&
        this.logs.has(origin) &&
        start <= end &&
        end <= BigInt(this.maxEntries),
      'MIRROR_HEADER',
    );
    const history = this.journal.get('mirror-checkpoint-history', origin + ':' + end),
      pending = this.journal.get('mirror-pending', origin);
    requireThat(pending, 'MIRROR_NO_CHECKPOINT');
    const store = this.store(origin);
    let row = this.journal.get('mirror-data', origin),
      state = row?.value ?? { size: 0, note: '' };
    const conflict = () => ({
      status: 409,
      type: 'text/x.tlog.mirror-info',
      body: `${history ? end : pending.value.size}\n${store.head().size}\n\n`,
    });
    if (!history || start > BigInt(store.head().size) || end < BigInt(state.size))
      return conflict();
    const cp = parseCheckpoint(history.value.note);
    let index = Number(start),
      committed = 0;
    while (index < Number(end) && pos < b.length) {
      const base = Math.floor(index / 256) * 256,
        limit = Math.min(Number(end), base + 256),
        newEntries = [];
      try {
        for (let i = index; i < limit; i++) newEntries.push(read(Number(u(2))));
        const count = Number(u(1));
        requireThat(count <= 63, 'MIRROR_PROOF_LIMIT');
        const proof = Array.from({ length: count }, () => read(32)),
          subtree = [...store.entries(base, index), ...newEntries];
        verifyConsistency({
          start: base,
          end: limit,
          size: end,
          node: treeHash(subtree),
          root: cp.root,
          proof,
        });
      } catch (e) {
        if (e.code === 'MIRROR_TRUNCATED' && committed) break;
        throw e;
      }
      for (let i = 0; i < newEntries.length; i++) {
        const at = index + i;
        if (at < store.head().size)
          requireThat(equal(store.entry(at), newEntries[i]), 'MIRROR_ENTRY_CONFLICT');
        else requireThat(store.append(newEntries[i], String(at)) === at, 'MIRROR_ENTRY_INDEX');
      }
      committed++;
      index = limit;
    }
    requireThat(index === Number(end) || committed > 0, 'MIRROR_EMPTY_UPLOAD');
    if (index < Number(end))
      return {
        status: 202,
        type: 'text/x.tlog.mirror-info',
        body: `${end}\n${store.head().size}\n\n`,
      };
    requireThat(pos === b.length, 'MIRROR_TRAILING');
    const cosignature = noteSignature(cp.body, this.signer);
    this.journal.put(
      'mirror-data',
      origin,
      { ...state, size: end, note: cp.note + cosignature },
      row?.revision ?? -1,
    );
    return { status: 200, type: 'text/plain', body: cosignature };
  }
  checkpoint(origin) {
    const r = this.journal.get('mirror-data', origin);
    requireThat(r?.value.note, 'MIRROR_UNCOMMITTED');
    requireThat(this.logs.has(origin), 'WITNESS_UNKNOWN_LOG');
    const checkpoint = verifyPublishedCheckpoint(r.value.note, this.logs.get(origin));
    requireThat(checkpoint.origin === origin, 'MIRROR_CHECKPOINT_ORIGIN');
    return r.value.note;
  }
  entryBundle(origin, tile, { width = 256 } = {}) {
    const state = this.journal.get('mirror-data', origin)?.value;
    requireThat(
      state &&
        Number.isSafeInteger(tile) &&
        tile >= 0 &&
        width >= 1 &&
        width <= 256 &&
        tile * 256 + width <= Number(state.size),
      'TILE_RANGE',
    );
    return Buffer.concat(
      this.store(origin)
        .entries(tile * 256, tile * 256 + width)
        .map((e) => vector(e, 2)),
    );
  }
  hashTile(origin, level, tile, { width = 256 } = {}) {
    const state = this.journal.get('mirror-data', origin)?.value,
      step = 2 ** (level * 8);
    requireThat(
      state &&
        Number.isSafeInteger(level) &&
        level >= 0 &&
        level <= 5 &&
        Number.isSafeInteger(tile) &&
        tile >= 0 &&
        width >= 1 &&
        width <= 256 &&
        (tile * 256 + width) * step <= Number(state.size),
      'TILE_RANGE',
    );
    return Buffer.concat(
      Array.from({ length: width }, (_, i) =>
        this.store(origin).root((tile * 256 + i + 1) * step, (tile * 256 + i) * step),
      ),
    );
  }
  signSubtree({ origin, start, end, proof, checkpoint }) {
    requireThat(this.logs.has(origin), 'WITNESS_UNKNOWN_LOG');
    requireThat(!this.signer.scheme.startsWith('ed25519'), 'SUBTREE_SIGNATURE_SCHEME');
    requireThat(parseCheckpoint(checkpoint).signatures.length === 1, 'SUBTREE_ONE_WITNESS');
    const cp = verifyNote(checkpoint, {
        ...this.signer,
        publicKey: this.signer.publicKey ?? createPublicKey(this.signer.privateKey),
      }),
      state = this.journal.get('mirror-data', origin)?.value;
    requireThat(
      cp.origin === origin && state && BigInt(state.size) >= cp.size && end <= cp.size,
      'MIRROR_SUBTREE_CONTEXT',
    );
    const root = this.store(origin).root(Number(end), Number(start));
    verifyConsistency({ start, end, size: cp.size, node: root, root: cp.root, proof });
    const signature = signCrypto(
      null,
      subtreeMessage({ name: this.signer.name, origin, start, end, root, timestamp: 0 }),
      this.signer.privateKey,
    );
    return { root, signature };
  }
}
export function landmarkRelativeCertificate(tbs, { entries, index, start, end }) {
  return certificateFromTBS(
    tbs,
    OID.mtc,
    encodeProof({
      start,
      end,
      inclusion: inclusionProof(entries, index, start, end),
      signatures: [],
    }),
  );
}

export function subtreeRequest({ start, end, root, proof, checkpoint }) {
  return encodeSubtreeRequest({ start, end, root, proof, checkpoint });
}
function rawSubtreeResponse(signature, scheme) {
  if (scheme === 'CERTCONCORD-MLDSA87-SUBTREE-v1') return encodeSubtreeResponse(signature);
  requireThat(scheme === 'mldsa44-cosign' && signature.length === 2420, 'SUBTREE_SIGNATURE_SCHEME');
  return base64(signature) + '\n';
}
export function verifySubtreeResponse(text, context, signer) {
  requireThat(
    typeof text === 'string' && /^[A-Za-z0-9+/]+={0,2}\n$/.test(text),
    'SUBTREE_RESPONSE_ENCODING',
  );
  const signature =
    signer.scheme === 'CERTCONCORD-MLDSA87-SUBTREE-v1'
      ? parseMldsa87SubtreeResponse(text)
      : unbase64(text.slice(0, -1));
  requireThat(
    (signer.scheme === 'CERTCONCORD-MLDSA87-SUBTREE-v1' &&
      signer.publicKey.asymmetricKeyType === 'ml-dsa-87' &&
      signature.length === 4627) ||
      (signer.scheme === 'mldsa44-cosign' &&
        signer.publicKey.asymmetricKeyType === 'ml-dsa-44' &&
        signature.length === 2420),
    'SUBTREE_SIGNATURE_SCHEME',
  );
  requireThat(
    verifyCrypto(
      null,
      subtreeMessage({ ...context, name: signer.name, timestamp: 0 }),
      signer.publicKey,
      signature,
    ),
    'SUBTREE_SIGNATURE',
  );
  return signature;
}
export function createTransparencyHandler(service) {
  return async (req, res) => {
    try {
      const path = new URL(req.url, 'https://localhost').pathname;
      let result;
      if (req.method === 'POST' && path.endsWith('/add-checkpoint'))
        result = service.addCheckpoint(
          (await readBody(req, { maxBytes: 1024 * 1024 })).toString('utf8'),
        );
      else if (req.method === 'POST' && path.endsWith('/add-entries')) {
        requireThat(service instanceof TlogMirror, 'MIRROR_REQUIRED');
        const encoding = req.headers['content-encoding'];
        requireThat(!encoding || encoding === 'gzip', 'MIRROR_CONTENT_ENCODING');
        result = service.addEntries(await readBody(req, { maxBytes: 16 * 1024 * 1024 }), {
          gzip: encoding === 'gzip',
        });
      } else if (req.method === 'POST' && path.endsWith('/sign-subtree')) {
        const q = parseSubtreeRequest(
            (await readBody(req, { maxBytes: 1024 * 1024 })).toString('utf8'),
          ),
          s = service.signSubtree(q);
        requireThat(equal(s.root, q.root), 'CONSISTENCY_HASH');
        result = {
          status: 200,
          type: 'text/plain',
          body: rawSubtreeResponse(s.signature, service.signer.scheme),
        };
      } else if (req.method === 'GET' && path.endsWith('/checkpoint')) {
        const hash = path.split('/').at(-2),
          origin = [...service.logs.keys()].find(
            (o) => sha256(Buffer.from(o)).toString('hex') === hash,
          );
        requireThat(origin, 'WITNESS_UNKNOWN_LOG');
        let note;
        if (service instanceof TlogMirror) note = service.checkpoint(origin);
        else {
          const row = service.journal.get(service.namespace, origin);
          requireThat(row, 'WITNESS_UNKNOWN_LOG');
          requireThat(
            typeof row.value.cosignature === 'string',
            'WITNESS_STORED_SIGNATURE_REQUIRED',
          );
          note = row.value.note + row.value.cosignature;
        }
        const published = verifyPublishedCheckpoint(note, service.logs.get(origin));
        requireThat(published.origin === origin, 'CHECKPOINT_ORIGIN');
        result = { status: 200, type: 'text/plain; charset=utf-8', body: note };
      } else if (req.method === 'GET' && service instanceof TlogMirror && path.includes('/tile/')) {
        const match =
          /^\/([a-f0-9]{64})\/tile\/(entries|[0-5])\/((?:x[0-9]{3}\/)*[0-9]{3})(?:\.p\/(0|[1-9][0-9]*))?$/.exec(
            path,
          );
        requireThat(match, 'TILE_PATH');
        const origin = [...service.logs.keys()].find(
            (o) => sha256(Buffer.from(o)).toString('hex') === match[1],
          ),
          parts = match[3].split('/'),
          tile = parts.reduce((n, p) => n * 1000 + Number(p.replace(/^x/, '')), 0),
          width = match[4] ? Number(match[4]) : 256;
        requireThat(
          origin && (parts.length === 1 || parts[0] !== 'x000') && Number.isSafeInteger(tile),
          'TILE_PATH',
        );
        result = {
          status: 200,
          type: 'application/octet-stream',
          body:
            match[2] === 'entries'
              ? service.entryBundle(origin, tile, { width })
              : service.hashTile(origin, Number(match[2]), tile, { width }),
        };
      } else {
        res.writeHead(404);
        return res.end();
      }
      res.writeHead(result.status, { 'content-type': result.type, 'cache-control': 'no-store' });
      res.end(result.body);
    } catch (e) {
      const code = e.code ?? e.message,
        status = /UNKNOWN_LOG/.test(code)
          ? 404
          : /UNTRUSTED_SIGNATURE/.test(code)
            ? 403
            : /CONSISTENCY/.test(code)
              ? 422
              : 400;
      res.writeHead(status, { 'content-type': 'text/plain' });
      res.end(/^[A-Z0-9_]+$/.test(code) ? code : 'INVALID_REQUEST');
    }
  };
}
