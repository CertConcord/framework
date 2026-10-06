import koffi from 'koffi';
import { createPublicKey } from 'node:crypto';
import { requireThat, sha256, verify, ALG, seq, oid, bit, parseDER } from './core.mjs';
import { p1363ToDER } from './providers.mjs';

const Attribute = koffi.struct('CERTCONCORD_CK_ATTRIBUTE', {
  type: 'ulong',
  pValue: 'void *',
  ulValueLen: 'ulong',
});
const Mechanism = koffi.struct('CERTCONCORD_CK_MECHANISM', {
  mechanism: 'ulong',
  pParameter: 'void *',
  ulParameterLen: 'ulong',
});
const Context = koffi.struct('CERTCONCORD_CK_SIGN_ADDITIONAL_CONTEXT', {
  hedgeVariant: 'ulong',
  pContext: 'void *',
  ulContextLen: 'ulong',
});
const ckLong = (n) => {
  const b = Buffer.alloc(koffi.sizeof('ulong'));
  if (b.length === 8) b.writeBigUInt64LE(BigInt(n));
  else b.writeUInt32LE(n);
  return b;
};
const attrs = (values) =>
  values.map(([type, value]) => ({ type, pValue: value, ulValueLen: value.length }));
// One session per instance. Callers serialize operations on a token session.
export class PKCS11Provider {
  constructor({ library, slot, pin, contextAuthentication, keys = new Map() }) {
    this.id = 'pkcs11-v3.2';
    this.keys = keys;
    this.contextAuthentication = contextAuthentication;
    this.library = koffi.load(library);
    const f = (name, args) => this.library.func('ulong ' + name + '(' + args + ')');
    this.f = {
      initialize: f('C_Initialize', 'void * args'),
      finalize: f('C_Finalize', 'void * reserved'),
      open: f(
        'C_OpenSession',
        'ulong slot, ulong flags, void * application, void * notify, _Out_ ulong * session',
      ),
      close: f('C_CloseSession', 'ulong session'),
      login: f('C_Login', 'ulong session, ulong userType, uint8_t * pin, ulong length'),
      logout: f('C_Logout', 'ulong session'),
      findInit: f('C_FindObjectsInit', 'ulong session, CERTCONCORD_CK_ATTRIBUTE * attrs, ulong count'),
      find: f(
        'C_FindObjects',
        'ulong session, _Out_ ulong * objects, ulong count, _Out_ ulong * found',
      ),
      findFinal: f('C_FindObjectsFinal', 'ulong session'),
      get: f(
        'C_GetAttributeValue',
        'ulong session, ulong object, CERTCONCORD_CK_ATTRIBUTE * attrs, ulong count',
      ),
      signInit: f('C_SignInit', 'ulong session, CERTCONCORD_CK_MECHANISM * mechanism, ulong key'),
      sign: f(
        'C_Sign',
        'ulong session, uint8_t * input, ulong length, _Out_ uint8_t * signature, _Inout_ ulong * size',
      ),
      generate: f(
        'C_GenerateKeyPair',
        'ulong session, CERTCONCORD_CK_MECHANISM * mechanism, CERTCONCORD_CK_ATTRIBUTE * publicAttrs, ulong publicCount, CERTCONCORD_CK_ATTRIBUTE * privateAttrs, ulong privateCount, _Out_ ulong * publicKey, _Out_ ulong * privateKey',
      ),
    };
    const status = this.f.initialize(null);
    this.ownsInitialization = status === 0;
    requireThat(status === 0 || status === 0x191, 'PKCS11_INITIALIZE');
    const h = [0];
    this.check(this.f.open(slot, 6, null, null, h));
    this.session = h[0];
    const secret = Buffer.from(pin);
    try {
      const r = this.f.login(this.session, 1, secret, secret.length);
      requireThat(r === 0 || r === 0x100, 'PKCS11_LOGIN');
    } finally {
      secret.fill(0);
    }
  }
  check(rv) {
    requireThat(Number(rv) === 0, 'PKCS11_' + Number(rv).toString(16));
  }
  close() {
    if (this.session !== undefined) {
      this.f.close(this.session);
      this.session = undefined;
    }
    if (this.ownsInitialization) {
      this.f.finalize(null);
      this.ownsInitialization = false;
    }
  }
  find(id, objectClass) {
    const a = attrs([
      [0, ckLong(objectClass)],
      [0x102, Buffer.from(id)],
    ]);
    this.check(this.f.findInit(this.session, a, a.length));
    try {
      const result = [0, 0],
        count = [0];
      this.check(this.f.find(this.session, result, 2, count));
      requireThat(count[0] === 1, 'PKCS11_KEY_NOT_UNIQUE');
      return result[0];
    } finally {
      this.f.findFinal(this.session);
    }
  }
  attribute(handle, type, max = 16384) {
    const b = Buffer.alloc(max),
      a = attrs([[type, b]]);
    const mem = koffi.alloc(Attribute, 1);
    try {
      koffi.encode(mem, Attribute, a[0]);
      this.check(this.f.get(this.session, handle, mem, 1));
      const out = koffi.decode(mem, Attribute);
      requireThat(Number(out.ulValueLen) <= max, 'PKCS11_ATTRIBUTE_SIZE');
      return b.subarray(0, Number(out.ulValueLen));
    } finally {
      koffi.free(mem);
    }
  }
  publicKey(id, algorithm) {
    const h = this.find(id, 2);
    if (algorithm === 'ec') {
      const point = parseDER(this.attribute(h, 0x181)).value;
      return createPublicKey({
        key: seq(seq(oid('1.2.840.10045.2.1'), oid('1.2.840.10045.3.1.7')), bit(point)),
        type: 'spki',
        format: 'der',
      });
    }
    requireThat(['ml-dsa-65', 'ml-dsa-87'].includes(algorithm), 'PKCS11_ALGORITHM');
    return createPublicKey({
      key: seq(seq(oid(ALG[algorithm].oid)), bit(this.attribute(h, 0x11))),
      type: 'spki',
      format: 'der',
    });
  }
  generate({ keyRef, id, algorithm }) {
    requireThat(!this.keys.has(keyRef) && Buffer.isBuffer(id) && id.length >= 16, 'PKCS11_KEY_ID');
    const common = [
        [1, Buffer.from([1])],
        [0x102, id],
        [3, Buffer.from(keyRef)],
      ],
      pub = [...common, [0x10a, Buffer.from([1])]],
      priv = [
        ...common,
        [2, Buffer.from([1])],
        [0x103, Buffer.from([1])],
        [0x162, Buffer.from([0])],
        [0x108, Buffer.from([1])],
      ];
    let mechanism;
    if (algorithm === 'ec') {
      mechanism = 0x1040;
      pub.push([0x180, oid('1.2.840.10045.3.1.7')]);
    } else {
      requireThat(['ml-dsa-65', 'ml-dsa-87'].includes(algorithm), 'PKCS11_ALGORITHM');
      mechanism = 0x1c;
      pub.push([0x61d, ckLong(algorithm === 'ml-dsa-65' ? 2 : 3)]);
    }
    const a = attrs(pub),
      b = attrs(priv),
      ph = [0],
      sh = [0];
    this.check(
      this.f.generate(
        this.session,
        { mechanism, pParameter: null, ulParameterLen: 0 },
        a,
        a.length,
        b,
        b.length,
        ph,
        sh,
      ),
    );
    const publicKey = this.publicKey(id, algorithm);
    this.keys.set(keyRef, { id, algorithm, publicKey });
    return publicKey;
  }
  async capabilities(keyRef) {
    const key = this.keys.get(keyRef);
    requireThat(key, 'PKCS11_KEY_PIN');
    const pub = this.publicKey(key.id, key.algorithm);
    requireThat(
      pub
        .export({ type: 'spki', format: 'der' })
        .equals(key.publicKey.export({ type: 'spki', format: 'der' })),
      'PKCS11_KEY_REPLACED',
    );
    const h = this.find(key.id, 3);
    requireThat(
      this.attribute(h, 0x162, 1)[0] === 0 && this.attribute(h, 0x103, 1)[0] === 1,
      'PKCS11_EXTRACTABLE',
    );
    return {
      publicKey: pub,
      algorithm: key.algorithm,
      input: 'MESSAGE',
      custody: 'TOKEN_UNATTESTED',
      localUV: false,
      exportable: false,
    };
  }
  async sign({ keyRef, tbs }) {
    this.pending = (this.pending ?? Promise.resolve())
      .catch(() => {})
      .then(() => this.signInternal({ keyRef, tbs }));
    return this.pending;
  }
  async signInternal({ keyRef, tbs }) {
    const c = await this.capabilities(keyRef),
      key = this.keys.get(keyRef),
      handle = this.find(key.id, 3),
      ec = key.algorithm === 'ec',
      ctx = koffi.alloc(Context, 1);
    try {
      koffi.encode(ctx, Context, { hedgeVariant: 1, pContext: null, ulContextLen: 0 });
      this.check(
        this.f.signInit(
          this.session,
          {
            mechanism: ec ? 0x1041 : 0x1d,
            pParameter: ec ? null : ctx,
            ulParameterLen: ec ? 0 : koffi.sizeof(Context),
          },
          handle,
        ),
      );
      if (this.attribute(handle, 0x202, 1)[0] === 1) {
        requireThat(
          typeof this.contextAuthentication === 'function',
          'PKCS11_CONTEXT_AUTH_REQUIRED',
        );
        const secret = Buffer.from(await this.contextAuthentication({ keyRef }));
        try {
          this.check(this.f.login(this.session, 2, secret, secret.length));
        } finally {
          secret.fill(0);
        }
      }
      const input = ec ? sha256(tbs) : tbs,
        size = [8192],
        out = Buffer.alloc(size[0]);
      this.check(this.f.sign(this.session, input, input.length, out, size));
      requireThat(size[0] <= out.length, 'PKCS11_SIGNATURE_SIZE');
      const raw = out.subarray(0, size[0]),
        signature = ec ? p1363ToDER(raw) : raw;
      requireThat(verify(tbs, signature, c.publicKey), 'PKCS11_SIGNATURE');
      return signature;
    } finally {
      koffi.free(ctx);
    }
  }
}
