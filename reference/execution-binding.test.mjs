import test from 'node:test';
import assert from 'node:assert/strict';
import { unlinkSync, mkdirSync } from 'node:fs';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import {
  Journal,
  SigningGateway,
  activationContext,
  issuePermit,
  evidenceObject,
  readControl,
} from './state.mjs';
import { RemoteCryptoKeyService } from './providers.mjs';
import {
  EXECUTION_BINDING_PROFILE,
  ExecutionBindingGateway,
  issueExecutionBinding,
  verifyExecutionEvidence,
} from './execution-binding.mjs';
import { runDemo } from './demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { verifySignaturePackage } from './evidence.mjs';
import { verifyMdocSignaturePackage } from './signer-mdoc.mjs';
import { createVerifier } from './sdk/index.mjs';

function fixture({ path, algorithm = 'ml-dsa-65' } = {}) {
  if (path) mkdirSync('.runtime', { recursive: true });
  const journal = new Journal(path),
    document = c.generate(algorithm),
    authority = c.generate('ml-dsa-87');
  const certificate = p.issueCertificate(
    {
      publicKey: authority.publicKey,
      issuer: p.name('Synthetic Control'),
      subject: p.name('Synthetic Control'),
      serial: 1,
      profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
    },
    authority.privateKey,
  );
  const policy = {
    schemaVersion: 1,
    activationMode: 'HUMAN_WEBAUTHN',
    allowedProfiles: ['CERTCONCORD-PERSON-SIGN-v1'],
    allowedOrigins: ['https://website.example'],
    audience: 'execution-broker',
    maxActivationLifetime: 120,
    executionBinding: {
      profile: EXECUTION_BINDING_PROFILE,
      providerID: 'test-broker',
      maxLeaseSeconds: 300,
    },
  };
  let at = c.now();
  const trustDomainID = c.random(),
    tbs = Buffer.from('Exact authorized input');
  const sim = {
    schemaVersion: 1,
    trustDomainID,
    transactionID: c.random(),
    subjectID: c.random(),
    profileID: 'CERTCONCORD-PERSON-SIGN-v1',
    keyID: c.keyID(document.publicKey),
    certificateID: c.random(64),
    certificateRepresentationHash: c.random(64),
    policyHash: c.H('SignaturePolicy', policy),
    origin: policy.allowedOrigins[0],
    issuedAt: at,
    expiresAt: at + 120,
  };
  const activation = activationContext({
    ...sim,
    tbs,
    simHash: c.H('SIM', sim),
    publicKey: document.publicKey,
    rpID: 'website.example',
    audience: policy.audience,
  });
  const permit = issuePermit(activation, {
    certificate,
    privateKey: authority.privateKey,
    activationEvidenceHash: c.random(64),
    proofMode: 'HUMAN_WEBAUTHN',
  });
  at = readControl(permit, 'OperationPermit', certificate).issuedAt;
  const binding = {
    schemaVersion: 1,
    profile: EXECUTION_BINDING_PROFILE,
    trustDomainID,
    providerID: 'test-broker',
    epoch: 1,
    status: 'ACTIVE',
    keyID: c.keyID(document.publicKey),
    permitKeyID: c.keyID(authority.publicKey),
    receiptKeyID: c.keyID(authority.publicKey),
    policyHash: sim.policyHash,
    audience: policy.audience,
    enforcement: 'BROKER_ENFORCED',
    issuedAt: at,
    expiresAt: at + 300,
  };
  const signBinding = (value) =>
    issueExecutionBinding(value, { certificate, privateKey: authority.privateKey });
  let calls = 0,
    time = at;
  const backend = {
    id: 'synthetic-provider',
    capabilities: async () => ({ publicKey: document.publicKey, input: 'MESSAGE' }),
    sign: async ({ tbs }) => {
      calls++;
      return c.sign(tbs, document.privateKey);
    },
  };
  const options = {
    journal,
    binding: signBinding(binding),
    bindingCertificate: certificate,
    permitCertificate: certificate,
    receiptCertificate: certificate,
    receiptKey: authority.privateKey,
    backend,
    keyRef: 'document',
    policy,
    trustDomainID,
    authorize: async () => true,
    clock: () => time,
  };
  return {
    journal,
    document,
    authority,
    certificate,
    policy,
    trustDomainID,
    binding,
    signBinding,
    backend,
    options,
    input: { permit, tbs, sim },
    activation,
    at,
    calls: () => calls,
    advance: (seconds) => {
      time += seconds;
    },
  };
}
function nextPermit(f, activation) {
  const previous = readControl(f.input.permit, 'OperationPermit', f.certificate);
  return p.signCMS(
    { content: c.D('OperationPermit', { ...previous, activation }), certificate: f.certificate },
    f.authority.privateKey,
  );
}
function verifyResult(f, result, status = () => true) {
  return verifyExecutionEvidence(
    {
      ...f.input,
      policy: f.policy,
      signature: result.signature,
      publicKey: f.document.publicKey,
      receipt: result.receipt,
      evidence: result.executionEvidence,
    },
    {
      bindingCertificate: f.certificate,
      permitCertificate: f.certificate,
      receiptCertificate: f.certificate,
      trustDomainID: f.trustDomainID,
      at: f.at,
      knowledgeTime: f.at,
      status,
    },
  );
}

test('execution binding validates independent PQ and P-256 results and retries the identical result', async () => {
  for (const algorithm of ['ml-dsa-65', 'ec']) {
    const f = fixture({ algorithm });
    try {
      const gateway = new ExecutionBindingGateway(f.options),
        result = await gateway.execute(f.input);
      assert.equal(verifyResult(f, result).enforcement, 'BROKER_ENFORCED');
      assert.deepEqual(c.dcbor(await gateway.execute(f.input)), c.dcbor(result));
      assert.equal(f.calls(), 1);
      assert.throws(() => verifyResult(f, result, () => false), /EXECUTION_STATUS/);
      const changed = { ...result, signature: Buffer.from(result.signature) };
      changed.signature[0] ^= 1;
      assert.throws(() => verifyResult(f, changed));
      const other = fixture();
      try {
        assert.throws(() =>
          verifyExecutionEvidence(
            {
              ...f.input,
              policy: f.policy,
              publicKey: f.document.publicKey,
              ...result,
              evidence: result.executionEvidence,
            },
            {
              bindingCertificate: other.certificate,
              permitCertificate: f.certificate,
              receiptCertificate: f.certificate,
              trustDomainID: f.trustDomainID,
              at: f.at,
              status: () => true,
            },
          ),
        );
      } finally {
        other.journal.close();
      }
    } finally {
      f.journal.close();
    }
  }
});

test('execution binding denies false/absent policy decisions and Passkey evidence substitution before invoking a key', async () => {
  for (const decision of [false, undefined, { approved: true }]) {
    const f = fixture();
    try {
      const gateway = new ExecutionBindingGateway({
        ...f.options,
        authorize: async () => decision,
      });
      await assert.rejects(gateway.execute(f.input), /EXECUTION_DENIED/);
      assert.equal(f.calls(), 0);
    } finally {
      f.journal.close();
    }
  }
  await assert.rejects(
    runFoundationDemo({
      executionBinding: true,
      documentKeyMode: 'PASSKEY_KEY',
      activationMode: 'HUMAN_WEBAUTHN',
    }),
    /EXECUTION_PASSKEY_COMPOSITION_UNDEFINED/,
  );
});

test('execution binding freezes caller bytes and separates policy callback inputs', async () => {
  const f = fixture();
  try {
    let release, entered;
    const ready = new Promise((resolve) => {
        entered = resolve;
      }),
      gate = new Promise((resolve) => {
        release = resolve;
      });
    const original = Buffer.from(f.input.tbs),
      originalPermit = Buffer.from(f.input.permit);
    const gateway = new ExecutionBindingGateway({
      ...f.options,
      authorize: async (request) => {
        request.permit.activation.tbsHash.fill(0);
        request.sim.subjectID.fill(0);
        entered();
        await gate;
        return true;
      },
    });
    const pending = gateway.execute(f.input);
    await ready;
    f.input.tbs.fill(0);
    f.input.permit.fill(0);
    f.input.sim.origin = 'https://attacker.example';
    release();
    const result = await pending;
    assert(c.verify(original, result.signature, f.document.publicKey));
    assert(!c.verify(f.input.tbs, result.signature, f.document.publicKey));
    assert.equal(f.calls(), 1);
    assert.notDeepEqual(originalPermit, f.input.permit);
  } finally {
    f.journal.close();
  }
});

test('execution binding rechecks expiry after authorization and keeps late outcomes unknown', async () => {
  const f = fixture();
  try {
    const gateway = new ExecutionBindingGateway({
      ...f.options,
      authorize: async () => {
        f.advance(31);
        return true;
      },
    });
    await assert.rejects(gateway.execute(f.input), /EXECUTION_PERMIT/);
    assert.equal(f.calls(), 0);
  } finally {
    f.journal.close();
  }
  const late = fixture();
  try {
    const original = late.backend.sign;
    late.backend.sign = async (args) => {
      const signature = await original(args);
      late.advance(31);
      return signature;
    };
    const gateway = new ExecutionBindingGateway(late.options);
    await assert.rejects(gateway.execute(late.input), /EXECUTION_PERMIT/);
    assert.equal(
      gateway.getOperationResult(late.activation.operationID).status,
      'UNKNOWN_EXECUTION',
    );
    await assert.rejects(gateway.execute(late.input));
    assert.equal(late.calls(), 1);
  } finally {
    late.journal.close();
  }
});

test('execution epochs reject rollback, forks and terminal revocation reversal', async () => {
  const f = fixture();
  try {
    const gateway = new ExecutionBindingGateway(f.options);
    assert.throws(
      () => gateway.installBinding(f.signBinding({ ...f.binding, expiresAt: f.at + 299 })),
      /EXECUTION_EPOCH_FORK/,
    );
    gateway.installBinding(f.signBinding({ ...f.binding, epoch: 2, status: 'SUSPENDED' }));
    await assert.rejects(gateway.execute(f.input), /EXECUTION_BINDING_INACTIVE/);
    assert.throws(() => gateway.installBinding(f.options.binding), /EXECUTION_EPOCH_ROLLBACK/);
    gateway.installBinding(f.signBinding({ ...f.binding, epoch: 3, status: 'REVOKED' }));
    assert.throws(
      () => gateway.installBinding(f.signBinding({ ...f.binding, epoch: 4 })),
      /EXECUTION_REVOCATION_TERMINAL/,
    );
    assert.equal(f.calls(), 0);
  } finally {
    f.journal.close();
  }
});

test('admission rejects substituted providers, keys, authorities and critical fields before dispatch', async () => {
  const f = fixture();
  try {
    for (const changed of [
      { providerID: 'other-broker' },
      { policyHash: c.random(64) },
      { trustDomainID: c.random() },
      { permitKeyID: c.random(64) },
      { receiptKeyID: c.random(64) },
      { audience: 'other-audience' },
      { expiresAt: f.at + 301 },
    ])
      assert.throws(
        () =>
          new ExecutionBindingGateway({
            ...f.options,
            binding: f.signBinding({ ...f.binding, ...changed }),
          }),
      );
    assert.throws(() => f.signBinding({ ...f.binding, unknownCritical: true }));
    assert.throws(
      () =>
        new ExecutionBindingGateway({
          ...f.options,
          policy: {
            ...f.policy,
            executionBinding: { ...f.policy.executionBinding, hardwareEnforced: true },
          },
        }),
    );
    assert.throws(
      () => new ExecutionBindingGateway({ ...f.options, binding: Buffer.alloc(65537) }),
      /BINDING_LIMIT/,
    );
    const wrongKey = new ExecutionBindingGateway({
      ...f.options,
      binding: f.signBinding({ ...f.binding, keyID: c.keyID(c.generate().publicKey) }),
    });
    await assert.rejects(wrongKey.execute(f.input), /EXECUTION_SCOPE/);
    const digestProvider = new ExecutionBindingGateway({
      ...f.options,
      backend: {
        ...f.backend,
        capabilities: async () => ({ publicKey: f.document.publicKey, input: 'DIGEST' }),
      },
    });
    await assert.rejects(digestProvider.execute(f.input), /MESSAGE_PROVIDER_REQUIRED/);
    assert.equal(f.calls(), 0);
  } finally {
    f.journal.close();
  }
});

test('execution receipt cannot backdate dispatch before provider admission', async () => {
  const f = fixture();
  try {
    f.advance(2);
    const binding = f.signBinding({
      ...f.binding,
      issuedAt: f.at + 1,
      expiresAt: f.at + 301,
    });
    const gateway = new ExecutionBindingGateway({ ...f.options, binding });
    const result = await gateway.execute(f.input);
    const atExecution = { ...f, at: f.at + 2 };
    assert.equal(verifyResult(atExecution, result).profile, EXECUTION_BINDING_PROFILE);
    const receipt = readControl(result.receipt, 'ExecutionReceipt', f.certificate);
    assert.throws(
      () =>
        verifyResult(atExecution, {
          ...result,
          receipt: p.signCMS(
            {
              content: c.D('ExecutionReceipt', { ...receipt, dispatchedAt: f.at }),
              certificate: f.certificate,
            },
            f.authority.privateKey,
          ),
        }),
      /EXECUTION_RECEIPT_BINDING/,
    );
  } finally {
    f.journal.close();
  }
});

test('signed malformed times, excessive inputs and forged execution receipts cannot gain acceptance', async () => {
  const f = fixture();
  try {
    const gateway = new ExecutionBindingGateway(f.options);
    const permit = readControl(f.input.permit, 'OperationPermit', f.certificate);
    for (const value of [
      { ...permit, issuedAt: String(f.at) },
      { ...permit, issuedAt: permit.activation.issuedAt - 1 },
      { ...permit, activation: { ...permit.activation, issuedAt: String(f.at) } },
      { ...permit, expiresAt: f.at + 31 },
    ]) {
      const signed = p.signCMS(
        { content: c.D('OperationPermit', value), certificate: f.certificate },
        f.authority.privateKey,
      );
      await assert.rejects(gateway.execute({ ...f.input, permit: signed }));
    }
    await assert.rejects(
      gateway.execute({ ...f.input, tbs: Buffer.alloc(16 * 1024 * 1024 + 1) }),
      /INPUT_LIMIT/,
    );
    await assert.rejects(
      gateway.execute({ ...f.input, permit: Buffer.alloc(1024 * 1024 + 1) }),
      /INPUT_LIMIT/,
    );
    assert.equal(f.calls(), 0);
    const result = await gateway.execute(f.input);
    const receipt = readControl(result.receipt, 'ExecutionReceipt', f.certificate);
    for (const changed of [
      { dispatchedAt: f.at - 1 },
      { executionRequestHash: c.random(64) },
      { executionBindingHash: c.random(64) },
      { provider: 'other-provider' },
      { enforcement: 'HARDWARE_ENFORCED' },
      { unknownCritical: true },
    ])
      assert.throws(() =>
        verifyResult(f, {
          ...result,
          receipt: p.signCMS(
            {
              content: c.D('ExecutionReceipt', { ...receipt, ...changed }),
              certificate: f.certificate,
            },
            f.authority.privateKey,
          ),
        }),
      );
    f.advance(31);
    await assert.rejects(gateway.execute(f.input));
    assert.deepEqual(
      c.dcbor(gateway.getOperationResult(f.activation.operationID).result),
      c.dcbor(result),
    );
    assert.equal(f.calls(), 1);
  } finally {
    f.journal.close();
  }
});

test('competing gateway instances retain a key lock while a provider call is pending', async () => {
  const path = '.runtime/execution-' + c.b64u(c.random()) + '.sqlite',
    f = fixture({ path });
  const secondJournal = new Journal(path);
  let release, pending;
  try {
    let entered;
    const ready = new Promise((resolve) => {
        entered = resolve;
      }),
      gate = new Promise((resolve) => {
        release = resolve;
      });
    const original = f.backend.sign;
    f.backend.sign = async (args) => {
      entered();
      await gate;
      return original(args);
    };
    const first = new ExecutionBindingGateway(f.options),
      second = new ExecutionBindingGateway({ ...f.options, journal: secondJournal });
    pending = first.execute(f.input);
    await ready;
    await assert.rejects(second.execute(f.input), /UNKNOWN_EXECUTION/);
    const nextActivation = { ...f.activation, operationID: c.random() };
    const next = {
      ...f.input,
      permit: nextPermit(f, nextActivation),
    };
    await assert.rejects(second.execute(next), /EXECUTION_KEY_PENDING/);
    assert.equal(secondJournal.result(c.b64u(nextActivation.operationID)), undefined);
    release();
    const result = await pending;
    assert.deepEqual(c.dcbor(await second.execute(f.input)), c.dcbor(result));
    assert.equal(f.calls(), 1);
    await second.execute(next);
    assert.equal(f.calls(), 2);
  } finally {
    release?.();
    if (pending) await pending.catch(() => {});
    secondJournal.close();
    f.journal.close();
    unlinkSync(path);
  }
});

test('lost results survive restart, block concurrent key use and reconcile without another invocation', async () => {
  const path = '.runtime/execution-' + c.b64u(c.random()) + '.sqlite',
    f = fixture({ path });
  let journal = f.journal;
  try {
    let originalSignature;
    const original = f.backend.sign;
    f.backend.sign = async (args) => {
      originalSignature = await original(args);
      throw Error('response lost');
    };
    let gateway = new ExecutionBindingGateway(f.options);
    await assert.rejects(gateway.execute(f.input), /response lost/);
    journal.close();
    journal = new Journal(path);
    gateway = new ExecutionBindingGateway({ ...f.options, journal });
    await assert.rejects(gateway.execute(f.input), /UNKNOWN_EXECUTION/);
    const nextActivation = { ...f.activation, operationID: c.random() };
    await assert.rejects(
      gateway.execute({ ...f.input, permit: nextPermit(f, nextActivation) }),
      /EXECUTION_KEY_PENDING/,
    );
    assert.equal(journal.result(c.b64u(nextActivation.operationID)), undefined);
    const result = await gateway.reconcile({
      operationID: f.activation.operationID,
      signature: originalSignature,
    });
    assert.equal(verifyResult(f, result).epoch, 1);
    assert.equal(f.calls(), 1);
    assert.deepEqual(
      c.dcbor(
        await gateway.reconcile({
          operationID: f.activation.operationID,
          signature: originalSignature,
        }),
      ),
      c.dcbor(result),
    );
  } finally {
    journal.close();
    unlinkSync(path);
  }
});

test('admission changed during provider execution prevents release of an accepted result', async () => {
  const f = fixture();
  try {
    const gateway = new ExecutionBindingGateway(f.options),
      original = f.backend.sign;
    f.backend.sign = async (args) => {
      const signature = await original(args);
      gateway.installBinding(f.signBinding({ ...f.binding, epoch: 2, status: 'REVOKED' }));
      return signature;
    };
    await assert.rejects(gateway.execute(f.input), /EXECUTION_BINDING_CHANGED/);
    assert.equal(gateway.getOperationResult(f.activation.operationID).status, 'UNKNOWN_EXECUTION');
  } finally {
    f.journal.close();
  }
});

test('legacy gateways require explicit authorization and freeze inputs before asynchronous policy work', async () => {
  for (const remote of [false, true]) {
    const f = fixture();
    try {
      const options = {
        ...f.options,
        provider: f.backend,
        audience: f.policy.audience,
        authorize: async () => false,
      };
      let gateway = remote ? new RemoteCryptoKeyService(options) : new SigningGateway(options);
      const data = () => ({
        version: 1,
        keyRef: 'document',
        permit: c.b64u(f.input.permit),
        tbs: c.b64u(f.input.tbs),
        operationID: c.b64u(f.activation.operationID),
      });
      await assert.rejects(
        remote
          ? gateway.handle('sign', data())
          : gateway.execute({ ...f.input, keyRef: 'document' }),
        /AUTHORIZATION_DENIED/,
      );
      assert.equal(f.calls(), 0);
      let release, entered;
      const ready = new Promise((resolve) => {
          entered = resolve;
        }),
        gate = new Promise((resolve) => {
          release = resolve;
        });
      options.authorize = async () => {
        entered();
        await gate;
        return true;
      };
      gateway = remote ? new RemoteCryptoKeyService(options) : new SigningGateway(options);
      const request = data(),
        original = Buffer.from(f.input.tbs);
      const pending = remote
        ? gateway.handle('sign', request)
        : gateway.execute({ ...f.input, keyRef: 'document' });
      await ready;
      request.tbs = c.b64u(Buffer.from('substituted'));
      f.input.tbs.fill(0);
      release();
      const result = await pending,
        signature = remote ? c.unb64u(result.signature) : result.signature;
      assert(c.verify(original, signature, f.document.publicKey));
      assert.equal(f.calls(), 1);
    } finally {
      f.journal.close();
    }
  }
});

test('legacy gateway and remote service recheck permit expiry after asynchronous work', async () => {
  for (const remote of [false, true])
    for (const stage of ['authorization', 'provider']) {
      const f = fixture();
      try {
        if (stage === 'provider') {
          const original = f.backend.sign;
          f.backend.sign = async (args) => {
            const result = await original(args);
            f.advance(31);
            return result;
          };
        }
        const options = {
          ...f.options,
          provider: f.backend,
          audience: f.policy.audience,
          authorize: async () => {
            if (stage === 'authorization') f.advance(31);
            return true;
          },
        };
        const gateway = remote ? new RemoteCryptoKeyService(options) : new SigningGateway(options);
        const call = remote
          ? gateway.handle('sign', {
              version: 1,
              keyRef: 'document',
              permit: c.b64u(f.input.permit),
              tbs: c.b64u(f.input.tbs),
              operationID: c.b64u(f.activation.operationID),
            })
          : gateway.execute({ ...f.input, keyRef: 'document' });
        await assert.rejects(call, /PERMIT/);
        assert.equal(f.calls(), stage === 'authorization' ? 0 : 1);
        assert.equal(
          f.journal.result(c.b64u(f.activation.operationID))?.status,
          stage === 'authorization' ? undefined : 'UNKNOWN_EXECUTION',
        );
      } finally {
        f.journal.close();
      }
    }
});

function downgraded(bundle, profile) {
  const objects = bundle.objects.filter(
    (o) => !['ExecutionBindingEvidence', 'VerificationPlan'].includes(o.type),
  );
  const plan = evidenceObject(
    'VerificationPlan',
    c.dcbor({
      schemaVersion: 1,
      profile,
      objects: Object.fromEntries(objects.map((o) => [o.type, o.id])),
    }),
    objects.map((o) => o.id),
  );
  return { schemaVersion: 1, root: plan.id, objects: [...objects, plan] };
}
test('execution evidence closes CMS/MTC and both mdoc key modes with mandatory anti-downgrade plans', async () => {
  for (const mode of ['CMS', 'INDEPENDENT_PQ', 'DEVICE_KEY']) {
    const r =
      mode === 'CMS'
        ? await runDemo({ executionBinding: true, activationMode: 'HUMAN_WEBAUTHN' })
        : await runFoundationDemo({
            executionBinding: true,
            documentKeyMode: mode,
            activationMode: 'HUMAN_WEBAUTHN',
            identityType: 'photoid',
          });
    const format = mode === 'CMS' ? 'CMS' : 'MDOC',
      verify = format === 'CMS' ? verifySignaturePackage : verifyMdocSignaturePackage;
    assert.equal(r.verification.execution.profile, EXECUTION_BINDING_PROFILE);
    assert.equal(
      createVerifier({ format, trust: r.trust }).verify(c.dcbor(r.bundle)).overall,
      'VALID',
    );
    assert.throws(
      () =>
        createVerifier({ format, trust: { ...r.trust, executionBindingCertificate: undefined } }),
      /SDK_EXECUTION_TRUST_REQUIRED/,
    );
    assert.throws(
      () => createVerifier({ format, trust: { ...r.trust, executionStatus: undefined } }),
      /SDK_EXECUTION_TRUST_REQUIRED/,
    );
    assert.throws(
      () => verify(r.bundle, { ...r.trust, executionStatus: () => false }),
      /EXECUTION_STATUS/,
    );
    assert.throws(
      () =>
        verify(
          downgraded(
            r.bundle,
            format === 'CMS' ? 'certconcord-ecp-cms-attested-v1' : 'certconcord-ecp-mdoc-attested-v1',
          ),
          r.trust,
        ),
      /EXECUTION_DOWNGRADE/,
    );
  }
});
