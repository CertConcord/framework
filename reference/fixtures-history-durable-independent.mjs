import assert from 'node:assert/strict';
import * as c from './core.mjs';
import { readControl } from './state.mjs';
import { createEvidencePackage, evidenceLeaf } from './evidence-plan.mjs';
import { OrganizationDelegationApplication } from './organization-delegation.mjs';
import {
  createOrganizationFixture,
  copy,
  signOrganizationControl,
} from './organization-delegation-fixtures.mjs';
import { createIndependentOrganizationHistoryFixture } from './fixtures-history-independent.mjs';

export function assertPublicHistoryData(value) {
  if (
    Buffer.isBuffer(value) ||
    value === null ||
    ['string', 'number', 'boolean'].includes(typeof value)
  )
    return;
  assert(value && typeof value === 'object');
  assert.equal(
    Object.getPrototypeOf(value),
    Array.isArray(value) ? Array.prototype : Object.prototype,
  );
  for (const [key, child] of Object.entries(value)) {
    assert(!/private|callback|resolver|expected/i.test(key), `Non-public field: ${key}`);
    assertPublicHistoryData(child);
  }
}

/** Parent-only authoring. The returned material contains public bytes and facts only. */
export async function createIndependentDurableHistoryMaterials() {
  const f = await createIndependentOrganizationHistoryFixture();
  let secondSource;
  try {
    const rawHistory = (history) =>
      history.map(({ manifest, signatures, publicationProof }) => ({
        manifest: c.dcbor(manifest),
        signatures: copy(signatures),
        publicationProof: Buffer.from(publicationProof),
      }));
    const body = (member) =>
      readControl(member.cms, 'OrganizationDelegationStatus', member.issuerCertificate);
    const original = f.originalStatusMembers;
    const finalIndex = original.findIndex(
      (member) => body(member).objectType === 'FINAL_AUTHORIZATION',
    );
    assert(finalIndex >= 0);
    const firstTarget = body(original[finalIndex]);
    const knowledge = (members, certificate = [f.certificateStatus()], K = f.K) => ({
      knowledgeTime: K,
      authorityHistory: rawHistory(f.history),
      statusMaterial: copy(members),
      certificateStatusMaterial: copy(certificate),
    });
    const good = (members, epoch = 5) =>
      members.map((member) => f.organizationStatus(member, { epoch }));
    const initial = knowledge(good(original, 2));
    const newerGood = knowledge(
      good(original),
      [f.certificateStatus({ publishedAt: f.K })],
      f.K + 1,
    );
    const replace = (member) =>
      original.map((row, index) =>
        index === finalIndex ? member : f.organizationStatus(row, { epoch: 2 }),
      );
    const compromised = f.organizationStatus(original[finalIndex], {
      epoch: 3,
      status: 'REVOKED',
      effectiveTime: f.K - 1,
      compromiseStart: f.A,
    });
    const ordinary = f.organizationStatus(original[finalIndex], {
      epoch: 2,
      status: 'REVOKED',
      effectiveTime: f.K - 1,
    });
    const conflict = knowledge([
      ...replace(ordinary),
      f.organizationStatus(original[finalIndex], { epoch: 2 }),
    ]);
    assert(body(ordinary).effectiveTime > f.P);
    assert(!Object.hasOwn(body(ordinary), 'compromiseStart'));
    const certificateCompromise = f.certificateStatus({
      status: 'REVOKED',
      effectiveTime: f.K - 1,
      compromiseStart: f.A,
    });

    // A snapshot is consumed only in this parent authoring function; it is never
    // returned, logged or persisted because it includes ephemeral fixture keys.
    const snapshot = c.decodeCBOR(f.source.snapshot());
    snapshot.operationID = c.random();
    snapshot.sim.organizationAuthorizationID = c.random();
    snapshot.sim.transactionID = c.random();
    snapshot.sim.nonce = c.random();
    delete snapshot.wire.activation;
    secondSource = createOrganizationFixture({ snapshot: c.dcbor(snapshot) });
    const app = new OrganizationDelegationApplication(secondSource.applicationOptions);
    const prepared = app.prepare(secondSource.prepareInput());
    assert.equal(prepared.overall, 'VALID', JSON.stringify(prepared));
    for (let i = 0; i < secondSource.persons.length; i++) {
      const approved = app.approve({
        operationID: secondSource.operationID,
        personID: secondSource.persons[i].body.personID,
        ...secondSource.assertion(prepared.request, i, { counter: 1 }),
      });
      assert.equal(approved.overall, 'VALID', JSON.stringify(approved));
    }
    assert.equal(app.authorize({ operationID: secondSource.operationID }).overall, 'VALID');
    const executed = await app.execute({ operationID: secondSource.operationID });
    assert.equal(executed.overall, 'VALID', JSON.stringify(executed));
    assert.equal(secondSource.calls.sign, 1);
    const secondBytes = Buffer.from(executed.bundle),
      secondBundle = c.decodeCBOR(secondBytes);
    const statusLeaf = secondBundle.objects.find(
      (leaf) => leaf.type === 'OrganizationDelegationStatus',
    );
    const secondMembers = c.decodeCBOR(statusLeaf.payload).statements;
    const secondTarget = body(
      secondMembers.find((member) => body(member).objectType === 'FINAL_AUTHORIZATION'),
    );
    assert(!c.equal(firstTarget.objectID, secondTarget.objectID));
    assert(!c.equal(firstTarget.objectHash, secondTarget.objectHash));
    assert(c.equal(firstTarget.subjectKeyID, secondTarget.subjectKeyID));
    assert(secondMembers.every((member) => !c.equal(body(member).objectID, firstTarget.objectID)));
    const second = { originalBytes: secondBytes, evidenceRecord: await f.preserve(secondBytes) };
    const secondGood = knowledge(
      good(secondMembers),
      [f.certificateStatus({ publishedAt: f.K })],
      f.K + 1,
    );
    const missingSIMBytes = c.dcbor(
      createEvidencePackage(
        f.bundle.plan.profile,
        f.bundle.objects
          .filter((leaf) => leaf.type !== 'SIM')
          .map((leaf) => evidenceLeaf(leaf.type, leaf.payload)),
      ),
    );
    const missingSIM = {
      originalBytes: missingSIMBytes,
      evidenceRecord: await f.preserve(missingSIMBytes),
    };
    const approvals = c.decodeCBOR(f.leaves.OrganizationApprovalSet),
      approval = approvals.approvals[0];
    approval.assertion.signature[0] ^= 1;
    const registration = readControl(
      approval.registrationCMS,
      'OrganizationApproverRegistration',
      approval.registrationIssuerCertificate,
    );
    assert.equal(
      c.verify(
        Buffer.concat([
          approval.assertion.authenticatorData,
          c.sha256(approval.assertion.clientDataJSON),
        ]),
        approval.assertion.signature,
        c.publicFromDER(registration.publicKeyDER),
      ),
      false,
    );
    const invalidApprovalBytes = f.replaceLeaf('OrganizationApprovalSet', c.dcbor(approvals));
    const invalidApproval = {
      originalBytes: invalidApprovalBytes,
      evidenceRecord: await f.preserve(invalidApprovalBytes),
    };
    const corrupt = copy(compromised);
    corrupt.cms[corrupt.cms.length - 1] ^= 1;
    const wrongTarget = f.organizationStatus(original[finalIndex], {
      epoch: 3,
      status: 'REVOKED',
      effectiveTime: f.K - 1,
      compromiseStart: f.A,
      objectHash: c.random(64),
    });
    const wrongDomain = f.organizationStatus(original[finalIndex], {
      epoch: 3,
      status: 'REVOKED',
      effectiveTime: f.K - 1,
      compromiseStart: f.A,
      trustDomainID: c.random(),
    });
    const unbound = f.organizationStatus(original[finalIndex], {
      epoch: 3,
      status: 'REVOKED',
      effectiveTime: f.K - 1,
      compromiseStart: f.A,
      objectID: c.random(),
    });
    const unauthorizedScope = f.organizationStatus(
      original[finalIndex],
      {
        epoch: 3,
        status: 'REVOKED',
        effectiveTime: f.K - 1,
        compromiseStart: f.A,
      },
      f.certificateStatusSuccessor,
    );
    const future = f.organizationStatus(original[finalIndex], {
      epoch: 3,
      status: 'REVOKED',
      effectiveTime: f.K + 10,
      compromiseStart: f.A,
      publishedAt: f.K + 10,
      nextUpdate: f.K + 299,
    });
    const malformedTargets = {};
    for (const kind of [
      'grant-future',
      'grant-empty-interval',
      'grant-parent',
      'grant-attenuation',
      'grant-unauthorized',
      'registration-future',
    ]) {
      const registration = kind.startsWith('registration'),
        changed = copy(f.bundle);
      const leaf = changed.objects.find(
        (row) =>
          row.type === (registration ? 'OrganizationApprovalSet' : 'OrganizationDelegationPath'),
      );
      const collection = c.decodeCBOR(leaf.payload);
      const selected = registration ? collection.approvals[0] : collection.grants.at(-1);
      const target = registration
        ? {
            cms: selected.registrationCMS,
            issuerCertificate: selected.registrationIssuerCertificate,
          }
        : selected;
      const label = registration
        ? 'OrganizationApproverRegistration'
        : 'OrganizationDelegationGrant';
      const signed = readControl(target.cms, label, target.issuerCertificate);
      const key = registration ? 'registrationID' : 'grantID';
      signed[key] = c.random();
      if (kind.endsWith('future')) signed.validFrom = f.P + 1;
      if (kind.endsWith('empty-interval')) signed.validUntil = signed.validFrom;
      if (kind.endsWith('parent')) signed.parentGrantHash = c.random(64);
      if (kind.endsWith('attenuation')) signed.remainingDelegations++;
      let signer = registration ? f.source.keys.registrar : f.source.keys.delegate0;
      if (kind.endsWith('unauthorized')) {
        signer = f.statusSuccessor;
        signed.issuerKeyID = c.keyID(signer.publicKey);
      }
      const changedTarget = {
        cms: signOrganizationControl(label, signed, signer),
        issuerCertificate: signer.certificate,
      };
      assert.deepEqual(
        readControl(changedTarget.cms, label, changedTarget.issuerCertificate),
        signed,
      );
      if (registration) {
        selected.registrationCMS = changedTarget.cms;
        selected.registrationIssuerCertificate = changedTarget.issuerCertificate;
      } else Object.assign(selected, changedTarget);
      leaf.payload = c.dcbor(collection);
      const bytes = c.dcbor(
        createEvidencePackage(
          changed.plan.profile,
          changed.objects.map((row) => evidenceLeaf(row.type, row.payload)),
        ),
      );
      const objectType = registration ? 'APPROVER_REGISTRATION' : 'GRANT';
      const originalTarget = original.find(
        (member) =>
          body(member).objectType === objectType &&
          c.equal(
            body(member).subjectKeyID,
            registration ? signed.keyID : signed.delegateAuthority.keyID,
          ),
      );
      assert(originalTarget);
      const adverse = f.organizationStatus(originalTarget, {
        objectID: signed[key],
        objectHash: c.sha512(changedTarget.cms),
        epoch: 3,
        status: 'REVOKED',
        effectiveTime: f.K - 1,
        compromiseStart: f.A,
      });
      const adverseBody = body(adverse);
      assert(c.equal(adverseBody.objectHash, c.sha512(changedTarget.cms)));
      assert(
        secondMembers.every((member) => !c.equal(body(member).objectID, adverseBody.objectID)),
      );
      malformedTargets[kind] = {
        input: { originalBytes: bytes, evidenceRecord: await f.preserve(bytes) },
        knowledge: knowledge([...good(original, 2), adverse]),
        target: copy(signed),
        adverse: copy(adverseBody),
      };
      if (kind === 'grant-future') {
        const originalAdverse = f.organizationStatus(
          originalTarget,
          {
            objectID: signed[key],
            objectHash: c.sha512(changedTarget.cms),
            epoch: 1,
            status: 'REVOKED',
            effectiveTime: f.A - 1,
            compromiseStart: f.A - 10,
            publishedAt: f.A - 1,
            nextUpdate: f.A + 299,
          },
          f.source.keys.status,
        );
        const withOriginalStatus = copy(changed);
        withOriginalStatus.objects.find(
          (row) => row.type === 'OrganizationDelegationStatus',
        ).payload = f.source.statusBytes([...original, originalAdverse]);
        const originalNegativeBytes = c.dcbor(
          createEvidencePackage(
            withOriginalStatus.plan.profile,
            withOriginalStatus.objects.map((row) => evidenceLeaf(row.type, row.payload)),
          ),
        );
        malformedTargets['grant-future-original-negative'] = {
          input: {
            originalBytes: originalNegativeBytes,
            evidenceRecord: await f.preserve(originalNegativeBytes),
          },
          knowledge: knowledge([]),
          target: copy(signed),
          adverse: copy(body(originalAdverse)),
        };
      }
    }
    const result = {
      configuration: copy(f.publicSourceConfiguration),
      first: copy(f.input),
      second,
      missingSIM,
      invalidApproval,
      initial,
      newerGood,
      secondGood,
      concurrentConflict: { good: initial, revoked: knowledge(replace(ordinary)) },
      incidents: {
        organization: knowledge(replace(compromised)),
        conflict,
        certificate: knowledge(good(original, 2), [certificateCompromise]),
      },
      rejected: {
        signature: knowledge(replace(corrupt)),
        target: knowledge(replace(wrongTarget)),
        domain: knowledge(replace(wrongDomain)),
        unbound: knowledge(replace(unbound)),
        scope: knowledge(replace(unauthorizedScope)),
        future: knowledge(replace(future)),
      },
      malformedTargets,
      facts: {
        A: f.A,
        P: f.P,
        K: f.K,
        firstTarget,
        secondTarget,
        secondTargetIDs: secondMembers.map((member) => body(member).objectID),
        firstSigningCalls: f.source.calls.sign,
        secondSigningCalls: secondSource.calls.sign,
      },
    };
    const publicData = copy(result);
    assertPublicHistoryData(publicData);
    return publicData;
  } finally {
    secondSource?.close();
    f.close();
  }
}

/** Genuine signed history reaches the aggregate RTM quota through public calls. */
export async function createIndependentDurableCapacityMaterials() {
  const f = await createIndependentOrganizationHistoryFixture();
  try {
    const rawHistory = (history) =>
      history.map(({ manifest, signatures, publicationProof }) => ({
        manifest: c.dcbor(manifest),
        signatures: copy(signatures),
        publicationProof: Buffer.from(publicationProof),
      }));
    const history = [...f.history];
    while (history.length < 256)
      history.push(f.manifest([], f.K - 1, history.at(-1), { signers: [f.successorRoot] }));
    const extra = f.manifest([], f.K - 1, history.at(-1), { signers: [f.successorRoot] });
    assert.equal(history.length, 256);
    assert.equal(extra.manifest.serial, 256);
    const terminal = f.originalStatusMembers.find(
      (member) =>
        readControl(member.cms, 'OrganizationDelegationStatus', member.issuerCertificate)
          .objectType === 'FINAL_AUTHORIZATION',
    );
    const adverse = f.organizationStatus(terminal, {
      epoch: 3,
      status: 'REVOKED',
      effectiveTime: f.K - 1,
      compromiseStart: f.A,
    });
    const firstKnowledge = {
      ...copy(f.knowledge),
      authorityHistory: rawHistory(f.history),
      statusMaterial: [...copy(f.knowledge.statusMaterial), adverse],
    };
    const result = {
      configuration: copy(f.publicSourceConfiguration),
      first: copy(f.input),
      firstKnowledge,
      initial: { ...copy(f.knowledge), authorityHistory: rawHistory(f.history) },
      afterLimit: {
        knowledgeTime: f.K + 1,
        authorityHistory: [],
        statusMaterial: f.originalStatusMembers.map((member) =>
          f.organizationStatus(member, { epoch: 5 }),
        ),
        certificateStatusMaterial: [f.certificateStatus({ publishedAt: f.K })],
      },
      atLimit: {
        knowledgeTime: f.K,
        authorityHistory: rawHistory(history),
        statusMaterial: [],
        certificateStatusMaterial: [],
      },
      beyondLimit: {
        knowledgeTime: f.K,
        authorityHistory: rawHistory([extra]),
        statusMaterial: [],
        certificateStatusMaterial: [],
      },
      unverifiableInput: { originalBytes: Buffer.from([0]), evidenceRecord: Buffer.from([0]) },
    };
    assertPublicHistoryData(result);
    return result;
  } finally {
    f.close();
  }
}
