import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import {
  epoch,
  padesFixture,
  independentApproval,
  independentTimestamp,
  independentDSS,
  loadPAdES,
  absentCapability,
  decision,
  expectOverall,
} from './pades-fixtures.mjs';

const api = await loadPAdES(),
  selected = { skip: !api && absentCapability };
let old, successor, policy;
before(() => {
  if (!api) return;
  old = padesFixture();
  const root = old.certificate('PAdES independent successor root');
  const tsa = old.certificate('PAdES independent successor TSA', { issuer: root, tsa: true });
  const crl = old.crl({ issuer: root });
  successor = {
    root,
    successor: tsa,
    material: () => ({ certificates: [root.der, tsa.der], crls: [crl] }),
    token: (request, options) => old.token(request, { authority: tsa, ...options }),
  };
  const oldResolver = old.authorities(),
    newResolver = createAuthorityResolver({
      trustDomainID: old.domain,
      authorities: [root, tsa].map((entry) => ({
        mode: 'CERTIFICATE',
        certificate: entry.der,
        knownAt: epoch - 100,
        validFrom: epoch - 100,
        validUntil: epoch + 100000,
        roles: entry === root ? ['ISSUER', 'STATUS_AUTHORITY'] : ['TIMESTAMP_AUTHORITY'],
        scopes: [old.scope],
        status: {
          authorityID: c.keyID(entry.publicKey),
          trustDomainID: old.domain,
          scope: 'AUTHORITY',
          status: 'GOOD',
          publishedAt: epoch - 100,
          nextUpdate: epoch + 100000,
        },
      })),
    });
  const newerKeys = [root, tsa].map((entry) => c.keyID(entry.publicKey));
  policy = old.policy({
    trustedRoots: [old.root.der, successor.root.der],
    authorityResolver: (query) =>
      newerKeys.some((key) => key.equals(query.authorityID))
        ? newResolver(query)
        : oldResolver(query),
    keyDeadlines: {
      ...old.policy().keyDeadlines,
      ...Object.fromEntries(newerKeys.map((key) => [key.toString('hex'), epoch + 100000])),
      [c.keyID(old.root.publicKey).toString('hex')]: epoch + 50,
    },
    currentMaterial: successor.material(),
  });
});
after(() => {
  old?.close();
});

function preserved({ intermediateTimestamp = false, materialAt = 40, withOldCRL = true } = {}) {
  const b = independentApproval(old).pdf;
  let pdf = independentTimestamp(old, b, { at: epoch + 20 }).pdf;
  if (intermediateTimestamp)
    pdf = independentTimestamp(successor, pdf, {
      at: epoch + 30,
      tokenOptions: { authority: successor.successor },
    }).pdf;
  pdf = independentDSS(pdf, {
    certificates: [...old.material().certificates, ...successor.material().certificates],
    crls: [...(withOldCRL ? old.material().crls : []), ...successor.material().crls],
  });
  return independentTimestamp(successor, pdf, {
    at: epoch + materialAt,
    tokenOptions: { authority: successor.successor },
  }).pdf;
}

for (const intermediateTimestamp of [false, true])
  test(
    `later authenticated material POE is independent from initial signer POE (${intermediateTimestamp ? 'earliest successor lacks CRL' : 'DSS follows first timestamp'})`,
    selected,
    async () => {
      const pdf = preserved({ intermediateTimestamp });
      const result = await decision(api, old, pdf, 'LTA', {
        policy,
        validationTime: epoch + 25,
        knowledgeTime: epoch + 200,
      });
      expectOverall(result, 'VALID');
      assert.equal(
        result.stateTime,
        epoch + 20,
        'later material evidence does not rewrite original signer existence time',
      );
      assert.equal(result.preservationTime, epoch + 40);
    },
  );

test(
  'later material without a covering authenticated timestamp remains incomplete',
  selected,
  async () => {
    const b = independentApproval(old).pdf,
      t = independentTimestamp(old, b, { at: epoch + 20 }).pdf;
    const after = independentDSS(t, {
      certificates: [...old.material().certificates, ...successor.material().certificates],
      crls: [...old.material().crls, ...successor.material().crls],
    });
    expectOverall(
      await decision(api, old, after, 'LT', {
        policy,
        validationTime: epoch + 25,
        knowledgeTime: epoch + 200,
      }),
      'INDETERMINATE',
    );
  },
);

test(
  'later material POE cannot authenticate old-root CRL after its protection cutoff',
  selected,
  async () => {
    const pdf = preserved({ materialAt: 60 });
    expectOverall(
      await decision(api, old, pdf, 'LTA', {
        policy,
        validationTime: epoch + 25,
        knowledgeTime: epoch + 200,
      }),
      'INDETERMINATE',
    );
  },
);

test(
  'a successor timestamp cannot invent historical validation material absent from its bytes',
  selected,
  async () => {
    const pdf = preserved({ withOldCRL: false });
    expectOverall(
      await decision(api, old, pdf, 'LTA', {
        policy,
        validationTime: epoch + 25,
        knowledgeTime: epoch + 200,
      }),
      'INDETERMINATE',
    );
  },
);
