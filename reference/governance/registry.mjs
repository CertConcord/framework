import { createHash } from 'node:crypto';
import { parseJSON } from '../json.mjs';
import { validateResult } from '../interop/import-result.mjs';

const hash = /^[a-f0-9]{64}$/;
const commitHash = /^[a-f0-9]{40}$/;
const fail = (ok, code) => {
  if (!ok) throw Error(code);
};
const text = (s) => typeof s === 'string' && s.length > 0 && s.length <= 4096;
const time = (s) =>
  typeof s === 'string' &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s) &&
  new Date(s).toISOString() === s;
const unique = (a) => Array.isArray(a) && a.length <= 10000 && new Set(a).size === a.length;
const strings = (a) => unique(a) && a.length > 0 && a.every(text);
const email = (s) => typeof s === 'string' && /^[^\s<>@]+@[^\s<>@]+$/.test(s);
const keys = (o, names) =>
  fail(
    o &&
      typeof o === 'object' &&
      !Array.isArray(o) &&
      Object.keys(o).sort().join('|') === [...names].sort().join('|'),
    'REGISTRY_FIELDS',
  );
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object')
    return (
      '{' +
      Object.keys(value)
        .sort()
        .map((k) => JSON.stringify(k) + ':' + canonical(value[k]))
        .join(',') +
      '}'
    );
  fail(
    value === null ||
      ['string', 'boolean'].includes(typeof value) ||
      (typeof value === 'number' && Number.isSafeInteger(value)),
    'CANONICAL_VALUE',
  );
  return JSON.stringify(value);
}
export const digest = (value) => createHash('sha256').update(canonical(value)).digest('hex');
export const byteDigest = (bytes) => createHash('sha256').update(bytes).digest('hex');
function reference(o) {
  keys(o, ['uri', 'sha256']);
  fail(text(o.uri) && /^https:\/\//.test(o.uri) && hash.test(o.sha256), 'REGISTRY_REFERENCE');
  const u = new URL(o.uri);
  fail(!u.username && !u.password, 'REGISTRY_REFERENCE');
}
function review(o) {
  keys(o, ['reviewer', 'reviewedAt', 'receipt']);
  fail(text(o.reviewer) && time(o.reviewedAt), 'REGISTRY_REVIEW');
  reference(o.receipt);
}
function scope(o) {
  keys(o, ['name', 'edition', 'sha256']);
  fail(text(o.name) && text(o.edition) && hash.test(o.sha256), 'REGISTRY_SCOPE');
}
function events(a) {
  fail(Array.isArray(a) && a.length > 0 && a.length <= 1000, 'REGISTRY_EVENTS');
  let previous = -Infinity,
    ended = false;
  for (const e of a) {
    keys(e, ['at', 'state', 'reason', 'receipt']);
    fail(
      time(e.at) &&
        Date.parse(e.at) > previous &&
        !ended &&
        ['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(e.state) &&
        text(e.reason),
      'REGISTRY_EVENT',
    );
    reference(e.receipt);
    previous = Date.parse(e.at);
    ended = e.state === 'REVOKED';
  }
}
function rows(a) {
  fail(
    Array.isArray(a) && a.length <= 10000 && new Set(a.map((r) => r.id)).size === a.length,
    'REGISTRY_ROWS',
  );
  for (const r of a)
    fail(typeof r.id === 'string' && /^[a-z0-9][a-z0-9._-]{0,127}$/.test(r.id), 'REGISTRY_ID');
}

export function validateRegistry(r) {
  keys(r, [
    'schemaVersion',
    'framework',
    'holders',
    'agreements',
    'contributions',
    'marks',
    'plans',
    'grants',
  ]);
  fail(r.schemaVersion === 1 && r.framework === 'CertConcord', 'REGISTRY_VERSION');
  for (const k of ['holders', 'agreements', 'contributions', 'marks', 'plans', 'grants'])
    rows(r[k]);
  for (const h of r.holders) {
    keys(h, ['id', 'legalName', 'authority', 'review']);
    fail(text(h.legalName), 'REGISTRY_HOLDER');
    reference(h.authority);
    review(h.review);
  }
  for (const a of r.agreements) {
    keys(a, [
      'id',
      'kind',
      'holderId',
      'specification',
      'instrument',
      'signedAt',
      'contributorEmails',
      'review',
    ]);
    fail(
      ['OWFA_PATENT_ONLY_1_0', 'OWF_CLA_1_0'].includes(a.kind) &&
        r.holders.some((h) => h.id === a.holderId) &&
        time(a.signedAt),
      'REGISTRY_AGREEMENT',
    );
    scope(a.specification);
    reference(a.instrument);
    review(a.review);
    fail(
      unique(a.contributorEmails) &&
        a.contributorEmails.every(email) &&
        (a.kind !== 'OWF_CLA_1_0' || a.contributorEmails.length > 0) &&
        Date.parse(a.signedAt) <= Date.parse(a.review.reviewedAt),
      'REGISTRY_AGREEMENT_AUTHORITY',
    );
  }
  for (const c of r.contributions) {
    keys(c, [
      'id',
      'agreementId',
      'digest',
      'receivedAt',
      'withdrawnAt',
      'withdrawalNotice',
      'review',
    ]);
    const a = r.agreements.find((a) => a.id === c.agreementId);
    fail(
      a?.kind === 'OWF_CLA_1_0' &&
        hash.test(c.digest) &&
        time(c.receivedAt) &&
        Date.parse(c.receivedAt) >= Date.parse(a.signedAt),
      'REGISTRY_CONTRIBUTION',
    );
    fail(
      c.withdrawnAt === null ||
        (time(c.withdrawnAt) && Date.parse(c.withdrawnAt) >= Date.parse(c.receivedAt)),
      'REGISTRY_WITHDRAWAL',
    );
    if (c.withdrawnAt === null) fail(c.withdrawalNotice === null, 'REGISTRY_WITHDRAWAL');
    else reference(c.withdrawalNotice);
    review(c.review);
    fail(Date.parse(c.review.reviewedAt) >= Date.parse(c.receivedAt), 'REGISTRY_CONTRIBUTION_TIME');
  }
  for (const m of r.marks) {
    keys(m, ['id', 'text', 'holderId', 'policySHA256', 'instrument', 'events', 'review']);
    fail(
      text(m.text) && r.holders.some((h) => h.id === m.holderId) && hash.test(m.policySHA256),
      'REGISTRY_MARK',
    );
    reference(m.instrument);
    events(m.events);
    review(m.review);
  }
  for (const p of r.plans) {
    keys(p, [
      'id',
      'markId',
      'specification',
      'role',
      'profile',
      'suite',
      'assessors',
      'category',
      'requirements',
      'review',
    ]);
    fail(
      r.marks.some((m) => m.id === p.markId) &&
        ['ISSUER', 'WALLET', 'VERIFIER', 'CORE', 'PROVIDER'].includes(p.role) &&
        text(p.profile) &&
        strings(p.assessors) &&
        ['LOCAL_ADAPTER', 'EXTERNAL_EXECUTION', 'INDEPENDENT_REVIEW', 'CERTIFICATION'].includes(
          p.category,
        ),
      'REGISTRY_PLAN',
    );
    scope(p.specification);
    keys(p.suite, ['name', 'revision']);
    fail(text(p.suite.name) && text(p.suite.revision), 'REGISTRY_SUITE');
    rows(p.requirements);
    fail(p.requirements.length > 0, 'REGISTRY_REQUIREMENTS');
    for (const req of p.requirements) {
      keys(req, ['id', 'tests']);
      fail(strings(req.tests), 'REGISTRY_REQUIREMENTS');
    }
    review(p.review);
  }
  for (const g of r.grants) {
    keys(g, [
      'id',
      'planId',
      'granteeId',
      'implementation',
      'sourceCommit',
      'manifestSHA256',
      'configurationSHA256',
      'reportSHA256',
      'validFrom',
      'validUntil',
      'instrument',
      'events',
      'review',
    ]);
    fail(
      r.plans.some((p) => p.id === g.planId) &&
        r.holders.some((h) => h.id === g.granteeId) &&
        commitHash.test(g.sourceCommit),
      'REGISTRY_GRANT',
    );
    keys(g.implementation, ['name', 'version', 'environment']);
    fail(Object.values(g.implementation).every(text), 'REGISTRY_IMPLEMENTATION');
    for (const k of ['manifestSHA256', 'configurationSHA256', 'reportSHA256'])
      fail(hash.test(g[k]), 'REGISTRY_GRANT_DIGEST');
    fail(
      time(g.validFrom) && time(g.validUntil) && Date.parse(g.validUntil) > Date.parse(g.validFrom),
      'REGISTRY_GRANT_TIME',
    );
    reference(g.instrument);
    events(g.events);
    review(g.review);
    fail(Date.parse(g.review.reviewedAt) <= Date.parse(g.validFrom), 'REGISTRY_GRANT_REVIEW');
  }
  return { structure: 'VALID', agreements: r.agreements.length, markGrants: r.grants.length };
}

export function openRegister(bytes, trustedSHA256) {
  fail(
    Buffer.byteLength(bytes) <= 4 * 1024 * 1024 &&
      hash.test(trustedSHA256) &&
      byteDigest(bytes) === trustedSHA256,
    'UNTRUSTED_REGISTRY',
  );
  const r = parseJSON(Buffer.from(bytes).toString('utf8'), { maxBytes: 4 * 1024 * 1024 });
  validateRegistry(r);
  const freeze = (v) => {
    if (v && typeof v === 'object') {
      Object.values(v).forEach(freeze);
      Object.freeze(v);
    }
    return v;
  };
  return freeze(r);
}

export function normativePath(path) {
  return (
    path.startsWith('spec/') ||
    ['reference/schemas.cddl', 'reference/adapter-lock.json', 'draft.json'].includes(path)
  );
}
export function contributionDigest(files, additionalNormativePaths = []) {
  fail(
    Array.isArray(files) &&
      files.length <= 3000 &&
      unique(files.map((f) => f.path)) &&
      unique(additionalNormativePaths),
    'CONTRIBUTION_FILES',
  );
  for (const f of files) {
    keys(f, ['path', 'sha', 'status', 'previousPath']);
    fail(
      text(f.path) &&
        !f.path.startsWith('/') &&
        !f.path.includes('\\') &&
        !f.path.split('/').some((s) => ['.', '..', ''].includes(s)) &&
        commitHash.test(f.sha) &&
        ['added', 'modified', 'removed', 'renamed'].includes(f.status) &&
        (f.previousPath === null || text(f.previousPath)),
      'CONTRIBUTION_FILE',
    );
  }
  fail(
    additionalNormativePaths.every((p) => files.some((f) => f.path === p)),
    'CONTRIBUTION_DECLARATION',
  );
  const selected = files
    .filter(
      (f) =>
        normativePath(f.path) ||
        (f.previousPath && normativePath(f.previousPath)) ||
        additionalNormativePaths.includes(f.path),
    )
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return selected.length ? digest(selected) : null;
}
export function checkContribution(r, submission, { now = Date.now(), final = false } = {}) {
  validateRegistry(r);
  keys(submission, ['files', 'commits', 'additionalNormativePaths']);
  fail(Number.isSafeInteger(now) && typeof final === 'boolean', 'CONTRIBUTION_TIME');
  const d = contributionDigest(submission.files, submission.additionalNormativePaths);
  fail(
    Array.isArray(submission.commits) &&
      submission.commits.length > 0 &&
      submission.commits.length <= 250,
    'CONTRIBUTION_COMMITS',
  );
  const softwarePath = (path) =>
    /\.(?:mjs|js|ts|tsx|go|rs|c|cpp|h|java|kt|kts|swift|cs|py|sh|ps1|bat|cddl|sql)$/i.test(path) ||
    (!/\.md$/i.test(path) &&
      !/^(?:LICENSES\/|LICENSE$|NOTICE$|datasets\/|test-vectors\/|governance\/DCO-1.1\.txt$)/.test(
        path,
      ));
  const software = submission.files.some(
    (f) => softwarePath(f.path) || (f.previousPath && softwarePath(f.previousPath)),
  );
  const authors = new Set();
  for (const c of submission.commits) {
    keys(c, ['sha', 'name', 'email', 'message']);
    fail(
      commitHash.test(c.sha) &&
        text(c.name) &&
        email(c.email) &&
        typeof c.message === 'string' &&
        c.message.length <= 200000,
      'CONTRIBUTION_AUTHOR',
    );
    const identities = [
      `${c.name} <${c.email}>`,
      ...[...c.message.matchAll(/^Co-authored-by: (.+ <[^<>]+>)\s*$/gim)].map((m) => m[1]),
    ];
    const trailerBlock = c.message
      .trimEnd()
      .split(/\r?\n\s*\r?\n/)
      .at(-1);
    const signs = new Set(
      [...trailerBlock.matchAll(/^Signed-off-by: (.+ <[^<>]+>)\s*$/gim)].map((m) => m[1]),
    );
    for (const identity of identities) {
      if (software) fail(signs.has(identity), 'DCO_REQUIRED');
      const e = identity.match(/<([^<>]+)>$/)?.[1];
      fail(email(e), 'CONTRIBUTION_AUTHOR');
      authors.add(e);
    }
  }
  let settledAt = null;
  if (d) {
    for (const author of authors) {
      const matches = r.contributions.filter(
        (c) =>
          c.digest === d &&
          c.withdrawnAt === null &&
          Date.parse(c.review.reviewedAt) <= now &&
          Date.parse(c.receivedAt) <= now &&
          r.agreements.some(
            (a) =>
              a.id === c.agreementId &&
              a.kind === 'OWF_CLA_1_0' &&
              a.specification.name === 'CertConcord' &&
              a.contributorEmails.includes(author) &&
              Date.parse(a.review.reviewedAt) <= now,
          ),
      );
      fail(matches.length > 0, 'SPECIFICATION_AGREEMENT_REQUIRED');
      const settled = Math.min(...matches.map((c) => Date.parse(c.receivedAt) + 45 * 86400000));
      settledAt = Math.max(settledAt ?? 0, settled);
      if (final) fail(now > settled, 'CONTRIBUTION_WITHDRAWAL_WINDOW');
    }
  }
  return {
    origin: software ? 'DCO_PRESENT' : 'NO_SOFTWARE_CHANGE',
    normativeDigest: d,
    specification: d
      ? now > settledAt
        ? 'SETTLED_CONTRIBUTION'
        : 'WITHDRAWAL_WINDOW_OPEN'
      : 'NO_DECLARED_NORMATIVE_CHANGE',
    settledAfter: settledAt === null ? null : new Date(settledAt).toISOString(),
    patentCoverage: 'CONSULT_SEPARATE_FINAL_AGREEMENTS',
  };
}

function active(record, now) {
  return (
    record.events.filter((e) => Date.parse(e.at) <= now).at(-1)?.state === 'ACTIVE' &&
    Date.parse(record.review.reviewedAt) <= now
  );
}
export async function checkMark(r, grantId, report, artifactDirectory, { now = Date.now() } = {}) {
  report = structuredClone(report);
  validateRegistry(r);
  fail(Number.isSafeInteger(now), 'MARK_TIME');
  const g = r.grants.find((g) => g.id === grantId);
  fail(
    g && now >= Date.parse(g.validFrom) && now < Date.parse(g.validUntil) && active(g, now),
    'MARK_GRANT_INACTIVE',
  );
  const p = r.plans.find((p) => p.id === g.planId),
    m = r.marks.find((m) => m.id === p.markId);
  fail(
    active(m, now) && Date.parse(p.review.reviewedAt) <= Date.parse(g.review.reviewedAt),
    'MARK_AUTHORITY',
  );
  fail(
    digest(report) === g.reportSHA256 &&
      report.sourceCommit === g.sourceCommit &&
      report.manifestSHA256 === g.manifestSHA256 &&
      report.configurationSHA256 === g.configurationSHA256,
    'MARK_REPORT_BINDING',
  );
  fail(
    report.role === p.role &&
      report.profile === p.profile &&
      report.category === p.category &&
      digest(report.suite) === digest(p.suite) &&
      p.assessors.includes(report.assessor),
    'MARK_ASSESSMENT_SCOPE',
  );
  fail(Date.parse(report.completedAt) <= Date.parse(g.review.reviewedAt), 'MARK_ASSESSMENT_TIME');
  await validateResult(report, artifactDirectory);
  const results = new Map(report.tests.map((t) => [t.id, t.result]));
  fail(
    !report.tests.some((t) => ['FAIL', 'INDETERMINATE'].includes(t.result)),
    'MARK_NONPASSING_RESULT',
  );
  for (const req of p.requirements)
    for (const id of req.tests) fail(results.get(id) === 'PASS', 'MARK_REQUIRED_RESULT');
  return {
    technicalScope: 'PASS',
    designation: m.text,
    authorization: 'ACTIVE_RECORDED_GRANT',
    grantId,
    implementation: g.implementation,
    specification: p.specification,
    profile: p.profile,
    validUntil: g.validUntil,
  };
}

export function validateTransition(previous, next) {
  validateRegistry(previous);
  validateRegistry(next);
  for (const kind of ['holders', 'agreements', 'contributions', 'marks', 'plans', 'grants']) {
    for (const before of previous[kind]) {
      const after = next[kind].find((r) => r.id === before.id);
      fail(after, 'REGISTRY_HISTORY_REMOVAL');
      const a = structuredClone(before),
        b = structuredClone(after);
      if (kind === 'marks' || kind === 'grants') {
        fail(
          b.events.length >= a.events.length &&
            digest(b.events.slice(0, a.events.length)) === digest(a.events),
          'REGISTRY_HISTORY_REWRITE',
        );
        delete a.events;
        delete b.events;
      }
      if (kind === 'contributions' && before.withdrawnAt === null && after.withdrawnAt !== null) {
        fail(
          Date.parse(after.review.reviewedAt) >= Date.parse(after.withdrawnAt),
          'REGISTRY_WITHDRAWAL_REVIEW',
        );
        for (const key of ['withdrawnAt', 'withdrawalNotice', 'review']) {
          delete a[key];
          delete b[key];
        }
      }
      fail(digest(a) === digest(b), 'REGISTRY_HISTORY_REWRITE');
    }
  }
  return { transition: 'VALID' };
}
