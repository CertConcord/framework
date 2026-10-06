import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
const seed = 'certconcord-mtc-synthetic-privacy-v1',
  id = (...parts) =>
    createHash('sha256')
      .update(JSON.stringify([seed, ...parts]))
      .digest('hex');
const subjects = 64,
  verifiers = 4,
  visits = 3;
const scenarios = [
  'REUSED_KEY',
  'PAIRWISE_KEY_STABLE_CREDENTIAL',
  'PAIRWISE_CREDENTIAL',
  'ONE_USE_BATCHED',
];
const output = process.argv[2] ?? 'datasets/privacy-v1';
await mkdir(output, { recursive: true });
const rows = [],
  reports = [];
for (const scenario of scenarios) {
  const events = [],
    cache = new Set();
  for (let visit = 0; visit < visits; visit++)
    for (let subject = 0; subject < subjects; subject++)
      for (let verifier = 0; verifier < verifiers; verifier++) {
        const oneUse = scenario === 'ONE_USE_BATCHED',
          pairwise = scenario === 'PAIRWISE_CREDENTIAL',
          scope = oneUse ? [verifier, visit] : pairwise ? [verifier] : [],
          issuer = 'https://issuer-' + (subject % 2) + '.example',
          cohort = oneUse ? Math.floor(subject / 32) : subject,
          statusURI = issuer + '/status/' + cohort,
          cacheKey = verifier + ':' + visit + ':' + statusURI,
          networkRequest = !oneUse || !cache.has(cacheKey);
        cache.add(cacheKey);
        const row = {
          scenario,
          subject: 'synthetic-' + subject,
          verifier: 'verifier-' + verifier,
          visit,
          deviceKey: id(
            'key',
            subject,
            ...(scenario === 'REUSED_KEY' ? [] : oneUse ? [verifier, visit] : [verifier]),
          ),
          credentialID: id('credential', subject, ...scope),
          statusHandle: oneUse
            ? id('status-index', subject, verifier, visit)
            : id('status-index', subject, ...scope),
          statusURI,
          issuer,
          credentialType: ['mDL', 'photoID', 'PID', 'custom'][subject % 4],
          validityHours: oneUse ? 24 : 720,
          issuanceBatch: oneUse ? Math.floor(subject / 32) : subject,
          networkRequest,
        };
        events.push(row);
        rows.push(row);
      }
  const metrics = {};
  const predicates = {
    deviceKey: (a, b) => a.deviceKey === b.deviceKey,
    credentialID: (a, b) => a.credentialID === b.credentialID,
    statusIndex: (a, b) => a.statusURI === b.statusURI && a.statusHandle === b.statusHandle,
    statusNetworkURL: (a, b) => a.statusURI === b.statusURI,
    issuerAndType: (a, b) => a.issuer === b.issuer && a.credentialType === b.credentialType,
  };
  for (const [name, predicate] of Object.entries(predicates)) {
    let tp = 0,
      fp = 0,
      fn = 0,
      tn = 0;
    for (let i = 0; i < events.length; i++)
      for (let j = i + 1; j < events.length; j++) {
        const a = events[i],
          b = events[j];
        if (a.verifier === b.verifier) continue;
        const truth = a.subject === b.subject,
          predicted = predicate(a, b);
        if (truth && predicted) tp++;
        else if (truth) fn++;
        else if (predicted) fp++;
        else tn++;
      }
    metrics[name] = {
      tp,
      fp,
      fn,
      tn,
      precision: tp + fp ? tp / (tp + fp) : null,
      recall: tp / (tp + fn),
      falsePositiveRate: fp / (fp + tn),
    };
  }
  reports.push({
    scenario,
    presentations: events.length,
    statusNetworkRequests: events.filter((x) => x.networkRequest).length,
    assumption:
      'All verifiers collude; equality attacker; no IP, timing, browser fingerprint or disclosed-name features',
    metrics,
  });
}
const config = {
  schemaVersion: 1,
  synthetic: true,
  seed,
  subjects,
  verifiers,
  visits,
  scenarios,
  license: 'CC-BY-4.0',
};
await writeFile(output + '/config.json', JSON.stringify(config, null, 2) + '\n');
await writeFile(output + '/events.jsonl', rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
await writeFile(output + '/results.json', JSON.stringify({ config, reports }, null, 2) + '\n');
console.log(
  JSON.stringify(
    reports.map(({ scenario, presentations, statusNetworkRequests, metrics }) => ({
      scenario,
      presentations,
      statusNetworkRequests,
      keyRecall: metrics.deviceKey.recall,
      credentialRecall: metrics.credentialID.recall,
      statusURLPrecision: metrics.statusNetworkURL.precision,
    })),
    null,
    2,
  ),
);
