import { readFile } from 'node:fs/promises';
import { parseJSON } from '../json.mjs';
import {
  byteDigest,
  openRegister,
  checkContribution,
  validateRegistry,
  validateTransition,
} from './registry.mjs';

// Run from the protected base only; pull-request source is never loaded.
const bytes = await readFile('reference/governance/registry.json');
const registry = openRegister(bytes, byteDigest(bytes));
if (process.env.GITHUB_EVENT_NAME === 'workflow_dispatch' && !process.env.CERTCONCORD_PR_NUMBER) {
  console.log(JSON.stringify(validateRegistry(registry)));
} else {
  const repo = process.env.GITHUB_REPOSITORY,
    number = Number(process.env.CERTCONCORD_PR_NUMBER);
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo) ||
    !['pull_request_target', 'workflow_dispatch'].includes(process.env.GITHUB_EVENT_NAME) ||
    (process.env.GITHUB_EVENT_NAME === 'workflow_dispatch' &&
      process.env.GITHUB_REF !== 'refs/heads/main') ||
    !Number.isSafeInteger(number) ||
    number < 1 ||
    (process.env.GITHUB_EVENT_NAME === 'pull_request_target' &&
      (!/^[a-f0-9]{40}$/.test(process.env.CERTCONCORD_HEAD_SHA) ||
        !/^[a-f0-9]{40}$/.test(process.env.CERTCONCORD_BASE_SHA)))
  )
    throw Error('CONTRIBUTION_TARGET');
  const get = async (path) => {
    const response = await fetch('https://api.github.com/repos/' + repo + path, {
      headers: {
        authorization: 'Bearer ' + process.env.GITHUB_TOKEN,
        accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10',
      },
      signal: AbortSignal.timeout(30000),
      redirect: 'error',
    });
    if (!response.ok) throw Error('CONTRIBUTION_METADATA_HTTP_' + response.status);
    const body = await response.text();
    if (Buffer.byteLength(body) > 16 * 1024 * 1024) throw Error('CONTRIBUTION_METADATA_LIMIT');
    return parseJSON(body, { maxBytes: 16 * 1024 * 1024 });
  };
  let statusSHA =
    process.env.GITHUB_EVENT_NAME === 'pull_request_target'
      ? process.env.CERTCONCORD_HEAD_SHA
      : null;
  const publish = async (state) => {
    if (!/^[a-f0-9]{40}$/.test(statusSHA)) throw Error('CONTRIBUTION_STATUS_TARGET');
    const response = await fetch(
      'https://api.github.com/repos/' + repo + '/statuses/' + statusSHA,
      {
        method: 'POST',
        headers: {
          authorization: 'Bearer ' + process.env.GITHUB_TOKEN,
          accept: 'application/vnd.github+json',
          'Content-Type': 'application/json',
          'X-GitHub-Api-Version': '2026-03-10',
        },
        body: JSON.stringify({
          state,
          context: 'contribution-policy',
          description:
            state === 'success'
              ? 'Contribution origin and normative rights checks passed'
              : state === 'pending'
                ? 'Evaluating against the protected base register'
                : 'Contribution policy requires attention',
        }),
        signal: AbortSignal.timeout(30000),
        redirect: 'error',
      },
    );
    if (!response.ok) throw Error('CONTRIBUTION_STATUS_HTTP_' + response.status);
  };
  try {
    if (statusSHA) await publish('pending');
    const current = await get('/pulls/' + number);
    if (
      (process.env.GITHUB_EVENT_NAME === 'pull_request_target' &&
        current.head.sha !== process.env.CERTCONCORD_HEAD_SHA) ||
      current.base.sha !==
        (process.env.GITHUB_EVENT_NAME === 'pull_request_target'
          ? process.env.CERTCONCORD_BASE_SHA
          : process.env.GITHUB_SHA) ||
      current.base.repo.full_name !== repo ||
      current.base.ref !== 'main' ||
      current.changed_files > 3000 ||
      current.commits > 250
    )
      throw Error('CONTRIBUTION_HEAD_OR_LIMIT');
    if (!statusSHA) {
      statusSHA = current.head.sha;
      await publish('pending');
    }
    const pages = async (kind, count) => {
      const values = [];
      for (let page = 1; values.length < count; page++) {
        const items = await get('/pulls/' + number + '/' + kind + '?per_page=100&page=' + page);
        if (!Array.isArray(items) || !items.length) throw Error('CONTRIBUTION_METADATA_INCOMPLETE');
        values.push(...items);
      }
      if (values.length !== count) throw Error('CONTRIBUTION_METADATA_CHANGED');
      return values;
    };
    const files = (await pages('files', current.changed_files)).map((f) => ({
      path: f.filename,
      sha: f.sha,
      status: f.status,
      previousPath: f.previous_filename ?? null,
    }));
    const commits = (await pages('commits', current.commits)).map((c) => ({
      sha: c.sha,
      name: c.commit.author.name,
      email: c.commit.author.email,
      message: c.commit.message,
    }));
    const additionalNormativePaths = [
      ...(current.body ?? '').matchAll(/^Normative-Path: (\S+)\s*$/gm),
    ].map((m) => m[1]);
    const registryChange = files.find(
      (f) =>
        f.path === 'reference/governance/registry.json' ||
        f.previousPath === 'reference/governance/registry.json',
    );
    if (registryChange) {
      if (
        registryChange.path !== 'reference/governance/registry.json' ||
        !['added', 'modified'].includes(registryChange.status)
      )
        throw Error('REGISTRY_HISTORY_REMOVAL');
      const blob = await get('/git/blobs/' + registryChange.sha);
      if (blob.encoding !== 'base64' || blob.size > 4 * 1024 * 1024)
        throw Error('REGISTRY_BLOB_LIMIT');
      const proposed = parseJSON(Buffer.from(blob.content, 'base64').toString('utf8'), {
        maxBytes: 4 * 1024 * 1024,
      });
      validateTransition(registry, proposed);
    }
    const final = await get('/pulls/' + number);
    if (
      final.head.sha !== current.head.sha ||
      final.base.sha !== current.base.sha ||
      final.body !== current.body
    )
      throw Error('CONTRIBUTION_METADATA_CHANGED');
    const result = checkContribution(registry, { files, commits, additionalNormativePaths });
    await publish('success');
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    if (statusSHA) await publish('failure');
    throw error;
  }
}
