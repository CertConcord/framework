import { isDeepStrictEqual } from 'node:util';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import * as sourceSDK from './sdk/index.mjs';
import {
  loadOrganizationHistoryVectorCorpus,
  assertLosslessVectorJSON,
} from './organization-vector-corpus.mjs';

export {
  defaultOrganizationHistoryVectorDirectory,
  loadOrganizationHistoryVectorCorpus,
} from './organization-vector-corpus.mjs';

/** Inject the two installed public exports; fixture expectations never become decisions. */
export function runOrganizationHistoryVectors({
  directory,
  createOrganizationHistorySource = sourceSDK.createOrganizationHistorySource,
  createOrganizationHistoryVerifier = sourceSDK.createOrganizationHistoryVerifier,
} = {}) {
  const corpus = loadOrganizationHistoryVectorCorpus(directory);
  if (
    typeof createOrganizationHistorySource !== 'function' ||
    typeof createOrganizationHistoryVerifier !== 'function'
  )
    throw Object.assign(new Error('ORG_VECTOR_FACTORY'), { code: 'ORG_VECTOR_FACTORY' });
  return corpus.manifest.cases.map((entry) => {
    const { configuration, knowledge, originalBytes, evidenceRecord } = corpus.input(entry);
    const source = createOrganizationHistorySource({
      configuration,
      readKnowledge: () => knowledge,
    });
    let actual;
    try {
      actual = createOrganizationHistoryVerifier({ source }).verify({
        originalBytes,
        evidenceRecord,
      });
      assertLosslessVectorJSON(actual);
    } finally {
      source.close();
    }
    // Expected JSON is interpreted only after verification and complete-result validation.
    const expected = corpus.expected(entry);
    if (!isDeepStrictEqual(actual, expected))
      throw Object.assign(new Error('ORG_VECTOR_EXPECTATION_MISMATCH'), {
        code: 'ORG_VECTOR_EXPECTATION_MISMATCH',
        id: entry.id,
        actual,
        expected,
      });
    return Object.freeze({ id: entry.id, actual });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length > 3)
      throw Object.assign(new Error('ORG_VECTOR_ARGUMENTS'), { code: 'ORG_VECTOR_ARGUMENTS' });
    console.log(
      JSON.stringify(
        runOrganizationHistoryVectors(
          process.argv[2] ? { directory: resolve(process.argv[2]) } : {},
        ),
        null,
        2,
      ),
    );
  } catch (error) {
    console.error(
      JSON.stringify(
        {
          error: error.code ?? error.message,
          id: error.id,
          actual: error.actual,
          expected: error.expected,
        },
        null,
        2,
      ),
    );
    process.exitCode = 1;
  }
}
