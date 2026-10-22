import assert from 'node:assert/strict';
import { writeSync } from 'node:fs';
import * as c from './core.mjs';
import { algID, OID } from './pki.mjs';
import { Journal } from './state.mjs';
import { createAuthorityResolver, requireAuthority } from './authority-history.mjs';
import { verifyERS } from './archive.mjs';
import { tokenFromResponse } from './timestamp.mjs';
import { requestBytes } from './transport.mjs';
import { ArchivePublicationStore, ArchiveRenewalCoordinator } from './retained-authorities.mjs';

const emit = (event, value) =>
  writeSync(1, JSON.stringify({ event, value: c.b64u(c.dcbor(value)) }) + '\n');

process.once('message', (configuration) => {
  const {
    journalPath,
    request,
    initial,
    data,
    history,
    at,
    mode,
    url,
    authorities,
    trustDomainID,
  } = configuration;
  const journal = new Journal(journalPath);
  const authorityResolver = createAuthorityResolver({ trustDomainID, authorities });
  const timestampTrust = {
    ...configuration.timestampTrust,
    issuerKey: c.publicFromDER(configuration.issuerKeyDER),
    authorityResolver,
    trustDomainID,
  };
  const operation = 'archive-renewal:' + c.b64u(request.operationID);
  let publicationReads = 0;
  const inspect = () => ({
    operation: journal.result(operation),
    publication: store.read(request.archiveID),
    revision: journal.get('archive-publication', request.archiveID)?.revision,
    publicationReads,
  });
  const pause = (stage) => {
    emit('paused', { stage, pid: process.pid, depth: journal.depth ?? 0, ...inspect() });
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
    assert.fail('The parent must forcibly terminate the paused process');
  };
  const store = new ArchivePublicationStore(journal, {
    validatePublication: (publication) => {
      assert.deepEqual(publication.dataHash, c.sha512(data));
      assert.deepEqual(publication.history, c.decodeCBOR(c.dcbor(history)));
      const verified = verifyERS(publication.evidenceRecord, data, {
        ...timestampTrust,
        at,
        maxFutureSkew: 0,
      });
      requireAuthority(authorityResolver, {
        publicKeyDER: configuration.custodianKeyDER,
        role: 'ARCHIVE_CUSTODIAN',
        scope: { trustDomainID, purpose: 'ARCHIVE_PRESERVATION' },
        stateTime: verified.poeUpperBound,
        knowledgeTime: at,
      });
      return { overall: verified.integrity };
    },
    crash: (point) => {
      if (mode === 'before-commit' && point === 'after-publication-before-commit') pause(mode);
    },
  });
  const coordinator = new ArchiveRenewalCoordinator({
    journal,
    store,
    timestampTrust,
    clock: () => at,
    requestTimestamp: async (der) => {
      const response = await requestBytes(url, {
        method: 'POST',
        body: der,
        headers: { 'content-type': 'application/timestamp-query' },
        allowLoopback: true,
      });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('content-type'), 'application/timestamp-reply');
      const token = tokenFromResponse(response.body);
      if (mode === 'after-token') pause(mode);
      return token;
    },
    buildPublication: (saved, token) => {
      // Append one timestamp to this fixture's single existing RFC 4998 chain.
      const root = c.parseDER(initial.publication.evidenceRecord);
      const chain = root.children[2].children[0];
      const stamp = c.seq(c.der(0xa0, c.parseDER(algID(OID.sha512)).value), token);
      const publication = {
        archiveID: saved.archiveID,
        previousHash: saved.previousHash,
        dataHash: c.sha512(data),
        evidenceRecord: c.seq(
          root.children[0].raw,
          root.children[1].raw,
          c.seq(c.seq(...chain.children.map((entry) => entry.raw), stamp)),
        ),
        history,
      };
      if (mode === 'changing-publication')
        Object.defineProperty(publication, 'archiveID', {
          enumerable: true,
          get: () => ++publicationReads === 1 ? saved.archiveID : 'different-archive',
        });
      return publication;
    },
  });
  process.on('message', async ({ action, token }) => {
    try {
      let result;
      if (action === 'inspect') result = inspect();
      else if (action === 'renew') result = await coordinator.renew(request);
      else if (action === 'reconcile') result = coordinator.reconcile(request.operationID, token);
      else assert.fail('Unexpected child action');
      if (action === 'renew' && mode === 'after-commit') pause(mode);
      emit('result', { result });
    } catch (error) {
      emit('result', {
        error: { code: error.code ?? error.message, overall: error.overall ?? null },
      });
    }
  });
  emit('ready', { pid: process.pid });
});
