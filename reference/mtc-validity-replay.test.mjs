import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as m from './mtc.mjs';
import { Journal, readControl } from './state.mjs';
import { createCSR, RegistrationAuthority } from './enrollment.mjs';
import { issuanceRequestID } from './enrollment-scope.mjs';
import { MTCIssuer } from './issuance.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';

const profileID = 'CERTCONCORD-PERSON-SIGN-v1',
  tags = (tbs) => c.parseDER(tbs).children[4].children.map((v) => v.tag);

for (const state of ['APPENDED', 'CERTIFIED'])
  test(
    'MTC issuer reopens retained GeneralizedTime ' + state + ' and appends a UTC leaf',
    async (t) => {
      t.mock.method(Date, 'now', () => Date.parse('2026-10-26T12:00:00Z'));
      const directory = mkdtempSync(join(tmpdir(), 'certconcord-validity-')),
        path = join(directory, 'issuer.sqlite'),
        transient = [],
        memoryJournal = () => {
          const journal = new Journal();
          transient.push(journal);
          return journal;
        },
        at = c.now(),
        control = (serial) => {
          const key = c.generate('ml-dsa-87'),
            subject = p.name('Synthetic time authority ' + serial);
          return {
            ...key,
            certificate: p.issueCertificate(
              {
                publicKey: key.publicKey,
                issuer: subject,
                subject,
                serial,
                profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
                notBefore: at - 60,
                notAfter: at + 86400,
              },
              key.privateKey,
            ),
          };
        },
        ra = control(1),
        ca = control(2),
        members = [1, 2].map((n) => ({
          id: '32473.' + (210 + n),
          operatorID: 'validity-mirror-' + n,
          ...c.generate('ml-dsa-87'),
        })),
        scope = {
          trustDomainID: c.random(),
          issuerID: '32473.210',
          issuerKeyID: c.keyID(ca.publicKey),
          representation: 'MTC',
        },
        policyHash = c.random(64),
        rtmHash = c.random(64),
        authorityResolver = exampleAuthorityResolver({
          trustDomainID: scope.trustDomainID,
          authorities: [
            { certificate: ra.certificate, roles: ['REGISTRATION_AUTHORITY'] },
            { certificate: ca.certificate, roles: ['ISSUER'] },
            ...members.map((member) => ({
              mode: 'RAW_KEY',
              publicKeyDER: c.spki(member.publicKey),
              roles: ['COSIGNER'],
              knownAt: at - 60,
              validFrom: at - 60,
              validUntil: at + 86400,
            })),
          ],
        }),
        raService = new RegistrationAuthority({
          journal: memoryJournal(),
          ...ra,
          approve: async () => ({ approved: true }),
        }),
        request = async () => {
          const key = c.generate('ml-dsa-65'),
            subject = p.name('Synthetic retained time subject'),
            csr = createCSR({ ...key, subject }),
            rar = await raService.authorize({
              csr,
              subjectID: c.random(),
              profileID,
              policyHash,
              identityEvidenceHash: c.random(64),
              issuanceScope: scope,
            });
          return { key, subject, csr, rar };
        },
        options = {
          raCertificate: ra.certificate,
          caID: scope.issuerID,
          logNumber: 1,
          privateKey: ca.privateKey,
          policyHash,
          rtmHash,
          membershipEpoch: 1,
          members,
          threshold: 2,
          mirrors: members.map(
            (member) =>
              new m.Mirror({
                journal: memoryJournal(),
                id: member.id,
                privateKey: member.privateKey,
              }),
          ),
          allowedProfiles: [profileID],
          issuanceScope: scope,
          authorityResolver,
          issuerCertificate: ca.certificate,
        },
        trust = {
          caID: scope.issuerID,
          caPublicKey: ca.publicKey,
          members,
          threshold: 2,
          policyHash,
          rtmHash,
          membershipEpoch: 1,
          profileID,
          at,
        };
      let journal = new Journal(path);
      try {
        const oldRequest = await request(),
          authorization = readControl(oldRequest.rar, 'RegistrationAuthorization', ra.certificate),
          id = issuanceRequestID(authorization),
          fields = c
            .parseDER(
              m.createMTCTBS(
                {
                  publicKey: oldRequest.key.publicKey,
                  subject: oldRequest.subject,
                  profileID,
                  notBefore: at - 60,
                  notAfter: at + 86400,
                  extraExtensions: [
                    p.extension(
                      p.RRA['id-pe-certconcordAuthorizationID'],
                      c.octet(c.H('RegistrationAuthorization', authorization)),
                    ),
                    p.extension(
                      p.RRA['id-pe-certconcordKeyAssurance'],
                      c.octet(c.D('KeyAssurance', { level: 'KAL1', custody: 'UNASSESSED' })),
                    ),
                  ],
                },
                { caID: scope.issuerID, logNumber: 1, index: 0 },
              ),
            )
            .children.map((v) => v.raw);
        // Seed the exact former issuer encoding before opening the upgraded service.
        fields[4] = c.seq(p.generalizedTime(at - 60), p.generalizedTime(at + 86400));
        const tbs = c.seq(...fields),
          entry = m.logEntryFromTBS(tbs),
          before = new MTCIssuer({ ...options, journal });
        assert.equal(before.log.append(entry, id), 0);
        const originalRoot = before.log.root(1),
          retainedCertificate = m.issueMTC(tbs, {
            caID: scope.issuerID,
            logNumber: 1,
            entries: [entry],
            index: 0,
            cosigners: [{ id: scope.issuerID, ...ca }, ...members],
          });
        journal.put('mtc-issuance', id, {
          state,
          tbs,
          index: 0,
          rarHash: c.sha512(oldRequest.rar),
          profileID,
          ...(state === 'CERTIFIED' ? { certificate: retainedCertificate } : {}),
        });
        journal.close();
        journal = new Journal(path);
        const reopened = new MTCIssuer({ ...options, journal }),
          certificate = await reopened.issue(oldRequest);
        assert.deepEqual(p.parseCertificate(certificate).tbs, tbs);
        assert.deepEqual(tags(p.parseCertificate(certificate).tbs), [24, 24]);
        if (state === 'CERTIFIED') assert.deepEqual(certificate, retainedCertificate);
        assert.equal(m.verifyMTC(certificate, trust).mode, 'STANDALONE');
        assert.deepEqual(await reopened.issue(oldRequest), certificate);
        assert.equal(reopened.log.head().size, 1);
        assert.deepEqual(reopened.log.root(1), originalRoot);
        journal.close();
        journal = new Journal(path);
        const again = new MTCIssuer({ ...options, journal });
        assert.deepEqual(await again.issue(oldRequest), certificate);
        const newCertificate = await again.issue(await request()),
          entries = again.log.entries(0, 2);
        assert.equal(again.log.head().size, 2);
        assert.deepEqual(entries[0], entry);
        assert.deepEqual(again.log.root(1), originalRoot);
        assert.deepEqual(tags(p.parseCertificate(newCertificate).tbs), [23, 23]);
        assert.equal(m.verifyMTC(newCertificate, trust).mode, 'STANDALONE');
        const mixedRoot = again.log.root(2),
          reproof = m.issueMTC(tbs, {
            caID: scope.issuerID,
            logNumber: 1,
            entries,
            index: 0,
            cosigners: [{ id: scope.issuerID, ...ca }, ...members],
          }),
          cache = [
            {
              ...trust,
              logNumber: 1,
              start: 0,
              end: 2,
              root: mixedRoot,
              mode: 'LIVE',
              validFrom: at - 1,
              expiresAt: at + 3600,
            },
          ];
        assert.deepEqual(p.parseCertificate(reproof).tbs, tbs);
        for (const raw of [reproof, newCertificate]) {
          assert.equal(m.verifyMTC(raw, trust).mode, 'STANDALONE');
          assert.equal(m.verifyMTC(raw, { ...trust, trustedSubtrees: cache }).mode, 'LANDMARK');
        }
        assert.deepEqual(journal.get('mtc-issuance', id).value.certificate, certificate);
      } finally {
        journal.close();
        for (const value of transient) value.close();
        rmSync(directory, { recursive: true, force: true });
      }
    },
  );
