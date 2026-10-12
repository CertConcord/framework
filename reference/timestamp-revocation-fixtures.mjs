// Test-only standard CRLs. Omitting reasonCode is a valid RFC 5280 choice;
// these fixtures do not change time encodings or construct malformed ASN.1.
import assert from 'node:assert/strict';
import { verify } from 'node:crypto';
import * as c from './core.mjs';
import { epoch } from './cades-fixtures.mjs';

export function revokedTSAStatus(
  f,
  {
    reason,
    revokedAt = epoch + 50,
    invalidityDate,
    thisUpdate = epoch + 60,
    nextUpdate = epoch + 300,
    number = 2,
  } = {},
) {
  let raw = f.crl({
    thisUpdate,
    nextUpdate,
    number,
    entries: [{ serial: f.tsa.cert.serial, reason: reason ?? 1, revokedAt, invalidityDate }],
  });
  if (reason === undefined) {
    const [tbs, algorithm] = c.parseDER(raw).children;
    const fields = tbs.children.map((node) => node.raw);
    fields[5] = c.seq(
      ...tbs.children[5].children.map((entry) => {
        const extensions = entry.children[2].children.filter(
          (node) => c.oidText(node.children[0]) !== '2.5.29.21',
        );
        return c.seq(
          entry.children[0].raw,
          entry.children[1].raw,
          ...(extensions.length ? [c.seq(...extensions.map((node) => node.raw))] : []),
        );
      }),
    );
    const next = c.seq(...fields);
    raw = c.seq(next, algorithm.raw, c.bit(c.sign(next, f.root.privateKey)));
  }
  const [tbs, , signature] = c.parseDER(raw).children;
  assert(verify('sha256', tbs.raw, f.root.publicKey, signature.value.subarray(1)));
  const entry = tbs.children[5].children[0];
  const extension = entry.children[2]?.children.find(
    (node) => c.oidText(node.children[0]) === '2.5.29.21',
  );
  assert.equal(extension !== undefined, reason !== undefined);
  if (extension) assert.equal(c.parseDER(extension.children.at(-1).value).value[0], reason);
  return raw;
}
