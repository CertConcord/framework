import { assertPreservationLifetimes } from './vendor/mtc-document-validation/lifetimes.mjs';
import { DOMParser } from '@xmldom/xmldom';
import { C14nCanonicalization } from 'xml-crypto';
import {
  seq,
  oid,
  octet,
  integer,
  der,
  parseDER,
  intValue,
  oidText,
  requireThat,
  sha256,
  sha512,
  equal,
} from './core.mjs';
import { algID, OID, parseCertificate, verifyCMS } from './pki.mjs';

const hashes = { [OID.sha256]: sha256, [OID.sha512]: sha512 };
export {
  timestampRequest,
  parseTimestampRequest,
  TimestampAuthority,
  tokenFromResponse,
  parseTSTInfo,
  verifyTimestampToken,
  requestTimestamp,
  cmsTimestampAttribute,
  verifyExternalTimestampToken,
} from './timestamp.mjs';
import { verifyTimestampToken, parseTSTInfo } from './timestamp.mjs';

function parseERS(raw) {
  const root = parseDER(raw),
    a = root.children;
  requireThat(
    root.tag === 48 &&
      a?.length === 3 &&
      intValue(a[0]) === 1n &&
      a[1].tag === 48 &&
      a[2].tag === 48,
    'ERS_STRUCTURE',
  );
  const algorithms = a[1].children.map((n) => {
    requireThat(
      n.tag === 48 && n.children?.length === 1 && n.children[0].tag === 6,
      'ERS_ALGORITHM_ENCODING',
    );
    return oidText(n.children[0]);
  });
  requireThat(
    algorithms.length > 0 &&
      new Set(algorithms).size === algorithms.length &&
      algorithms.every((a) => hashes[a]),
    'ERS_ALGORITHMS',
  );
  const chains = a[2].children;
  requireThat(chains.length > 0 && chains.length <= 64, 'ERS_CHAIN_LIMIT');
  requireThat(
    chains.every((c) => c.tag === 48 && c.children.length > 0 && c.children.length <= 64),
    'ERS_STAMP_LIMIT',
  );
  return { algorithms, chains };
}
const ersEncode = (algorithms, chains) =>
  seq(integer(1), seq(...algorithms.map(algID)), seq(...chains));
function atsParts(n) {
  const a = n.children;
  requireThat(n.tag === 48 && a?.length >= 1 && a.length <= 3, 'ERS_ATS_STRUCTURE');
  let hashOID,
    reduced,
    previousTag = -1;
  for (const x of a.slice(0, -1)) {
    requireThat(x.tag > previousTag, 'ERS_ATS_ORDER');
    previousTag = x.tag;
    if (x.tag === 0xa0) {
      requireThat(!hashOID, 'ERS_DUPLICATE_ALGORITHM');
      requireThat(x.children.length === 1 && x.children[0].tag === 6, 'ERS_ALGORITHM_ENCODING');
      hashOID = oidText(x.children[0]);
    } else if (x.tag === 0xa2) {
      requireThat(!reduced, 'ERS_DUPLICATE_TREE');
      requireThat(x.children.length > 0, 'ERS_TREE_STRUCTURE');
      reduced = x.children.map((s) => {
        requireThat(s.tag === 48 && s.children.length > 0, 'ERS_TREE_STRUCTURE');
        return s.children.map((o) => {
          requireThat(o.tag === 4, 'ERS_HASH_TYPE');
          return o.value;
        });
      });
    } else throw Error('ERS_UNSUPPORTED_ATTRIBUTES');
  }
  const token = a.at(-1).raw;
  hashOID ??= parseTSTInfo(verifyCMS(token, { expectedContentType: OID.tstInfo }).content).hashOID;
  return { hashOID, reduced, token };
}
// RFC 4998 Figure 4; erratum 7411 reports the conflicting prose in section 5.2.
function renewedImprint(h, data, chains) {
  return h(Buffer.concat([h(data), h(seq(...chains))].sort(Buffer.compare)));
}
export async function createERS(data, { tsa, hashOID = OID.sha512 }) {
  requireThat(hashes[hashOID], 'ERS_HASH');
  const token = await tsa(hashes[hashOID](data), hashOID);
  return ersEncode([hashOID], [seq(seq(der(0xa0, parseDER(algID(hashOID)).value), token))]);
}
export async function renewERS(raw, data, { tsa, hashRenewal = false, hashOID = OID.sha512 }) {
  const e = parseERS(raw),
    chains = e.chains.map((n) => n.raw),
    last = e.chains.at(-1).children.at(-1),
    lastParts = atsParts(last);
  let imprint;
  if (hashRenewal) {
    requireThat(hashes[hashOID], 'ERS_HASH');
    const h = hashes[hashOID];
    imprint = renewedImprint(h, data, chains);
    const token = await tsa(imprint, hashOID);
    chains.push(seq(seq(der(0xa0, parseDER(algID(hashOID)).value), token)));
  } else {
    hashOID = lastParts.hashOID;
    requireThat(hashes[hashOID], 'ERS_HASH');
    imprint = hashes[hashOID](lastParts.token);
    const token = await tsa(imprint, hashOID);
    chains[chains.length - 1] = seq(
      ...e.chains.at(-1).children.map((n) => n.raw),
      seq(der(0xa0, parseDER(algID(hashOID)).value), token),
    );
  }
  return ersEncode([...new Set([...e.algorithms, hashOID])], chains);
}
function walkERS(raw, data, verifyToken) {
  const e = parseERS(raw);
  let previousTime = -Infinity,
    latest;
  const records = [];
  for (let i = 0; i < e.chains.length; i++) {
    const chain = e.chains[i];
    let chainHash;
    for (let k = 0; k < chain.children.length; k++) {
      const a = atsParts(chain.children[k]),
        hashOID = a.hashOID,
        h = hashes[hashOID];
      requireThat(
        h && e.algorithms.includes(hashOID) && (!chainHash || chainHash === hashOID),
        'ERS_HASH_CHANGE',
      );
      chainHash = hashOID;
      let expected;
      if (k > 0) expected = h(atsParts(chain.children[k - 1]).token);
      else if (i === 0) expected = h(data);
      else
        expected = renewedImprint(
          h,
          data,
          e.chains.slice(0, i).map((n) => n.raw),
        );
      if (a.reduced) {
        for (const [index, level] of a.reduced.entries()) {
          requireThat(
            level.every((x) => x.length === expected.length) &&
              (index > 0 || level.some((x) => equal(x, expected))),
            'ERS_TREE_MEMBERSHIP',
          );
          const sorted = [...level, ...(index > 0 ? [expected] : [])].sort(Buffer.compare);
          expected = sorted.length === 1 ? sorted[0] : h(Buffer.concat(sorted));
        }
      }
      latest = verifyToken(a.token, { imprint: expected, hashOID });
      requireThat(latest.genTime >= previousTime, 'ERS_TIME_ORDER');
      previousTime = latest.genTime;
      records.push({ ...latest, chain: i, hashOID });
    }
  }
  return { chains: e.chains.length, records };
}
export function verifyERS(raw, data, trust) {
  const { chains, records } = walkERS(raw, data, (token, binding) =>
    verifyTimestampToken(token, { ...trust, ...binding }),
  );
  return {
    chains,
    poeUpperBound: records.at(-1).poeUpperBound,
    integrity: 'VALID',
    preservation: 'NOT_EVALUATED',
  };
}

/** Evaluate preservation under externally supplied authority and security lifetimes. */
export function verifyERSPreservation(
  raw,
  data,
  { at, dataValidUntil, hashValidUntil, resolveTimestamp },
) {
  const deadline = (v) => Number.isSafeInteger(v) && v > 0;
  requireThat(
    Number.isSafeInteger(at) &&
      at >= 0 &&
      deadline(dataValidUntil) &&
      hashValidUntil &&
      typeof resolveTimestamp === 'function',
    'ERS_PRESERVATION_POLICY',
  );
  const { chains, records } = walkERS(raw, data, (token, binding) => {
    const trust = resolveTimestamp(Buffer.from(token));
    requireThat(
      trust?.certificate &&
        trust.issuerKey &&
        typeof trust.policy === 'string' &&
        trust.policy.length > 0 &&
        deadline(trust.validUntil) &&
        typeof trust.status === 'function',
      'ERS_TSA_TRUST_REQUIRED',
    );
    const info = verifyTimestampToken(token, { ...trust, ...binding, at, maxFutureSkew: 0 }),
      cert = parseCertificate(trust.certificate);
    requireThat(
      Number.isFinite(info.accuracy) && info.accuracy >= 0 && Number.isFinite(info.poeUpperBound),
      'ERS_ACCURACY_REQUIRED',
    );
    requireThat(
      info.genTime - info.accuracy >= cert.notBefore &&
        info.poeUpperBound < cert.notAfter &&
        info.poeUpperBound <= at,
      'ERS_TIMESTAMP_INTERVAL',
    );
    requireThat(
      trust.status({
        certificate: trust.certificate,
        genTime: info.genTime,
        stateTime: info.poeUpperBound,
        knowledgeTime: at,
      }) === true,
      'ERS_TSA_STATUS',
    );
    const validUntil = Math.min(cert.notAfter, trust.validUntil, trust.revokedAt ?? Infinity);
    requireThat(info.poeUpperBound < validUntil, 'ERS_TIMESTAMP_LIFETIME');
    return { ...info, validUntil };
  });
  assertPreservationLifetimes(records, { at, dataValidUntil, hashValidUntil }, (code) => requireThat(false, code));
  return {
    chains,
    timestamps: records.length,
    integrity: 'VALID',
    preservation: 'VALID',
    proofOfExistenceUpperBound: records[0].poeUpperBound,
    latestRenewalUpperBound: records.at(-1).poeUpperBound,
    verifiedAt: at,
  };
}

const XMLNS = 'urn:ietf:params:xml:ns:ers',
  C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  XMLHASH = {
    [OID.sha256]: 'http://www.w3.org/2001/04/xmlenc#sha256',
    [OID.sha512]: 'http://www.w3.org/2001/04/xmlenc#sha512',
  };
function xmlDocument(xml) {
  requireThat(
    typeof xml === 'string' && xml.length <= 16 * 1024 * 1024 && !/<!DOCTYPE|<!ENTITY/i.test(xml),
    'XML_EXTERNAL_ENTITY_OR_SIZE',
  );
  const errors = [];
  const d = new DOMParser({ onError: (_level, message) => errors.push(message) }).parseFromString(
    xml,
    'application/xml',
  );
  requireThat(!errors.length && d.documentElement.namespaceURI === XMLNS, 'XML_PARSE_OR_NAMESPACE');
  return d;
}
const children = (node) => Array.from(node.childNodes).filter((n) => n.nodeType === 1);
function child(node, name) {
  const matches = children(node).filter((n) => n.namespaceURI === XMLNS && n.localName === name);
  requireThat(matches.length === 1, 'XML_CARDINALITY_' + name);
  return matches[0];
}
function canonical(node) {
  const copy = node.cloneNode(true);
  copy.setAttribute('xmlns', XMLNS);
  return Buffer.from(new C14nCanonicalization().process(copy, {}));
}
function tokenXML(token) {
  return `<TimeStamp><TimeStampToken Type="RFC3161">${token.toString('base64')}</TimeStampToken></TimeStamp>`;
}
function atsXML(token, order, tree = '') {
  return `<ArchiveTimeStamp Order="${order}">${tree}${tokenXML(token)}</ArchiveTimeStamp>`;
}
function chainXML(content, order, hashOID) {
  return `<ArchiveTimeStampChain Order="${order}"><DigestMethod Algorithm="${XMLHASH[hashOID]}"/><CanonicalizationMethod Algorithm="${C14N}"/>${content}</ArchiveTimeStampChain>`;
}
export async function createXMLERS(data, { tsa, hashOID = OID.sha512 }) {
  requireThat(hashes[hashOID], 'XMLERS_HASH');
  const token = await tsa(hashes[hashOID](data), hashOID);
  return `<EvidenceRecord xmlns="${XMLNS}" Version="1.0"><ArchiveTimeStampSequence>${chainXML(atsXML(token, 1), 1, hashOID)}</ArchiveTimeStampSequence></EvidenceRecord>`;
}
export async function renewXMLERS(xml, data, { tsa, hashRenewal = false, hashOID = OID.sha512 }) {
  const doc = xmlDocument(xml),
    sequence = child(doc.documentElement, 'ArchiveTimeStampSequence'),
    chains = children(sequence),
    last = chains.at(-1),
    stamps = children(last).filter((n) => n.localName === 'ArchiveTimeStamp');
  let addition;
  if (hashRenewal) {
    const h = hashes[hashOID];
    requireThat(h, 'XMLERS_HASH');
    const values = [h(data), h(canonical(sequence))].sort(Buffer.compare),
      imprint = h(Buffer.concat(values)),
      token = await tsa(imprint, hashOID),
      tree = `<HashTree><Sequence Order="1">${values.map((v) => `<DigestValue>${v.toString('base64')}</DigestValue>`).join('')}</Sequence></HashTree>`;
    addition = chainXML(atsXML(token, 1, tree), chains.length + 1, hashOID);
    const fragment = xmlDocument(`<EvidenceRecord xmlns="${XMLNS}">${addition}</EvidenceRecord>`);
    sequence.appendChild(doc.importNode(fragment.documentElement.firstChild, true));
  } else {
    const uri = child(last, 'DigestMethod').getAttribute('Algorithm');
    hashOID = Object.keys(XMLHASH).find((k) => XMLHASH[k] === uri);
    requireThat(hashOID, 'XMLERS_HASH');
    const token = await tsa(hashes[hashOID](canonical(child(stamps.at(-1), 'TimeStamp'))), hashOID),
      fragment = xmlDocument(
        `<EvidenceRecord xmlns="${XMLNS}">${atsXML(token, stamps.length + 1)}</EvidenceRecord>`,
      );
    last.appendChild(doc.importNode(fragment.documentElement.firstChild, true));
  }
  return doc.toString();
}
export function verifyXMLERS(xml, data, trust) {
  const doc = xmlDocument(xml),
    root = doc.documentElement;
  requireThat(
    root.localName === 'EvidenceRecord' &&
      root.getAttribute('Version') === '1.0' &&
      children(root).length === 1,
    'XMLERS_STRUCTURE',
  );
  const sequence = child(root, 'ArchiveTimeStampSequence'),
    chains = children(sequence);
  requireThat(chains.length > 0 && chains.length <= 64, 'XMLERS_LIMIT');
  let latest,
    lastTime = -Infinity;
  for (let i = 0; i < chains.length; i++) {
    const chain = chains[i];
    requireThat(
      chain.localName === 'ArchiveTimeStampChain' && chain.getAttribute('Order') === String(i + 1),
      'XMLERS_ORDER',
    );
    const hashOID = Object.keys(XMLHASH).find(
      (k) => XMLHASH[k] === child(chain, 'DigestMethod').getAttribute('Algorithm'),
    );
    requireThat(
      hashOID && child(chain, 'CanonicalizationMethod').getAttribute('Algorithm') === C14N,
      'XMLERS_ALGORITHM',
    );
    const h = hashes[hashOID],
      stamps = children(chain).filter((n) => n.localName === 'ArchiveTimeStamp');
    requireThat(
      stamps.length > 0 && children(chain).length === stamps.length + 2,
      'XMLERS_CHILDREN',
    );
    for (let j = 0; j < stamps.length; j++) {
      const ats = stamps[j];
      requireThat(ats.getAttribute('Order') === String(j + 1), 'XMLERS_ORDER');
      let expected,
        required = [];
      if (j > 0) expected = h(canonical(child(stamps[j - 1], 'TimeStamp')));
      else if (i === 0) expected = h(data);
      else {
        const preceding = sequence.cloneNode(false);
        for (const c of chains.slice(0, i)) preceding.appendChild(c.cloneNode(true));
        required = [h(data), h(canonical(preceding))].sort(Buffer.compare);
        expected = h(Buffer.concat(required));
      }
      const trees = children(ats).filter((n) => n.localName === 'HashTree');
      requireThat(
        trees.length <= 1 && children(ats).length === 1 + trees.length,
        'XMLERS_ATS_CHILDREN',
      );
      if (trees.length) {
        const levels = children(trees[0]);
        for (let n = 0; n < levels.length; n++) {
          const level = levels[n];
          requireThat(
            level.localName === 'Sequence' && level.getAttribute('Order') === String(n + 1),
            'XMLERS_TREE_ORDER',
          );
          const values = children(level).map((v) => {
            requireThat(v.localName === 'DigestValue', 'XMLERS_DIGEST');
            return Buffer.from(v.textContent, 'base64');
          });
          requireThat(
            values.length > 0 && values.every((v) => v.length === h(Buffer.alloc(0)).length),
            'XMLERS_DIGEST_LENGTH',
          );
          if (i > 0 && j === 0 && n === 0)
            requireThat(
              values.length === 2 && values.every((v, k) => equal(v, required[k])),
              'XMLERS_RENEWAL_DATA',
            );
          else
            requireThat(
              values.some((v) => equal(v, expected)),
              'XMLERS_TREE_MEMBERSHIP',
            );
          expected =
            values.length === 1 ? values[0] : h(Buffer.concat([...values].sort(Buffer.compare)));
        }
      } else requireThat(!required.length, 'XMLERS_RENEWAL_TREE');
      const timeStamp = child(ats, 'TimeStamp'),
        token = child(timeStamp, 'TimeStampToken');
      requireThat(
        token.getAttribute('Type') === 'RFC3161' &&
          children(timeStamp).length === 1 &&
          children(token).length === 0,
        'XMLERS_TIMESTAMP',
      );
      latest = verifyTimestampToken(Buffer.from(token.textContent, 'base64'), {
        ...trust,
        imprint: expected,
        hashOID,
      });
      requireThat(latest.genTime >= lastTime, 'XMLERS_TIME_ORDER');
      lastTime = latest.genTime;
    }
  }
  return {
    chains: chains.length,
    poeUpperBound: latest.poeUpperBound,
    integrity: 'VALID',
    preservation: 'NOT_EVALUATED',
  };
}
