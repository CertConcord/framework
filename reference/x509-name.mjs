import { ProtocolError, parseDER, oidText } from './core.mjs';
import { caseFoldB2, unassignedA1, displayChangeC8 } from './rfc3454-tables.mjs';

// RFC 5280 section 7.1 uses RFC 4518 LDAP StringPrep for DirectoryString
// equality. Unknown attribute types retain exact DER equality, so their
// matching rule is never guessed from an ASN.1 string tag alone.
const CASE_IGNORE = new Set([
  '2.5.4.3', // commonName
  '2.5.4.4', // surname
  '2.5.4.5', // serialNumber
  '2.5.4.6', // countryName
  '2.5.4.7', // localityName
  '2.5.4.8', // stateOrProvinceName
  '2.5.4.9', // streetAddress
  '2.5.4.10', // organizationName
  '2.5.4.11', // organizationalUnitName
  '2.5.4.12', // title
  '2.5.4.15', // businessCategory
  '2.5.4.17', // postalCode
  '2.5.4.42', // givenName
  '2.5.4.43', // initials
  '2.5.4.44', // generationQualifier
  '2.5.4.46', // dnQualifier
  '2.5.4.65', // pseudonym
]);
const DOMAIN_COMPONENT = '0.9.2342.19200300.100.1.25';
const fail = () => { throw new ProtocolError('CADES_ISSUER_NAME_ENCODING'); };
const inRange = (cp, lo, hi) => cp >= lo && cp <= hi;
function inRanges(cp, ranges) {
  let lo = 0, hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (cp < ranges[mid][0]) hi = mid - 1;
    else if (cp > ranges[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}
function removed(cp) {
  return cp === 0xad || cp === 0x1806 || cp === 0x034f ||
    inRange(cp, 0x180b, 0x180d) || inRange(cp, 0xfe00, 0xfe0f) ||
    cp === 0xfffc || cp === 0x200b ||
    inRange(cp, 0, 8) || inRange(cp, 0xe, 0x1f) ||
    inRange(cp, 0x7f, 0x84) || inRange(cp, 0x86, 0x9f) ||
    cp === 0x06dd || cp === 0x070f || cp === 0x180e ||
    inRange(cp, 0x200c, 0x200f) || inRange(cp, 0x202a, 0x202e) ||
    inRange(cp, 0x2060, 0x2063) || inRange(cp, 0x206a, 0x206f) ||
    cp === 0xfeff || inRange(cp, 0xfff9, 0xfffb) ||
    inRange(cp, 0x1d173, 0x1d17a) || cp === 0xe0001 ||
    inRange(cp, 0xe0020, 0xe007f);
}
function space(cp) {
  return cp === 0x20 || cp === 0xa0 || cp === 0x1680 ||
    inRange(cp, 0x2000, 0x200a) || inRange(cp, 0x2028, 0x2029) ||
    cp === 0x202f || cp === 0x205f || cp === 0x3000 ||
    inRange(cp, 9, 13) || cp === 0x85;
}
function prohibited(cp) {
  return inRanges(cp, unassignedA1) || displayChangeC8.has(cp) ||
    inRange(cp, 0xe000, 0xf8ff) || inRange(cp, 0xf0000, 0xffffd) ||
    inRange(cp, 0x100000, 0x10fffd) || inRange(cp, 0xfdd0, 0xfdef) ||
    (cp & 0xffff) >= 0xfffe || inRange(cp, 0xd800, 0xdfff) || cp === 0xfffd;
}
function insignificantSpaces(input) {
  const chars = Array.from(input);
  const mark = (char) => /\p{M}/u.test(char);
  const insignificant = (i) => chars[i] === ' ' && !(i + 1 < chars.length && mark(chars[i + 1]));
  if (chars.every((_, i) => insignificant(i))) return '  ';
  let out = '';
  for (let i = 0; i < chars.length;) {
    if (!insignificant(i)) {
      out += chars[i++];
      continue;
    }
    let end = i + 1;
    while (end < chars.length && insignificant(end)) end++;
    out += i === 0 || end === chars.length ? ' ' : '  ';
    i = end;
  }
  if (!out.startsWith(' ')) out = ` ${out}`;
  if (!out.endsWith(' ')) out += ' ';
  return out;
}
function prepareDirectoryString(value) {
  let mapped = '';
  for (const char of value) {
    const cp = char.codePointAt(0);
    if (inRanges(cp, unassignedA1)) fail();
    if (removed(cp)) continue;
    if (space(cp)) {
      mapped += ' ';
      continue;
    }
    mapped += caseFoldB2.get(cp) ?? char;
  }
  const normalized = mapped.normalize('NFKC');
  for (const char of normalized) if (prohibited(char.codePointAt(0))) fail();
  return insignificantSpaces(normalized);
}
function canonicalValue(id, node) {
  if (id === DOMAIN_COMPONENT) {
    if (node.tag !== 0x16 || !node.value.length || node.value.some((byte) => byte > 0x7f)) fail();
    return `dc:${node.value.toString('ascii').toLowerCase()}`;
  }
  if (CASE_IGNORE.has(id)) {
    if (node.tag === 0x0c || node.tag === 0x13) {
      if (!node.value.length) fail();
      let value;
      if (node.tag === 0x0c) {
        try { value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(node.value); }
        catch { fail(); }
      } else {
        // latin1 preserves each original octet; ascii would clear its high bit.
        value = node.value.toString('latin1');
        if (!/^[A-Za-z0-9 '()+,\-./:=?]+$/.test(value)) fail();
      }
      return `ci:${prepareDirectoryString(value)}`;
    }
    // Legacy TeletexString, UniversalString and BMPString are optional in
    // RFC 5280. Exact bytes remain matchable without guessing a transcoding.
    if (![0x14, 0x1c, 0x1e].includes(node.tag)) fail();
  }
  return `der:${node.raw.toString('hex')}`;
}
function canonicalName(raw) {
  const name = parseDER(raw);
  if (name.tag !== 0x30 || !name.children?.length) fail();
  return name.children.map((rdn) => {
    if (rdn.tag !== 0x31 || !rdn.children?.length) fail();
    const attrs = rdn.children.map((attr) => {
      if (attr.tag !== 0x30 || attr.children?.length !== 2 || attr.children[0].tag !== 0x06) fail();
      const id = oidText(attr.children[0]);
      return JSON.stringify([id, canonicalValue(id, attr.children[1])]);
    });
    return attrs.sort();
  });
}
export function sameDistinguishedName(left, right) {
  return JSON.stringify(canonicalName(left)) === JSON.stringify(canonicalName(right));
}
