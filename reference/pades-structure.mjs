import {
  PDFObjectParser,
  PDFContext,
  PDFDict,
  PDFArray,
  PDFName,
  PDFNull,
  PDFRef,
  PDFNumber,
  PDFBool,
  PDFHexString,
  PDFString,
  PDFRawStream,
} from 'pdf-lib';
import { inflateSync } from 'node:zlib';
import { X509Certificate } from 'node:crypto';
import { ProtocolError, parseDER, intValue, oidText, random } from './core.mjs';

// pdf-lib supplies the object model and lexical parser. This selected-profile
// layer does not invoke its recovery scanner: every indirect object is reached
// through a checked classic xref entry, and every signed gap has a source span.
const MAX_OBJECTS = 20000,
  MAX_REVISIONS = 32,
  MAX_MATERIAL = 128;
const WS = '[\\x00\\x09\\x0a\\x0c\\x0d\\x20]';
const whitespace = (byte) => [0, 9, 10, 12, 13, 32].includes(byte);
const delimiter = (byte) =>
  byte === undefined || whitespace(byte) || '()<>[]{}/%'.includes(String.fromCharCode(byte));
const get = (dict, key) => dict?.get(PDFName.of(key));
const name = (value) => (value instanceof PDFName ? value.decodeText() : undefined);
const number = (value) => (value instanceof PDFNumber ? value.asNumber() : NaN);
const refID = (value) => (value instanceof PDFRef ? value.toString() : undefined);
const undefinedRef = (rev, value) => {
  if (!(value instanceof PDFRef)) return false;
  const entry = rev.active.get(value.objectNumber);
  return !entry?.used || entry.generation !== value.generationNumber;
};
const report = (overall, reason) => ({ overall, status: overall, reason });
function failure(code, overall = 'INVALID') {
  const error = new ProtocolError(code);
  error.overall = overall;
  return error;
}
function check(condition, code, overall = 'INVALID') {
  if (!condition) throw failure(code, overall);
}
function integer(value, code) {
  const n = number(value);
  check(Number.isSafeInteger(n) && n >= 0, code);
  return n;
}
function sourceInteger(value, code, integerObjects) {
  check(value instanceof PDFNumber && integerObjects.has(value), code);
  return integer(value, code);
}

class StrictObjectParser extends PDFObjectParser {
  constructor(raw, offset, context, spans, integerObjects, budget) {
    super(PDFObjectParser.forBytes(raw, context).bytes, context);
    this.raw = raw;
    this.spans = spans;
    this.integerObjects = integerObjects;
    this.budget = budget;
    this.depth = 0;
    this.bytes.moveTo(offset);
  }
  parseObject() {
    check(++this.budget.nodes <= 200000 && ++this.depth <= 64, 'PADES_OBJECT_LIMIT', 'UNSUPPORTED');
    try {
      const value = super.parseObject();
      if (value instanceof PDFRef)
        check(
          Number.isSafeInteger(value.objectNumber) &&
            value.objectNumber > 0 &&
            Number.isSafeInteger(value.generationNumber) &&
            value.generationNumber >= 0 &&
            value.generationNumber <= 65535,
          'PADES_REFERENCE',
        );
      return value;
    } finally {
      this.depth--;
    }
  }
  parseRawNumber() {
    const start = this.bytes.offset(),
      value = super.parseRawNumber();
    const token = this.raw.subarray(start, this.bytes.offset()).toString('ascii');
    check(/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(token) && Number.isFinite(value), 'PADES_NUMBER');
    check(Math.abs(value) <= Number.MAX_SAFE_INTEGER, 'PADES_NUMBER_LIMIT', 'UNSUPPORTED');
    return value;
  }
  parseNumberOrRef() {
    const start = this.bytes.offset(),
      value = super.parseNumberOrRef();
    if (value instanceof PDFNumber) {
      let end = start;
      while (!delimiter(this.raw[end])) end++;
      const token = this.raw.toString('ascii', start, end);
      if (/^[+-]?\d+$/.test(token)) this.integerObjects.add(value);
    }
    return value;
  }
  parseName() {
    this.bytes.assertNext(47);
    const start = this.bytes.offset();
    while (!delimiter(this.bytes.peek())) this.bytes.next();
    const token = this.raw.subarray(start, this.bytes.offset()).toString('latin1');
    check(token.length <= 1024, 'PADES_NAME_LIMIT', 'UNSUPPORTED');
    check(
      !/#(?![0-9a-fA-F]{2})/.test(token) && !/#00/i.test(token) && !token.includes('\x00'),
      'PADES_NAME',
    );
    // pdf-lib 1.17.1 normalizes uppercase hex escapes only. Normalize the escape
    // spelling first, without recursively decoding an escaped '#' character.
    return PDFName.of(token.replace(/#[0-9a-fA-F]{2}/g, (escape) => escape.toUpperCase()));
  }
  parseHexString() {
    const value = super.parseHexString();
    const token = value.asString().replace(/[\x00\x09\x0a\x0c\x0d\x20]/g, '');
    check(/^[0-9a-fA-F]*$/.test(token), 'PADES_HEX_STRING');
    return PDFHexString.of(token.length % 2 ? token + '0' : token);
  }
  parseDict() {
    this.bytes.assertNext(60);
    this.bytes.assertNext(60);
    const entries = new Map(),
      spans = new Map();
    this.skipWhitespaceAndComments();
    while (!(this.bytes.peek() === 62 && this.bytes.peekAhead(1) === 62)) {
      check(!this.bytes.done(), 'PADES_DICTIONARY_TRUNCATED');
      const key = this.parseName();
      check(!entries.has(key), 'PADES_DUPLICATE_DICTIONARY_KEY');
      this.skipWhitespaceAndComments();
      const start = this.bytes.offset(),
        value = this.parseObject();
      entries.set(key, value);
      spans.set(key.decodeText(), { start, end: this.bytes.offset() });
      this.skipWhitespaceAndComments();
    }
    this.bytes.assertNext(62);
    this.bytes.assertNext(62);
    const dict = PDFDict.fromMapWithContext(entries, this.context);
    this.spans.set(dict, spans);
    return dict;
  }
  parseDictOrStream() {
    const dict = this.parseDict();
    this.skipWhitespaceAndComments();
    const at = this.bytes.offset();
    if (this.raw.subarray(at, at + 6).toString('ascii') !== 'stream') return dict;
    check(delimiter(this.raw[at + 6]), 'PADES_STREAM_TOKEN');
    const startLine = /^stream[ \t]*(?:\r\n|\n)/.exec(
      this.raw.subarray(at, at + 256).toString('latin1'),
    );
    check(startLine, 'PADES_STREAM_EOL');
    const lengthValue = get(dict, 'Length');
    check(!(lengthValue instanceof PDFRef), 'PADES_INDIRECT_STREAM_LENGTH', 'UNSUPPORTED');
    const length = integer(lengthValue, 'PADES_STREAM_LENGTH'),
      start = at + startLine[0].length,
      end = start + length;
    check(end <= this.raw.length, 'PADES_STREAM_LENGTH');
    this.bytes.moveTo(end);
    if (this.bytes.peek() === 13) {
      this.bytes.next();
      if (this.bytes.peek() === 10) this.bytes.next();
    } else if (this.bytes.peek() === 10) this.bytes.next();
    const tail = this.bytes.offset();
    check(
      this.raw.subarray(tail, tail + 9).toString('ascii') === 'endstream' &&
        delimiter(this.raw[tail + 9]),
      'PADES_STREAM_LENGTH',
    );
    this.bytes.moveTo(tail + 9);
    return PDFRawStream.of(dict, this.raw.subarray(start, end));
  }
}

function skipIgnored(raw, start, end = raw.length) {
  let offset = start;
  while (offset < end) {
    if (whitespace(raw[offset])) offset++;
    else if (raw[offset] === 37) {
      // A reference boundary cannot terminate a comment. Only an actual EOL
      // or the end of the input does so; offsets into its text are not tokens.
      while (offset < raw.length && raw[offset] !== 10 && raw[offset] !== 13) offset++;
      if (offset > end) return -1;
    } else break;
  }
  return offset;
}
function ignored(raw, start, end) {
  return skipIgnored(raw, start, end) === end;
}
function indirectHeader(raw, start) {
  let at = start;
  const integerToken = () => {
    const begin = at;
    while (raw[at] >= 48 && raw[at] <= 57) at++;
    if (at === begin || !delimiter(raw[at])) return undefined;
    const value = Number(raw.subarray(begin, at).toString('ascii'));
    return Number.isSafeInteger(value) ? value : undefined;
  };
  const separator = () => {
    const next = skipIgnored(raw, at);
    if (next === at) return false;
    at = next;
    return true;
  };
  const id = integerToken();
  if (id === undefined || !separator()) return undefined;
  const generation = integerToken();
  if (generation === undefined || !separator()) return undefined;
  if (raw.subarray(at, at + 3).toString('ascii') !== 'obj' || !delimiter(raw[at + 3]))
    return undefined;
  return { id, generation, bodyOffset: at + 3 };
}
function dictionaryView(dict, excluded = []) {
  return dict
    .entries()
    .filter(([key]) => !excluded.includes(key.decodeText()))
    .map(([key, value]) => `${key}:${value}`)
    .sort()
    .join('\n');
}
function derFromHex(value) {
  check(value instanceof PDFHexString, 'PADES_CONTENTS_HEX');
  const raw = Buffer.from(value.asBytes());
  check(raw[0] === 48 && raw.length >= 2, 'PADES_CONTENTS_DER');
  let at = 2,
    length = raw[1];
  if (length & 128) {
    const width = length & 127;
    check(width > 0 && width <= 4 && at + width <= raw.length, 'PADES_CONTENTS_DER');
    length = 0;
    for (let i = 0; i < width; i++) length = length * 256 + raw[at++];
  }
  check(
    at + length <= raw.length && raw.subarray(at + length).every((byte) => byte === 0),
    'PADES_CONTENTS_PADDING',
  );
  const cms = raw.subarray(0, at + length);
  parseDER(cms);
  return cms;
}
function pdfDate(value) {
  check(value instanceof PDFString || value instanceof PDFHexString, 'PADES_SIGNING_TIME');
  const text = value.decodeText();
  // The bounded profile requires seconds and an explicit UTC offset. Truncated
  // PDF dates are valid PDF capabilities, but cannot supply this selected time.
  const match = /^D:(\d{4})(\d\d)?(\d\d)?(\d\d)?(\d\d)?(\d\d)?(Z|[+-]\d\d(?:'\d\d'?)?)?$/.exec(
    text,
  );
  check(match, 'PADES_SIGNING_TIME');
  const [year, month, day, hour, minute, second] = match
    .slice(1, 7)
    .map((value, index) =>
      value === undefined ? (index === 1 || index === 2 ? 1 : 0) : Number(value),
    );
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  check(
    date.getUTCFullYear() === year &&
      date.getUTCMonth() === month - 1 &&
      date.getUTCDate() === day &&
      date.getUTCHours() === hour &&
      date.getUTCMinutes() === minute &&
      date.getUTCSeconds() === second,
    'PADES_SIGNING_TIME',
  );
  let offset = 0;
  if (match[7] && match[7] !== 'Z') {
    const hours = Number(match[7].slice(1, 3)),
      minutes = match[7].length > 3 ? Number(match[7].slice(4, 6)) : 0;
    check(hours <= 23 && minutes <= 59, 'PADES_SIGNING_TIME');
    offset = (hours * 60 + minutes) * 60 * (match[7][0] === '+' ? 1 : -1);
  }
  check(
    match[6] !== undefined && (match[7] === 'Z' || /^[+-]\d\d'\d\d'?$/.test(match[7] ?? '')),
    'PADES_DATE_PRECISION',
    'UNSUPPORTED',
  );
  const seconds = date.getTime() / 1000 - offset;
  check(Number.isSafeInteger(seconds), 'PADES_SIGNING_TIME');
  check(seconds >= 0, 'PADES_DATE_RANGE_UNSUPPORTED', 'UNSUPPORTED');
  return seconds;
}

function parseDocument(input) {
  const raw = Buffer.from(input);
  check(raw.length <= 64 * 1024 * 1024, 'PADES_SIZE_LIMIT', 'UNSUPPORTED');
  check(/^%PDF-\d\.\d(?:\r\n|\r|\n)/.test(raw.subarray(0, 16).toString('latin1')), 'PADES_HEADER');
  check(
    raw.subarray(0, 8).toString('ascii') === '%PDF-1.7',
    'PADES_VERSION_UNSUPPORTED',
    'UNSUPPORTED',
  );
  const spans = new WeakMap(),
    integerObjects = new WeakSet(),
    budget = { nodes: 0 },
    context = PDFContext.create(),
    definitions = new Map();
  const diagnostics = [],
    revisions = [];
  const diagnostic = (reason, overall = 'UNSUPPORTED') => {
    if (!diagnostics.some((item) => item.reason === reason && item.overall === overall))
      diagnostics.push(report(overall, reason));
  };
  const parser = (offset) => new StrictObjectParser(raw, offset, context, spans, integerObjects, budget);
  const text = raw.toString('latin1');
  const firstParser = parser(0);
  firstParser.skipWhitespaceAndComments();
  const firstHeader = indirectHeader(raw, firstParser.bytes.offset());
  if (firstHeader) {
    firstParser.bytes.moveTo(firstHeader.bodyOffset);
    const firstObject = firstParser.parseObject();
    if (firstObject instanceof PDFDict && get(firstObject, 'Linearized') !== undefined)
      throw failure('PADES_LINEARIZED_UNSUPPORTED', 'UNSUPPORTED');
  }
  const last = new RegExp(`(?:^|[\\r\\n])startxref${WS}+(\\d+)${WS}+%%EOF${WS}*$`).exec(
    text.slice(-4096),
  );
  check(last, 'PADES_TRAILER');
  let xrefOffset = Number(last[1]);
  const visited = new Set();
  while (true) {
    check(
      Number.isSafeInteger(xrefOffset) && xrefOffset >= 9 && xrefOffset < raw.length,
      'PADES_XREF_OFFSET',
    );
    check(!visited.has(xrefOffset), 'PADES_PREV_CYCLE');
    visited.add(xrefOffset);
    check(visited.size <= MAX_REVISIONS, 'PADES_REVISION_LIMIT', 'UNSUPPORTED');
    if (!text.startsWith('xref', xrefOffset)) {
      check(indirectHeader(raw, xrefOffset), 'PADES_XREF_OFFSET');
      throw failure('PADES_XREF_STREAM_UNSUPPORTED', 'UNSUPPORTED');
    }
    let at = xrefOffset;
    function line() {
      const match = /^([^\r\n]*)(?:\r\n|\r|\n)/.exec(text.slice(at, at + 1024));
      check(match, 'PADES_XREF_LINE');
      at += match[0].length;
      return match[1];
    }
    check(line() === 'xref', 'PADES_XREF_TOKEN');
    const entries = new Map();
    while (true) {
      while (whitespace(raw[at])) at++;
      if (text.startsWith('trailer', at)) break;
      const section = /^(\d+) (\d+)[ \t]*$/.exec(line());
      check(section, 'PADES_XREF_SUBSECTION');
      const first = Number(section[1]),
        count = Number(section[2]);
      check(
        Number.isSafeInteger(first) &&
          Number.isSafeInteger(count) &&
          count > 0 &&
          first + count <= MAX_OBJECTS,
        'PADES_OBJECT_LIMIT',
        'UNSUPPORTED',
      );
      for (let i = 0; i < count; i++) {
        const entry = /^(\d{10}) (\d{5}) ([nf])(?: \r| \n|\r\n)$/.exec(text.slice(at, at + 20));
        check(entry, 'PADES_XREF_ENTRY');
        at += 20;
        const id = first + i,
          offset = Number(entry[1]),
          generation = Number(entry[2]);
        check(!entries.has(id) && generation <= 65535, 'PADES_XREF_DUPLICATE_OR_GENERATION');
        if (id === 0) check(entry[3] === 'f' && generation === 65535, 'PADES_XREF_ZERO');
        else if (entry[3] === 'n')
          check(
            offset >= 9 && offset < xrefOffset && generation < 65535,
            'PADES_XREF_OBJECT_OFFSET',
          );
        entries.set(id, { id, offset, generation, used: entry[3] === 'n' });
      }
    }
    check(delimiter(raw[at + 7]), 'PADES_TRAILER');
    const p = parser(at + 7),
      trailer = p.parseObject();
    check(trailer instanceof PDFDict, 'PADES_TRAILER');
    p.skipWhitespaceAndComments();
    const tail = new RegExp(`^startxref${WS}+(\\d+)${WS}+%%EOF(?:\\r\\n|\\r|\\n)?`).exec(
      text.slice(p.bytes.offset()),
    );
    check(tail && Number(tail[1]) === xrefOffset, 'PADES_STARTXREF_MISMATCH');
    const length = p.bytes.offset() + tail[0].length;
    const markerEnd = p.bytes.offset() + tail[0].indexOf('%%EOF') + 5;
    if (get(trailer, 'Encrypt')) throw failure('PADES_ENCRYPTION_UNSUPPORTED', 'UNSUPPORTED');
    if (get(trailer, 'XRefStm')) throw failure('PADES_HYBRID_XREF_UNSUPPORTED', 'UNSUPPORTED');
    const size = integer(get(trailer, 'Size'), 'PADES_TRAILER_SIZE');
    check(
      size > 0 && size <= MAX_OBJECTS && [...entries.keys()].every((id) => id < size),
      'PADES_TRAILER_SIZE',
    );
    check(get(trailer, 'Root') instanceof PDFRef, 'PADES_ROOT');
    for (const key of trailer.keys())
      if (!['Size', 'Root', 'Info', 'ID', 'Prev'].includes(key.decodeText()))
        diagnostic('PADES_TRAILER_EXTENSION_UNSUPPORTED');
    revisions.push({ xrefOffset, length, markerEnd, trailer, entries, size });
    const previous = get(trailer, 'Prev');
    if (previous === undefined) break;
    const prev = integer(previous, 'PADES_PREV');
    check(prev > 0 && prev < xrefOffset, 'PADES_PREV_ORDER');
    xrefOffset = prev;
  }
  revisions.reverse();
  check(ignored(raw, revisions.at(-1).length, raw.length), 'PADES_TRAILING_DATA');
  revisions.at(-1).length = raw.length;
  let active = new Map();
  for (let i = 0; i < revisions.length; i++) {
    const rev = revisions[i],
      start = i ? revisions[i - 1].length : 0;
    check(start < rev.xrefOffset, 'PADES_REVISION_OVERLAP');
    const objects = [];
    for (const entry of rev.entries.values()) {
      const old = active.get(entry.id);
      if (entry.used) {
        if (entry.offset < start && i)
          check(
            old?.used && old.offset === entry.offset && old.generation === entry.generation,
            'PADES_XREF_RETROACTIVE_OBJECT',
          );
        let def = definitions.get(entry.offset);
        if (!def) {
          const header = indirectHeader(raw, entry.offset);
          check(
            header && header.id === entry.id && header.generation === entry.generation,
            'PADES_XREF_OBJECT_HEADER',
          );
          const p = parser(header.bodyOffset),
            object = p.parseObject();
          p.skipWhitespaceAndComments();
          const end = p.bytes.offset();
          check(text.startsWith('endobj', end) && delimiter(raw[end + 6]), 'PADES_ENDOBJ');
          def = {
            object,
            offset: entry.offset,
            end: end + 6,
            id: entry.id,
            generation: entry.generation,
          };
          definitions.set(entry.offset, def);
        }
        check(
          def.id === entry.id && def.generation === entry.generation && def.end <= rev.xrefOffset,
          'PADES_OBJECT_OVERLAP',
        );
        if (entry.offset >= start) objects.push(def);
        entry.def = def;
      }
      active.set(entry.id, entry);
    }
    check(active.size === rev.size && active.has(0), 'PADES_XREF_MISSING_ENTRY');
    objects.sort((a, b) => a.offset - b.offset);
    let end = start;
    for (const def of objects) {
      check(
        def.offset >= end && ignored(raw, end, def.offset),
        'PADES_UNINDEXED_OR_OVERLAPPING_OBJECT',
      );
      end = def.end;
    }
    check(ignored(raw, end, rev.xrefOffset), 'PADES_UNINDEXED_OBJECT');
    rev.active = new Map(active);
    rev.resolve = (value) => {
      if (!(value instanceof PDFRef)) return value;
      const entry = rev.active.get(value.objectNumber);
      check(entry?.used && entry.generation === value.generationNumber, 'PADES_DANGLING_REFERENCE');
      return entry.def.object;
    };
    rev.root = get(rev.trailer, 'Root');
    rev.catalog = rev.resolve(rev.root);
    check(
      rev.catalog instanceof PDFDict && name(get(rev.catalog, 'Type')) === 'Catalog',
      'PADES_CATALOG',
    );
    if (get(rev.catalog, 'Version') && name(get(rev.catalog, 'Version')) !== '1.7')
      diagnostic('PADES_VERSION_UNSUPPORTED');
    inspectCapabilities(rev, diagnostic);
    inspectSignedPageText(rev, diagnostic, integerObjects);
    rev.form = rev.resolve(get(rev.catalog, 'AcroForm'));
    check(rev.form === undefined || rev.form instanceof PDFDict, 'PADES_ACROFORM');
    if (rev.form && get(rev.form, 'SigFlags') !== undefined) {
      const flags = sourceInteger(rev.resolve(get(rev.form, 'SigFlags')), 'PADES_SIG_FLAGS', integerObjects);
      check(flags <= 3, 'PADES_SIG_FLAGS');
    }
    rev.fieldsValue = get(rev.form, 'Fields');
    const fields = rev.resolve(rev.fieldsValue);
    check(!rev.form || fields instanceof PDFArray, 'PADES_FIELDS');
    rev.fields = fields?.asArray() ?? [];
    rev.signatures = collectSignatures(rev, raw, spans, integerObjects, revisions, i, diagnostic);
    rev.material = dssMaterial(rev, diagnostic);
  }
  const signatures = [],
    seen = new Map();
  let modificationPolicy = report('VALID', 'PADES_PRESERVATION_APPEND');
  for (let i = 0; i < revisions.length; i++) {
    const rev = revisions[i];
    for (const signature of rev.signatures) {
      const old = seen.get(signature.id);
      if (!old) {
        check(signature.revisionIndex === i, 'PADES_RETROACTIVE_SIGNATURE_FIELD');
        seen.set(signature.id, signature);
        signatures.push(signature);
      } else
        check(
          old.cms.equals(signature.cms) &&
            old.signedRevisionLength === signature.signedRevisionLength,
          'PADES_SIGNATURE_REPLACED',
        );
    }
    if (i && revisions[i - 1].signatures.length) {
      try {
        enforceAppend(revisions[i - 1], rev, raw);
      } catch (error) {
        modificationPolicy = report(error.overall ?? 'INVALID', error.code ?? 'PADES_MODIFICATION');
      }
    }
  }
  if (signatures.filter((s) => s.kind === 'SIGNATURE').length > 1)
    diagnostic('PADES_MULTIPLE_APPROVALS_UNSUPPORTED');
  if (signatures.length && signatures[0].kind !== 'SIGNATURE')
    diagnostic('PADES_TIMESTAMP_WITHOUT_APPROVAL', 'INVALID');
  check(signatures.length <= 32, 'PADES_SIGNATURE_LIMIT', 'UNSUPPORTED');
  return { raw, revisions, signatures, modificationPolicy, diagnostics };
}

const MAX_PAGE_CONTENT = 16 * 1024 * 1024;
const CONTENT_OPERATORS = new Set([
  'q', 'Q', 'cm', 'w', 'J', 'j', 'M', 'd', 'ri', 'i', 'gs',
  'm', 'l', 'c', 'v', 'y', 'h', 're', 'S', 's', 'f', 'F', 'f*',
  'B', 'B*', 'b', 'b*', 'n', 'W', 'W*', 'BT', 'ET',
  'Tc', 'Tw', 'Tz', 'TL', 'Tf', 'Tr', 'Ts', 'Td', 'TD',
  'Tm', 'T*', 'Tj', 'TJ', "'", '"', 'd0', 'd1',
  'CS', 'cs', 'SC', 'SCN', 'sc', 'scn', 'G', 'g', 'RG',
  'rg', 'K', 'k', 'sh', 'Do', 'MP', 'DP', 'BMC', 'BDC',
  'EMC', 'BX', 'EX',
]);

function inspectContentTextOperators(bytes, context, diagnostic, fontAvailable, resourceAvailable) {
  const raw = Buffer.from(bytes);
  const parser = new StrictObjectParser(
    raw, 0, context, new WeakMap(), new WeakSet(), { nodes: 0 },
  );
  let operands = [], inText = false;
  const string = value => value instanceof PDFString || value instanceof PDFHexString;
  const numeric = value => value instanceof PDFNumber && Number.isFinite(value.asNumber());
  const requireOperands = types => {
    check(operands.length === types.length, 'PADES_TEXT_OPERAND');
    for (let i = 0; i < types.length; i++) {
      const valid = types[i] === 'number' ? numeric(operands[i])
        : types[i] === 'name' ? operands[i] instanceof PDFName
          : types[i] === 'string' ? string(operands[i])
            : false;
      check(valid, 'PADES_TEXT_OPERAND');
    }
  };
  while (true) {
    parser.skipWhitespaceAndComments();
    if (parser.bytes.done()) break;
    const at = parser.bytes.offset(), byte = raw[at];
    const keyword = (text) =>
      raw.subarray(at, at + text.length).toString('ascii') === text &&
      delimiter(raw[at + text.length]);
    const objectStart = byte === 47 || byte === 40 || byte === 60 || byte === 91 ||
      byte === 43 || byte === 45 || byte === 46 || (byte >= 48 && byte <= 57) ||
      keyword('true') || keyword('false') || keyword('null');
    if (objectStart) {
      try {
        operands.push(parser.parseObject());
      } catch (error) {
        if (error instanceof ProtocolError) throw error;
        throw failure('PADES_CONTENT_TOKEN');
      }
      check(operands.length <= 128, 'PADES_CONTENT_OPERAND_LIMIT', 'UNSUPPORTED');
      continue;
    }
    let end = at;
    while (end < raw.length && !delimiter(raw[end])) end++;
    check(end > at, 'PADES_CONTENT_TOKEN');
    const operator = raw.toString('ascii', at, end);
    check(/^[\x21-\x7e]{1,32}$/.test(operator), 'PADES_CONTENT_OPERATOR');
    parser.bytes.moveTo(end);
    if (operator === 'BI') throw failure('PADES_INLINE_IMAGE_UNSUPPORTED', 'UNSUPPORTED');
    if (!CONTENT_OPERATORS.has(operator)) diagnostic('PADES_CONTENT_OPERATOR_UNSUPPORTED');
    if (operator === 'BT') {
      check(operands.length === 0 && !inText, 'PADES_TEXT_BALANCE');
      inText = true;
    } else if (operator === 'ET') {
      check(operands.length === 0 && inText, 'PADES_TEXT_BALANCE');
      inText = false;
    } else if (['Tc', 'Tw', 'Tz', 'TL', 'Ts'].includes(operator)) {
      requireOperands(['number']);
    } else if (operator === 'Tr') {
      requireOperands(['number']);
      check(Number.isInteger(operands[0].asNumber()) &&
        operands[0].asNumber() >= 0 && operands[0].asNumber() <= 7, 'PADES_TEXT_OPERAND');
    } else if (operator === 'Tf') {
      requireOperands(['name', 'number']);
      check(fontAvailable(name(operands[0])), 'PADES_TEXT_FONT_RESOURCE');
    } else if (operator === 'gs' || operator === 'sh' || operator === 'Do') {
      check(operands.length === 1 && operands[0] instanceof PDFName,
        'PADES_PAGE_RESOURCE_MEMBER');
      const category = operator === 'gs' ? 'ExtGState'
        : operator === 'sh' ? 'Shading' : 'XObject';
      check(resourceAvailable(category, name(operands[0])), 'PADES_PAGE_RESOURCE_MEMBER');
    } else if (operator === 'scn' || operator === 'SCN') {
      const patternName = operands.at(-1);
      if (patternName instanceof PDFName)
        check(resourceAvailable('Pattern', name(patternName)), 'PADES_PAGE_RESOURCE_MEMBER');
    } else if (operator === 'Tm') {
      check(inText, 'PADES_TEXT_SCOPE');
      requireOperands(Array(6).fill('number'));
    } else if (operator === 'Td' || operator === 'TD') {
      check(inText, 'PADES_TEXT_SCOPE');
      requireOperands(['number', 'number']);
    } else if (operator === 'T*') {
      check(inText, 'PADES_TEXT_SCOPE');
      requireOperands([]);
    } else if (operator === 'Tj' || operator === "'") {
      check(inText, 'PADES_TEXT_SCOPE');
      requireOperands(['string']);
    } else if (operator === '"') {
      check(inText, 'PADES_TEXT_SCOPE');
      requireOperands(['number', 'number', 'string']);
    } else if (operator === 'TJ') {
      check(inText && operands.length === 1 && operands[0] instanceof PDFArray,
        'PADES_TEXT_OPERAND');
      for (const item of operands[0].asArray())
        check(string(item) || numeric(item), 'PADES_TEXT_OPERAND');
    }
    operands = [];
  }
  check(!inText, 'PADES_TEXT_BALANCE');
  check(operands.length === 0, 'PADES_CONTENT_TRAILING_OPERAND');
}

const IMAGE_FILTERS = new Set([
  'ASCIIHexDecode', 'ASCII85Decode', 'LZWDecode', 'FlateDecode',
  'RunLengthDecode', 'CCITTFaxDecode', 'JBIG2Decode', 'DCTDecode',
  'JPXDecode', 'Crypt',
]);

function inspectImageXObject(rev, resources, stream, diagnostic, integerObjects) {
  const dict = stream.dict;
  const entry = key => {
    const raw = get(dict, key);
    if (raw === undefined || undefinedRef(rev, raw)) return undefined;
    const value = rev.resolve(raw);
    return value === PDFNull ? undefined : value;
  };
  const type = entry('Type');
  check(type === undefined || name(type) === 'XObject', 'PADES_IMAGE_TYPE');
  const width = sourceInteger(entry('Width'), 'PADES_IMAGE_WIDTH', integerObjects);
  const height = sourceInteger(entry('Height'), 'PADES_IMAGE_HEIGHT', integerObjects);
  check(width > 0, 'PADES_IMAGE_WIDTH');
  check(height > 0, 'PADES_IMAGE_HEIGHT');

  const filterValue = entry('Filter');
  const filters = filterValue === undefined ? []
    : filterValue instanceof PDFArray ? filterValue.asArray().map(value => name(rev.resolve(value)))
      : [name(filterValue)];
  check(filters.every(filter => typeof filter === 'string'), 'PADES_IMAGE_FILTER');
  const unsupportedFilter = filters.some(
    filter => !IMAGE_FILTERS.has(filter) || filter === 'Crypt',
  );
  const jpx = filters.at(-1) === 'JPXDecode';
  const imageMaskValue = entry('ImageMask');
  check(imageMaskValue === undefined || imageMaskValue instanceof PDFBool, 'PADES_IMAGE_MASK');
  const imageMask = imageMaskValue?.asBoolean() ?? false;
  if (imageMask) check(entry('Mask') === undefined, 'PADES_IMAGE_MASK');

  const colorsRaw = get(resources, 'ColorSpace');
  const resourceColors = () => {
    if (colorsRaw === undefined || undefinedRef(rev, colorsRaw)) return undefined;
    const colors = rev.resolve(colorsRaw);
    if (colors === PDFNull) return undefined;
    check(colors instanceof PDFDict, 'PADES_IMAGE_COLORSPACE');
    return colors;
  };
  const colorComponents = (value, seen = new Set(), allowDefault = true,
    expectedDefaultComponents) => {
    if (value instanceof PDFArray) {
      const family = name(rev.resolve(value.get(0)));
      check(['CalGray', 'CalRGB', 'Lab', 'ICCBased', 'Indexed', 'Separation',
        'DeviceN'].includes(family), 'PADES_IMAGE_COLORSPACE');
      if (expectedDefaultComponents !== undefined) {
        check(!['Lab', 'Indexed'].includes(family), 'PADES_IMAGE_COLORSPACE');
        const knownComponents = { CalGray: 1, CalRGB: 3, Separation: 1 };
        let components = knownComponents[family];
        if (family === 'ICCBased') {
          const profile = rev.resolve(value.get(1));
          if (profile instanceof PDFRawStream)
            components = sourceInteger(rev.resolve(get(profile.dict, 'N')),
              'PADES_IMAGE_COLORSPACE', integerObjects);
        } else if (family === 'DeviceN') {
          const names = rev.resolve(value.get(1));
          if (names instanceof PDFArray) components = names.size();
        }
        if (components !== undefined)
          check(components === expectedDefaultComponents, 'PADES_IMAGE_COLORSPACE');
      }
      diagnostic('PADES_IMAGE_COLORSPACE_UNSUPPORTED');
      return undefined;
    }
    const colorName = name(value);
    check(colorName !== undefined && colorName !== 'Pattern', 'PADES_IMAGE_COLORSPACE');
    const deviceComponents = { DeviceGray: 1, DeviceRGB: 3, DeviceCMYK: 4 };
    if (Object.hasOwn(deviceComponents, colorName)) {
      const components = deviceComponents[colorName];
      if (allowDefault) {
        const defaultRaw = get(resourceColors(), `Default${colorName.slice(6)}`);
        if (defaultRaw !== undefined && !undefinedRef(rev, defaultRaw)) {
          const resolved = rev.resolve(defaultRaw);
          if (resolved !== PDFNull) {
            const defaultComponents = colorComponents(resolved, seen, false, components);
            if (defaultComponents === undefined) return undefined;
            check(defaultComponents === components, 'PADES_IMAGE_COLORSPACE');
          }
        }
      }
      return components;
    }
    check(!seen.has(colorName), 'PADES_IMAGE_COLORSPACE');
    seen.add(colorName);
    const colors = resourceColors();
    check(colors instanceof PDFDict, 'PADES_IMAGE_COLORSPACE');
    const member = get(colors, colorName);
    check(member !== undefined && !undefinedRef(rev, member), 'PADES_IMAGE_COLORSPACE');
    const resolved = rev.resolve(member);
    check(resolved !== PDFNull, 'PADES_IMAGE_COLORSPACE');
    return colorComponents(resolved, seen, allowDefault, expectedDefaultComponents);
  };
  const colorValue = entry('ColorSpace');
  if (imageMask) check(colorValue === undefined, 'PADES_IMAGE_COLORSPACE');
  else if (!jpx) check(colorValue !== undefined, 'PADES_IMAGE_COLORSPACE');
  const components = imageMask ? 1 : colorValue === undefined ? undefined
    : colorComponents(colorValue);

  const bitsValue = entry('BitsPerComponent');
  let bits;
  if (!jpx) {
    if (imageMask && bitsValue === undefined) bits = 1;
    else {
      bits = sourceInteger(bitsValue, 'PADES_IMAGE_BITS_PER_COMPONENT', integerObjects);
      check(imageMask ? bits === 1 : [1, 2, 4, 8, 16].includes(bits),
        'PADES_IMAGE_BITS_PER_COMPONENT');
    }
  }
  if (bits !== undefined) {
    const sampleFilter = filters.at(-1);
    if (['CCITTFaxDecode', 'JBIG2Decode'].includes(sampleFilter))
      check(bits === 1, 'PADES_IMAGE_BITS_PER_COMPONENT');
    if (['DCTDecode', 'RunLengthDecode'].includes(sampleFilter))
      check(bits === 8, 'PADES_IMAGE_BITS_PER_COMPONENT');
  }

  const decode = entry('Decode');
  if (decode !== undefined && (imageMask || !jpx)) {
    check(decode instanceof PDFArray, 'PADES_IMAGE_DECODE');
    const values = decode.asArray().map(value => number(rev.resolve(value)));
    check(values.every(Number.isFinite), 'PADES_IMAGE_DECODE');
    if (imageMask)
      check(values.length === 2 && ((values[0] === 0 && values[1] === 1) ||
        (values[0] === 1 && values[1] === 0)), 'PADES_IMAGE_DECODE');
    else if (components !== undefined)
      check(values.length === 2 * components, 'PADES_IMAGE_DECODE');
  }
  if (filters.length === 0 && components !== undefined && bits !== undefined) {
    const rowBytes = (BigInt(width) * BigInt(components) * BigInt(bits) + 7n) / 8n;
    const expected = rowBytes * BigInt(height);
    check(expected <= 64n * 1024n * 1024n, 'PADES_IMAGE_LIMIT', 'UNSUPPORTED');
    check(BigInt(stream.getContents().length) === expected, 'PADES_IMAGE_DATA_LENGTH');
  }
  if (unsupportedFilter) diagnostic('PADES_IMAGE_FILTER_UNSUPPORTED');
}

// Admit only a directly selected axial shading with one Type 2 function.
// Other function families and function arrays need a separate rendering contract.
function inspectAxialType2Function(rev, resources, shading, diagnostic, integerObjects) {
  const shadingDict = shading instanceof PDFRawStream ? shading.dict : shading;
  const shadingType = sourceInteger(rev.resolve(get(shadingDict, 'ShadingType')),
    'PADES_SHADING_TYPE', integerObjects);
  check(shadingType >= 1 && shadingType <= 7, 'PADES_SHADING_TYPE');
  if (shadingType !== 2) return;
  check(shading instanceof PDFDict, 'PADES_SHADING_TYPE');
  const numericArray = (dict, key, required, code) => {
    const raw = get(dict, key);
    if (raw === undefined || undefinedRef(rev, raw)) {
      check(!required, code);
      return undefined;
    }
    const value = rev.resolve(raw);
    if (value === PDFNull) {
      check(!required, code);
      return undefined;
    }
    check(value instanceof PDFArray, code);
    const values = value.asArray().map(item => number(rev.resolve(item)));
    check(values.length > 0 && values.every(Number.isFinite), code);
    return values;
  };
  check(numericArray(shadingDict, 'Coords', true, 'PADES_SHADING_COORDS').length === 4,
    'PADES_SHADING_COORDS');
  const bbox = numericArray(shadingDict, 'BBox', false, 'PADES_SHADING_BBOX');
  if (bbox !== undefined) check(bbox.length === 4, 'PADES_SHADING_BBOX');
  const rawExtend = get(shadingDict, 'Extend');
  if (rawExtend !== undefined && !undefinedRef(rev, rawExtend)) {
    const extend = rev.resolve(rawExtend);
    if (extend !== PDFNull) {
      check(extend instanceof PDFArray && extend.size() === 2,
        'PADES_SHADING_EXTEND');
      check(extend.asArray().every(item => rev.resolve(item) instanceof PDFBool),
        'PADES_SHADING_EXTEND');
    }
  }
  const rawFunction = get(shadingDict, 'Function');
  check(rawFunction !== undefined && !undefinedRef(rev, rawFunction),
    'PADES_TYPE2_FUNCTION_TYPE');
  const resolved = rev.resolve(rawFunction);
  if (resolved instanceof PDFArray || resolved instanceof PDFRawStream) {
    diagnostic('PADES_SHADING_FUNCTION_UNSUPPORTED');
    return;
  }
  check(resolved instanceof PDFDict, 'PADES_TYPE2_FUNCTION_TYPE');
  const functionType = sourceInteger(rev.resolve(get(resolved, 'FunctionType')),
    'PADES_TYPE2_FUNCTION_TYPE', integerObjects);
  if (functionType !== 2) {
    check([0, 3, 4].includes(functionType), 'PADES_TYPE2_FUNCTION_TYPE');
    diagnostic('PADES_SHADING_FUNCTION_UNSUPPORTED');
    return;
  }
  const functionArray = (key, required) => numericArray(resolved, key, required,
    `PADES_TYPE2_FUNCTION_${key.toUpperCase()}`);
  const shadingDomain = numericArray(shadingDict, 'Domain', false, 'PADES_SHADING_DOMAIN') ?? [0, 1];
  check(shadingDomain.length === 2 && shadingDomain[0] <= shadingDomain[1],
    'PADES_SHADING_DOMAIN');
  const domain = functionArray('Domain', true);
  check(domain.length === 2 && domain[0] <= domain[1], 'PADES_TYPE2_FUNCTION_DOMAIN');
  check(domain[0] <= shadingDomain[0] && domain[1] >= shadingDomain[1],
    'PADES_TYPE2_FUNCTION_DOMAIN');
  const c0 = functionArray('C0', false) ?? [0];
  const c1 = functionArray('C1', false) ?? [1];
  check(c0.length === c1.length, 'PADES_TYPE2_FUNCTION_C1');
  check(c0.length <= 32, 'PADES_TYPE2_FUNCTION_LIMIT', 'UNSUPPORTED');
  const exponent = number(rev.resolve(get(resolved, 'N')));
  check(Number.isFinite(exponent), 'PADES_TYPE2_FUNCTION_N');
  check(Number.isInteger(exponent) || domain[0] >= 0, 'PADES_TYPE2_FUNCTION_DOMAIN');
  check(exponent >= 0 || domain[0] > 0 || domain[1] < 0,
    'PADES_TYPE2_FUNCTION_DOMAIN');
  const range = functionArray('Range', false);
  if (range !== undefined) {
    check(range.length === 2 * c0.length, 'PADES_TYPE2_FUNCTION_RANGE');
    for (let i = 0; i < range.length; i += 2)
      check(range[i] <= range[i + 1], 'PADES_TYPE2_FUNCTION_RANGE');
  }
  const colorSpace = name(rev.resolve(get(shadingDict, 'ColorSpace')));
  const components = { DeviceGray: 1, DeviceRGB: 3, DeviceCMYK: 4 }[colorSpace];
  if (components === undefined) diagnostic('PADES_SHADING_COLORSPACE_UNSUPPORTED');
  else {
    check(c0.length === components, 'PADES_TYPE2_FUNCTION_C1');
    const colorResources = rev.resolve(get(resources, 'ColorSpace'));
    if (colorResources instanceof PDFDict) {
      const defaultColor = get(colorResources, `Default${colorSpace.slice(6)}`);
      if (defaultColor !== undefined && !undefinedRef(rev, defaultColor) &&
          rev.resolve(defaultColor) !== PDFNull)
        diagnostic('PADES_SHADING_COLORSPACE_UNSUPPORTED');
    }
  }
}

function inspectSignedPageText(rev, diagnostic, integerObjects) {
  const pagesRoot = get(rev.catalog, 'Pages');
  check(pagesRoot instanceof PDFRef, 'PADES_PAGES_REFERENCE');
  const seen = new Set();
  let pageCount = 0, decodedBytes = 0;
  const optionalPageEntry = (dict, key) => {
    const value = get(dict, key);
    if (value === undefined) return undefined;
    if (undefinedRef(rev, value)) return undefined;
    const resolved = rev.resolve(value);
    return resolved === PDFNull ? undefined : resolved;
  };
  const checkedMediaBox = value => {
    const rectangle = rev.resolve(value);
    check(rectangle instanceof PDFArray && rectangle.size() === 4, 'PADES_PAGE_MEDIABOX');
    for (const item of rectangle.asArray()) {
      const coordinate = rev.resolve(item);
      check(coordinate instanceof PDFNumber && Number.isFinite(coordinate.asNumber()),
        'PADES_PAGE_MEDIABOX');
    }
    return rectangle;
  };
  const checkedRotate = value => {
    const rotation = rev.resolve(value);
    check(rotation instanceof PDFNumber && integerObjects.has(rotation), 'PADES_PAGE_ROTATE');
    const degrees = rotation.asNumber();
    check(Number.isSafeInteger(degrees) && degrees % 90 === 0, 'PADES_PAGE_ROTATE');
  };
  const checkedLineArray = (value, length, code) => {
    const array = rev.resolve(value);
    check(array instanceof PDFArray && array.size() === length, code);
    for (const item of array.asArray())
      check(Number.isFinite(number(rev.resolve(item))), code);
  };
  const inspectLineAnnotations = page => {
    const annotations = optionalPageEntry(page, 'Annots');
    if (!(annotations instanceof PDFArray)) return;
    for (const entry of annotations.asArray()) {
      const annotation = rev.resolve(entry);
      if (!(annotation instanceof PDFDict) ||
          name(rev.resolve(get(annotation, 'Subtype'))) !== 'Line') continue;
      // An appearance stream overrides these dictionary fields; it needs its own admission.
      if (optionalPageEntry(annotation, 'AP') !== undefined) {
        diagnostic('PADES_LINE_AP_UNSUPPORTED');
        continue;
      }
      checkedLineArray(get(annotation, 'L'), 4, 'PADES_LINE_L');
      const endings = optionalPageEntry(annotation, 'LE');
      if (endings !== undefined) {
        check(endings instanceof PDFArray && endings.size() === 2, 'PADES_LINE_LE');
        const styles = new Set(['None', 'Square', 'Circle', 'Diamond', 'OpenArrow',
          'ClosedArrow', 'Butt', 'ROpenArrow', 'RClosedArrow', 'Slash']);
        for (const item of endings.asArray())
          check(styles.has(name(rev.resolve(item))), 'PADES_LINE_LE');
      }
      const leader = optionalPageEntry(annotation, 'LL');
      if (leader !== undefined)
        check(Number.isFinite(number(leader)), 'PADES_LINE_LL');
      const extension = optionalPageEntry(annotation, 'LLE');
      if (extension !== undefined) {
        check(leader !== undefined && Number.isFinite(number(extension)) &&
          number(extension) >= 0, 'PADES_LINE_LLE');
      }
      const captionOffset = optionalPageEntry(annotation, 'CO');
      if (captionOffset !== undefined)
        checkedLineArray(captionOffset, 2, 'PADES_LINE_CO');
    }
  };
  const streamBytes = reference => {
    check(reference instanceof PDFRef, 'PADES_PAGE_CONTENT_REFERENCE');
    const stream = rev.resolve(reference);
    check(stream instanceof PDFRawStream, 'PADES_PAGE_CONTENT_STREAM');
    const filterValue = rev.resolve(get(stream.dict, 'Filter'));
    const filter = filterValue instanceof PDFArray && filterValue.size() === 1
      ? rev.resolve(filterValue.get(0)) : filterValue;
    const paramsValue = rev.resolve(get(stream.dict, 'DecodeParms'));
    const params = paramsValue instanceof PDFArray && paramsValue.size() === 1
      ? rev.resolve(paramsValue.get(0)) : paramsValue;
    if (filter !== undefined && name(filter) !== 'FlateDecode') {
      diagnostic('PADES_PAGE_CONTENT_FILTER_UNSUPPORTED');
      return undefined;
    }
    if (params !== undefined && params !== PDFNull) {
      diagnostic('PADES_PAGE_CONTENT_FILTER_UNSUPPORTED');
      return undefined;
    }
    let bytes = Buffer.from(stream.getContents());
    if (filter !== undefined) {
      try {
        bytes = inflateSync(bytes, { maxOutputLength: MAX_PAGE_CONTENT });
      } catch (error) {
        if (error?.code === 'ERR_BUFFER_TOO_LARGE')
          throw failure('PADES_PAGE_CONTENT_LIMIT', 'UNSUPPORTED');
        throw failure('PADES_PAGE_CONTENT_FLATE');
      }
    }
    decodedBytes += bytes.length;
    check(decodedBytes <= MAX_PAGE_CONTENT, 'PADES_PAGE_CONTENT_LIMIT', 'UNSUPPORTED');
    return bytes;
  };
  const visit = (reference, depth = 0, inheritedResources, inheritedMediaBox, parentReference) => {
    check(reference instanceof PDFRef, 'PADES_PAGE_TREE_REFERENCE');
    const id = refID(reference);
    check(!seen.has(id) && depth <= 64, 'PADES_PAGE_TREE_CYCLE_OR_DEPTH');
    seen.add(id);
    const dict = rev.resolve(reference);
    check(dict instanceof PDFDict, 'PADES_PAGE_TREE_NODE');
    const resourceValue = optionalPageEntry(dict, 'Resources');
    const resources = resourceValue === undefined ? inheritedResources : resourceValue;
    check(resources === undefined || resources instanceof PDFDict, 'PADES_PAGE_RESOURCES');
    const mediaValue = optionalPageEntry(dict, 'MediaBox');
    const mediaBox = mediaValue === undefined ? inheritedMediaBox : checkedMediaBox(mediaValue);
    const rotateValue = optionalPageEntry(dict, 'Rotate');
    if (rotateValue !== undefined) checkedRotate(rotateValue);
    const type = name(get(dict, 'Type'));
    if (type === 'Pages') {
      const parent = get(dict, 'Parent');
      if (depth === 0) check(optionalPageEntry(dict, 'Parent') === undefined,
        'PADES_PAGE_TREE_PARENT');
      else check(parent instanceof PDFRef && refID(parent) === refID(parentReference),
        'PADES_PAGE_TREE_PARENT');
      const children = rev.resolve(get(dict, 'Kids'));
      check(children instanceof PDFArray, 'PADES_PAGE_KIDS');
      check(children.size() <= MAX_OBJECTS, 'PADES_PAGE_LIMIT', 'UNSUPPORTED');
      const count = sourceInteger(rev.resolve(get(dict, 'Count')), 'PADES_PAGE_TREE_COUNT', integerObjects);
      let actual = 0;
      for (const child of children.asArray())
        actual += visit(child, depth + 1, resources, mediaBox, reference);
      check(count === actual, 'PADES_PAGE_TREE_COUNT');
      return actual;
    } else {
      check(type === 'Page', 'PADES_PAGE_TYPE');
      const parent = get(dict, 'Parent');
      check(parent instanceof PDFRef && refID(parent) === refID(parentReference),
        'PADES_PAGE_PARENT');
      check(mediaBox instanceof PDFArray, 'PADES_PAGE_MEDIABOX');
      check(resources instanceof PDFDict, 'PADES_PAGE_RESOURCES');
      check(++pageCount <= MAX_OBJECTS, 'PADES_PAGE_LIMIT', 'UNSUPPORTED');
      inspectLineAnnotations(dict);
      const value = get(dict, 'Contents');
      if (value === undefined || rev.resolve(value) === PDFNull) return 1;
      const content = rev.resolve(value);
      const references = content instanceof PDFArray ? content.asArray() : [value];
      const parts = references.map(streamBytes);
      if (parts.some(part => part === undefined)) return 1;
      const fontAvailable = fontName => {
        if (!(resources instanceof PDFDict)) return false;
        const fonts = rev.resolve(get(resources, 'Font'));
        if (!(fonts instanceof PDFDict)) return false;
        return rev.resolve(get(fonts, fontName)) instanceof PDFDict;
      };
      const resourceAvailable = (category, resourceName) => {
        const categoryValue = get(resources, category);
        if (categoryValue === undefined || undefinedRef(rev, categoryValue)) return false;
        const members = rev.resolve(categoryValue);
        if (!(members instanceof PDFDict)) return false;
        const value = get(members, resourceName);
        if (value === undefined || value === PDFNull || undefinedRef(rev, value)) return false;
        const resolved = rev.resolve(value);
        if (category === 'ExtGState') return resolved instanceof PDFDict;
        if (category === 'Shading' || category === 'Pattern') {
          const typed = resolved instanceof PDFDict || resolved instanceof PDFRawStream;
          if (typed && category === 'Shading')
            inspectAxialType2Function(rev, resources, resolved, diagnostic, integerObjects);
          return typed;
        }
        if (!(resolved instanceof PDFRawStream)) return false;
        const subtype = name(rev.resolve(get(resolved.dict, 'Subtype')));
        if (subtype === 'Image')
          inspectImageXObject(rev, resources, resolved, diagnostic, integerObjects);
        else if (subtype === 'PS') diagnostic('PADES_XOBJECT_SUBTYPE_UNSUPPORTED');
        else check(subtype === 'Form', 'PADES_XOBJECT_SUBTYPE');
        return true;
      };
      inspectContentTextOperators(
        Buffer.concat(parts), dict.context, diagnostic, fontAvailable, resourceAvailable,
      );
      return 1;
    }
  };
  visit(pagesRoot);
}

function inspectCapabilities(rev, diagnostic) {
  const visited = new Set();
  const resourceDictionaries = new WeakSet(), memberDictionaries = new WeakSet();
  const categories = new Set(['ExtGState', 'Shading', 'Pattern', 'XObject']);
  for (const entry of rev.active.values()) {
    const page = entry.used ? entry.def.object : undefined;
    if (!(page instanceof PDFDict) || !['Page', 'Pages'].includes(name(get(page, 'Type'))))
      continue;
    const resourceValue = get(page, 'Resources');
    if (resourceValue === undefined || undefinedRef(rev, resourceValue)) continue;
    const resources = rev.resolve(resourceValue);
    if (!(resources instanceof PDFDict)) continue;
    resourceDictionaries.add(resources);
    for (const category of categories) {
      const value = get(resources, category);
      if (value === undefined || undefinedRef(rev, value)) continue;
      const members = rev.resolve(value);
      if (members instanceof PDFDict) memberDictionaries.add(members);
    }
  }
  function visit(object, depth = 0) {
    check(depth <= 64, 'PADES_OBJECT_LIMIT', 'UNSUPPORTED');
    if (!object || visited.has(object)) return;
    visited.add(object);
    if (object instanceof PDFRef) {
      rev.resolve(object);
      return;
    }
    const dict = object instanceof PDFRawStream ? object.dict : object;
    if (dict instanceof PDFDict) {
      const type = name(get(dict, 'Type')),
        action = name(get(dict, 'S'));
      if (['ObjStm', 'XRef'].includes(type)) diagnostic('PADES_OBJECT_STREAM_UNSUPPORTED');
      if (
        [
          'JavaScript',
          'Launch',
          'GoToR',
          'GoToE',
          'URI',
          'SubmitForm',
          'ImportData',
          'Rendition',
          'Sound',
          'Movie',
        ].includes(action)
      )
        diagnostic('PADES_ACTIVE_CONTENT_UNSUPPORTED');
      for (const [key, value] of dict.entries()) {
        if (
          [
            'JS',
            'JavaScript',
            'OpenAction',
            'AA',
            'XFA',
            'RichMedia',
            'EmbeddedFiles',
            'Collection',
          ].includes(key.decodeText())
        )
          diagnostic('PADES_ACTIVE_CONTENT_UNSUPPORTED');
        if (['DocMDP', 'FieldMDP'].includes(name(value)) || key.decodeText() === 'Perms')
          diagnostic('PADES_TRANSFORM_UNSUPPORTED');
        if (
          object instanceof PDFRawStream &&
          ['F', 'FFilter', 'FDecodeParms'].includes(key.decodeText())
        )
          diagnostic('PADES_EXTERNAL_STREAM_UNSUPPORTED');
        const pageEntry = type === 'Page' || type === 'Pages';
        const optionalPageKey = ['Rotate', 'MediaBox', 'Resources'].includes(key.decodeText()) ||
          (type === 'Pages' && key.decodeText() === 'Parent');
        const optionalResourceReference = undefinedRef(rev, value) &&
          ((resourceDictionaries.has(dict) && categories.has(key.decodeText())) ||
            memberDictionaries.has(dict));
        if (!(undefinedRef(rev, value) && pageEntry && optionalPageKey) &&
            !optionalResourceReference)
          visit(value, depth + 1);
      }
    } else if (object instanceof PDFArray)
      object.asArray().forEach((item) => visit(item, depth + 1));
  }
  for (const entry of rev.active.values()) if (entry.used) visit(entry.def.object);
  const extensions = rev.resolve(get(rev.catalog, 'Extensions'));
  if (extensions) {
    check(extensions instanceof PDFDict, 'PADES_EXTENSIONS');
    for (const [key, value] of extensions.entries()) {
      const spec = rev.resolve(value);
      if (
        !(spec instanceof PDFDict) ||
        name(get(spec, 'BaseVersion')) !== '1.7' ||
        !(
          (key.decodeText() === 'ADBE' && number(get(spec, 'ExtensionLevel')) === 8) ||
          (key.decodeText() === 'ESIC' && [1, 2].includes(number(get(spec, 'ExtensionLevel'))))
        ) ||
        spec.keys().some((k) => !['BaseVersion', 'ExtensionLevel'].includes(k.decodeText()))
      )
        diagnostic('PADES_EXTENSION_UNSUPPORTED');
    }
  }
}

function collectSignatures(rev, raw, spans, integerObjects, revisions, index, diagnostic) {
  const found = [],
    fieldsSeen = new Set(),
    signatureIDs = new Set(),
    fieldNames = new Set(),
    signedNames = new Map(),
    leafRepresentations = new Map();
  const sameFieldValue = (left, right) => {
    if (left === PDFNull) left = undefined;
    if (right === PDFNull) right = undefined;
    if (left === undefined || right === undefined) return left === right;
    if (left instanceof PDFRef || right instanceof PDFRef)
      return left instanceof PDFRef && right instanceof PDFRef && refID(left) === refID(right);
    if (left instanceof PDFName && right instanceof PDFName)
      return name(left) === name(right);
    if ((left instanceof PDFString || left instanceof PDFHexString) &&
        (right instanceof PDFString || right instanceof PDFHexString))
      return left.decodeText() === right.decodeText();
    if (left instanceof PDFNumber && right instanceof PDFNumber)
      return Object.is(left.asNumber(), right.asNumber());
    return left.constructor === right.constructor && left.toString() === right.toString();
  };
  function visit(reference, inheritedType, depth = 0, parentName = '', parentReference, inheritedDefaultValue, inheritedValue) {
    check(reference instanceof PDFRef, 'PADES_FIELD_INDIRECT');
    const id = refID(reference);
    check(!fieldsSeen.has(id) && depth <= 20, 'PADES_FIELD_CYCLE_OR_DEPTH');
    fieldsSeen.add(id);
    const field = rev.resolve(reference);
    check(field instanceof PDFDict, 'PADES_FIELD');
    if (parentReference !== undefined) {
      const actualParent = get(field, 'Parent');
      check(
        actualParent instanceof PDFRef && refID(actualParent) === refID(parentReference),
        'PADES_FIELD_PARENT',
      );
    }
    const partialName = get(field, 'T');
    check(
      partialName === undefined ||
        partialName instanceof PDFString ||
        partialName instanceof PDFHexString,
      'PADES_FIELD_NAME',
    );
    const component = partialName?.decodeText();
    check(component === undefined || !component.includes('.'), 'PADES_FIELD_NAME');
    const qualifiedName =
      component === undefined
        ? parentName
        : [parentName, component].filter(Boolean).join('.');
    if (partialName !== undefined) {
      check(!fieldNames.has(qualifiedName), 'PADES_DUPLICATE_FIELD_NAME');
      fieldNames.add(qualifiedName);
    }
    const localType = rev.resolve(get(field, 'FT'));
    check(
      localType === undefined || localType === PDFNull || localType instanceof PDFName,
      'PADES_FIELD_TYPE',
    );
    const type = name(localType) ?? inheritedType;
    const localValue = get(field, 'V');
    const value = localValue === undefined || rev.resolve(localValue) === PDFNull
      ? inheritedValue : localValue;
    const localDefaultValue = get(field, 'DV');
    const defaultValue = localDefaultValue === undefined || rev.resolve(localDefaultValue) === PDFNull
      ? inheritedDefaultValue : localDefaultValue;
    const isLeaf = get(field, 'Kids') === undefined;
    const isWidget = name(rev.resolve(get(field, 'Subtype'))) === 'Widget';
    const previousSigned = signedNames.get(qualifiedName);
    if (previousSigned !== undefined)
      check(
        isLeaf && partialName === undefined && isWidget &&
          type === previousSigned.type && sameFieldValue(value, previousSigned.value) &&
          sameFieldValue(defaultValue, previousSigned.defaultValue),
        'PADES_DUPLICATE_FIELD_NAME',
      );
    if (isLeaf) {
      const previous = leafRepresentations.get(qualifiedName);
      if (previous !== undefined) {
        check(
          qualifiedName.length > 0 && partialName === undefined && previous.unnamed &&
            isWidget && previous.widget && type === previous.type &&
            sameFieldValue(value, previous.value) &&
            sameFieldValue(defaultValue, previous.defaultValue),
          'PADES_DUPLICATE_FIELD_NAME',
        );
        return;
      }
      leafRepresentations.set(qualifiedName, {
        unnamed: partialName === undefined, widget: isWidget, type, value, defaultValue,
      });
    }
    if (type === 'Sig' && value !== undefined) {
      if (previousSigned !== undefined) return;
      signedNames.set(qualifiedName, { type, value, defaultValue });
      check(value instanceof PDFRef, 'PADES_SIGNATURE_INDIRECT');
      const signatureID = refID(value),
        signature = rev.resolve(value);
      check(
        signature instanceof PDFDict && !signatureIDs.has(signatureID),
        'PADES_SIGNATURE_DICTIONARY',
      );
      signatureIDs.add(signatureID);
      for (const item of signature.values())
        check(!(item instanceof PDFRef), 'PADES_SIGNATURE_DIRECT_VALUES');
      const typeValue = get(signature, 'Type'),
        kind = name(typeValue) === 'DocTimeStamp' ? 'TIMESTAMP' : 'SIGNATURE';
      check(
        typeValue === undefined || name(typeValue) === (kind === 'TIMESTAMP' ? 'DocTimeStamp' : 'Sig'),
        'PADES_SIGNATURE_TYPE',
      );
      check(get(signature, 'Filter') instanceof PDFName, 'PADES_SIGNATURE_FILTER');
      // The selected PAdES baseline forbids Cert for approval signatures
      // and document timestamps (clause 5.4.3).
      check(get(signature, 'Cert') === undefined, 'PADES_SIGNATURE_CERT_FORBIDDEN');
      const selected = kind === 'TIMESTAMP' ? 'ETSI.RFC3161' : 'ETSI.CAdES.detached';
      if (name(get(signature, 'SubFilter')) !== selected) diagnostic('PADES_SUBFILTER_UNSUPPORTED');
      if (kind === 'TIMESTAMP') {
        for (const forbidden of [
          'Cert',
          'Reference',
          'Changes',
          'R',
          'Prop_AuthTime',
          'Prop_AuthType',
        ])
          check(get(signature, forbidden) === undefined, 'PADES_TIMESTAMP_FORBIDDEN_FIELD');
        if (get(signature, 'V') !== undefined)
          check(
            sourceInteger(get(signature, 'V'), 'PADES_TIMESTAMP_VERSION', integerObjects) === 0,
            'PADES_TIMESTAMP_VERSION',
          );
      } else if (get(signature, 'V') !== undefined) {
        sourceInteger(get(signature, 'V'), 'PADES_SIGNATURE_VERSION', integerObjects);
      }
      if (get(signature, 'Reference')) diagnostic('PADES_TRANSFORM_UNSUPPORTED');
      const allowed = [
        'Type',
        'Filter',
        'SubFilter',
        'Contents',
        'ByteRange',
        'M',
        'Name',
        'Location',
        'Reason',
        'ContactInfo',
        'V',
        'Prop_Build',
      ];
      for (const key of signature.keys())
        if (!allowed.includes(key.decodeText()))
          diagnostic('PADES_SIGNATURE_EXTENSION_UNSUPPORTED');
      const ranges = get(signature, 'ByteRange');
      check(ranges instanceof PDFArray && ranges.size() === 4, 'PADES_BYTE_RANGE');
      const byteRange = ranges.asArray().map((v) => sourceInteger(v, 'PADES_BYTE_RANGE', integerObjects));
      const [start, firstLength, secondStart, secondLength] = byteRange;
      check(
        start === 0 &&
          firstLength > 0 &&
          secondStart > firstLength + 2 &&
          secondStart + secondLength <= raw.length,
        'PADES_BYTE_RANGE',
      );
      const contentSpan = spans.get(signature)?.get('Contents');
      check(
        contentSpan &&
          contentSpan.start === firstLength &&
          contentSpan.end === secondStart &&
          raw[firstLength] === 60 &&
          raw[secondStart - 1] === 62,
        'PADES_CONTENTS_ASSOCIATION',
      );
      const signedRevisionLength = secondStart + secondLength;
      const signedIndex = revisions.findIndex(
        (r, at) =>
          at <= index &&
          signedRevisionLength >= r.markerEnd &&
          signedRevisionLength <= (revisions[at + 1]?.xrefOffset ?? raw.length) &&
          ignored(raw, r.markerEnd, signedRevisionLength) &&
          (at < revisions.length - 1 || signedRevisionLength === raw.length),
      );
      check(signedIndex >= 0, 'PADES_SIGNED_REVISION_END');
      check(secondStart <= revisions[signedIndex].xrefOffset, 'PADES_SIGNATURE_REVISION');
      if (signedIndex === index) rev.length = signedRevisionLength;
      let signingTime;
      const hasM = kind === 'SIGNATURE' && get(signature, 'M') !== undefined;
      if (kind === 'SIGNATURE') {
        if (hasM)
          try {
            signingTime = pdfDate(get(signature, 'M'));
          } catch (error) {
            if (error.overall === 'UNSUPPORTED') diagnostic(error.code);
            else throw error;
          }
      }
      found.push({
        id: signatureID,
        fieldID: id,
        kind,
        cms: derFromHex(get(signature, 'Contents')),
        byteRange,
        signedRevisionLength,
        hasM,
        signingTime,
        revisionIndex: signedIndex,
      });
    }
    const kids = rev.resolve(get(field, 'Kids'));
    if (kids !== undefined) {
      check(kids instanceof PDFArray, 'PADES_FIELD_KIDS');
      kids.asArray().forEach((kid) =>
        visit(kid, type, depth + 1, qualifiedName, reference, defaultValue, value));
    }
  }
  rev.fields.forEach((field) => visit(field));
  rev.fieldNames = fieldNames;
  check(found.length <= 32, 'PADES_SIGNATURE_LIMIT', 'UNSUPPORTED');
  return found.sort((a, b) => a.signedRevisionLength - b.signedRevisionLength);
}

// Check every DSS object's declared category, including material that is not
// used by a selected path. These are schema checks, not trust decisions. CRL
// authority, signature, extension semantics and freshness remain in the shared
// material verifier. The CertificateList schema follows RFC 5280 section 5.1.
function materialSchema(bytes, kind) {
  const root = parseDER(bytes);
  if (kind === 'Certs') {
    try {
      check(new X509Certificate(bytes).raw.equals(bytes), 'PADES_DSS_CERTIFICATE_STRUCTURE');
    } catch {
      throw failure('PADES_DSS_CERTIFICATE_STRUCTURE');
    }
    return;
  }
  const code = 'PADES_DSS_CRL_STRUCTURE';
  const sequence = (node, length) => {
    check(node?.tag === 0x30 && (length === undefined || node.children.length === length), code);
    return node.children;
  };
  const algorithm = (node) => {
    const fields = sequence(node);
    check([1, 2].includes(fields.length) && fields[0].tag === 6, code);
    oidText(fields[0]);
  };
  const time = (node) => {
    check([23, 24].includes(node?.tag), code);
    let value = node.value.toString('ascii');
    check(node.tag === 23 ? /^\d{12}Z$/.test(value) : /^\d{14}Z$/.test(value), code);
    if (node.tag === 23) value = (Number(value.slice(0, 2)) >= 50 ? '19' : '20') + value;
    const date = new Date(
      `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(8, 10)}:${value.slice(10, 12)}:${value.slice(12, 14)}Z`,
    );
    check(
      Number.isFinite(date.getTime()) &&
        date.toISOString().replace(/[-:T]/g, '').replace('.000Z', 'Z') === value,
      code,
    );
  };
  const extensions = (node) => {
    const values = sequence(node),
      seen = new Set();
    check(values.length > 0, code);
    for (const extension of values) {
      const fields = sequence(extension);
      check([2, 3].includes(fields.length) && fields[0].tag === 6 && fields.at(-1).tag === 4, code);
      const id = oidText(fields[0]);
      check(!seen.has(id), code);
      seen.add(id);
      if (fields.length === 3) check(fields[1].raw.equals(Buffer.from('0101ff', 'hex')), code);
      parseDER(fields.at(-1).value);
    }
  };
  const [tbs, signatureAlgorithm, signature] = sequence(root, 3);
  algorithm(signatureAlgorithm);
  check(signature.tag === 3 && signature.value.length > 1 && signature.value[0] === 0, code);
  const fields = sequence(tbs);
  let index = 0,
    version = 0;
  if (fields[index]?.tag === 2) {
    check(intValue(fields[index++]) === 1n, code);
    version = 1;
  }
  algorithm(fields[index]);
  check(fields[index++].raw.equals(signatureAlgorithm.raw), code);
  const issuer = sequence(fields[index++]);
  check(issuer.length > 0, code);
  for (const rdn of issuer) {
    check(rdn.tag === 0x31 && rdn.children.length > 0, code);
    for (const attribute of rdn.children) {
      const [id] = sequence(attribute, 2);
      check(id.tag === 6, code);
      oidText(id);
    }
  }
  time(fields[index++]);
  if ([23, 24].includes(fields[index]?.tag)) time(fields[index++]);
  if (fields[index]?.tag === 0x30) {
    const records = sequence(fields[index++]);
    check(records.length > 0, code);
    for (const record of records) {
      const entry = sequence(record);
      check([2, 3].includes(entry.length) && entry[0].tag === 2 && intValue(entry[0]) > 0n, code);
      time(entry[1]);
      if (entry.length === 3) {
        check(version === 1, code);
        extensions(entry[2]);
      }
    }
  }
  if (fields[index]?.tag === 0xa0) {
    const wrapper = fields[index++];
    check(version === 1 && wrapper.children.length === 1, code);
    extensions(wrapper.children[0]);
  }
  check(index === fields.length, code);
}

function dssMaterial(rev, diagnostic) {
  const reference = get(rev.catalog, 'DSS'),
    dss = rev.resolve(reference);
  const result = {
    certificates: [],
    crls: [],
    dssPresent: dss !== undefined,
    refs: new Set(),
    containers: new Set(),
    streams: new Set(),
    certificateRefs: [],
    crlRefs: [],
  };
  function remember(value, set = result.containers) {
    if (value instanceof PDFRef) {
      set.add(refID(value));
      result.refs.add(refID(value));
    }
  }
  if (!dss) return result;
  check(dss instanceof PDFDict, 'PADES_DSS_DICTIONARY');
  remember(reference);
  for (const key of dss.keys())
    if (!['Type', 'Certs', 'CRLs'].includes(key.decodeText()))
      diagnostic(
        key.decodeText() === 'OCSPs'
          ? 'PADES_OCSP_UNSUPPORTED'
          : key.decodeText() === 'VRI'
            ? 'PADES_VRI_UNSUPPORTED'
            : 'PADES_DSS_EXTENSION_UNSUPPORTED',
      );
  if (get(dss, 'Type')) check(name(get(dss, 'Type')) === 'DSS', 'PADES_DSS_TYPE');
  let total = 0;
  for (const [key, target, refs] of [
    ['Certs', 'certificates', 'certificateRefs'],
    ['CRLs', 'crls', 'crlRefs'],
  ]) {
    const arrayValue = get(dss, key),
      array = rev.resolve(arrayValue);
    if (array === undefined) continue;
    remember(arrayValue);
    check(array instanceof PDFArray, 'PADES_DSS_ARRAY');
    check(array.size() <= MAX_MATERIAL, 'PADES_MATERIAL_LIMIT', 'UNSUPPORTED');
    for (const item of array.asArray()) {
      check(item instanceof PDFRef, 'PADES_DSS_STREAM_INDIRECT');
      const stream = rev.resolve(item);
      check(stream instanceof PDFRawStream, 'PADES_DSS_STREAM');
      remember(item, result.streams);
      result[refs].push(item);
      for (const k of stream.dict.keys())
        if (!['Length', 'Filter', 'DecodeParms'].includes(k.decodeText()))
          diagnostic('PADES_DSS_STREAM_EXTENSION_UNSUPPORTED');
      let bytes = Buffer.from(stream.getContents());
      const filter = get(stream.dict, 'Filter');
      if (filter !== undefined) {
        if (name(filter) !== 'FlateDecode' || get(stream.dict, 'DecodeParms') !== undefined) {
          diagnostic('PADES_DSS_FILTER_UNSUPPORTED');
          continue;
        }
        try {
          bytes = inflateSync(bytes, { maxOutputLength: 16 * 1024 * 1024 });
        } catch {
          throw failure('PADES_DSS_FLATE');
        }
      } else check(get(stream.dict, 'DecodeParms') === undefined, 'PADES_DSS_DECODE_PARAMETERS');
      total += bytes.length;
      check(total <= 16 * 1024 * 1024, 'PADES_MATERIAL_LIMIT', 'UNSUPPORTED');
      materialSchema(bytes, key);
      result[target].push(bytes);
    }
  }
  return result;
}

function enforceAppend(prior, current, raw) {
  check(
    prior.signatures.every((old) =>
      current.signatures.some(
        (s) => s.id === old.id && s.fieldID === old.fieldID && s.cms.equals(old.cms),
      ),
    ),
    'PADES_SIGNATURE_REMOVED',
  );
  check(
    dictionaryView(prior.catalog, ['AcroForm', 'DSS', 'Extensions']) ===
      dictionaryView(current.catalog, ['AcroForm', 'DSS', 'Extensions']),
    'PADES_CATALOG_CHANGED',
  );
  check(
    current.fields.length >= prior.fields.length &&
      prior.fields.every((field, index) => refID(field) === refID(current.fields[index])),
    'PADES_FIELDS_CHANGED',
  );
  const formView = (form) => (form ? dictionaryView(form, ['Fields', 'SigFlags']) : '');
  check(formView(prior.form) === formView(current.form), 'PADES_FORM_CHANGED');
  const oldTrailer = dictionaryView(prior.trailer, ['Size', 'Prev', 'Root', 'ID']),
    newTrailer = dictionaryView(current.trailer, ['Size', 'Prev', 'Root', 'ID']);
  check(oldTrailer === newTrailer, 'PADES_TRAILER_CHANGED');
  const oldID = get(prior.trailer, 'ID'),
    newID = get(current.trailer, 'ID');
  if (oldID)
    check(
      oldID instanceof PDFArray &&
        newID instanceof PDFArray &&
        oldID.get(0).toString() === newID.get(0).toString(),
      'PADES_DOCUMENT_ID_CHANGED',
    );
  const oldRoles = mutableRoles(prior),
    newRoles = mutableRoles(current);
  const immutable = immutableReferences(prior);
  const allowed = new Set([...newRoles.keys(), ...current.material.streams]);
  for (const key of ['certificates', 'crls'])
    check(
      prior.material[key].every((bytes) =>
        current.material[key].some((value) => bytes.equals(value)),
      ),
      'PADES_DSS_MATERIAL_REMOVED',
    );
  for (const fieldRef of current.fields.slice(prior.fields.length)) {
    const field = current.resolve(fieldRef),
      value = get(field, 'V');
    check(
      field instanceof PDFDict &&
        name(get(field, 'FT')) === 'Sig' &&
        value instanceof PDFRef &&
        field.keys().every((key) => ['FT', 'T', 'V'].includes(key.decodeText())) &&
        current.signatures.some((s) => s.id === refID(value)),
      'PADES_NON_PRESERVATION_FIELD',
    );
    allowed.add(refID(fieldRef));
    allowed.add(refID(value));
  }
  const oldExtensions = prior.resolve(get(prior.catalog, 'Extensions')),
    newExtensions = current.resolve(get(current.catalog, 'Extensions'));
  if (oldExtensions)
    check(
      newExtensions instanceof PDFDict &&
        dictionaryView(oldExtensions) === dictionaryView(newExtensions),
      'PADES_EXTENSIONS_CHANGED',
    );
  else if (newExtensions) {
    check(
      newExtensions instanceof PDFDict && newExtensions.keys().length === 1,
      'PADES_EXTENSIONS_CHANGED',
    );
    const adobe = current.resolve(get(newExtensions, 'ADBE'));
    check(
      adobe instanceof PDFDict && dictionaryView(adobe) === '/BaseVersion:/1.7\n/ExtensionLevel:8',
      'PADES_EXTENSIONS_CHANGED',
    );
    for (const value of [get(current.catalog, 'Extensions'), get(newExtensions, 'ADBE')])
      if (value instanceof PDFRef) allowed.add(refID(value));
  }
  for (const [id, old] of prior.active) {
    if (!old.used) continue;
    const entry = current.active.get(id);
    check(entry?.used && entry.generation === old.generation, 'PADES_OBJECT_REMOVED');
    if (
      entry.offset !== old.offset &&
      !raw
        .subarray(entry.def.offset, entry.def.end)
        .equals(raw.subarray(old.def.offset, old.def.end))
    ) {
      const reference = `${id} ${entry.generation} R`;
      // An object's new role is not authorization to overwrite its old role.
      // Even a previously mutable container is immutable through any other
      // retained document path (for example a shared page or annotation array).
      check(
        !immutable.has(reference) &&
          oldRoles.has(reference) &&
          [...oldRoles.get(reference)].some((role) => newRoles.get(reference)?.has(role)),
        'PADES_EXISTING_OBJECT_CHANGED',
      );
    }
  }
  for (const [id, entry] of current.active)
    if (entry.used && !prior.active.get(id)?.used)
      check(allowed.has(`${id} ${entry.generation} R`), 'PADES_UNAPPROVED_OBJECT_ADDED');
}

function mutableRoles(rev) {
  const roles = new Map();
  const add = (value, role) => {
    if (!(value instanceof PDFRef)) return;
    const id = refID(value);
    if (!roles.has(id)) roles.set(id, new Set());
    roles.get(id).add(role);
  };
  add(rev.root, 'CATALOG');
  add(get(rev.catalog, 'AcroForm'), 'FORM');
  add(rev.fieldsValue, 'FIELDS');
  const dssValue = get(rev.catalog, 'DSS'),
    dss = rev.resolve(dssValue);
  add(dssValue, 'DSS');
  if (dss instanceof PDFDict) {
    add(get(dss, 'Certs'), 'DSS_CERTS');
    add(get(dss, 'CRLs'), 'DSS_CRLS');
  }
  return roles;
}

function immutableReferences(rev) {
  const protectedRefs = new Set(),
    seen = new Set();
  function visit(value, depth = 0) {
    check(depth <= 64, 'PADES_REFERENCE_DEPTH', 'UNSUPPORTED');
    if (!value || seen.has(value)) return;
    seen.add(value);
    if (value instanceof PDFRef) {
      protectedRefs.add(refID(value));
      visit(rev.resolve(value), depth + 1);
    } else if (value instanceof PDFArray) value.asArray().forEach((item) => visit(item, depth + 1));
    else {
      const dict = value instanceof PDFRawStream ? value.dict : value;
      if (dict instanceof PDFDict) dict.values().forEach((item) => visit(item, depth + 1));
    }
  }
  for (const [key, value] of rev.catalog.entries())
    if (!['AcroForm', 'DSS'].includes(key.decodeText())) visit(value);
  for (const [key, value] of rev.trailer.entries()) if (key.decodeText() !== 'Root') visit(value);
  for (const [key, value] of rev.form?.entries() ?? [])
    if (!['Fields', 'SigFlags'].includes(key.decodeText())) visit(value);
  rev.fields.forEach((value) => visit(value));
  for (const id of rev.material.streams) {
    const [objectNumber, generationNumber] = id.split(' ').map(Number);
    visit(PDFRef.of(objectNumber, generationNumber));
  }
  return protectedRefs;
}

function acceptable(document) {
  check(document.modificationPolicy.overall === 'VALID', document.modificationPolicy.reason);
  if (document.diagnostics.length) {
    const first =
      document.diagnostics.find((d) => d.overall === 'INVALID') ?? document.diagnostics[0];
    throw failure(first.reason, first.overall);
  }
}
function catalogText(rev, updates) {
  const entries = rev.catalog
    .entries()
    .filter(([key]) => !Object.hasOwn(updates, key.decodeText()));
  return `<< ${entries.map(([key, value]) => `${key} ${value}`).join('\n')}\n${Object.entries(
    updates,
  )
    .map(([key, value]) => `/${key} ${value}`)
    .join('\n')} >>`;
}
function extensionUpdate(rev) {
  return get(rev.catalog, 'Extensions')
    ? {}
    : { Extensions: '<< /ADBE << /BaseVersion /1.7 /ExtensionLevel 8 >> >>' };
}
function appendObjects(document, objects, size) {
  check(
    Number.isSafeInteger(size) && size > 0 && size <= MAX_OBJECTS,
    'PADES_OBJECT_LIMIT',
    'UNSUPPORTED',
  );
  const prior = document.revisions.at(-1),
    chunks = [document.raw, Buffer.from('\n')],
    xref = [];
  let offset = document.raw.length + 1;
  for (const object of objects) {
    check(object.id > 0 && object.id < size, 'PADES_WRITE_OBJECT');
    const body = Buffer.isBuffer(object.body) ? object.body : Buffer.from(object.body, 'latin1');
    const bytes = Buffer.concat([
      Buffer.from(`${object.id} ${object.generation ?? 0} obj\n`),
      body,
      Buffer.from('\nendobj\n'),
    ]);
    xref.push({ ...object, offset });
    chunks.push(bytes);
    offset += bytes.length;
  }
  const xrefText = xref
    .sort((a, b) => a.id - b.id)
    .map(
      (object) =>
        `${object.id} 1\n${String(object.offset).padStart(10, '0')} ${String(object.generation ?? 0).padStart(5, '0')} n \n`,
    )
    .join('');
  const retained = prior.trailer
    .entries()
    .filter(([key]) => !['Size', 'Prev'].includes(key.decodeText()))
    .map(([key, value]) => `${key} ${value}`)
    .join('\n');
  chunks.push(
    Buffer.from(
      `xref\n${xrefText}trailer\n<< /Size ${size}\n${retained}\n/Prev ${prior.xrefOffset} >>\nstartxref\n${offset}\n%%EOF\n`,
      'latin1',
    ),
  );
  const output = Buffer.concat(chunks);
  check(output.length <= 64 * 1024 * 1024, 'PADES_SIZE_LIMIT', 'UNSUPPORTED');
  return output;
}

export function inspectPAdESContainer(input) {
  const document = parseDocument(input);
  return {
    signatures: document.signatures.map(({ id, fieldID, ...signature }) => signature),
    revisions: document.revisions.map((rev) => ({
      length: rev.length,
      xrefOffset: rev.xrefOffset,
      certificates: rev.material.certificates,
      crls: rev.material.crls,
      dssPresent: rev.material.dssPresent,
    })),
    modificationPolicy: document.modificationPolicy,
    diagnostics: document.diagnostics,
  };
}

export function preparePAdESContainer(
  input,
  {
    kind,
    signingTime,
    signatureBytes = 32768,
    fieldName = 'CERTCONCORD-' + random(8).toString('hex'),
  } = {},
) {
  check(['SIGNATURE', 'TIMESTAMP'].includes(kind), 'PADES_SIGNATURE_KIND');
  check(
    Number.isSafeInteger(signatureBytes) && signatureBytes >= 8192 && signatureBytes <= 1048576,
    'PADES_SIGNATURE_SPACE',
  );
  check(
    typeof fieldName === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(fieldName),
    'PADES_FIELD_NAME',
  );
  const document = parseDocument(input);
  acceptable(document);
  check(
    kind === 'SIGNATURE'
      ? document.signatures.length === 0
      : document.signatures.some((s) => s.kind === 'SIGNATURE'),
    'PADES_SIGNATURE_SEQUENCE',
  );
  let dateEntry = '';
  if (kind === 'SIGNATURE') {
    check(
      Number.isSafeInteger(signingTime) && signingTime >= 0 && signingTime <= 253402300799,
      'PADES_SIGNING_TIME',
    );
    const date = new Date(signingTime * 1000).toISOString().slice(0, 19).replace(/[-:T]/g, '');
    dateEntry = ` /M (D:${date}Z)`;
  }
  const rev = document.revisions.at(-1),
    first = rev.size;
  check(!rev.fieldNames.has(fieldName), 'PADES_DUPLICATE_FIELD_NAME');
  const placeholder = '0 ' + '0'.repeat(20) + ' ' + '0'.repeat(20) + ' ' + '0'.repeat(20);
  const signatureText = `<< /Type /${kind === 'SIGNATURE' ? 'Sig' : 'DocTimeStamp'} /Filter /Adobe.PPKLite /SubFilter /${kind === 'SIGNATURE' ? 'ETSI.CAdES.detached' : 'ETSI.RFC3161'}${dateEntry} /ByteRange [${placeholder}] /Contents <${'0'.repeat(signatureBytes * 2)}> >>`;
  const formProperties = rev.form
    ? rev.form
        .entries()
        .filter(([key]) => !['Fields', 'SigFlags'].includes(key.decodeText()))
        .map(([key, value]) => `${key} ${value}`)
        .join('\n')
    : '';
  const objects = [
    { id: first, body: signatureText },
    { id: first + 1, body: `<< /FT /Sig /T (${fieldName}) /V ${first} 0 R >>` },
    {
      id: first + 2,
      body: `<< ${formProperties} /Fields [${rev.fields.join(' ')} ${first + 1} 0 R] /SigFlags 3 >>`,
    },
    {
      id: rev.root.objectNumber,
      generation: rev.root.generationNumber,
      body: catalogText(rev, { AcroForm: `${first + 2} 0 R`, ...extensionUpdate(rev) }),
    },
  ];
  const output = appendObjects(document, objects, first + 3);
  const contentsAt = output.indexOf(Buffer.from('/Contents <'), document.raw.length) + 11;
  const contentsEnd = contentsAt + signatureBytes * 2 + 1;
  check(
    contentsAt > document.raw.length &&
      output[contentsAt - 1] === 60 &&
      output[contentsEnd - 1] === 62,
    'PADES_CONTENTS_OFFSET',
  );
  const byteRange = [0, contentsAt - 1, contentsEnd, output.length - contentsEnd];
  const rangeAt = output.indexOf(Buffer.from(placeholder), document.raw.length),
    rangeText = byteRange.join(' ').padEnd(placeholder.length, ' ');
  check(
    rangeAt > document.raw.length && rangeText.length === placeholder.length,
    'PADES_RANGE_SPACE',
  );
  output.write(rangeText, rangeAt, 'ascii');
  return {
    output,
    contentsAt,
    signatureBytes,
    content: Buffer.concat([output.subarray(0, byteRange[1]), output.subarray(contentsEnd)]),
    byteRange,
    signedRevisionLength: output.length,
  };
}

export function appendPAdESDSS(input, { certificates = [], crls = [] } = {}) {
  check(Array.isArray(certificates) && Array.isArray(crls), 'PADES_DSS_INPUT');
  const document = parseDocument(input);
  acceptable(document);
  check(
    document.signatures.some((s) => s.kind === 'SIGNATURE'),
    'PADES_SIGNATURE_SEQUENCE',
  );
  const rev = document.revisions.at(-1),
    objects = [];
  let next = rev.size,
    total = 0;
  const result = {};
  for (const [key, provided, retained, retainedRefs] of [
    ['Certs', certificates, rev.material.certificates, rev.material.certificateRefs],
    ['CRLs', crls, rev.material.crls, rev.material.crlRefs],
  ]) {
    const values = retained.map((value) => Buffer.from(value)),
      refs = [...retainedRefs];
    for (const inputBytes of provided) {
      check(inputBytes instanceof Uint8Array, 'PADES_DSS_INPUT');
      const bytes = Buffer.from(inputBytes);
      materialSchema(bytes, key);
      total += bytes.length;
      check(total <= 16 * 1024 * 1024, 'PADES_MATERIAL_LIMIT', 'UNSUPPORTED');
      if (values.some((value) => value.equals(bytes))) continue;
      const id = next++;
      values.push(bytes);
      refs.push(PDFRef.of(id, 0));
      objects.push({
        id,
        body: Buffer.concat([
          Buffer.from(`<< /Length ${bytes.length} >>\nstream\n`),
          bytes,
          Buffer.from('\nendstream'),
        ]),
      });
    }
    check(values.length <= MAX_MATERIAL, 'PADES_MATERIAL_LIMIT', 'UNSUPPORTED');
    result[key] = `[${refs.join(' ')}]`;
  }
  if (!objects.length && rev.material.dssPresent) return Buffer.from(document.raw);
  const dssID = next++;
  objects.push({ id: dssID, body: `<< /Type /DSS /Certs ${result.Certs} /CRLs ${result.CRLs} >>` });
  objects.push({
    id: rev.root.objectNumber,
    generation: rev.root.generationNumber,
    body: catalogText(rev, { DSS: `${dssID} 0 R`, ...extensionUpdate(rev) }),
  });
  const output = appendObjects(document, objects, next);
  acceptable(parseDocument(output));
  return output;
}
