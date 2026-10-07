import {
  PDFObjectParser,
  PDFContext,
  PDFDict,
  PDFArray,
  PDFName,
  PDFRef,
  PDFNumber,
  PDFHexString,
  PDFString,
  PDFRawStream,
} from 'pdf-lib';
import { inflateSync } from 'node:zlib';
import { ProtocolError, parseDER, random } from './core.mjs';

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

class StrictObjectParser extends PDFObjectParser {
  constructor(raw, offset, context, spans, budget) {
    super(PDFObjectParser.forBytes(raw, context).bytes, context);
    this.raw = raw;
    this.spans = spans;
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

function ignored(raw, start, end) {
  let offset = start;
  while (offset < end) {
    if (whitespace(raw[offset])) offset++;
    else if (raw[offset] === 37) {
      while (offset < end && raw[offset] !== 10 && raw[offset] !== 13) offset++;
    } else return false;
  }
  return true;
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
  const match = /^D:(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(Z|[+-]\d\d'\d\d')$/.exec(text);
  if (!match) {
    check(/^D:\d{4}(?:\d\d){0,5}(?:Z|[+-]\d\d(?:'\d\d'?)?)?$/.test(text), 'PADES_SIGNING_TIME');
    throw failure('PADES_DATE_PRECISION', 'UNSUPPORTED');
  }
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
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
  if (match[7] !== 'Z') {
    const hours = Number(match[7].slice(1, 3)),
      minutes = Number(match[7].slice(4, 6));
    check(hours <= 23 && minutes <= 59, 'PADES_SIGNING_TIME');
    offset = (hours * 60 + minutes) * 60 * (match[7][0] === '+' ? 1 : -1);
  }
  const seconds = date.getTime() / 1000 - offset;
  check(Number.isSafeInteger(seconds) && seconds >= 0, 'PADES_SIGNING_TIME');
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
    budget = { nodes: 0 },
    context = PDFContext.create(),
    definitions = new Map();
  const diagnostics = [],
    revisions = [];
  const diagnostic = (reason, overall = 'UNSUPPORTED') => {
    if (!diagnostics.some((item) => item.reason === reason && item.overall === overall))
      diagnostics.push(report(overall, reason));
  };
  const parser = (offset) => new StrictObjectParser(raw, offset, context, spans, budget);
  const text = raw.toString('latin1');
  const firstParser = parser(0);
  firstParser.skipWhitespaceAndComments();
  const firstHeader = /^(\d+)\s+(\d+)\s+obj\b/.exec(
    text.slice(firstParser.bytes.offset(), firstParser.bytes.offset() + 100),
  );
  if (firstHeader) {
    firstParser.bytes.moveTo(firstParser.bytes.offset() + firstHeader[0].length);
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
      check(
        /^\d+\s+\d+\s+obj\b/.test(text.slice(xrefOffset, xrefOffset + 100)),
        'PADES_XREF_OFFSET',
      );
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
          const header = /^(\d+) (\d+) obj(?:[\x00\x09\x0a\x0c\x0d\x20]|(?=[/<\[]))/.exec(
            text.slice(entry.offset, entry.offset + 100),
          );
          check(
            header && Number(header[1]) === entry.id && Number(header[2]) === entry.generation,
            'PADES_XREF_OBJECT_HEADER',
          );
          const p = parser(entry.offset + header[0].length),
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
    rev.form = rev.resolve(get(rev.catalog, 'AcroForm'));
    check(rev.form === undefined || rev.form instanceof PDFDict, 'PADES_ACROFORM');
    rev.fieldsValue = get(rev.form, 'Fields');
    const fields = rev.resolve(rev.fieldsValue);
    check(!rev.form || fields instanceof PDFArray, 'PADES_FIELDS');
    rev.fields = fields?.asArray() ?? [];
    rev.signatures = collectSignatures(rev, raw, spans, revisions, i, diagnostic);
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

function inspectCapabilities(rev, diagnostic) {
  const visited = new Set();
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

function collectSignatures(rev, raw, spans, revisions, index, diagnostic) {
  const found = [],
    fieldsSeen = new Set(),
    signatureIDs = new Set(),
    fieldNames = new Set(),
    signedNames = new Set();
  function visit(reference, inheritedType, depth = 0, parentName = '') {
    check(reference instanceof PDFRef, 'PADES_FIELD_INDIRECT');
    const id = refID(reference);
    check(!fieldsSeen.has(id) && depth <= 20, 'PADES_FIELD_CYCLE_OR_DEPTH');
    fieldsSeen.add(id);
    const field = rev.resolve(reference);
    check(field instanceof PDFDict, 'PADES_FIELD');
    const partialName = get(field, 'T');
    check(
      partialName === undefined ||
        partialName instanceof PDFString ||
        partialName instanceof PDFHexString,
      'PADES_FIELD_NAME',
    );
    const qualifiedName =
      partialName === undefined
        ? parentName
        : [parentName, partialName.decodeText()].filter(Boolean).join('.');
    if (partialName !== undefined) {
      check(!fieldNames.has(qualifiedName), 'PADES_DUPLICATE_FIELD_NAME');
      fieldNames.add(qualifiedName);
    }
    const type = name(get(field, 'FT')) ?? inheritedType,
      value = get(field, 'V');
    if (type === 'Sig' && value !== undefined) {
      check(!signedNames.has(qualifiedName), 'PADES_DUPLICATE_FIELD_NAME');
      signedNames.add(qualifiedName);
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
      const kind = name(get(signature, 'Type')) === 'DocTimeStamp' ? 'TIMESTAMP' : 'SIGNATURE';
      check(
        name(get(signature, 'Type')) === (kind === 'TIMESTAMP' ? 'DocTimeStamp' : 'Sig'),
        'PADES_SIGNATURE_TYPE',
      );
      check(get(signature, 'Filter') instanceof PDFName, 'PADES_SIGNATURE_FILTER');
      // EN 319 142-1 V1.2.1 Table 1 forbids Cert for baseline approval
      // signatures as well as for document timestamps (clause 5.4.3).
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
          check(number(get(signature, 'V')) === 0, 'PADES_TIMESTAMP_VERSION');
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
      const byteRange = ranges.asArray().map((v) => integer(v, 'PADES_BYTE_RANGE'));
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
      if (kind === 'SIGNATURE') {
        if (get(signature, 'M') === undefined)
          diagnostic('PADES_SIGNING_TIME_REQUIRED', 'INDETERMINATE');
        else
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
        signingTime,
        revisionIndex: signedIndex,
      });
    }
    const kids = rev.resolve(get(field, 'Kids'));
    if (kids !== undefined) {
      check(kids instanceof PDFArray, 'PADES_FIELD_KIDS');
      kids.asArray().forEach((kid) => visit(kid, type, depth + 1, qualifiedName));
    }
  }
  rev.fields.forEach((field) => visit(field));
  rev.fieldNames = fieldNames;
  check(found.length <= 32, 'PADES_SIGNATURE_LIMIT', 'UNSUPPORTED');
  return found.sort((a, b) => a.signedRevisionLength - b.signedRevisionLength);
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
      parseDER(bytes);
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
  const entries = rev.catalog.entries().filter(([key]) => !(key.decodeText() in updates));
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
      parseDER(bytes);
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
