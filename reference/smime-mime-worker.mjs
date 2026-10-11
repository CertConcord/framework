import { parentPort, workerData } from 'node:worker_threads';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import mailsplit from '@zone-eu/mailsplit';
import MimeNode from 'nodemailer/lib/mime-node';
import { bytes, check, copy, failure, hash, LIMITS } from './smime-adapter-common.mjs';
import { headerMailbox, hasMultipleHeaderMailboxes } from './smime-address.mjs';

const writerOptions = Object.freeze({ disableFileAccess: true, disableUrlAccess: true });
const token = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const singleton = new Set([
  'from',
  'sender',
  'to',
  'cc',
  'bcc',
  'reply-to',
  'subject',
  'date',
  'message-id',
  'mime-version',
]);
const entityHeader = (name) => name.startsWith('content-');

function headers(raw) {
  raw = bytes(raw, LIMITS.headerBytes);
  check(!raw.some((b) => b > 127), 'SMIME_UTF8_HEADER_UNSUPPORTED', 'UNSUPPORTED');
  const text = raw.toString('latin1');
  check(!/\r(?!\n)/.test(text) && /\r?\n\r?\n$/.test(text), 'SMIME_HEADER_FRAMING');
  const pieces = text.replace(/\r?\n\r?\n$/, '').split(/(\r?\n)/),
    records = [];
  if (pieces.length === 1 && pieces[0] === '') return records;
  for (let index = 0; index < pieces.length; index += 2) {
    const line = pieces[index];
    check(line.length <= 998 && !/[\x00-\x08\x0b-\x1f\x7f]/.test(line), 'SMIME_HEADER_SYNTAX');
    if (/^[ \t]/.test(line)) {
      check(records.length > 0, 'SMIME_HEADER_FOLD');
      const previous = records.at(-1);
      previous.raw = Buffer.concat([
        previous.raw,
        Buffer.from(`${pieces[index - 1]}${line}`, 'ascii'),
      ]);
      previous.value += ` ${line.trim()}`;
      continue;
    }
    const at = line.indexOf(':');
    check(at > 0 && /^[\x21-\x39\x3b-\x7e]+$/.test(line.slice(0, at)), 'SMIME_HEADER_SYNTAX');
    const name = line.slice(0, at).toLowerCase();
    check(name !== 'hp-outer', 'SMIME_HEADER_PROTECTION_UNSUPPORTED', 'UNSUPPORTED');
    if (singleton.has(name) || entityHeader(name))
      check(!records.some((record) => record.name === name), 'SMIME_DUPLICATE_HEADER');
    records.push({ name, value: line.slice(at + 1).trim(), raw: Buffer.from(line, 'ascii') });
    check(records.length <= LIMITS.headers, 'SMIME_HEADER_LIMIT', 'UNSUPPORTED');
  }
  const version = records.find((record) => record.name === 'mime-version');
  if (version) check(version.value === '1.0', 'SMIME_MIME_VERSION_UNSUPPORTED', 'UNSUPPORTED');
  return records;
}
const field = (records, name) => records.find((record) => record.name === name)?.value;

// Validate every physical parameter before the library's convenience map can
// collapse duplicates. This does not parse or split multipart body boundaries.
function parameterized(value) {
  let at = 0;
  const end = value.indexOf(';');
  const main = (end < 0 ? value : value.slice(0, end)).trim().toLowerCase();
  at = end < 0 ? value.length : end;
  const params = new Map(),
    logical = new Set();
  while (at < value.length) {
    check(value[at++] === ';', 'SMIME_PARAMETER_SYNTAX');
    while (/[ \t]/.test(value[at] ?? '') && at < value.length) at++;
    const start = at;
    while (at < value.length && value[at] !== '=' && !/[ \t;]/.test(value[at])) at++;
    const name = value.slice(start, at).toLowerCase();
    check(token.test(name), 'SMIME_PARAMETER_SYNTAX');
    while (at < value.length && /[ \t]/.test(value[at])) at++;
    check(value[at++] === '=', 'SMIME_PARAMETER_SYNTAX');
    while (at < value.length && /[ \t]/.test(value[at])) at++;
    let content = '';
    if (value[at] === '"') {
      at++;
      let closed = false;
      while (at < value.length) {
        const c = value[at++];
        if (c === '"') {
          closed = true;
          break;
        }
        if (c === '\\') {
          check(at < value.length, 'SMIME_PARAMETER_SYNTAX');
          content += value[at++];
        } else content += c;
      }
      check(closed, 'SMIME_PARAMETER_SYNTAX');
    } else {
      const startValue = at;
      while (at < value.length && !/[ \t;]/.test(value[at])) at++;
      content = value.slice(startValue, at);
      check(
        token.test(content) || /^[A-Za-z0-9!#$&+.^_`|~%'*-]+$/.test(content),
        'SMIME_PARAMETER_SYNTAX',
      );
    }
    while (at < value.length && /[ \t]/.test(value[at])) at++;
    check(at === value.length || value[at] === ';', 'SMIME_PARAMETER_SYNTAX');
    const base = name.replace(/\*.*$/, '');
    check(!params.has(name) && !logical.has(base), 'SMIME_DUPLICATE_PARAMETER');
    check(!/\*\d/.test(name), 'SMIME_PARAMETER_CONTINUATION_UNSUPPORTED', 'UNSUPPORTED');
    params.set(name, content);
    logical.add(base);
  }
  return { main, params };
}
function metadata(node, records) {
  const ct = field(records, 'content-type'),
    parsed = parameterized(ct ?? 'text/plain; charset=us-ascii'),
    cd = field(records, 'content-disposition'),
    disposition = cd === undefined ? null : parameterized(cd),
    encoding = (field(records, 'content-transfer-encoding') ?? '7bit').toLowerCase();
  check(
    /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+\/[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(parsed.main),
    'SMIME_CONTENT_TYPE',
  );
  for (const name of parsed.params.keys())
    check(
      ['charset', 'boundary', 'name', 'name*', 'smime-type'].includes(name),
      'SMIME_CONTENT_PARAMETER_UNSUPPORTED',
      'UNSUPPORTED',
    );
  if (disposition) {
    check(
      ['inline', 'attachment'].includes(disposition.main),
      'SMIME_DISPOSITION_UNSUPPORTED',
      'UNSUPPORTED',
    );
    for (const name of disposition.params.keys())
      check(
        ['filename', 'filename*'].includes(name),
        'SMIME_DISPOSITION_PARAMETER_UNSUPPORTED',
        'UNSUPPORTED',
      );
  }
  check(token.test(encoding), 'SMIME_TRANSFER_ENCODING');
  check(
    ['7bit', 'base64', 'quoted-printable'].includes(encoding),
    'SMIME_TRANSFER_ENCODING_UNSUPPORTED',
    'UNSUPPORTED',
  );
  if (ct !== undefined) check(node.contentType === parsed.main, 'SMIME_CONTENT_TYPE_AMBIGUOUS');
  const isText = parsed.main.startsWith('text/'),
    charset = isText ? (parsed.params.get('charset') ?? 'us-ascii').toLowerCase() : null;
  const filename = node.filename || null;
  if (filename) check(!/[\x00-\x1f\x7f]/.test(filename), 'SMIME_FILENAME');
  const contentID = field(records, 'content-id') ?? null;
  if (contentID) check(/^<[^<>\s]+>$/.test(contentID), 'SMIME_CONTENT_ID');
  return {
    mediaType: parsed.main,
    charset,
    disposition: disposition?.main ?? null,
    filename,
    contentID,
    encoding,
    params: parsed.params,
  };
}
function envelopeHeaders(records, format) {
  check(['MESSAGE', 'ENTITY'].includes(format), 'SMIME_MIME_FORMAT');
  const outerHeaders = records.filter((record) => !entityHeader(record.name));
  if (format === 'ENTITY') {
    check(outerHeaders.length === 0, 'SMIME_ENTITY_OUTER_HEADERS');
    return { outerHeaders: [], headerClaims: { fromMailbox: null, senderMailbox: null } };
  }
  const from = field(records, 'from'),
    sender = field(records, 'sender');
  check(from !== undefined, 'SMIME_FROM_REQUIRED');
  if (hasMultipleHeaderMailboxes(from)) {
    check(sender !== undefined, 'SMIME_MULTIPLE_FROM_REQUIRES_SENDER');
    headerMailbox(sender);
    throw failure('SMIME_MULTIPLE_FROM_UNSUPPORTED', 'UNSUPPORTED');
  }
  return {
    outerHeaders,
    headerClaims: {
      fromMailbox: headerMailbox(from),
      senderMailbox: sender === undefined ? null : headerMailbox(sender),
    },
  };
}
async function collect(stream, limit) {
  const chunks = [];
  let length = 0;
  for await (const chunk of stream) {
    length += chunk.length;
    if (length > limit) {
      stream.destroy();
      throw failure('SMIME_SIZE_LIMIT', 'UNSUPPORTED');
    }
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks, length);
}
function transferSyntax(raw, encoding) {
  const text = raw.toString('latin1');
  check(!/\r(?!\n)/.test(text), 'SMIME_TRANSFER_LINE_ENDING');
  if (encoding === 'base64') {
    check(!/[^A-Za-z0-9+/=\r\n \t]/.test(text), 'SMIME_BASE64');
    const compact = text.replace(/[\r\n \t]/g, '');
    check(
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact),
      'SMIME_BASE64',
    );
    check(Buffer.from(compact, 'base64').toString('base64') === compact, 'SMIME_BASE64');
    check(
      text.split(/\r?\n/).every((line) => line.length <= 76),
      'SMIME_TRANSFER_LINE_LENGTH',
    );
  } else if (encoding === 'quoted-printable') {
    check(!/[^\x09\x0a\x0d\x20-\x7e]/.test(text), 'SMIME_QUOTED_PRINTABLE');
    check(!/=(?![0-9A-Fa-f]{2}|\r?\n)/.test(text), 'SMIME_QUOTED_PRINTABLE');
    check(
      text.split(/\r?\n/).every((line) => line.length <= 76 && !/[ \t]$/.test(line)),
      'SMIME_QUOTED_PRINTABLE',
    );
  } else {
    check(!/[\x00\x80-\xff]/.test(text), 'SMIME_7BIT');
    check(
      text.split(/\r?\n/).every((line) => line.length <= 998),
      'SMIME_TRANSFER_LINE_LENGTH',
    );
  }
}
function textValue(item) {
  check(
    ['us-ascii', 'utf-8'].includes(item.meta.charset),
    'SMIME_CHARSET_UNSUPPORTED',
    'UNSUPPORTED',
  );
  if (item.meta.charset === 'us-ascii')
    check(!item.decoded.some((b) => b > 127), 'SMIME_ASCII_CONTENT');
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(item.decoded);
  } catch {
    throw failure('SMIME_UTF8_CONTENT');
  }
}
async function parse(raw, format, carrier = false) {
  raw = bytes(raw);
  const splitter = new mailsplit.Splitter({
      maxHeadSize: LIMITS.headerBytes,
      maxChildNodes: LIMITS.parts,
      ignoreEmbedded: true,
    }),
    nodes = [],
    nodeMap = new Map(),
    framing = [];
  let rawBodies = 0;
  splitter.on('data', (object) => {
    try {
      if (object.type === 'node') {
        const parent = object.parentNode ? nodeMap.get(object.parentNode) : null;
        check(!object.parentNode || parent, 'SMIME_MIME_TREE');
        const path = parent ? [...parent.path, parent.children.length] : [];
        check(
          path.length < LIMITS.depth && nodes.length < LIMITS.parts,
          'SMIME_MIME_TREE_LIMIT',
          'UNSUPPORTED',
        );
        const records = headers(object.getHeaders());
        const actual = object.headers.getList();
        check(
          actual.length === records.length &&
            actual.every((record, i) => record.key === records[i].name),
          'SMIME_HEADER_AMBIGUOUS',
        );
        if (parent) envelopeHeaders(records, 'ENTITY');
        const item = {
          object,
          path,
          parent,
          children: [],
          records,
          meta: metadata(object, records),
          body: [],
          decoded: null,
        };
        if (parent) parent.children.push(item);
        nodes.push(item);
        nodeMap.set(object, item);
      } else if (object.type === 'body') {
        const item = nodeMap.get(object.node);
        check(item, 'SMIME_MIME_TREE');
        rawBodies += object.value.length;
        check(rawBodies <= LIMITS.input, 'SMIME_SIZE_LIMIT', 'UNSUPPORTED');
        item.body.push(Buffer.from(object.value));
      } else if (object.type === 'data') framing.push(Buffer.from(object.value));
    } catch (error) {
      splitter.destroy(error);
    }
  });
  try {
    await pipeline(Readable.from([raw]), splitter);
  } catch (error) {
    if (error.code === 'EMAXLEN') throw failure('SMIME_MIME_LIMIT', 'UNSUPPORTED');
    throw error.code ? error : failure('SMIME_MIME_PARSE');
  }
  check(nodes.length > 0, 'SMIME_MIME_EMPTY');
  const root = nodes[0],
    outer = envelopeHeaders(root.records, format);
  if (carrier) check(nodes.length === 1, 'SMIME_PROTECTED_ROOT');
  // Independently check the mature parser's framing events. The parser owns
  // all part segmentation; this check never splits or reconstructs body parts.
  const boundaries = new Map();
  for (const item of nodes) {
    const multipart = item.meta.mediaType.startsWith('multipart/');
    if (multipart) {
      check(
        !carrier && ['multipart/mixed', 'multipart/alternative'].includes(item.meta.mediaType),
        'SMIME_MULTIPART_UNSUPPORTED',
        'UNSUPPORTED',
      );
      check(item.meta.encoding === '7bit', 'SMIME_MULTIPART_ENCODING');
      const boundary = item.meta.params.get('boundary');
      check(
        typeof boundary === 'string' &&
          /^[0-9A-Za-z'()+_,\-./:=? ]{1,70}$/.test(boundary) &&
          !boundary.endsWith(' '),
        'SMIME_BOUNDARY',
      );
      check(!boundaries.has(boundary), 'SMIME_BOUNDARY_AMBIGUOUS');
      for (let parent = item.parent; parent; parent = parent.parent)
        check(
          !boundary.startsWith(parent.meta.params.get('boundary') ?? '\0'),
          'SMIME_BOUNDARY_AMBIGUOUS',
        );
      boundaries.set(boundary, { item, opened: 0, closed: false });
      check(item.children.length > 0, 'SMIME_EMPTY_MULTIPART');
    } else check(item.children.length === 0, 'SMIME_MIME_TREE');
  }
  for (const line of Buffer.concat(framing).toString('latin1').split(/\r?\n/)) {
    if (!line.trim()) continue;
    const matched = [...boundaries].find(
      ([boundary]) =>
        line === `--${boundary}` ||
        line === `--${boundary}--` ||
        new RegExp(`^--${boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:--)?[ \\t]+$`).test(
          line,
        ),
    );
    check(matched, 'SMIME_PREAMBLE_EPILOGUE_UNSUPPORTED', 'UNSUPPORTED');
    const [boundary, state] = matched;
    check(!state.closed, 'SMIME_BOUNDARY_AFTER_CLOSE');
    if (line.trimEnd() === `--${boundary}--`) state.closed = true;
    else state.opened++;
  }
  for (const state of boundaries.values())
    check(state.closed && state.opened === state.item.children.length, 'SMIME_BOUNDARY_INCOMPLETE');
  let decodedTotal = 0;
  for (const item of nodes) {
    if (item.children.length) continue;
    if (!carrier) {
      check(
        !item.meta.mediaType.startsWith('message/'),
        'SMIME_MESSAGE_PART_UNSUPPORTED',
        'UNSUPPORTED',
      );
      check(
        ![
          'application/pkcs7-mime',
          'application/x-pkcs7-mime',
          'application/pkcs7-signature',
        ].includes(item.meta.mediaType),
        'SMIME_NESTED_CRYPTO_UNSUPPORTED',
        'UNSUPPORTED',
      );
      if (item.meta.mediaType.startsWith('text/'))
        check(
          ['text/plain', 'text/html'].includes(item.meta.mediaType),
          'SMIME_TEXT_TYPE_UNSUPPORTED',
          'UNSUPPORTED',
        );
      else check(item.meta.encoding !== '7bit', 'SMIME_BINARY_ENCODING_UNSUPPORTED', 'UNSUPPORTED');
    }
    const encoded = Buffer.concat(item.body);
    transferSyntax(encoded, item.meta.encoding);
    const decoder = item.object.getDecoder(),
      collecting = collect(decoder, (carrier ? LIMITS.input : LIMITS.decoded) - decodedTotal);
    await Promise.all([pipeline(Readable.from([encoded]), decoder), collecting]);
    item.decoded = await collecting;
    decodedTotal += item.decoded.length;
    if (!carrier && item.meta.mediaType.startsWith('text/')) textValue(item);
  }
  return { root, nodes, ...outer };
}
function writerNode(type, parent, filename) {
  const options = { ...writerOptions, ...(filename ? { filename } : {}) };
  return parent
    ? parent.createChild(type, options)
    : new MimeNode('multipart/mixed', writerOptions).createChild(type, options);
}
async function prepare({ message }) {
  const parsed = await parse(message, 'MESSAGE');
  check(!(field(parsed.root.records, 'bcc') ?? '').trim(), 'SMIME_BCC_UNSUPPORTED', 'UNSUPPORTED');
  const normalization = {
    textParts: 0,
    lineEndingsChanged: 0,
    charsetsChanged: 0,
    transferEncodingsChanged: 0,
    originalMessageHash: hash(message),
  };
  function build(item, parent) {
    const text = item.meta.mediaType.startsWith('text/'),
      type = `${item.meta.mediaType}${text ? '; charset=utf-8' : ''}`,
      node = writerNode(type, parent, item.meta.filename);
    for (const record of item.records)
      if (
        entityHeader(record.name) &&
        !['content-type', 'content-transfer-encoding', 'content-disposition'].includes(record.name)
      )
        node.setHeader(record.name, record.value);
    if (item.meta.disposition) node.setHeader('Content-Disposition', item.meta.disposition);
    if (item.children.length) for (const child of item.children) build(child, node);
    else {
      let content = item.decoded;
      if (text) {
        normalization.textParts++;
        const original = textValue(item),
          canonical = original.replace(/\r\n|\r|\n/g, '\r\n');
        if (canonical !== original) normalization.lineEndingsChanged++;
        if (item.meta.charset !== 'utf-8') normalization.charsetsChanged++;
        content = Buffer.from(canonical, 'utf8');
      }
      if (item.meta.encoding !== 'base64') normalization.transferEncodingsChanged++;
      node.setHeader('Content-Transfer-Encoding', 'base64');
      node.setContent(content);
    }
    return node;
  }
  const mime = await collect(build(parsed.root).createReadStream(), LIMITS.content);
  return {
    mime,
    outerHeaders: parsed.outerHeaders,
    headerClaims: parsed.headerClaims,
    normalization,
  };
}
async function parseProtected({ message, format }) {
  const parsed = await parse(message, format, true),
    meta = parsed.root.meta;
  check(meta.mediaType === 'application/pkcs7-mime', 'SMIME_CARRIER_UNSUPPORTED', 'UNSUPPORTED');
  check(meta.encoding === 'base64', 'SMIME_CARRIER_ENCODING_UNSUPPORTED', 'UNSUPPORTED');
  const kind = { 'signed-data': 'SIGNED_DATA', 'authenveloped-data': 'AUTH_ENVELOPED_DATA' }[
    (meta.params.get('smime-type') ?? '').toLowerCase()
  ];
  check(kind, 'SMIME_CARRIER_TYPE_UNSUPPORTED', 'UNSUPPORTED');
  return {
    cms: parsed.root.decoded,
    kind,
    outerHeaders: parsed.outerHeaders,
    headerClaims: parsed.headerClaims,
  };
}
async function packageCMS({ cms, kind, format, outerHeaders }) {
  cms = bytes(cms);
  check(['MESSAGE', 'ENTITY'].includes(format), 'SMIME_MIME_FORMAT');
  const type = { SIGNED_DATA: 'signed-data', AUTH_ENVELOPED_DATA: 'authEnveloped-data' }[kind];
  check(type, 'SMIME_CARRIER_TYPE_UNSUPPORTED', 'UNSUPPORTED');
  const supplied = outerHeaders ?? [];
  check(Array.isArray(supplied) && supplied.length <= LIMITS.headers, 'SMIME_HEADER_INPUT');
  check(format === 'MESSAGE' || supplied.length === 0, 'SMIME_ENTITY_OUTER_HEADERS');
  const node =
    format === 'MESSAGE'
      ? new MimeNode(`application/pkcs7-mime; smime-type=${type}`, writerOptions)
      : writerNode(`application/pkcs7-mime; smime-type=${type}`);
  if (format === 'MESSAGE') {
    const values = supplied
      .map((record) => {
        check(
          typeof record?.name === 'string' &&
            /^[\x21-\x39\x3b-\x7e]+$/.test(record.name) &&
            record.name === record.name.toLowerCase() &&
            !entityHeader(record.name),
          'SMIME_OUTER_HEADER',
        );
        check(
          typeof record.value === 'string' && !/[\r\n]/.test(record.value),
          'SMIME_OUTER_HEADER',
        );
        return `${record.name}: ${record.value}\r\n`;
      })
      .join('');
    const checked = headers(Buffer.from(`${values}\r\n`, 'utf8'));
    envelopeHeaders(checked, 'MESSAGE');
    check(!(field(checked, 'bcc') ?? '').trim(), 'SMIME_BCC_UNSUPPORTED', 'UNSUPPORTED');
    for (const record of checked) node.addHeader(record.name, record.value);
  }
  node.setHeader('Content-Transfer-Encoding', 'base64');
  node.setContent(cms);
  return { message: await collect(node.createReadStream(), LIMITS.input) };
}
async function inspect({ mime }) {
  const parsed = await parse(mime, 'ENTITY');
  const view = (item) => ({
    path: item.path,
    mediaType: item.meta.mediaType,
    charset: item.meta.charset,
    disposition: item.meta.disposition,
    filename: item.meta.filename,
    contentID: item.meta.contentID,
  });
  return {
    tree: parsed.nodes.map((item) => ({ ...view(item), children: item.children.length })),
    parts: parsed.nodes
      .filter((item) => !item.children.length)
      .map((item) => ({ ...view(item), bytes: item.decoded })),
  };
}
try {
  const methods = { prepare, parse: parseProtected, package: packageCMS, inspect };
  check(Object.hasOwn(methods, workerData.action), 'SMIME_WORKER_ACTION');
  parentPort.postMessage({
    ok: true,
    value: await methods[workerData.action](copy(workerData.input)),
  });
} catch (error) {
  parentPort.postMessage({
    ok: false,
    code: error.code ?? 'SMIME_MIME_PARSE',
    overall: error.overall ?? 'INVALID',
  });
}
