// Test-only, independent classic-xref PDF and detached CMS producers. These
// helpers understand their own generated fixtures, not arbitrary hostile PDFs.
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import {
  O,
  epoch,
  fixture as certificates,
  attr,
  cmsView,
  hash,
  expectOverall,
} from './cades-fixtures.mjs';
export { O, epoch, attr, cmsView, hash, expectOverall };

const bytes = (value) =>
  Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value, 'binary');
const alg = (oid) => c.seq(c.oid(oid));
const date = (at) => new Date(at * 1000).toISOString().replace(/[-:T]/g, '').replace('.000Z', 'Z');
export const absentCapability =
  'Selected new PAdES API is absent at the frozen CAdES base; this is not an existing semantic failure';
export async function loadPAdES() {
  try {
    return await import('./pades.mjs');
  } catch (error) {
    if (
      error.code === 'ERR_MODULE_NOT_FOUND' &&
      error.url === new URL('./pades.mjs', import.meta.url).href
    )
      return undefined;
    throw error;
  }
}

export function plainPDF() {
  const stream = 'BT /F1 12 Tf 40 120 Td (Independent PAdES fixture) Tj ET\n';
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}endstream`,
  ];
  let output = Buffer.from('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n', 'binary');
  const offsets = [0];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(output.length);
    output = Buffer.concat([output, bytes(`${i + 1} 0 obj\n${objects[i]}\nendobj\n`)]);
  }
  const xref = output.length;
  return Buffer.concat([
    output,
    bytes(
      `xref\n0 ${offsets.length}\n0000000000 65535 f \n${offsets
        .slice(1)
        .map((n) => `${String(n).padStart(10, '0')} 00000 n \n`)
        .join('')}trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`,
    ),
  ]);
}

export function fixtureState(pdf) {
  const source = pdf.toString('binary'),
    objects = new Map();
  for (const match of source.matchAll(/(?:^|\n)(\d+) (\d+) obj\s*\n([\s\S]*?)\nendobj/g))
    objects.set(Number(match[1]), {
      number: Number(match[1]),
      generation: Number(match[2]),
      body: match[3],
    });
  const xref = [...source.matchAll(/startxref\s+(\d+)\s+%%EOF/g)].at(-1);
  const root = [...source.matchAll(/\/Root\s+(\d+)\s+(\d+)\s+R/g)].at(-1);
  const size = [...source.matchAll(/\/Size\s+(\d+)/g)].at(-1);
  assert(xref && root && size, 'fixture writer requires its own classic-xref input');
  return {
    objects,
    xref: Number(xref[1]),
    root: Number(root[1]),
    rootGeneration: Number(root[2]),
    size: Number(size[1]),
  };
}

export function appendRevision(
  pdf,
  entries,
  { trailer = '', root, prev, size, offsetDelta = 0 } = {},
) {
  const state = fixtureState(pdf);
  root ??= `${state.root} ${state.rootGeneration} R`;
  let output = Buffer.concat([pdf, bytes('\n')]);
  const offsets = [];
  for (const entry of entries) {
    const { number, generation = 0 } = entry;
    offsets.push({ number, generation, offset: output.length });
    output = Buffer.concat([
      output,
      bytes(`${number} ${generation} obj\n`),
      bytes(entry.body),
      bytes('\nendobj\n'),
    ]);
  }
  const xref = output.length;
  size ??= Math.max(state.size, ...entries.map((entry) => entry.number + 1));
  const rows = offsets
    .sort((a, b) => a.number - b.number)
    .map(
      ({ number, generation, offset }) =>
        `${number} 1\n${String(offset + offsetDelta).padStart(10, '0')} ${String(generation).padStart(5, '0')} n \n`,
    )
    .join('');
  return Buffer.concat([
    output,
    bytes(
      `xref\n${rows}trailer\n<< /Size ${size} /Root ${root} /Prev ${prev ?? state.xref}${trailer ? ` ${trailer}` : ''} >>\nstartxref\n${xref}\n%%EOF\n`,
    ),
  ]);
}

function setCatalogReference(body, name, reference) {
  const old = new RegExp(`/${name}\\s+\\d+\\s+\\d+\\s+R`);
  return old.test(body)
    ? body.replace(old, `/${name} ${reference}`)
    : body.replace(/>>\s*$/, `/${name} ${reference} >>`);
}

export function signatureContainer(
  pdf,
  {
    kind = 'SIGNATURE',
    signingTime = epoch + 10,
    signatureBytes = 8192,
    fieldName,
    extra = '',
    dictionary,
    transformByteRange,
    omitM = false,
    subFilter = kind === 'SIGNATURE' ? 'ETSI.CAdES.detached' : 'ETSI.RFC3161',
    type = kind === 'SIGNATURE' ? 'Sig' : 'DocTimeStamp',
  } = {},
) {
  const state = fixtureState(pdf),
    sig = state.size,
    field = sig + 1,
    form = sig + 2;
  fieldName ??= kind === 'SIGNATURE' ? 'Approval' : `Timestamp-${sig}`;
  const oldCatalog = state.objects.get(state.root).body;
  const oldFormRef = /\/AcroForm\s+(\d+)\s+\d+\s+R/.exec(oldCatalog);
  const oldFields = oldFormRef
    ? (/\/Fields\s*\[([^\]]*)\]/.exec(state.objects.get(Number(oldFormRef[1])).body)?.[1] ?? '')
    : '';
  let catalog = setCatalogReference(oldCatalog, 'AcroForm', `${form} 0 R`);
  if (!/\/Extensions\b/.test(catalog))
    catalog = catalog.replace(
      />>\s*$/,
      '/Extensions << /ADBE << /BaseVersion /1.7 /ExtensionLevel 8 >> >> >>',
    );
  const range = '0 ' + Array(3).fill('0'.repeat(20)).join(' ');
  let body = `<< /Type /${type} /Filter /Adobe.PPKLite /SubFilter /${subFilter}${kind === 'SIGNATURE' && !omitM ? ` /M (D:${date(signingTime)})` : ''}${kind === 'TIMESTAMP' ? ' /V 0' : ''} /ByteRange [${range}] /Contents <${'0'.repeat(signatureBytes * 2)}>${extra ? ` ${extra}` : ''} >>`;
  if (dictionary) body = dictionary(body);
  const output = appendRevision(pdf, [
    { number: sig, body },
    {
      number: field,
      body: `<< /FT /Sig /T (${fieldName.replace(/[()\\]/g, '_')}) /V ${sig} 0 R >>`,
    },
    { number: form, body: `<< /Fields [${oldFields} ${field} 0 R] /SigFlags 3 >>` },
    { number: state.root, generation: state.rootGeneration, body: catalog },
  ]);
  const contentsAt = output.indexOf(bytes('/Contents <'), pdf.length) + '/Contents <'.length;
  assert(contentsAt > pdf.length);
  const end = contentsAt + signatureBytes * 2 + 1;
  let byteRange = [0, contentsAt - 1, end, output.length - end];
  if (transformByteRange) byteRange = transformByteRange([...byteRange], output);
  const rangeAt = output.indexOf(bytes('/ByteRange ['), pdf.length) + '/ByteRange ['.length;
  const encoded = byteRange.join(' ');
  assert(encoded.length <= range.length);
  output.write(encoded.padEnd(range.length, ' '), rangeAt, 'ascii');
  const content = Buffer.concat([
    output.subarray(byteRange[0], byteRange[0] + byteRange[1]),
    output.subarray(byteRange[2], byteRange[2] + byteRange[3]),
  ]);
  return {
    output,
    contentsAt,
    signatureBytes,
    content,
    byteRange,
    signedRevisionLength: output.length,
    objectNumber: sig,
    fieldNumber: field,
    formNumber: form,
  };
}

export function fillContainer(container, cms) {
  assert(
    cms.length <= container.signatureBytes,
    'fixture CMS exceeds its reserved binary capacity',
  );
  const output = Buffer.from(container.output);
  output.write(
    cms.toString('hex').padEnd(container.signatureBytes * 2, '0'),
    container.contentsAt,
    'ascii',
  );
  return output;
}

export function independentCMS(
  f,
  content,
  {
    signed,
    additionalSigned = [],
    unsigned = [],
    certificates: certs = [f.signer.der, f.root.der],
    signature,
    embedded = false,
  } = {},
) {
  const attrs = signed ?? [
    attr(O.contentType, c.oid(O.data)),
    attr(O.messageDigest, c.octet(c.sha256(content))),
    attr(O.ess, c.seq(c.seq(c.seq(c.octet(c.sha256(f.signer.der)))))),
    ...additionalSigned,
  ];
  const tbs = c.set(...attrs);
  const si = c.seq(
    c.integer(1),
    c.seq(f.signer.cert.issuer, c.integer(f.signer.cert.serial)),
    alg(O.sha256),
    c.der(0xa0, c.parseDER(tbs).value),
    alg(O.es256),
    c.octet(signature ?? c.sign(tbs, f.signer.privateKey)),
    ...(unsigned.length ? [c.der(0xa1, c.parseDER(c.set(...unsigned)).value)] : []),
  );
  return c.seq(
    c.oid(O.signedData),
    c.der(
      0xa0,
      c.seq(
        c.integer(1),
        c.set(alg(O.sha256)),
        c.seq(c.oid(O.data), ...(embedded ? [c.der(0xa0, c.octet(content))] : [])),
        ...(certs.length ? [c.der(0xa0, c.parseDER(c.set(...certs)).value)] : []),
        c.set(si),
      ),
    ),
  );
}

export function independentApproval(f, { pdf = plainPDF(), cmsOptions, ...options } = {}) {
  const prepared = signatureContainer(pdf, options);
  const cms = independentCMS(f, prepared.content, cmsOptions);
  return { ...prepared, cms, pdf: fillContainer(prepared, cms) };
}
export function independentTimestamp(
  f,
  pdf,
  { at = epoch + 20, hashOID = O.sha256, tokenOptions = {}, ...options } = {},
) {
  const prepared = signatureContainer(pdf, { ...options, kind: 'TIMESTAMP' });
  const imprint = hash(prepared.content, hashOID);
  const token = f.token(
    { hashOID, imprint, policy: O.policy, nonce: 701n },
    { genTime: at, ...tokenOptions },
  );
  return { ...prepared, token, pdf: fillContainer(prepared, token) };
}

export function independentDSS(
  pdf,
  { certificates = [], crls = [] },
  { dictionary = '', direct = false, streamOptions = '' } = {},
) {
  const state = fixtureState(pdf),
    entries = [],
    refs = { Certs: [], CRLs: [] };
  let next = state.size;
  for (const [key, values] of [
    ['Certs', certificates],
    ['CRLs', crls],
  ]) {
    for (const value of values) {
      if (direct) refs[key].push(`<${value.toString('hex')}>`);
      else {
        const number = next++;
        refs[key].push(`${number} 0 R`);
        entries.push({
          number,
          body: Buffer.concat([
            bytes(
              `<< /Length ${value.length}${streamOptions ? ` ${streamOptions}` : ''} >>\nstream\n`,
            ),
            value,
            bytes('\nendstream'),
          ]),
        });
      }
    }
  }
  const dss = next++;
  entries.push({
    number: dss,
    body: `<< /Certs [${refs.Certs.join(' ')}] /CRLs [${refs.CRLs.join(' ')}] ${dictionary} >>`,
  });
  entries.push({
    number: state.root,
    generation: state.rootGeneration,
    body: setCatalogReference(state.objects.get(state.root).body, 'DSS', `${dss} 0 R`),
  });
  return appendRevision(pdf, entries);
}

// Inspect only the simple signature dictionaries produced by this fixture and
// the selected generator. This is not used as the security decision oracle.
export function pdfSignatures(pdf) {
  const source = pdf.toString('binary'),
    signatures = [];
  for (const object of source.matchAll(/(?:^|\n)(\d+) (\d+) obj\s*\n([\s\S]*?)\nendobj/g)) {
    const body = object[3],
      range = /\/ByteRange\s*\[([^\]]+)\]/.exec(body),
      contents = /\/Contents\s*<([0-9a-fA-F\s]*)>/.exec(body);
    if (!range || !contents) continue;
    const byteRange = range[1].trim().split(/\s+/).map(Number);
    const padded = Buffer.from(contents[1].replace(/\s/g, ''), 'hex');
    let length = padded[1],
      header = 2;
    if (length & 128) {
      const count = length & 127;
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + padded[2 + i];
      header += count;
    }
    const contentsAt = object.index + object[0].indexOf(contents[0]) + contents[0].indexOf('<') + 1;
    signatures.push({
      objectNumber: Number(object[1]),
      generation: Number(object[2]),
      body,
      byteRange,
      contentsAt,
      signatureBytes: contents[1].replace(/\s/g, '').length / 2,
      cms: padded.subarray(0, header + length),
      padding: padded.subarray(header + length),
      signedRevisionLength: byteRange[2] + byteRange[3],
      kind: /\/Type\s*\/DocTimeStamp\b/.test(body) ? 'TIMESTAMP' : 'SIGNATURE',
    });
  }
  return signatures;
}

export function replaceCMS(pdf, index, mutate) {
  const entry = pdfSignatures(pdf).at(index),
    result = mutate(Buffer.from(entry.cms));
  return fillContainer({ ...entry, output: pdf }, result);
}

export function padesFixture(options) {
  const f = certificates(options);
  const certificatePolicy = f.policy;
  f.policy = (changes = {}) =>
    certificatePolicy({ scope: { ...f.scope, trustDomainID: Buffer.from(f.domain) }, ...changes });
  let nonce = 900n;
  const base = plainPDF();
  const sign = async (api, { pdf = base, ...options } = {}) => {
    const prepared = await api.preparePAdESSignature(pdf, {
      certificate: f.signer.der,
      certificates: [f.root.der],
      signingTime: epoch + 10,
      signatureBytes: 8192,
      ...options,
    });
    return prepared.finish(c.sign(prepared.tbs, f.signer.privateKey));
  };
  const augment = async (
    api,
    pdf,
    targetLevel,
    {
      at = epoch + 30,
      finishAt,
      knowledgeTime,
      policy = f.policy(),
      validationMaterial = targetLevel === 'T' ? { certificates: [], crls: [] } : f.material(),
      hashOID = O.sha256,
      authority = f.tsa,
      ...tokenOptions
    } = {},
  ) => {
    const prepared = await api.preparePAdESAugmentation(pdf, {
      targetLevel,
      validationMaterial,
      timestampRequestOptions: { hashOID, policy: O.policy, nonce: nonce++ },
      policy,
      signatureBytes: 8192,
    });
    const token = prepared.requestDER
      ? f.token(prepared.requestDER, { genTime: at, authority, ...tokenOptions })
      : undefined;
    const result = await prepared.finish(token, {
      validationTime: finishAt ?? at + (tokenOptions.accuracy ?? 0),
      knowledgeTime: knowledgeTime ?? finishAt ?? at + (tokenOptions.accuracy ?? 0),
      policy,
    });
    return { pdf: result, prepared, token };
  };
  const lifecycle = async (api) => {
    const b = await sign(api),
      t = (await augment(api, b, 'T', { at: epoch + 20 })).pdf;
    const lt = (await augment(api, t, 'LT', { at: epoch + 25 })).pdf;
    const lta = (await augment(api, lt, 'LTA', { at: epoch + 30 })).pdf;
    return { b, t, lt, lta };
  };
  return { ...f, pdf: base, sign, augment, lifecycle };
}

export async function decision(api, f, pdf, minimumLevel = 'B', changes = {}) {
  return api.verifyPAdES(pdf, {
    minimumLevel,
    validationTime: epoch + 40,
    knowledgeTime: epoch + 40,
    policy: f.policy(),
    ...changes,
  });
}
