import { PDFDocument, PDFName, PDFArray, PDFDict, PDFRef, StandardFonts } from 'pdf-lib';
import { random, requireThat, parseDER, equal, sha512 } from './core.mjs';

export async function examplePDF(text = 'CertConcord draft 02 synthetic document') {
  const d = await PDFDocument.create();
  const p = d.addPage([595, 842]),
    f = await d.embedFont(StandardFonts.Helvetica);
  p.drawText(text, { x: 50, y: 760, size: 16, font: f });
  return Buffer.from(await d.save({ useObjectStreams: false }));
}
function lookup(ctx, dict, key) {
  const v = dict.get(PDFName.of(key));
  return v && ctx.lookup(v);
}
function fieldList(doc) {
  const form = lookup(doc.context, doc.catalog, 'AcroForm');
  if (!form) return [];
  requireThat(form instanceof PDFDict && !form.has(PDFName.of('XFA')), 'PDF_XFA_UNSUPPORTED');
  const fields = lookup(doc.context, form, 'Fields');
  requireThat(fields instanceof PDFArray, 'PDF_FIELDS');
  return fields.asArray();
}
function collectSignatures(doc) {
  const out = [],
    active = new Set();
  function visit(value, depth) {
    requireThat(depth < 20, 'PDF_FIELD_DEPTH');
    const key = value.toString();
    requireThat(!active.has(key), 'PDF_FIELD_CYCLE');
    active.add(key);
    const f = doc.context.lookup(value);
    requireThat(f instanceof PDFDict, 'PDF_FIELD');
    const type = f.get(PDFName.of('FT'));
    if (type?.toString() === '/Sig' && f.get(PDFName.of('V')))
      out.push(doc.context.lookup(f.get(PDFName.of('V'))));
    const kids = lookup(doc.context, f, 'Kids');
    if (kids) kids.asArray().forEach((k) => visit(k, depth + 1));
    active.delete(key);
  }
  fieldList(doc).forEach((f) => visit(f, 0));
  return out;
}
function enforceAppendPolicy(doc) {
  const perms = lookup(doc.context, doc.catalog, 'Perms');
  if (perms) {
    const signature = lookup(doc.context, perms, 'DocMDP');
    if (signature) {
      const refs = lookup(doc.context, signature, 'Reference');
      requireThat(refs instanceof PDFArray, 'PDF_DOCMDP');
      for (const ref of refs.asArray()) {
        const r = doc.context.lookup(ref);
        if (r.get(PDFName.of('TransformMethod'))?.toString() === '/DocMDP') {
          const params = lookup(doc.context, r, 'TransformParams');
          const permission = Number(params?.get(PDFName.of('P'))?.toString() ?? '2');
          requireThat(false, 'PDF_DOCMDP_UNSUPPORTED_TRANSFORM');
        }
      }
    }
  }
  for (const sig of collectSignatures(doc)) {
    const refs = lookup(doc.context, sig, 'Reference');
    if (refs)
      for (const ref of refs.asArray()) {
        const r = doc.context.lookup(ref);
        if (r.get(PDFName.of('TransformMethod'))?.toString() === '/FieldMDP') {
          const params = lookup(doc.context, r, 'TransformParams');
          requireThat(
            params?.get(PDFName.of('Action'))?.toString() !== '/All',
            'PDF_ALL_FIELDS_LOCKED',
          );
        }
      }
  }
}

// An incremental update preserves every byte of the previous revision.
export async function preparePDF(
  input,
  { signatureBytes = 32768, fieldName = 'CERTCONCORD-' + random(8).toString('hex') } = {},
) {
  const original = Buffer.from(input);
  requireThat(
    original.length < 64 * 1024 * 1024 &&
      original.subarray(0, 5).toString() === '%PDF-' &&
      signatureBytes >= 8192 &&
      signatureBytes <= 1048576,
    'PDF_LIMIT',
  );
  requireThat(/^[A-Za-z0-9_-]{1,80}$/.test(fieldName), 'PDF_FIELD_NAME');
  const doc = await PDFDocument.load(original, { updateMetadata: false });
  requireThat(!doc.isEncrypted, 'PDF_ENCRYPTED');
  enforceAppendPolicy(doc);
  const previous = /startxref\s+(\d+)\s+%%EOF\s*$/.exec(original.toString('latin1'));
  requireThat(previous, 'PDF_TRAILER');
  const root = doc.context.trailerInfo.Root;
  requireThat(root instanceof PDFRef, 'PDF_ROOT');
  const first = doc.context.largestObjectNumber + 1,
    signatureRef = first,
    fieldRef = first + 1,
    formRef = first + 2,
    rangePlaceholder =
      '0 ' + ''.padEnd(20, '0') + ' ' + ''.padEnd(20, '0') + ' ' + ''.padEnd(20, '0');
  const existing = fieldList(doc);
  const catalog = doc.catalog
    .entries()
    .filter(([key]) => key.toString() !== '/AcroForm')
    .map(([k, v]) => `${k} ${v}`)
    .join('\n');
  const oldForm = lookup(doc.context, doc.catalog, 'AcroForm'),
    formProperties = oldForm
      ? oldForm
          .entries()
          .filter(([k]) => !['/Fields', '/SigFlags'].includes(k.toString()))
          .map(([k, v]) => `${k} ${v}`)
          .join('\n')
      : '';
  const objects = [
    {
      number: signatureRef,
      generation: 0,
      text: `<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [${rangePlaceholder}] /Contents <${'0'.repeat(signatureBytes * 2)}> >>`,
    },
    {
      number: fieldRef,
      generation: 0,
      text: `<< /FT /Sig /T (${fieldName}) /V ${signatureRef} 0 R >>`,
    },
    {
      number: formRef,
      generation: 0,
      text: `<< ${formProperties} /Fields [${existing.join(' ')} ${fieldRef} 0 R] /SigFlags 3 >>`,
    },
    {
      number: root.objectNumber,
      generation: root.generationNumber,
      text: `<< ${catalog}\n/AcroForm ${formRef} 0 R >>`,
    },
  ];
  let offset = original.length + 1;
  const chunks = [original, Buffer.from('\n')],
    xref = [];
  for (const o of objects) {
    xref.push({ ...o, offset });
    const chunk = Buffer.from(`${o.number} ${o.generation} obj\n${o.text}\nendobj\n`);
    chunks.push(chunk);
    offset += chunk.length;
  }
  const xrefOffset = offset,
    xrefText = xref
      .sort((a, b) => a.number - b.number)
      .map(
        (o) =>
          `${o.number} 1\n${String(o.offset).padStart(10, '0')} ${String(o.generation).padStart(5, '0')} n \n`,
      )
      .join('');
  const id = doc.context.trailerInfo.ID,
    info = doc.context.trailerInfo.Info;
  chunks.push(
    Buffer.from(
      `xref\n${xrefText}trailer\n<< /Size ${first + 3} /Root ${root}${info ? ' /Info ' + info : ''}${id ? ' /ID ' + id : ''} /Prev ${previous[1]} >>\nstartxref\n${xrefOffset}\n%%EOF\n`,
    ),
  );
  const output = Buffer.concat(chunks),
    start = original.length,
    contentsAt = output.indexOf(Buffer.from('/Contents <'), start) + 10,
    contentsEnd = contentsAt + signatureBytes * 2 + 2;
  requireThat(output[contentsAt] === 60 && output[contentsEnd - 1] === 62, 'PDF_CONTENTS_OFFSET');
  const range = [0, contentsAt, contentsEnd, output.length - contentsEnd],
    at = output.indexOf(Buffer.from(rangePlaceholder), start);
  requireThat(at > start, 'PDF_RANGE_OFFSET');
  const rangeText = range.join(' ').padEnd(rangePlaceholder.length, ' ');
  requireThat(rangeText.length === rangePlaceholder.length, 'PDF_RANGE_SPACE');
  output.write(rangeText, at, 'ascii');
  const content = Buffer.concat([output.subarray(0, contentsAt), output.subarray(contentsEnd)]);
  return {
    byteRange: range,
    content,
    contentHash: sha512(content),
    output,
    contentsAt,
    signatureBytes,
  };
}

function derFromPaddedHex(hex) {
  requireThat(/^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0, 'PDF_SIGNATURE_HEX');
  const raw = Buffer.from(hex, 'hex');
  requireThat(raw[0] === 48 && raw.length >= 2, 'PDF_SIGNATURE_DER');
  let h = 2,
    n = raw[1];
  if (n & 128) {
    const width = n & 127;
    requireThat(width >= 1 && width <= 4 && h + width <= raw.length, 'PDF_DER_LENGTH');
    n = 0;
    for (let i = 0; i < width; i++) n = n * 256 + raw[h++];
  }
  requireThat(
    h + n <= raw.length && raw.subarray(h + n).every((b) => b === 0),
    'PDF_CONTENTS_PADDING',
  );
  const value = raw.subarray(0, h + n);
  parseDER(value);
  return value;
}
export async function verifyPDF(input) {
  const raw = Buffer.from(input);
  requireThat(raw.length <= 64 * 1024 * 1024, 'PDF_LIMIT');
  const doc = await PDFDocument.load(raw, { updateMetadata: false });
  requireThat(!doc.isEncrypted, 'PDF_ENCRYPTED');
  const signatures = collectSignatures(doc);
  requireThat(signatures.length > 0 && signatures.length <= 100, 'PDF_SIGNATURE_COUNT');
  const results = [];
  for (const sig of signatures) {
    requireThat(
      sig instanceof PDFDict &&
        sig.get(PDFName.of('SubFilter'))?.toString() === '/ETSI.CAdES.detached',
      'PDF_SUBFILTER',
    );
    const ranges = lookup(doc.context, sig, 'ByteRange');
    requireThat(ranges instanceof PDFArray && ranges.size() === 4, 'PDF_BYTE_RANGE');
    const a = ranges.asArray().map((n) => Number(n.toString()));
    requireThat(
      a.every(Number.isSafeInteger) &&
        a[0] === 0 &&
        a[1] > 0 &&
        a[2] > a[1] + 2 &&
        a[3] >= 0 &&
        a[2] + a[3] <= raw.length,
      'PDF_BYTE_RANGE',
    );
    requireThat(raw[a[1]] === 60 && raw[a[2] - 1] === 62, 'PDF_CONTENTS_GAP');
    const cms = derFromPaddedHex(raw.subarray(a[1] + 1, a[2] - 1).toString('ascii')),
      contents = sig.get(PDFName.of('Contents')).toString();
    requireThat(
      contents.toLowerCase() === raw.subarray(a[1], a[2]).toString('ascii').toLowerCase(),
      'PDF_CONTENTS_REFERENCE',
    );

    requireThat(
      /%%EOF\s*$/.test(raw.subarray(0, a[2] + a[3]).toString('latin1')),
      'PDF_SIGNED_REVISION_END',
    );
    requireThat(
      results.reduce((sum, r) => sum + r.cms.length, 0) + cms.length <= 16 * 1024 * 1024,
      'PDF_SIGNATURE_TOTAL',
    );
    results.push({
      cms,
      byteRange: a,
      signedRevisionLength: a[2] + a[3],
      subsequentBytes: raw.length - a[2] - a[3],
      currentRevisionCovered: a[2] + a[3] === raw.length,
    });
  }
  const modifications = [];
  for (const result of results) {
    if (result.currentRevisionCovered) {
      modifications.push('UNCHANGED');
      continue;
    }
    const prior = await PDFDocument.load(raw.subarray(0, result.signedRevisionLength), {
      updateMetadata: false,
    });
    modifications.push(classifyAppend(prior, doc));
  }
  return {
    signatures: results,
    currentRevisionCovered: results.some((r) => r.currentRevisionCovered),
    modificationPolicy: modifications.every((x) => ['UNCHANGED', 'SIGNATURES_ONLY'].includes(x))
      ? 'ACCEPTED_SIGNATURE_APPEND'
      : 'REJECTED',
    modifications,
  };
}
function dictionaryView(dict, exclude = []) {
  return dict
    .entries()
    .filter(([k]) => !exclude.includes(k.toString()))
    .map(([k, v]) => `${k}:${v}`)
    .sort()
    .join('\n');
}
function classifyAppend(prior, current) {
  if (
    lookup(prior.context, prior.catalog, 'Perms') ||
    collectSignatures(prior).some((s) => s.has(PDFName.of('Reference')))
  )
    return 'RESTRICTED_REVISION_POLICY';
  if (
    dictionaryView(prior.catalog, ['/AcroForm']) !== dictionaryView(current.catalog, ['/AcroForm'])
  )
    return 'CATALOG_CHANGED';
  const oldFields = fieldList(prior),
    newFields = fieldList(current);
  if (
    newFields.length < oldFields.length ||
    oldFields.some((f, i) => f.toString() !== newFields[i].toString())
  )
    return 'FIELDS_CHANGED';
  const oldForm = lookup(prior.context, prior.catalog, 'AcroForm'),
    newForm = lookup(current.context, current.catalog, 'AcroForm');
  if (
    (oldForm ? dictionaryView(oldForm, ['/Fields', '/SigFlags']) : '') !==
    (newForm ? dictionaryView(newForm, ['/Fields', '/SigFlags']) : '')
  )
    return 'FORM_CHANGED';
  const allowed = new Set([
    current.context.trailerInfo.Root.toString(),
    current.catalog.get(PDFName.of('AcroForm')).toString(),
  ]);
  for (const f of newFields.slice(oldFields.length)) {
    const field = current.context.lookup(f);
    if (
      !(field instanceof PDFDict) ||
      field.get(PDFName.of('FT'))?.toString() !== '/Sig' ||
      field.entries().some(([k]) => !['/FT', '/T', '/V'].includes(k.toString()))
    )
      return 'NON_SIGNATURE_FIELD_ADDED';
    allowed.add(f.toString());
    const v = field.get(PDFName.of('V'));
    if (!(v instanceof PDFRef)) return 'DIRECT_SIGNATURE_ADDED';
    allowed.add(v.toString());
  }
  const originals = new Map(
    prior.context.enumerateIndirectObjects().map(([ref, obj]) => [ref.toString(), obj]),
  );
  for (const [ref, obj] of current.context.enumerateIndirectObjects()) {
    const id = ref.toString(),
      old = originals.get(id);
    if (old) {
      if (id !== prior.context.trailerInfo.Root.toString() && old.toString() !== obj.toString())
        return 'EXISTING_OBJECT_CHANGED';
      originals.delete(id);
    } else if (!allowed.has(id)) return 'UNAPPROVED_OBJECT_ADDED';
  }
  if (originals.size) return 'OBJECT_REMOVED';
  return 'SIGNATURES_ONLY';
}
