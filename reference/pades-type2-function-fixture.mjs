import { plainPDF, appendRevision } from './pades-fixtures.mjs';

export const standardType2Function = {
  FunctionType: '2', Domain: '[0 1]', C0: '[1 0 0]',
  C1: '[0 0 1]', N: '1', Range: '[0 1 0 1 0 1]',
};

export function axialType2Document(entries = {}, {
  colorSpace = '/DeviceRGB', functionValue, content = '/Sh1 sh\n', objects = [],
  colorResources = '', shadingDomain, shadingType = '2', shadingStream = false,
  coords = '[0 0 100 0]', extend = '[true true]', bbox,
} = {}) {
  const fields = { ...standardType2Function, ...entries };
  const dictionary = Object.entries(fields)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `/${key} ${value}`).join(' ');
  return appendRevision(plainPDF(), [
    { number: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] ' +
      `/Resources << /Shading << /Sh1 6 0 R >> ${colorResources} >> /Contents 5 0 R >>` },
    { number: 5, body: `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}endstream` },
    { number: 6, body: `<< /ShadingType ${shadingType} /ColorSpace ${colorSpace} ` +
      `${coords == null ? '' : `/Coords ${coords} `}` +
      `${shadingDomain === undefined ? '' : `/Domain ${shadingDomain} `}` +
      `/Function ${functionValue ?? `<< ${dictionary} >>`} ` +
      `${extend == null ? '' : `/Extend ${extend} `}` +
      `${bbox === undefined ? '' : `/BBox ${bbox} `}` +
      (shadingStream ? '/Length 0 >>\nstream\nendstream' : '>>') },
    ...objects,
  ]);
}
