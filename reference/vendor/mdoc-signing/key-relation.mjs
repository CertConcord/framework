import {createPublicKey,timingSafeEqual} from 'node:crypto';
export function documentKeyRelation(mode, documentSPKI, holderSPKI) {
  const parse = bytes => createPublicKey({key:bytes,format:'der',type:'spki'});
  const document = parse(documentSPKI), holder = parse(holderSPKI);
  const normalized = key => key.export({format:'der',type:'spki'});
  const d=normalized(document),h=normalized(holder);
  const same=d.length===h.length && timingSafeEqual(d,h);
  const ec=document.asymmetricKeyType==='ec' && document.asymmetricKeyDetails.namedCurve==='prime256v1';
  const codes={INDEPENDENT_PQ:'DOCUMENT_INDEPENDENT_PQ_KEY',DEVICE_KEY:'DOCUMENT_DEVICE_KEY_BINDING',PASSKEY_KEY:'DOCUMENT_PASSKEY_KEY_BINDING'};
  const valid=mode==='INDEPENDENT_PQ' ? ['ml-dsa-65','ml-dsa-87'].includes(document.asymmetricKeyType) && !same :
    mode==='DEVICE_KEY' ? ec && same : mode==='PASSKEY_KEY' ? ec && !same : false;
  if(!valid){const error=new Error(codes[mode]??'DOCUMENT_KEY_MODE');error.code=error.message;throw error;}
  return mode;
}
