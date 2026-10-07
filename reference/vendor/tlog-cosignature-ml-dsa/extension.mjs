import {createHash,createPublicKey,verify} from 'node:crypto';
const requireValue = (condition,code) => {if(!condition){const e=new Error(code);e.code=code;throw e;}};
const u64 = n => {n=BigInt(n);requireValue(n>=0n&&n<=0xffffffffffffffffn,'SUBTREE_INTEGER');const b=Buffer.alloc(8);b.writeBigUInt64BE(n);return b;};
const text = s => {requireValue(typeof s==='string'&&/^[\x21-\x2a\x2c-\x7e]{1,255}$/.test(s),'SUBTREE_NAME');const b=Buffer.from(s);return Buffer.concat([Buffer.from([b.length]),b]);};
export function mlDsa87KeyID(name,key) {
  text(name);
  const publicKey=key.type==='public'?key:createPublicKey(key);
  requireValue(publicKey.asymmetricKeyType==='ml-dsa-87','NOTE_KEY_SCHEME');
  return createHash('sha256').update(Buffer.concat([
    Buffer.from('certconcord/tlog-ml-dsa-87/v1\n'),Buffer.from(name+'\n'),
    publicKey.export({type:'spki',format:'der'}),
  ])).digest().subarray(0,4);
}
export function subtreeInput({name,origin,start=0n,end,root,timestamp=0}) {
  start=BigInt(start);end=BigInt(end);timestamp=BigInt(timestamp);
  requireValue(start>=0n&&end>=start&&end<=0xffffffffffffffffn&&(!timestamp||start===0n),'SUBTREE_CONTEXT');
  let width=1n;while(width<end-start)width<<=1n;
  requireValue(start%width===0n&&Buffer.isBuffer(root)&&root.length===32,'SUBTREE_CONTEXT');
  return Buffer.concat([Buffer.from('subtree/v1\n\0'),text(name),u64(timestamp),text(origin),u64(start),u64(end),root]);
}
export function verifyCosignature(context,signature,key) {
  requireValue(key.asymmetricKeyType==='ml-dsa-87','NOTE_KEY_SCHEME');
  return Buffer.isBuffer(signature)&&signature.length===4627&&verify(null,subtreeInput(context),key,signature);
}
