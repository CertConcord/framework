import { KeyObject, X509Certificate } from 'node:crypto';
import { types } from 'node:util';

const typedArrayConstructors = new Map([
  [Int8Array.prototype, Int8Array],
  [Uint8Array.prototype, Uint8Array],
  [Uint8ClampedArray.prototype, Uint8ClampedArray],
  [Int16Array.prototype, Int16Array],
  [Uint16Array.prototype, Uint16Array],
  [Int32Array.prototype, Int32Array],
  [Uint32Array.prototype, Uint32Array],
  [BigInt64Array.prototype, BigInt64Array],
  [BigUint64Array.prototype, BigUint64Array],
  [Float32Array.prototype, Float32Array],
  [Float64Array.prototype, Float64Array],
]);

// Copy closed relying-party trust data. Functions are live external policy inputs;
// KeyObject handles are deliberately retained because they expose no mutable key bytes.
export function snapshotTrust(value, seen = new WeakMap()) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return value;
  if (types.isProxy(value)) throw new TypeError('SDK_TRUST_PROXY');
  if (typeof value === 'function') return value;
  if (seen.has(value)) return seen.get(value);
  if (value instanceof KeyObject) return value;
  if (value instanceof X509Certificate) return new X509Certificate(value.raw);
  if (Buffer.isBuffer(value)) {
    const result = Buffer.from(value);
    seen.set(value, result);
    return result;
  }
  if (value instanceof ArrayBuffer) {
    if (Object.getPrototypeOf(value) !== ArrayBuffer.prototype || Reflect.ownKeys(value).length)
      throw new TypeError('SDK_TRUST_OBJECT_TYPE');
    const result = new ArrayBuffer(value.byteLength);
    new Uint8Array(result).set(new Uint8Array(value));
    seen.set(value, result);
    return result;
  }
  if (ArrayBuffer.isView(value)) {
    const proto = Object.getPrototypeOf(value);
    const ctor = typedArrayConstructors.get(proto);
    if (proto !== DataView.prototype && !ctor) throw new TypeError('SDK_TRUST_OBJECT_TYPE');
    const ownKeys = Reflect.ownKeys(value);
    if (proto === DataView.prototype ? ownKeys.length !== 0
      : ownKeys.some((key, index) => key !== String(index)))
      throw new TypeError('SDK_TRUST_OBJECT_TYPE');
    const result = proto === DataView.prototype
      ? new DataView(snapshotTrust(value.buffer, seen), value.byteOffset, value.byteLength)
      : new ctor(value);
    seen.set(value, result);
    return result;
  }
  if (Array.isArray(value)) {
    const result = new Array(value.length);
    seen.set(value, result);
    copyOwnValues(value, result, seen);
    return result;
  }
  if (value instanceof Map) {
    if (Object.getPrototypeOf(value) !== Map.prototype) throw new TypeError('SDK_TRUST_OBJECT_TYPE');
    const result = new Map();
    seen.set(value, result);
    for (const [key, entry] of Map.prototype.entries.call(value))
      result.set(snapshotTrust(key, seen), snapshotTrust(entry, seen));
    return result;
  }
  if (value instanceof Set) {
    if (Object.getPrototypeOf(value) !== Set.prototype) throw new TypeError('SDK_TRUST_OBJECT_TYPE');
    const result = new Set();
    seen.set(value, result);
    for (const entry of Set.prototype.values.call(value)) result.add(snapshotTrust(entry, seen));
    return result;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new TypeError('SDK_TRUST_OBJECT_TYPE');
  const result = Object.create(proto);
  seen.set(value, result);
  copyOwnValues(value, result, seen);
  return result;
}

function copyOwnValues(source, target, seen) {
  for (const key of Reflect.ownKeys(source)) {
    if (Array.isArray(source) && key === 'length') continue;
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (!('value' in descriptor)) throw new TypeError('SDK_TRUST_ACCESSOR');
    Object.defineProperty(target, key, {
      value: snapshotTrust(descriptor.value, seen),
      enumerable: descriptor.enumerable,
      writable: true,
      configurable: true,
    });
  }
}
