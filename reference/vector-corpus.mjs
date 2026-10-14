import fs from 'node:fs';
import { resolve, relative, sep, isAbsolute } from 'node:path';

const need = (condition, code) => {
  if (!condition) throw Object.assign(new Error(code), { code });
};

/** Shared bounded file reader; it makes no trust or verification decisions. */
export function createVectorReader(directory) {
  const root = fs.realpathSync(directory);
  const readContained = (name, limit, sizeCode, expectedSize) => {
    need(
      typeof name === 'string' &&
        name.length <= 240 &&
        /^[a-zA-Z0-9][a-zA-Z0-9._/-]*$/.test(name) &&
        name.split('/').every((part) => part !== '' && part !== '.' && part !== '..'),
      'VECTOR_PATH',
    );
    const path = resolve(root, name);
    const flags =
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);
    let fd;
    try {
      fd = fs.openSync(path, flags);
    } catch (error) {
      need(!['ELOOP', 'EISDIR'].includes(error.code), 'VECTOR_FILE_TYPE');
      throw error;
    }
    try {
      const before = fs.fstatSync(fd, { bigint: true });
      need(before.isFile(), 'VECTOR_FILE_TYPE');
      const checkPath = (opened) => {
        const linked = fs.lstatSync(path, { bigint: true });
        need(!linked.isSymbolicLink() && linked.isFile(), 'VECTOR_FILE_TYPE');
        need(linked.dev === opened.dev && linked.ino === opened.ino, 'VECTOR_FILE_CHANGED');
        const suffix = relative(root, fs.realpathSync(path));
        need(
          suffix && !isAbsolute(suffix) && suffix !== '..' && !suffix.startsWith('..' + sep),
          'VECTOR_PATH',
        );
      };
      // These path checks reject observed links/escapes, but do not provide an
      // atomic directory sandbox on platforms without descriptor-relative open.
      checkPath(before);
      need(
        before.size >= 0n &&
          before.size <= BigInt(limit) &&
          (expectedSize === undefined || before.size === BigInt(expectedSize)),
        sizeCode,
      );
      const bytes = Buffer.alloc(Number(before.size));
      let offset = 0;
      while (offset < bytes.length) {
        const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
        need(count > 0, 'VECTOR_FILE_CHANGED');
        offset += count;
      }
      // A growing file cannot cause an unbounded read or allocation.
      need(fs.readSync(fd, Buffer.alloc(1), 0, 1, offset) === 0, 'VECTOR_FILE_CHANGED');
      const after = fs.fstatSync(fd, { bigint: true });
      need(
        after.isFile() &&
          after.dev === before.dev &&
          after.ino === before.ino &&
          after.size === before.size &&
          after.mtimeNs === before.mtimeNs &&
          after.ctimeNs === before.ctimeNs,
        'VECTOR_FILE_CHANGED',
      );
      checkPath(after);
      return bytes;
    } finally {
      fs.closeSync(fd);
    }
  };
  return Object.freeze({ root, readContained });
}
