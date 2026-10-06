import { requireThat, equal, sha256 } from '../core.mjs';
import { leafHash, nodeHash, validSubtree } from '../mtc.mjs';

const split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
// Leaves and complete subtree hashes are immutable rows. A head is the only updated row.
export class IndexedMerkleLog {
  constructor(journal, origin, { maxEntries = 2 ** 40, maxBytes = Number.MAX_SAFE_INTEGER } = {}) {
    requireThat(typeof origin === 'string' && origin.length <= 1024, 'LOG_ORIGIN');
    Object.assign(this, { journal, origin, maxEntries, maxBytes });
    this.ns = 'merkle:' + origin;
  }
  head() {
    return this.journal.get(this.ns, 'head')?.value ?? { size: 0, bytes: 0 };
  }
  entry(index) {
    requireThat(Number.isSafeInteger(index) && index >= 0, 'LOG_INDEX');
    const row = this.journal.get(this.ns, 'entry:' + index);
    requireThat(row, 'LOG_MISSING_ENTRY');
    return row.value;
  }
  entries(start, end) {
    requireThat(
      Number.isSafeInteger(start) &&
        Number.isSafeInteger(end) &&
        start >= 0 &&
        end >= start &&
        end - start <= 256 &&
        end <= this.head().size,
      'LOG_RANGE',
    );
    return Array.from({ length: end - start }, (_, i) => this.entry(start + i));
  }
  append(bytes, id) {
    requireThat(
      Buffer.isBuffer(bytes) &&
        bytes.length <= 65535 &&
        typeof id === 'string' &&
        id.length <= 1024,
      'LOG_ENTRY',
    );
    return this.journal.transaction(() => {
      const previous = this.journal.get(this.ns, 'id:' + id);
      if (previous) {
        requireThat(equal(this.entry(previous.value.index), bytes), 'LOG_ID_CONFLICT');
        return previous.value.index;
      }
      const old = this.journal.get(this.ns, 'head'),
        head = old?.value ?? { size: 0, bytes: 0 },
        index = head.size;
      requireThat(
        index < this.maxEntries && head.bytes + bytes.length <= this.maxBytes,
        'LOG_CAPACITY',
      );
      this.journal.put(this.ns, 'entry:' + index, bytes);
      this.journal.put(this.ns, 'id:' + id, { index });
      let width = 1,
        start = index,
        hash = leafHash(bytes);
      this.journal.put(this.ns, `node:${start}:${width}`, hash);
      while (start % (width * 2) === width) {
        start -= width;
        const left = this.journal.get(this.ns, `node:${start}:${width}`);
        requireThat(left, 'LOG_MISSING_NODE');
        hash = nodeHash(left.value, hash);
        width *= 2;
        this.journal.put(this.ns, `node:${start}:${width}`, hash);
      }
      this.journal.put(
        this.ns,
        'head',
        { size: index + 1, bytes: head.bytes + bytes.length },
        old?.revision ?? -1,
      );
      return index;
    });
  }
  root(size = this.head().size, start = 0) {
    requireThat(
      Number.isSafeInteger(size) &&
        Number.isSafeInteger(start) &&
        validSubtree(start, size) &&
        size <= this.head().size,
      'LOG_RANGE',
    );
    const n = size - start;
    if (!n) return sha256(Buffer.alloc(0));
    const row = this.journal.get(this.ns, `node:${start}:${n}`);
    if (row) return row.value;
    const k = split(n);
    return nodeHash(this.root(start + k, start), this.root(size, start + k));
  }
  inclusion(index, size = this.head().size, start = 0) {
    requireThat(
      Number.isSafeInteger(index) &&
        index >= start &&
        index < size &&
        validSubtree(start, size) &&
        size <= this.head().size,
      'LOG_RANGE',
    );
    const walk = (a, b) => {
      if (b - a === 1) return [];
      const k = a + split(b - a);
      return index < k ? [...walk(a, k), this.root(b, k)] : [...walk(k, b), this.root(k, a)];
    };
    return walk(start, size);
  }
  consistency(start, end, size = this.head().size) {
    requireThat(
      validSubtree(start, end) &&
        Number.isSafeInteger(size) &&
        end <= size &&
        size <= this.head().size,
      'LOG_RANGE',
    );
    if (start === end) return [];
    const sub = (a, b, s, e, complete) => {
      if (s === a && e === b) return complete ? [] : [this.root(b, a)];
      const k = a + split(b - a);
      if (e <= k) return [...sub(a, k, s, e, complete), this.root(b, k)];
      if (s >= k) return [...sub(k, b, s, e, complete), this.root(k, a)];
      requireThat(s === a, 'LOG_ALIGNMENT');
      return [...sub(k, b, k, e, false), this.root(k, a)];
    };
    return sub(0, size, start, end, true);
  }
}

// Explicit, repeatable migration. Preserve the source row for audit and rollback to the old release.
export function migrateArrayLog(journal, { namespace, id, origin, ids }) {
  return journal.transaction(() => {
    const legacy = journal.get(namespace, id);
    requireThat(Array.isArray(legacy?.value.entries), 'LOG_MIGRATION_SOURCE');
    const log = new IndexedMerkleLog(journal, origin);
    for (const [index, entry] of legacy.value.entries.entries()) {
      const entryID = ids?.[index] ?? legacy.value.ids?.[index] ?? 'legacy:' + index;
      if (index < log.head().size)
        requireThat(equal(log.entry(index), entry), 'LOG_MIGRATION_CONFLICT');
      else requireThat(log.append(entry, entryID) === index, 'LOG_MIGRATION_INDEX');
    }
    const marker = journal.get('log-migration', origin);
    if (!marker)
      journal.put('log-migration', origin, {
        namespace,
        id,
        sourceRevision: legacy.revision,
        size: legacy.value.entries.length,
      });
    return log.head();
  });
}

export function migrateMirrorLog(journal, { kind, origin }) {
  requireThat(['tlog', 'mtc-mirror'].includes(kind), 'LOG_MIGRATION_KIND');
  const namespace = kind === 'tlog' ? 'mirror-data' : 'mirror';
  return journal.transaction(() => {
    const row = journal.get(namespace, origin);
    requireThat(row, 'LOG_MIGRATION_SOURCE');
    const archiveID = kind + ':' + origin;
    if (!row.value.entries) {
      requireThat(journal.get('log-migration-archive', archiveID), 'LOG_MIGRATION_SOURCE');
      return new IndexedMerkleLog(journal, archiveID).head();
    }
    const ids = row.value.entries.map((_, i) => String(i));
    const head = migrateArrayLog(journal, { namespace, id: origin, origin: archiveID, ids });
    const log = new IndexedMerkleLog(journal, archiveID);
    if (row.value.root)
      requireThat(equal(log.root(Number(row.value.size)), row.value.root), 'LOG_MIGRATION_ROOT');
    if (row.value.note) {
      // Parse only the signed note's root line; normal note validation remains a deployment prerequisite.
      const lines = row.value.note.split('\n');
      requireThat(
        lines[0] === origin &&
          Number(lines[1]) === Number(row.value.size) &&
          equal(log.root(Number(row.value.size)), Buffer.from(lines[2], 'base64')),
        'LOG_MIGRATION_ROOT',
      );
    }
    journal.put('log-migration-archive', archiveID, row.value);
    const { entries, ...metadata } = row.value;
    journal.put(namespace, origin, metadata, row.revision);
    return head;
  });
}
