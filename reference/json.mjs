// Duplicate members are rejected before object construction, including escaped duplicates.
export function parseJSON(text, { maxBytes = 1048576, maxDepth = 32 } = {}) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > maxBytes)
    throw Error('JSON_SIZE');
  let p = 0;
  const ws = () => {
    while (/[\x20\t\r\n]/.test(text[p] ?? '!')) p++;
  };
  function string() {
    const start = p++;
    while (p < text.length) {
      if (text[p] === '\\') {
        p += 2;
        continue;
      }
      if (text[p++] === '"') return JSON.parse(text.slice(start, p));
    }
    throw Error('JSON_STRING');
  }
  function value(depth) {
    if (depth > maxDepth) throw Error('JSON_DEPTH');
    ws();
    const ch = text[p];
    if (ch === '"') return string();
    if (ch === '{' || ch === '[') {
      p++;
      ws();
      const object = ch === '{',
        out = object ? Object.create(null) : [],
        end = object ? '}' : ']',
        keys = new Set();
      if (text[p] === end) {
        p++;
        return out;
      }
      while (p < text.length) {
        let key;
        if (object) {
          if (text[p] !== '"') throw Error('JSON_KEY');
          key = string();
          if (keys.has(key)) throw Error('JSON_DUPLICATE');
          keys.add(key);
          ws();
          if (text[p++] !== ':') throw Error('JSON_COLON');
        }
        const item = value(depth + 1);
        if (object) out[key] = item;
        else out.push(item);
        ws();
        if (text[p] === end) {
          p++;
          return out;
        }
        if (text[p++] !== ',') throw Error('JSON_SEPARATOR');
        ws();
      }
      throw Error('JSON_TRUNCATED');
    }
    for (const [word, v] of [
      ['true', true],
      ['false', false],
      ['null', null],
    ])
      if (text.startsWith(word, p)) {
        p += word.length;
        return v;
      }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(p));
    if (!match) throw Error('JSON_VALUE');
    p += match[0].length;
    const n = Number(match[0]);
    if (!Number.isFinite(n)) throw Error('JSON_NUMBER');
    return n;
  }
  const out = value(0);
  ws();
  if (p !== text.length) throw Error('JSON_TRAILING');
  return out;
}
