// RFC 8785 JCS, UTF-8 output, integer-only profile (mirror of jcs.py).
// Usage: node jcs.mjs <dataset.json>  -> prints "<index>\t<sha256(JCS(record))>" per record
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export function canon(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new Error('non-integer or unsafe number');
    return String(v);
  }
  if (typeof v === 'string') {
    if (/[\uD800-\uDFFF]/.test(v.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, '')))
      throw new Error('lone surrogate');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort(); // default sort = UTF-16 code units (RFC 8785 3.2.3)
    for (const k of keys) canon(k); // keys obey the same string rules (lone surrogates rejected)
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  throw new Error('unsupported type ' + typeof v);
}

export const digest = v => createHash('sha256').update(Buffer.from(canon(v), 'utf8')).digest('hex');

if (process.argv[2]) {
  const ds = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  const input = Array.isArray(ds) ? ds : ds.records;
  input.forEach((r, i) => console.log(i + '\t' + digest(r)));
}
