import { requireThat } from './core.mjs';
import { parseJSON } from './json.mjs';
export async function readBody(stream, { maxBytes = 8 * 1024 * 1024 } = {}) {
  if (!stream) return Buffer.alloc(0);
  const chunks = [];
  let size = 0;
  for await (const data of stream) {
    const chunk = Buffer.from(data);
    size += chunk.length;
    requireThat(size <= maxBytes, 'HTTP_BODY_LIMIT');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
export function endpoint(url, { allowLoopback = false } = {}) {
  const u = new URL(url);
  requireThat(
    !u.username &&
      !u.password &&
      !u.hash &&
      (u.protocol === 'https:' ||
        (allowLoopback && u.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(u.hostname))),
    'HTTPS_REQUIRED',
  );
  return u;
}
export async function requestBytes(
  url,
  {
    method = 'GET',
    headers = {},
    body,
    maxBytes = 8 * 1024 * 1024,
    timeout = 15000,
    allowLoopback = false,
  } = {},
) {
  endpoint(url, { allowLoopback });
  const response = await fetch(url, {
    method,
    headers,
    body,
    redirect: 'error',
    signal: AbortSignal.timeout(timeout),
  });
  const bytes = await readBody(response.body, { maxBytes });
  return { status: response.status, headers: response.headers, body: bytes };
}
export async function requestJSON(url, options = {}) {
  const r = await requestBytes(url, options);
  requireThat(r.status >= 200 && r.status < 300, 'HTTP_' + r.status);
  requireThat(
    (r.headers.get('content-type') ?? '').split(';')[0] === 'application/json',
    'HTTP_MEDIA_TYPE',
  );
  return parseJSON(r.body.toString('utf8'));
}
export const postJSON = (url, value, options = {}) =>
  requestJSON(url, {
    ...options,
    method: 'POST',
    headers: { ...options.headers, 'content-type': 'application/json' },
    body: JSON.stringify(value),
  });
export function sendJSON(response, status, value, headers = {}) {
  const b = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'content-length': b.length,
    ...headers,
  });
  response.end(b);
}
