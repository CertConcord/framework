import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { runFoundationDemo } from './foundation-demo.mjs';
import { sendJSON, readBody } from './transport.mjs';

const port = Number(process.env.PORT ?? 8787),
  token = randomBytes(32).toString('base64url');
let running = false;
if (!Number.isInteger(port) || port < 1024 || port > 65535)
  throw Error('PORT must be an integer from 1024 through 65535');
const origin = 'http://127.0.0.1:' + port;
const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CertConcord Document Signing Example</title><link rel="stylesheet" href="/style.css"><main><p>CertConcord · Document Trust Infrastructure 1.0</p><h1>Credential issuance and document signing</h1><p>Follow a sample identity through verification, signing-credential issuance, wallet presentation and approval of a document signature.</p><ol><li>Verify a sample identity credential and obtain registration-authority approval</li><li>Issue a personal signer mdoc and deliver it through OpenID4VCI</li><li>Present the credential through OpenID4VP for the requested document</li><li>Authorize the operation and create an ML-DSA document signature</li><li>Verify the signature, credential and evidence package</li></ol><button id="run">Run example</button><pre id="result" aria-live="polite">Ready.</pre><p>Each run generates its own sample identity, document and software keys. The result lists the signing mode and verification assertions.</p></main><script src="/client.js"></script></html>`;
const server = createServer(async (req, res) => {
  if (req.headers.host !== new URL(origin).host) {
    res.writeHead(400);
    return res.end();
  }
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'GET' && req.url === '/') {
    res.setHeader('content-type', 'text/html;charset=utf-8');
    return res.end(html);
  }
  if (req.method === 'GET' && req.url === '/style.css') {
    res.setHeader('content-type', 'text/css');
    return res.end(
      'body{font:16px system-ui;background:#f7f9fb;color:#162c3d;margin:0}main{max-width:850px;margin:5vh auto;padding:32px}h1{font-size:40px}li{margin:12px 0}button{background:#143f6b;color:white;border:0;padding:14px 24px;cursor:pointer}button:disabled{opacity:.5}pre{background:#e7edf3;padding:24px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.5}p{line-height:1.6}',
    );
  }
  if (req.method === 'GET' && req.url === '/client.js') {
    res.setHeader('content-type', 'text/javascript');
    return res.end(
      `const b=document.querySelector('#run'),r=document.querySelector('#result');b.onclick=async()=>{b.disabled=true;r.textContent='Running protocol exchange…';try{const x=await fetch('/exchange',{method:'POST',headers:{'x-lab-token':'${token}'}});r.textContent=JSON.stringify(await x.json(),null,2);}catch{r.textContent='Exchange failed';}finally{b.disabled=false;}};`,
    );
  }
  if (req.method === 'POST' && req.url === '/exchange') {
    if (req.headers.origin !== origin || req.headers['x-lab-token'] !== token)
      return sendJSON(res, 403, { error: 'LOCAL_ORIGIN_REQUIRED' });
    if (running) return sendJSON(res, 429, { error: 'EXCHANGE_IN_PROGRESS' });
    running = true;
    try {
      await readBody(req, { maxBytes: 0 });
      const r = await runFoundationDemo();
      return sendJSON(res, 200, r.summary);
    } catch (e) {
      return sendJSON(res, 500, { error: e.code ?? 'EXCHANGE_FAILED' });
    } finally {
      running = false;
    }
  }
  sendJSON(res, 404, { error: 'not_found' });
});
server.listen(port, '127.0.0.1', () => console.log('CertConcord document signing example: ' + origin));
