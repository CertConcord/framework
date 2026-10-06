import { readBody, sendJSON } from './transport.mjs';
import { parseJSON } from './json.mjs';
import { requireThat } from './core.mjs';

export async function requestParameters(req) {
  const body = await readBody(req),
    type = req.headers['content-type']?.split(';')[0];
  if (type === 'application/json') return parseJSON(body.toString('utf8'));
  requireThat(type === 'application/x-www-form-urlencoded', 'HTTP_MEDIA_TYPE');
  const entries = [...new URLSearchParams(body.toString('utf8'))];
  requireThat(new Set(entries.map(([k]) => k)).size === entries.length, 'HTTP_DUPLICATE_PARAMETER');
  return Object.fromEntries(entries);
}
function sendBytes(res, body, type, status = 200) {
  const bytes = Buffer.from(body);
  res.writeHead(status, {
    'content-type': type,
    'content-length': bytes.length,
    'cache-control': 'no-store',
  });
  res.end(bytes);
}

// The host application supplies authenticated subject/session decisions. This handler never infers them from request parameters.
export function createProtocolHandler({
  issuer,
  verifier,
  approveAuthorization,
  sessionForRequest,
}) {
  const issuerPath = new URL(issuer.issuer).pathname.replace(/\/$/, ''),
    vpPath = verifier && new URL(verifier.baseURL).pathname.replace(/\/$/, '');
  return async (req, res) => {
    try {
      const u = new URL(req.url, issuer.issuer),
        path = u.pathname;
      if (req.method === 'GET' && path === '/.well-known/openid-credential-issuer' + issuerPath)
        return sendJSON(res, 200, {
          ...issuer.metadata(),
          signed_metadata: issuer.signedMetadata(),
        });
      if (req.method === 'GET' && path === '/.well-known/oauth-authorization-server' + issuerPath)
        return sendJSON(res, 200, issuer.authorizationMetadata());
      if (req.method === 'GET' && path === issuerPath + '/status/1')
        return sendBytes(res, issuer.status.token(), 'application/statuslist+jwt');
      if (req.method === 'GET' && path === issuerPath + '/authorize') {
        requireThat(typeof approveAuthorization === 'function', 'AUTHORIZATION_UI_REQUIRED');
        const params = Object.fromEntries(u.searchParams),
          decision = await approveAuthorization(req, params),
          r = issuer.authorize(params, decision),
          redirect = new URL(r.redirect_uri);
        for (const k of ['code', 'state', 'iss']) redirect.searchParams.set(k, r[k]);
        res.writeHead(302, { location: redirect.href, 'cache-control': 'no-store' });
        return res.end();
      }
      if (req.method === 'POST' && path === issuerPath + '/nonce')
        return sendJSON(res, 200, issuer.nonce());
      for (const name of ['par', 'token', 'credential', 'deferred', 'notification'])
        if (req.method === 'POST' && path === issuerPath + '/' + name) {
          const out = issuer[name](await requestParameters(req), req.headers),
            headers = issuer.enforceDPoPNonce ? { 'dpop-nonce': issuer.dpopNonce() } : {};
          if (typeof out === 'string') return sendBytes(res, out, 'application/jwt');
          return sendJSON(res, name === 'par' ? 201 : 200, out, headers);
        }
      if (verifier && req.method === 'GET' && path.startsWith(vpPath + '/request/')) {
        const id = path.slice((vpPath + '/request/').length),
          row = verifier.journal.get('vp', id);
        requireThat(row?.value.status === 'REQUESTED', 'VP_STATE');
        return sendBytes(res, verifier.signedRequest(id), 'application/oauth-authz-req+jwt');
      }
      if (verifier && req.method === 'GET' && path.startsWith(vpPath + '/complete/')) {
        const sessionID = await sessionForRequest?.(req);
        requireThat(sessionID, 'VP_SESSION');
        verifier.complete(path.slice((vpPath + '/complete/').length), {
          sessionID,
          responseCode: u.searchParams.get('response_code'),
        });
        return sendJSON(res, 200, { status: 'COMPLETED' });
      }
      if (verifier && req.method === 'POST' && path.startsWith(vpPath + '/response/')) {
        const id = path.slice((vpPath + '/response/').length),
          p = await requestParameters(req),
          row = verifier.journal.get('vp', id),
          mode = row?.value.request.response_mode;
        requireThat(row, 'VP_STATE');
        const sessionID = mode === 'dc_api.jwt' ? await sessionForRequest?.(req) : undefined;
        requireThat(mode !== 'dc_api.jwt' || sessionID, 'VP_SESSION');
        return sendJSON(res, 200, await verifier.response(id, p.response, { sessionID, mode }));
      }
      sendJSON(res, 404, { error: 'not_found' });
    } catch (e) {
      const code = e.code ?? e.message;
      if (code === 'use_dpop_nonce')
        return sendJSON(
          res,
          400,
          { error: 'use_dpop_nonce' },
          { 'dpop-nonce': issuer.dpopNonce() },
        );
      sendJSON(res, 400, { error: /^[A-Za-z0-9_]+$/.test(code) ? code : 'invalid_request' });
    }
  };
}
