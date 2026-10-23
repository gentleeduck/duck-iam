/**
 * An OpenID provider on `@gentleduck/auth/oidc/op`, with a demo sign-in and a consent page.
 *
 * One file, one port, everything in memory. For a database, pass the Drizzle stores from
 * `@gentleduck/auth/oidc/op/drizzle/{pg,mysql,sqlite}` to `createOidcOP` as `stores`.
 */

import { createHmac } from 'node:crypto'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { memoryAdapter } from '@gentleduck/auth/adapters/memory'
import { createAuth, verifyCsrf } from '@gentleduck/auth/core'
import { cookieTransport } from '@gentleduck/auth/core/transport'
import { authMemoryClientStore, createOidcOP } from '@gentleduck/auth/oidc/op'
import { executeIntents, nodeHeadersToFetch } from '@gentleduck/auth/server/generic'

const PORT = Number(process.env.PORT ?? 8787)
const ISSUER = `http://localhost:${PORT}`
const ID_TOKEN_HS256_SECRET = 'demo-secret-do-not-use-in-prod'

// http, so the cookie cannot carry `Secure`.
const auth = createAuth({
  baseUrl: ISSUER,
  stores: memoryAdapter(),
  transport: cookieTransport({ name: 'duck-sid', secure: false }),
})

// Kept in hand: a declined consent checks its redirect_uri here before sending the person to it.
const clients = authMemoryClientStore()

const op = createOidcOP({
  auth,
  config: { allowHttp: true, issuer: ISSUER, supportedScopes: ['openid', 'profile', 'email', 'offline_access'] },
  signIdToken: (payload) => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const sig = createHmac('sha256', ID_TOKEN_HS256_SECRET).update(`${header}.${body}`).digest('base64url')
    return `${header}.${body}.${sig}`
  },
  stores: { clients },
})

await op.registerClient({
  client_id: 'demo-spa',
  client_name: 'Demo SPA',
  redirect_uris: [`${ISSUER}/callback`],
  scope: ['openid', 'profile', 'email', 'offline_access'],
  token_endpoint_auth_method: 'none',
})

const demoUser = await auth.identities.create({
  emailVerified: true,
  profile: { email: 'user@example.com', name: 'Demo User', username: 'demo' },
})

/** The authorize URL to come back to once signed in, without `login` or `max_age`: that sign-in answered both. */
function resumeUrl(url: URL): string {
  const next = new URL(url)
  const prompt = (next.searchParams.get('prompt') ?? '').split(' ').filter((p) => p.length > 0 && p !== 'login')
  if (prompt.length > 0) next.searchParams.set('prompt', prompt.join(' '))
  else next.searchParams.delete('prompt')
  next.searchParams.delete('max_age')
  return `${next.pathname}${next.search}`
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

const STYLE =
  '<style>body{font-family:system-ui;max-width:480px;margin:48px auto;padding:24px}button{padding:10px 24px;margin-right:8px}code{display:block;margin:8px 0}</style>'

function loginPage(returnTo: string): string {
  return `<!doctype html><html><head><title>Sign in</title>${STYLE}</head><body>
<h1>Sign in</h1>
<p>A demo: this signs you in as <code>user@example.com</code>.</p>
<form method="POST" action="/login">
  <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}"/>
  <button>Sign in as the demo user</button>
</form></body></html>`
}

function consentPage(clientName: string, scope: string[], hidden: Record<string, string>): string {
  const inputs = Object.entries(hidden)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}"/>`)
    .join('\n')
  return `<!doctype html><html><head><title>Consent</title>${STYLE}</head><body>
<h1>Allow ${escapeHtml(clientName)}?</h1>
<p>It is asking for:</p>
${scope.map((s) => `<code>${escapeHtml(s)}</code>`).join('')}
<form method="POST" action="/consent">
  ${inputs}
  <button name="decision" value="allow">Allow</button>
  <button name="decision" value="deny">Deny</button>
</form></body></html>`
}

const html = (body: string) => new Response(body, { headers: { 'content-type': 'text/html; charset=utf-8' } })
const redirect = (location: string) => new Response(null, { headers: { location }, status: 302 })
const tokenHint = (v: string | null): 'access_token' | 'refresh_token' | undefined =>
  v === 'access_token' || v === 'refresh_token' ? v : undefined

/** An authorize error the client should see, sent to its redirect_uri when `authorize` vouched for it. */
function authorizeError(result: {
  status: number
  body: { error: string; error_description?: string; state?: string }
  redirectUri?: string
}): Response {
  if (result.status !== 302 || !result.redirectUri) return Response.json(result.body, { status: result.status })
  const u = new URL(result.redirectUri)
  for (const [k, v] of Object.entries(result.body)) if (v !== undefined) u.searchParams.set(k, v)
  return redirect(u.toString())
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url)
  const route = `${req.method} ${url.pathname}`

  // The two form posts act on the person's cookie, so a page on another origin must not be able to send them.
  if (route === 'POST /login' || route === 'POST /consent') {
    verifyCsrf({ cfg: { allowedOrigins: [ISSUER], mode: 'origin-only' }, headers: req.headers, method: req.method })
  }

  if (route === 'GET /authorize') {
    const q = url.searchParams
    const param = (k: string) => q.get(k) ?? undefined
    const result = await op.authorize(
      {
        client_id: q.get('client_id') ?? '',
        code_challenge: param('code_challenge'),
        code_challenge_method: param('code_challenge_method'),
        max_age: param('max_age'),
        nonce: param('nonce'),
        prompt: param('prompt'),
        redirect_uri: q.get('redirect_uri') ?? '',
        response_type: q.get('response_type') ?? '',
        scope: q.get('scope') ?? '',
        state: param('state'),
      },
      { headers: req.headers },
    )
    switch (result.kind) {
      case 'redirect':
        return redirect(result.url)
      case 'login_required':
        return html(loginPage(resumeUrl(url)))
      case 'consent_required':
        return html(
          consentPage(result.client.client_name ?? result.client.client_id, result.scope, {
            client_id: result.client.client_id,
            code_challenge: q.get('code_challenge') ?? '',
            code_challenge_method: q.get('code_challenge_method') ?? '',
            nonce: q.get('nonce') ?? '',
            redirect_uri: q.get('redirect_uri') ?? '',
            scope: result.scope.join(' '),
            state: q.get('state') ?? '',
          }),
        )
      case 'error':
        return authorizeError(result)
    }
  }

  if (route === 'POST /login') {
    const form = new URLSearchParams(await req.text())
    const returnTo = form.get('returnTo') ?? ''
    const { session, sid, csrfToken } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: demoUser.id,
      kind: 'user',
    })
    // Only back into `/authorize`: anything else here is an open redirect.
    const intents = auth.transport.issue(sid, session, { absolute: false, csrfToken, fresh: true })
    return executeIntents([...intents, { type: 'redirect', url: returnTo.startsWith('/authorize?') ? returnTo : '/' }])
  }

  if (route === 'POST /consent') {
    const form = new URLSearchParams(await req.text())
    const redirectUri = form.get('redirect_uri') ?? ''
    const resolved = await auth.resolveSession({ headers: req.headers }).orNull()
    if (!resolved?.identity) return Response.json({ error: 'login_required' }, { status: 401 })
    const field = (k: string) => form.get(k) || undefined
    if (form.get('decision') !== 'allow') {
      const client = await clients.findById(form.get('client_id') ?? '')
      if (!client?.redirect_uris.includes(redirectUri))
        return Response.json({ error: 'invalid_request' }, { status: 400 })
      return authorizeError({ body: { error: 'access_denied', state: field('state') }, redirectUri, status: 302 })
    }
    const completed = await op.completeConsent({
      client_id: form.get('client_id') ?? '',
      code_challenge: field('code_challenge'),
      code_challenge_method: field('code_challenge_method'),
      identity: resolved.identity,
      nonce: field('nonce'),
      redirect_uri: redirectUri,
      scope: (form.get('scope') ?? '').split(' ').filter((s) => s.length > 0),
      sid: resolved.session.id,
      state: field('state'),
      tenant_id: null,
    })
    if (completed.kind === 'redirect') return redirect(completed.url)
    if (completed.kind === 'error') return Response.json(completed.body, { status: completed.status })
    return Response.json({ error: 'server_error' }, { status: 500 })
  }

  if (route === 'POST /token') {
    const form = new URLSearchParams(await req.text())
    const field = (k: string) => form.get(k) ?? undefined
    const out = await op.token(
      {
        client_id: field('client_id'),
        client_secret: field('client_secret'),
        code: field('code'),
        code_verifier: field('code_verifier'),
        grant_type: form.get('grant_type') ?? '',
        redirect_uri: field('redirect_uri'),
        refresh_token: field('refresh_token'),
        scope: field('scope'),
      },
      req.headers,
    )
    if ('error' in out) return Response.json(out, { status: out.error === 'invalid_client' ? 401 : 400 })
    return Response.json(out, { headers: { 'cache-control': 'no-store' } })
  }

  if (route === 'GET /userinfo') {
    const out = await op.userinfo(req.headers)
    return Response.json(out, { status: 'error' in out ? 401 : 200 })
  }

  // A client authenticates here as it does at `/token`: Basic, or `client_id` (and `client_secret`) in the body.
  if (route === 'POST /introspect' || route === 'POST /revoke') {
    const form = new URLSearchParams(await req.text())
    const body = {
      client_id: form.get('client_id') ?? undefined,
      client_secret: form.get('client_secret') ?? undefined,
      token: form.get('token') ?? '',
      token_type_hint: tokenHint(form.get('token_type_hint')),
    }
    if (route === 'POST /introspect') return Response.json(await op.introspect(body, req.headers))
    const refused = await op.revoke(body, req.headers)
    return refused ? Response.json(refused, { status: 401 }) : new Response(null, { status: 200 })
  }

  return Response.json({ error: 'not_found' }, { status: 404 })
}

/** Runs `handle` for a Node request, so the handlers above stay plain Fetch. */
async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let out: Response
  try {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(Buffer.from(chunk))
    const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : Buffer.concat(chunks)
    out = await handle(
      new Request(new URL(req.url ?? '/', ISSUER), {
        body,
        headers: nodeHeadersToFetch(req.headers),
        method: req.method,
      }),
    )
  } catch (err) {
    const code = err instanceof Error && 'code' in err ? err.code : undefined
    if (code !== 'AUTH_CSRF') console.error('handler error', err)
    out = Response.json(
      { error: code === 'AUTH_CSRF' ? 'forbidden' : 'server_error' },
      { status: code === 'AUTH_CSRF' ? 403 : 500 },
    )
  }
  const headers: Record<string, string | string[]> = {}
  out.headers.forEach((v, k) => {
    if (k !== 'set-cookie') headers[k] = v
  })
  const cookies = out.headers.getSetCookie()
  if (cookies.length > 0) headers['set-cookie'] = cookies
  res.writeHead(out.status, headers)
  res.end(Buffer.from(await out.arrayBuffer()))
}

createServer((req, res) => void serve(req, res)).listen(PORT, () => {
  console.log(`OP listening at ${ISSUER}`)
})
