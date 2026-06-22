/**
 * Minimal end-to-end OIDC OP wired up with `@gentleduck/auth/oidc/op`.
 *
 * Single file, single port. State is in-memory. To swap memory for
 * Postgres / SQLite / MySQL, replace the `stores: {}` default with the
 * Drizzle ports under `@gentleduck/auth/oidc/op/drizzle/{pg,sqlite,mysql}`.
 */

import { createHmac } from 'node:crypto'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { MemoryAdapter } from '@gentleduck/auth/adapters/memory'
import { AuthRoot, CookieTransport, ScryptHasher } from '@gentleduck/auth/core'
import { createOidcOP } from '@gentleduck/auth/oidc/op'

const PORT = Number(process.env.PORT ?? 8787)
const ID_TOKEN_HS256_SECRET = 'demo-secret-do-not-use-in-prod'
const ISSUER = `http://localhost:${PORT}`

interface Profile {
  email: string
  name?: string
}

const adapter = new MemoryAdapter<Profile>()
const auth = new AuthRoot<Profile>({
  baseUrl: ISSUER,
  stores: { identities: adapter.identities, credentials: adapter.credentials, sessions: adapter.sessions },
  transport: new CookieTransport({ name: 'duck-sid' }),
  passwords: { hasher: new ScryptHasher() },
})

const op = createOidcOP<Profile>({
  auth,
  config: {
    issuer: ISSUER,
    supportedScopes: ['openid', 'profile', 'email', 'offline_access'],
    allowHttp: true,
  },
  signIdToken: (payload) => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const sig = createHmac('sha256', ID_TOKEN_HS256_SECRET).update(`${header}.${body}`).digest('base64url')
    return `${header}.${body}.${sig}`
  },
})

await op.registerClient({
  client_id: 'demo-spa',
  redirect_uris: ['http://localhost:8787/callback'],
  token_endpoint_auth_method: 'none',
  scope: ['openid', 'profile', 'email', 'offline_access'],
  client_name: 'Demo SPA',
})

function consentPage(scope: string[], hidden: Record<string, string>): string {
  const inputs = Object.entries(hidden)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}"/>`)
    .join('\n')
  return `<!doctype html>
<html><head><title>Consent</title>
<style>body{font-family:system-ui;max-width:480px;margin:48px auto;padding:24px}
.s{display:block;margin:8px 0}.b{margin-top:24px}button{padding:10px 24px;margin-right:8px}</style>
</head><body>
<h1>Allow Demo SPA?</h1>
<p>This app is asking for:</p>
${scope.map((s) => `<code class="s">${escapeHtml(s)}</code>`).join('')}
<form method="POST" action="/consent" class="b">
  ${inputs}
  <button name="decision" value="allow">Allow</button>
  <button name="decision" value="deny" formaction="/deny">Deny</button>
</form>
</body></html>`
}

function loginPage(): string {
  return `<!doctype html>
<html><head><title>Sign in</title>
<style>body{font-family:system-ui;max-width:480px;margin:48px auto;padding:24px}
button{padding:10px 24px}</style>
</head><body>
<h1>Sign in</h1>
<p>This is a demo. Click below to sign in as <code>user@example.com</code>.</p>
<form method="POST" action="/login">
  <input type="hidden" name="returnTo" value="${escapeHtml(currentUrl ?? '/')}"/>
  <button>Sign in as demo user</button>
</form>
</body></html>`
}

let currentUrl: string | null = null

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

async function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

function parseForm(body: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const pair of body.split('&')) {
    if (!pair) continue
    const idx = pair.indexOf('=')
    const k = decodeURIComponent(idx >= 0 ? pair.slice(0, idx) : pair)
    const v = decodeURIComponent(idx >= 0 ? pair.slice(idx + 1) : '')
    out[k] = v
  }
  return out
}

function reqHeaders(req: IncomingMessage): Headers {
  const h = new Headers()
  for (const [k, v] of Object.entries(req.headers)) {
    if (typeof v === 'string') h.set(k, v)
    else if (Array.isArray(v)) h.set(k, v.join(','))
  }
  return h
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

function sendHtml(res: ServerResponse, status: number, html: string) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' })
  res.end(html)
}

function sendRedirect(res: ServerResponse, url: string) {
  res.writeHead(302, { location: url })
  res.end()
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', ISSUER)
  const path = url.pathname

  if (req.method === 'GET' && path === '/authorize') {
    currentUrl = req.url ?? '/'
    const params = Object.fromEntries(url.searchParams.entries())
    const result = await op.authorize(
      {
        client_id: params.client_id ?? '',
        redirect_uri: params.redirect_uri ?? '',
        response_type: params.response_type ?? '',
        scope: params.scope ?? '',
        ...(params.state !== undefined && { state: params.state }),
        ...(params.nonce !== undefined && { nonce: params.nonce }),
        ...(params.code_challenge !== undefined && { code_challenge: params.code_challenge }),
        ...(params.code_challenge_method !== undefined && {
          code_challenge_method: params.code_challenge_method,
        }),
        ...(params.prompt !== undefined && { prompt: params.prompt }),
      },
      { headers: reqHeaders(req) },
    )
    if (result.kind === 'redirect') return sendRedirect(res, result.url)
    if (result.kind === 'login_required') return sendHtml(res, 200, loginPage())
    if (result.kind === 'consent_required') {
      return sendHtml(
        res,
        200,
        consentPage(result.scope, {
          client_id: result.client.client_id,
          identity_id: result.identity.id,
          redirect_uri: params.redirect_uri ?? '',
          scope: result.scope.join(' '),
          state: params.state ?? '',
          nonce: params.nonce ?? '',
          code_challenge: params.code_challenge ?? '',
          code_challenge_method: params.code_challenge_method ?? '',
          tenant_id: '',
        }),
      )
    }
    if (result.kind === 'error') {
      if (result.status === 302 && result.redirectUri) {
        const u = new URL(result.redirectUri)
        u.searchParams.set('error', result.body.error)
        if (result.body.error_description) u.searchParams.set('error_description', result.body.error_description)
        if (result.body.state) u.searchParams.set('state', result.body.state)
        return sendRedirect(res, u.toString())
      }
      return sendJson(res, result.status, result.body)
    }
  }

  if (req.method === 'POST' && path === '/login') {
    const body = parseForm(await readBody(req))
    const id = await auth.identities.create({ profile: { email: 'user@example.com', name: 'Demo User' } })
    const created = await auth.sessions.createForIdentity(id.id, {
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: Date.now() }],
    })
    const cookie = `duck-sid=${created.sid}; Path=/; HttpOnly; SameSite=Lax`
    res.writeHead(302, { location: body.returnTo ?? '/', 'set-cookie': cookie })
    return res.end()
  }

  if (req.method === 'POST' && path === '/consent') {
    const body = parseForm(await readBody(req))
    if (body.decision !== 'allow') return sendJson(res, 403, { error: 'access_denied' })
    const resolved = await auth.resolveSession({ headers: reqHeaders(req) })
    if (!resolved?.identity) return sendJson(res, 401, { error: 'unauthenticated' })
    const completed = await op.completeConsent({
      client_id: body.client_id ?? '',
      identity: resolved.identity,
      redirect_uri: body.redirect_uri ?? '',
      scope: (body.scope ?? '').split(/\s+/).filter((s) => s.length > 0),
      ...(body.state ? { state: body.state } : {}),
      ...(body.nonce ? { nonce: body.nonce } : {}),
      ...(body.code_challenge ? { code_challenge: body.code_challenge } : {}),
      ...(body.code_challenge_method ? { code_challenge_method: body.code_challenge_method } : {}),
      sid: resolved.session.id,
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') return sendJson(res, 400, { error: 'failed' })
    return sendRedirect(res, completed.url)
  }

  if (req.method === 'POST' && path === '/token') {
    const body = parseForm(await readBody(req))
    const out = await op.token(
      {
        grant_type: body.grant_type ?? '',
        ...(body.code !== undefined && { code: body.code }),
        ...(body.redirect_uri !== undefined && { redirect_uri: body.redirect_uri }),
        ...(body.client_id !== undefined && { client_id: body.client_id }),
        ...(body.client_secret !== undefined && { client_secret: body.client_secret }),
        ...(body.refresh_token !== undefined && { refresh_token: body.refresh_token }),
        ...(body.code_verifier !== undefined && { code_verifier: body.code_verifier }),
        ...(body.scope !== undefined && { scope: body.scope }),
      },
      reqHeaders(req),
    )
    if ('error' in out) return sendJson(res, 400, out)
    return sendJson(res, 200, out)
  }

  if (req.method === 'GET' && path === '/userinfo') {
    const out = await op.userinfo(reqHeaders(req))
    if ('error' in out) return sendJson(res, 401, out)
    return sendJson(res, 200, out)
  }

  if (req.method === 'POST' && path === '/introspect') {
    const body = parseForm(await readBody(req))
    const out = await op.introspect(
      {
        token: body.token ?? '',
        ...(body.token_type_hint ? { token_type_hint: body.token_type_hint as 'access_token' | 'refresh_token' } : {}),
      },
      reqHeaders(req),
    )
    return sendJson(res, 200, out)
  }

  if (req.method === 'POST' && path === '/revoke') {
    const body = parseForm(await readBody(req))
    await op.revoke(
      {
        token: body.token ?? '',
        ...(body.token_type_hint ? { token_type_hint: body.token_type_hint as 'access_token' | 'refresh_token' } : {}),
      },
      reqHeaders(req),
    )
    return sendJson(res, 200, {})
  }

  return sendJson(res, 404, { error: 'not_found' })
}

const server = createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error('handler error', err)
    sendJson(res, 500, { error: 'server_error' })
  })
})

server.listen(PORT, () => {
  console.log(`OP listening at ${ISSUER}`)
  console.log(`Try: GET ${ISSUER}/authorize?client_id=demo-spa&...`)
})
