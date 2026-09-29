/**
 * Demo Hono backend: its own routes over `auth.flows`. CORS is wired for the Storybook origin so Live stories
 * on :6006 can speak to :8787 with credentials.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthError } from '@gentleduck/auth/core'
import {
  errorResponse,
  executeIntents,
  isSafeRedirectUrl,
  jsonResponse,
  readBodyJson,
  readBodyText,
} from '@gentleduck/auth/server/generic'
import { honoCaller, honoCsrf, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { type Context, Hono } from 'hono'
import { cors } from 'hono/cors'
import { auth } from './auth'

const ORIGINS = (process.env.CORS_ORIGINS ?? 'http://localhost:6006,http://localhost:6007')
  .split(',')
  .map((o) => o.trim())

/** A string field of a parsed JSON body, or `''`. */
function field(body: unknown, name: string): string {
  const value: unknown = typeof body === 'object' && body !== null ? Reflect.get(body, name) : undefined
  return typeof value === 'string' ? value : ''
}

const app = new Hono()

app.onError((err) => errorResponse(err))

app.use(
  '/auth/*',
  cors({
    allowHeaders: ['Content-Type', 'X-CSRF-Token', 'Sec-Fetch-Site'],
    credentials: true,
    exposeHeaders: ['Set-Cookie'],
    maxAge: 600,
    origin: (origin) => (ORIGINS.includes(origin) ? origin : ''),
  }),
)

// Where the IdP returns the browser. Never CSRF-guarded: Apple's form post is cross-site by design, and the
// signed state is the proof.
const callback = async (c: Context): Promise<Response> => {
  const provider = auth.providers.get(c.req.param('id') ?? '')
  if (provider.kind !== 'oauth') throw new AuthError('AUTH_PROVIDER_FAILED', { providerId: provider.id })
  const params =
    c.req.method === 'POST'
      ? new URLSearchParams((await readBodyText(c.req.raw)) ?? '')
      : new URL(c.req.url).searchParams
  const user = params.get('user')
  const { intents } = await auth.flows.signIn({
    input: {
      code: params.get('code') ?? '',
      cookieHeader: c.req.header('cookie') ?? '',
      state: params.get('state') ?? '',
      ...(user !== null && { user }),
    },
    providerId: provider.id,
    ...honoCaller(toHonoAdapterCtx(c)),
    previousSid: auth.transport.extract(c.req.raw) ?? undefined,
  })
  const failed = intents.some((i) => i.type === 'error')
  return executeIntents(failed ? intents : [...intents, { type: 'redirect', url: ORIGINS[0] ?? '/' }])
}
app.get('/auth/providers/:id/callback', callback)
app.post('/auth/providers/:id/callback', callback)

// The link the magic-link provider mails; a GET, so the guard below would pass it anyway.
app.get('/auth/magic-link/verify', async (c) => {
  const { intents } = await auth.flows.signIn({
    input: { token: c.req.query('token') ?? '' },
    providerId: 'magic-link',
    ...honoCaller(toHonoAdapterCtx(c)),
    previousSid: auth.transport.extract(c.req.raw) ?? undefined,
  })
  return executeIntents(intents)
})

// Everything below takes the guard.
app.use('/auth/*', (c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))

app.post('/auth/signin', async (c) => {
  const body = await readBodyJson(c.req.raw)
  const providerId = field(body, 'providerId')
  if (!providerId) throw new AuthError('AUTH_INVALID_PARAMETERS')
  const input: unknown = typeof body === 'object' && body !== null ? Reflect.get(body, 'input') : undefined
  const { intents } = await auth.flows.signIn({
    input: input ?? {},
    providerId,
    ...honoCaller(toHonoAdapterCtx(c)),
    previousSid: auth.transport.extract(c.req.raw) ?? undefined,
  })
  return executeIntents(intents)
})

app.post('/auth/signout', async (c) => {
  const sid = auth.transport.extract(c.req.raw)
  return executeIntents(sid ? (await auth.flows.signOut(sid)).intents : auth.transport.revoke())
})

app.get('/auth/session', async (c) => {
  const resolved = await auth.resolveSession(c.req.raw).orNull()
  if (!resolved) return jsonResponse(200, { session: null, identity: null })
  // `csrfHash` is server-side state; the browser holds the plaintext.
  const { csrfHash: _csrfHash, ...session } = resolved.session
  return jsonResponse(200, { session, identity: resolved.identity })
})

// A script cannot follow the redirect to the IdP, so it gets `{ url }` to navigate to.
app.post('/auth/providers/:id/begin', async (c) => {
  const intents = await auth.flows.beginProvider(c.req.param('id'), (await readBodyJson(c.req.raw)) ?? {})
  return executeIntents(
    intents.map((i) =>
      i.type === 'redirect' && isSafeRedirectUrl(i.url) ? { body: { url: i.url }, status: 200, type: 'json' } : i,
    ),
  )
})

// Bootstrap a fresh user for the demo (production uses flows.beginSignUp).
app.post('/auth/signup', async (c) => {
  const body = await readBodyJson(c.req.raw)
  const email = field(body, 'email')
  const identity = await auth.identities.create({ profile: { username: email, email, emailVerified: false } })
  await auth.passwords.set(identity.id, field(body, 'password'), auth.cfg.stores.credentials)
  return c.json({ identityId: identity.id, ok: true })
})

app.get('/', (c) => c.json({ docs: 'README.md', name: 'duck-auth-demo', providers: auth.providers.list() }))

export default { fetch: app.fetch, port: Number(process.env.PORT ?? 8787) }
