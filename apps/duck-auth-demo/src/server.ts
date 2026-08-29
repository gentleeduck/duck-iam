/**
 * Demo Hono backend. Every duck-auth flow is mounted in one call;
 * CORS is wired for the Storybook origin so Live stories on :6006
 * can speak to :8787 with credentials.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { mountHono } from '@gentleduck/auth/server/hono'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { auth } from './auth'

const ORIGINS = (process.env.CORS_ORIGINS ?? 'http://localhost:6006,http://localhost:6007')
  .split(',')
  .map((o) => o.trim())

const app = new Hono()

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

// Bootstrap a fresh user for the demo (production uses flows.beginSignUp).
app.post('/auth/signup', async (c) => {
  const { email, password: pw } = (await c.req.json()) as { email: string; password: string }
  const identity = await auth.identities.create({ profile: { username: email, email, emailVerified: false } })
  await auth.passwords.set(identity.id, pw, auth.cfg.stores.credentials)
  return c.json({ identityId: identity.id, ok: true })
})

mountHono(app, auth)

app.get('/', (c) => c.json({ docs: 'README.md', name: 'duck-auth-demo', providers: auth.providers.list() }))

export default { fetch: app.fetch, port: Number(process.env.PORT ?? 8787) }
