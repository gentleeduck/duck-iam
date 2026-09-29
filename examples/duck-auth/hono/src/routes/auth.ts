import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { beginProvider, currentSession, providerCallback, signIn, signOut } from '@examples/duck-auth-shared/routes'
import { signUp } from '@examples/duck-auth-shared/signup'
import { executeIntents, jsonResponse, readBodyJson, readBodyText } from '@gentleduck/auth/server/generic'
import { honoCaller, honoCsrf, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { type Context, Hono } from 'hono'
import { getConnInfo } from 'hono/bun'

/** Hono resolves no caller address itself; Bun's socket has it. */
const withIp = (c: Context) => ({ ...toHonoAdapterCtx(c), ip: getConnInfo(c).remote.address })

export function authRouter(auth: AppAuth) {
  const router = new Hono()

  router.get('/providers', (c) => c.json({ providers: auth.providers.list() }))

  // Where the IdP returns the browser. Apple's form post is read as text, the same query string a redirect carries.
  router.on(['GET', 'POST'], '/providers/:id/callback', async (c) => {
    const params =
      c.req.method === 'POST'
        ? new URLSearchParams((await readBodyText(c.req.raw)) ?? '')
        : new URL(c.req.url).searchParams
    const headers = c.req.raw.headers
    return executeIntents(await providerCallback(auth, c.req.param('id'), params, headers, honoCaller(withIp(c))))
  })

  // Everything below takes the guard.
  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))

  router.post('/signin', async (c) => {
    const body = await readBodyJson(c.req.raw)
    return executeIntents(await signIn(auth, c.req.raw.headers, body, honoCaller(withIp(c))))
  })

  router.post('/signout', async (c) => executeIntents(await signOut(auth, c.req.raw.headers)))

  router.get('/session', async (c) => jsonResponse(200, await currentSession(auth, c.req.raw.headers)))

  router.post('/providers/:id/begin', async (c) => {
    return executeIntents(await beginProvider(auth, c.req.param('id'), await readBodyJson(c.req.raw)))
  })

  router.post('/signup', async (c) => {
    return c.json(await signUp(auth, await readBodyJson(c.req.raw)), 201)
  })

  router.post('/password/forgot', async (c) => {
    await auth.flows.requestPasswordReset({
      input: { email: readString(await readBodyJson(c.req.raw), 'email') ?? '', callbackPath: PAGES.resetPassword },
      findIdentityByEmail: (e) => auth.identities.getByEmail(e).orNull(),
    })
    return c.json({ ok: true })
  })

  router.post('/password/reset', async (c) => {
    const body = await readBodyJson(c.req.raw)
    const { intents } = await auth.flows.completePasswordReset({
      token: readString(body, 'token') ?? '',
      newPassword: readString(body, 'password') ?? '',
      currentSid: auth.transport.extract({ headers: c.req.raw.headers }) ?? undefined,
    })
    return executeIntents([...intents, { type: 'json', status: 200, body: { ok: true } }])
  })

  router.post('/email/verify', async (c) => {
    const token = readString(await readBodyJson(c.req.raw), 'token') ?? ''
    const { identityId } = await auth.flows.completeEmailVerification({ token })
    return c.json({ identityId })
  })

  return router
}
