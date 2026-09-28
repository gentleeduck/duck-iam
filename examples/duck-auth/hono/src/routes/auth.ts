import { type AppAuth, landing, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signUp } from '@examples/duck-auth-shared/signup'
import { executeIntents, oauthCallback, readBodyJson, readBodyText } from '@gentleduck/auth/server/generic'
import {
  honoCaller,
  honoCsrf,
  honoProviderBegin,
  honoSession,
  honoSignIn,
  honoSignOut,
  toHonoAdapterCtx,
} from '@gentleduck/auth/server/hono'
import { type Context, Hono } from 'hono'
import { getConnInfo } from 'hono/bun'

/** Hono resolves no caller address itself; Bun's socket has it. */
const withIp = (c: Context) => ({ ...toHonoAdapterCtx(c), ip: getConnInfo(c).remote.address })

export function authRouter(auth: AppAuth) {
  const router = new Hono()

  router.get('/providers', (c) => c.json({ providers: auth.providers.list() }))

  // duck-auth's own handlers guard their CSRF themselves.
  router.post('/signin', (c) => honoSignIn(auth)(withIp(c)))
  router.post('/signout', (c) => honoSignOut(auth)(withIp(c)))
  router.get('/session', (c) => honoSession(auth)(withIp(c)))
  router.post('/providers/:id/begin', (c) => honoProviderBegin(auth)(withIp(c)))

  // Where the IdP returns the browser; the cookies land, then the app takes over.
  router.on(['GET', 'POST'], '/providers/:id/callback', async (c) => {
    const body = c.req.method === 'POST' ? ((await readBodyText(c.req.raw)) ?? '') : undefined
    const request = { body, cookie: c.req.header('cookie'), method: c.req.method, url: c.req.url }
    const intents = await landing(oauthCallback(auth, c.req.param('id'), request, honoCaller(withIp(c))))
    return executeIntents(intents)
  })

  // Everything below is this app's own, so it takes the guard.
  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))

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
