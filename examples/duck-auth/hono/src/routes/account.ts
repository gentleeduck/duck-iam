import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { signedIn } from '@examples/duck-auth-shared/session'
import { honoCsrf, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { Hono } from 'hono'

export function accountRouter(auth: AppAuth) {
  const router = new Hono()
  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))

  router.get('/', async (c) => {
    const { identity, session, totp } = await signedIn(auth, c.req.raw.headers)
    const view = { id: session.id, aal: session.aal, expiresAt: session.expiresAt }
    return c.json({ identity, totp, session: view }, 200, { 'cache-control': 'no-store' })
  })

  router.post('/email/resend', async (c) => {
    const { identity } = await signedIn(auth, c.req.raw.headers)
    return c.json(
      await auth.flows.requestEmailVerification({ identityId: identity.id, callbackPath: PAGES.verifyEmail }),
    )
  })

  router.get('/sessions', async (c) => {
    const { identity } = await signedIn(auth, c.req.raw.headers)
    return c.json({ sessions: await auth.sessions.listForIdentity(identity.id) }, 200, { 'cache-control': 'no-store' })
  })

  router.post('/sessions/revoke-others', async (c) => {
    const headers = c.req.raw.headers
    const { identity } = await signedIn(auth, headers)
    return c.json(await auth.sessions.revokeAllExcept(identity.id, auth.transport.extract({ headers }) ?? ''))
  })

  return router
}
