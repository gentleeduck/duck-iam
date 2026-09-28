import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { signedIn } from '@examples/duck-auth-shared/session'
import { expressCsrf, toHeaders } from '@gentleduck/auth/server/express'
import { Router } from 'express'

export function accountRouter(auth: AppAuth) {
  const router = Router()
  router.use(expressCsrf(auth))

  router.get('/', async (req, res) => {
    const { identity, session, totp } = await signedIn(auth, toHeaders(req.headers))
    res
      .set('cache-control', 'no-store')
      .json({ identity, totp, session: { id: session.id, aal: session.aal, expiresAt: session.expiresAt } })
  })

  router.post('/email/resend', async (req, res) => {
    const { identity } = await signedIn(auth, toHeaders(req.headers))
    res.json(await auth.flows.requestEmailVerification({ identityId: identity.id, callbackPath: PAGES.verifyEmail }))
  })

  router.get('/sessions', async (req, res) => {
    const { identity } = await signedIn(auth, toHeaders(req.headers))
    res.set('cache-control', 'no-store').json({ sessions: await auth.sessions.listForIdentity(identity.id) })
  })

  router.post('/sessions/revoke-others', async (req, res) => {
    const headers = toHeaders(req.headers)
    const { identity } = await signedIn(auth, headers)
    res.json(await auth.sessions.revokeAllExcept(identity.id, auth.transport.extract({ headers }) ?? ''))
  })

  return router
}
