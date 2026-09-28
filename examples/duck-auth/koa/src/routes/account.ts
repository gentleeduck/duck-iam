import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { signedIn } from '@examples/duck-auth-shared/session'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import { koaCsrf } from '@gentleduck/auth/server/koa'
import Router from '@koa/router'

export function accountRouter(auth: AppAuth) {
  const router = new Router({ prefix: '/me' })
  router.use(koaCsrf(auth))

  router.get('/', async (ctx) => {
    const { identity, session, totp } = await signedIn(auth, nodeHeadersToFetch(ctx.request.headers))
    ctx.set('cache-control', 'no-store')
    ctx.body = { identity, totp, session: { id: session.id, aal: session.aal, expiresAt: session.expiresAt } }
  })

  router.post('/email/resend', async (ctx) => {
    const { identity } = await signedIn(auth, nodeHeadersToFetch(ctx.request.headers))
    ctx.body = await auth.flows.requestEmailVerification({ identityId: identity.id, callbackPath: PAGES.verifyEmail })
  })

  router.get('/sessions', async (ctx) => {
    const { identity } = await signedIn(auth, nodeHeadersToFetch(ctx.request.headers))
    ctx.set('cache-control', 'no-store')
    ctx.body = { sessions: await auth.sessions.listForIdentity(identity.id) }
  })

  router.post('/sessions/revoke-others', async (ctx) => {
    const headers = nodeHeadersToFetch(ctx.request.headers)
    const { identity } = await signedIn(auth, headers)
    ctx.body = await auth.sessions.revokeAllExcept(identity.id, auth.transport.extract({ headers }) ?? '')
  })

  return router
}
