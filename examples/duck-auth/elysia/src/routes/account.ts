import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { signedIn } from '@examples/duck-auth-shared/session'
import { elysiaCsrf } from '@gentleduck/auth/server/elysia'
import { Elysia } from 'elysia'

export function accountRoutes(auth: AppAuth) {
  return new Elysia({ prefix: '/me' })
    .onBeforeHandle(elysiaCsrf(auth))

    .get('/', async ({ request, set }) => {
      const { identity, session, totp } = await signedIn(auth, request.headers)
      set.headers['cache-control'] = 'no-store'
      return { identity, totp, session: { id: session.id, aal: session.aal, expiresAt: session.expiresAt } }
    })

    .post('/email/resend', async ({ request }) => {
      const { identity } = await signedIn(auth, request.headers)
      return auth.flows.requestEmailVerification({ identityId: identity.id, callbackPath: PAGES.verifyEmail })
    })

    .get('/sessions', async ({ request, set }) => {
      const { identity } = await signedIn(auth, request.headers)
      set.headers['cache-control'] = 'no-store'
      return { sessions: await auth.sessions.listForIdentity(identity.id) }
    })

    .post('/sessions/revoke-others', async ({ request }) => {
      const { identity } = await signedIn(auth, request.headers)
      return auth.sessions.revokeAllExcept(identity.id, auth.transport.extract({ headers: request.headers }) ?? '')
    })
}
