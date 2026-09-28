import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { signedIn } from '@examples/duck-auth-shared/session'
import { fastifyCsrf } from '@gentleduck/auth/server/fastify'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import type { FastifyInstance } from 'fastify'

export function accountRoutes(auth: AppAuth) {
  return async (app: FastifyInstance) => {
    app.addHook('preHandler', fastifyCsrf(auth))

    app.get('/', async (req, reply) => {
      const { identity, session, totp } = await signedIn(auth, nodeHeadersToFetch(req.headers))
      reply.header('cache-control', 'no-store')
      return { identity, totp, session: { id: session.id, aal: session.aal, expiresAt: session.expiresAt } }
    })

    app.post('/email/resend', async (req) => {
      const { identity } = await signedIn(auth, nodeHeadersToFetch(req.headers))
      return auth.flows.requestEmailVerification({ identityId: identity.id, callbackPath: PAGES.verifyEmail })
    })

    app.get('/sessions', async (req, reply) => {
      const { identity } = await signedIn(auth, nodeHeadersToFetch(req.headers))
      reply.header('cache-control', 'no-store')
      return { sessions: await auth.sessions.listForIdentity(identity.id) }
    })

    app.post('/sessions/revoke-others', async (req) => {
      const headers = nodeHeadersToFetch(req.headers)
      const { identity } = await signedIn(auth, headers)
      return auth.sessions.revokeAllExcept(identity.id, auth.transport.extract({ headers }) ?? '')
    })
  }
}
