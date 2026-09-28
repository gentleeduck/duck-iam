import { type AppAuth, landing, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signUp } from '@examples/duck-auth-shared/signup'
import {
  fastifyCaller,
  fastifyCsrf,
  fastifyProviderBegin,
  fastifySession,
  fastifySignIn,
  fastifySignOut,
} from '@gentleduck/auth/server/fastify'
import { executeIntents, nodeHeadersToFetch, oauthCallback } from '@gentleduck/auth/server/generic'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

export function authRoutes(auth: AppAuth) {
  return async (app: FastifyInstance) => {
    app.get('/providers', async () => ({ providers: auth.providers.list() }))

    // duck-auth's own handlers guard their CSRF themselves.
    app.post('/signin', fastifySignIn(auth))
    app.post('/signout', fastifySignOut(auth))
    app.get('/session', fastifySession(auth))
    app.post('/providers/:id/begin', fastifyProviderBegin(auth))

    // Where the IdP returns the browser; the cookies land, then the app takes over.
    const callback = async (req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
      const request = { body: req.body, cookie: req.headers.cookie, method: req.method, url: req.url }
      const intents = await landing(oauthCallback(auth, req.params.id, request, fastifyCaller(req)))
      return reply.send(executeIntents(intents))
    }
    app.get('/providers/:id/callback', callback)
    app.post('/providers/:id/callback', callback)

    // A scope of this app's own routes, so the guard covers them and nothing above.
    app.register(async (own) => {
      own.addHook('preHandler', fastifyCsrf(auth))

      own.post('/signup', async (req, reply) => {
        return reply.status(201).send(await signUp(auth, req.body))
      })

      own.post('/password/forgot', async (req) => {
        await auth.flows.requestPasswordReset({
          input: { email: readString(req.body, 'email') ?? '', callbackPath: PAGES.resetPassword },
          findIdentityByEmail: (e) => auth.identities.getByEmail(e).orNull(),
        })
        return { ok: true }
      })

      own.post('/password/reset', async (req, reply) => {
        const { intents } = await auth.flows.completePasswordReset({
          token: readString(req.body, 'token') ?? '',
          newPassword: readString(req.body, 'password') ?? '',
          currentSid: auth.transport.extract({ headers: nodeHeadersToFetch(req.headers) }) ?? undefined,
        })
        return reply.send(executeIntents([...intents, { type: 'json', status: 200, body: { ok: true } }]))
      })

      own.post('/email/verify', async (req) => {
        const { identityId } = await auth.flows.completeEmailVerification({
          token: readString(req.body, 'token') ?? '',
        })
        return { identityId }
      })
    })
  }
}
