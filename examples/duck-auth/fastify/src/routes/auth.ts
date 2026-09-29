import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { beginProvider, currentSession, providerCallback, signIn, signOut } from '@examples/duck-auth-shared/routes'
import { signUp } from '@examples/duck-auth-shared/signup'
import { fastifyCaller, fastifyCsrf } from '@gentleduck/auth/server/fastify'
import { executeIntents, jsonResponse, nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

export function authRoutes(auth: AppAuth) {
  return async (app: FastifyInstance) => {
    app.get('/providers', async () => ({ providers: auth.providers.list() }))

    // Where the IdP returns the browser. Apple's form post arrives as its raw text, the same query string a redirect carries.
    const callback = async (req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
      const form = typeof req.body === 'string' ? req.body : ''
      const params =
        req.method === 'POST' ? new URLSearchParams(form) : new URL(req.url, 'http://localhost').searchParams
      const headers = nodeHeadersToFetch(req.headers)
      return reply.send(
        executeIntents(await providerCallback(auth, req.params.id, params, headers, fastifyCaller(req))),
      )
    }
    app.get('/providers/:id/callback', callback)
    app.post('/providers/:id/callback', callback)

    // A scope for everything else, so the guard covers it and not the callback.
    app.register(async (own) => {
      own.addHook('preHandler', fastifyCsrf(auth))

      own.post('/signin', async (req, reply) => {
        return reply.send(
          executeIntents(await signIn(auth, nodeHeadersToFetch(req.headers), req.body, fastifyCaller(req))),
        )
      })

      own.post('/signout', async (req, reply) => {
        return reply.send(executeIntents(await signOut(auth, nodeHeadersToFetch(req.headers))))
      })

      own.get('/session', async (req, reply) => {
        return reply.send(jsonResponse(200, await currentSession(auth, nodeHeadersToFetch(req.headers))))
      })

      own.post<{ Params: { id: string } }>('/providers/:id/begin', async (req, reply) => {
        return reply.send(executeIntents(await beginProvider(auth, req.params.id, req.body)))
      })

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
