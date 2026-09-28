/** Fastify adapter. Fastify is Node-native, so this translates between the Web Fetch `Response`
 *  `executeIntents` returns and Fastify's reply API. Mount each handler yourself, or use
 *  {@link registerFastify}. */

import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import { isRecord } from '~/core/predicates'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  executeIntents,
  isValidProviderId,
  nodeHeadersToFetch,
  oauthCallback,
  parseProviderBeginBody,
  parseSignInBody,
  redirectForScript,
  requestSecurity,
} from '../generic'

import type { FastifyAdapter } from './fastify.types'

/** Convert the loose Fastify header bag into a Web Fetch Headers object. */
const toFetchHeaders: (headers: FastifyAdapter.Request['headers']) => Headers = nodeHeadersToFetch

/** Forward `executeIntents`' `Response` onto the Fastify reply, one header per cookie. Answers with
 *  the reply, so a handler can `return` it straight. */
async function forward(response: Response, reply: FastifyAdapter.Reply): Promise<FastifyAdapter.Reply> {
  reply.status(response.status)
  for (const cookie of response.headers.getSetCookie()) {
    reply.header('set-cookie', cookie)
  }
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') return // already handled
    reply.header(key, value)
  })
  const body = response.body ? await response.text() : ''
  reply.send(body)
  return reply
}

function handleError(err: unknown, reply: FastifyAdapter.Reply): FastifyAdapter.Reply {
  const { status, body } = errorToHttp(err)
  reply.status(status)
  reply.header('cache-control', 'no-store')
  reply.header('content-type', 'application/json; charset=utf-8')
  reply.send(JSON.stringify(body))
  return reply
}

/** Fastify handler for the sign-in route. CSRF-guarded. */
export function fastifySignIn(auth: AuthEngine): FastifyAdapter.Handler {
  return async (req, reply) => {
    try {
      const headers = toFetchHeaders(req.headers)
      await csrfGuard(auth, { headers, method: req.method })
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const result = await auth.flows.signIn({
        ...parsed,
        ...fastifyCaller(req),
        previousSid: auth.transport.extract({ headers }) ?? undefined,
      })
      return forward(executeIntents(result.intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** Fastify handler for sign-out. CSRF-guarded. */
export function fastifySignOut(auth: AuthEngine): FastifyAdapter.Handler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method })
      const sid = auth.transport.extract({ headers: toFetchHeaders(req.headers) })
      if (!sid) return forward(executeIntents(auth.transport.revoke()), reply)
      const { intents } = await auth.flows.signOut(sid)
      return forward(executeIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** Fastify handler for the session-introspection route. */
export function fastifySession(auth: AuthEngine): FastifyAdapter.Handler {
  return async (req, reply) => {
    try {
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(req.headers) }).orNull()
      // `csrfHash` is server-side state: the browser holds the plaintext in its cookie and never needs the hash.
      const { csrfHash: _csrfHash, ...session } = resolved?.session ?? { csrfHash: null }
      reply.status(200)
      reply.header('cache-control', 'no-store')
      reply.header('content-type', 'application/json; charset=utf-8')
      reply.send(
        JSON.stringify(resolved ? { session, identity: resolved.identity } : { session: null, identity: null }),
      )
      return reply
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Fastify handler for the per-provider begin step (oauth start /
 * passkey-options / etc.). CSRF-guarded.
 */
export function fastifyProviderBegin(auth: AuthEngine): FastifyAdapter.Handler {
  return async (req, reply) => {
    try {
      const headers = toFetchHeaders(req.headers)
      await csrfGuard(auth, { headers, method: req.method })
      const id = isRecord(req.params) ? req.params.id : undefined
      if (!isValidProviderId(id)) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }]), reply)
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      return forward(executeIntents(redirectForScript(await auth.flows.beginProvider(id, body), headers)), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** Fastify handler for the oauth callback, GET and POST. A form post needs a urlencoded body parser,
 *  `@fastify/formbody` or your own, or Fastify answers it 415. See {@link oauthCallback}. */
export function fastifyProviderCallback(auth: AuthEngine): FastifyAdapter.Handler {
  return async (req, reply) => {
    try {
      const id = isRecord(req.params) ? req.params.id : undefined
      const request = { body: req.body, cookie: req.headers.cookie, method: req.method, url: req.url }
      return forward(executeIntents(await oauthCallback(auth, id, request, fastifyCaller(req))), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** Mount every handler under `/auth/*` in one call. Wire the handlers directly instead for a custom
 *  path layout. */
export function registerFastify(
  fastify: {
    post: (path: string, handler: FastifyAdapter.Handler) => void
    get: (path: string, handler: FastifyAdapter.Handler) => void
  },
  auth: AuthEngine,
  opts: { prefix?: string } = {},
): void {
  const prefix = opts.prefix ?? '/auth'
  fastify.post(`${prefix}/signin`, fastifySignIn(auth))
  fastify.post(`${prefix}/signout`, fastifySignOut(auth))
  fastify.get(`${prefix}/session`, fastifySession(auth))
  fastify.post(`${prefix}/providers/:id/begin`, fastifyProviderBegin(auth))
  fastify.get(`${prefix}/providers/:id/callback`, fastifyProviderCallback(auth))
  fastify.post(`${prefix}/providers/:id/callback`, fastifyProviderCallback(auth))
}

/** The fingerprint Fastify resolved, the same pair {@link fastifySignIn} stamps at sign-in. */
export function fastifyCaller(req: FastifyAdapter.Request): CallerFingerprint {
  return callerContext({ ip: req.ip, userAgent: req.headers['user-agent'] })
}

/** {@link ActorOptions} over Fastify's request. */
export type FastifyActorOptions<Req extends FastifyAdapter.Request = FastifyAdapter.Request> = ActorOptions<Req>

/** Wrap one handler so its writes carry the request's actor; per-handler, since Fastify composes no
 *  `next`. A handler annotated with Fastify's own request and reply types keeps them. See
 *  `core/actor/README.md` for what runs unbound and what raises. */
export function fastifyWithActor<Req extends FastifyAdapter.Request, Reply extends FastifyAdapter.Reply, Out>(
  auth: AuthEngine,
  handler: (req: Req, reply: Reply) => Promise<Out>,
  opts: FastifyActorOptions<Req> = {},
): (req: Req, reply: Reply) => Promise<Out> {
  return (req, reply) =>
    withRequestActor(
      auth,
      { headers: toFetchHeaders(req.headers) },
      () => handler(req, reply),
      requestSecurity(auth, { caller: opts.getCaller?.(req), onAnomaly: opts.onAnomaly, onHijack: opts.onHijack }),
    )
}

/** CSRF guard for your own routes: `fastify.addHook('preHandler', fastifyCsrf(auth))`. */
export function fastifyCsrf(auth: AuthEngine, opts: Csrf.GuardOptions = {}): FastifyAdapter.PreHandler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method }, opts)
    } catch (err) {
      // SECURITY: `await`: Fastify's Reply is thenable, and only awaiting it stops the handler running after
      // the 403.
      await handleError(err, reply)
    }
  }
}

export type { FastifyAdapter } from './fastify.types'
