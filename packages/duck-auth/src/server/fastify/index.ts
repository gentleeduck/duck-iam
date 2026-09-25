/** Fastify adapter. Fastify is Node-native, so this translates between the Web Fetch `Response`
 *  `executeIntents` returns and Fastify's reply API. Mount each handler yourself, or use
 *  {@link registerFastify}. */

import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  executeIntents,
  extractSetCookies,
  isValidProviderId,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
  requestSecurity,
} from '../generic'

import type { FastifyAdapter } from './fastify.types'

/** Convert the loose Fastify header bag into a Web Fetch Headers object. */
const toFetchHeaders: (headers: FastifyAdapter.Request['headers']) => Headers = nodeHeadersToFetch

/** Forward `executeIntents`' `Response` onto the Fastify reply, one header per cookie. Answers with
 *  the reply, so a handler can `return` it straight. */
async function forward(response: Response, reply: FastifyAdapter.Reply): Promise<FastifyAdapter.Reply> {
  reply.status(response.status)
  for (const cookie of extractSetCookies(response)) {
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
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method })
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const result = await auth.flows.signIn({
        ...parsed,
        ...fastifyCaller(req),
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
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method })
      const id = req.params?.id
      if (!isValidProviderId(id)) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }]), reply)
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const intents = await auth.flows.beginProvider(id, body)
      return forward(executeIntents(intents), reply)
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
}

/** The fingerprint Fastify resolved, the same pair {@link fastifySignIn} stamps at sign-in. */
export function fastifyCaller(req: FastifyAdapter.Request): CallerFingerprint {
  return callerContext({ ip: req.ip, userAgent: req.headers['user-agent'] })
}

export type FastifyActorOptions = ActorOptions<FastifyAdapter.Request>

/** Wrap one handler so its writes carry the request's actor; per-handler, since Fastify composes no
 *  `next`. See `core/actor/README.md` for what runs unbound and what raises. */
export function fastifyWithActor(
  auth: AuthEngine,
  handler: FastifyAdapter.Handler,
  opts: FastifyActorOptions = {},
): FastifyAdapter.Handler {
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
      // SECURITY: `await`, because Fastify's Reply is thenable and awaiting it is what waits for the send.
      // Dropping it resolved the hook with the response still in flight, Fastify ran the chain on, and the
      // protected handler executed after the 403 had been written - the request refused on the wire and the
      // write performed anyway, which is the whole of what a CSRF attack is after. Returning the reply does
      // not help; only awaiting it does.
      await handleError(err, reply)
    }
  }
}

export type { FastifyAdapter } from './fastify.types'
