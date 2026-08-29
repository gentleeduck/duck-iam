/**
 * Fastify adapter. Fastify is Node-native (req/reply rather than
 * Web-Fetch), so the adapter translates between the Web Fetch
 * `Response` that `executeIntents` returns and Fastify's reply API.
 *
 * Mount each handler on your Fastify instance:
 *
 *   fastify.post('/AUTH/signin',  fastifySignIn(auth))
 *   fastify.post('/AUTH/signout', fastifySignOut(auth))
 *   fastify.get('/AUTH/session',  fastifySession(auth))
 *   fastify.post('/AUTH/providers/:id/begin', fastifyProviderBegin(auth))
 */

import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import {
  callerContext,
  errorToHttp,
  executeIntents,
  extractSetCookies,
  isValidProviderId,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
} from '../generic'

import type { FastifyAdapter } from './fastify.types'

/** Convert the loose Fastify header bag into a Web Fetch Headers object. */
const toFetchHeaders: (headers: FastifyAdapter.Request['headers']) => Headers = nodeHeadersToFetch

/**
 * Forward the Web Fetch `Response` produced by `executeIntents` onto
 * the Fastify reply. Handles Set-Cookie multiplicity correctly (one
 * header per cookie). Returns the reply so the caller can `return`
 * straight from the handler.
 */
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
        ...callerContext({ ip: req.ip, userAgent: req.headers['user-agent'] }),
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
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(req.headers) })
      reply.status(200)
      reply.header('content-type', 'application/json; charset=utf-8')
      reply.send(
        JSON.stringify(
          resolved ? { session: resolved.session, identity: resolved.identity } : { session: null, identity: null },
        ),
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

/**
 * Convenience plugin function that mounts every handler under
 * `/AUTH/*` in one call. Apps that want a custom path layout can
 * skip this and wire each handler directly.
 */
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

/** CSRF guard for your own routes: `fastify.addHook('preHandler', fastifyCsrf(auth))`. */
export function fastifyCsrf(auth: AuthEngine, opts: Csrf.GuardOptions = {}): FastifyAdapter.PreHandler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method }, opts)
    } catch (err) {
      handleError(err, reply)
    }
  }
}

export type { FastifyAdapter } from './fastify.types'
