/**
 * @packageDocumentation
 * Fastify adapter. Fastify is Node-native (req/reply rather than
 * Web-Fetch), so the adapter translates between the Web Fetch
 * `Response` that `executeIntents` returns and Fastify's reply API.
 *
 * Mount each handler on your Fastify instance:
 *
 *   fastify.post('/auth/signin',  fastifySignIn(auth))
 *   fastify.post('/auth/signout', fastifySignOut(auth))
 *   fastify.get('/auth/session',  fastifySession(auth))
 *   fastify.post('/auth/providers/:id/begin', fastifyProviderBegin(auth))
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { AuthRoot } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import { executeIntents } from '../generic'

/**
 * Narrow subset of `fastify.FastifyRequest` we depend on. Lets us
 * accept Fastify request objects without importing fastify types as a
 * hard dep.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface FastifyLikeRequest {
  method: string
  url: string
  headers: Record<string, string | string[] | undefined>
  body?: unknown
  params?: Record<string, string>
}

/**
 * Narrow subset of `fastify.FastifyReply`. Mirrors the Set-Cookie /
 * status / send / header surface the adapter touches; lets tests
 * inject a simple stub.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface FastifyLikeReply {
  status(code: number): FastifyLikeReply
  header(key: string, value: string): FastifyLikeReply
  send(payload: unknown): FastifyLikeReply | void | Promise<unknown>
}

/**
 * Fastify route-handler shape. Returns the reply (Fastify convention)
 * so the host's `done` callback fires.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type FastifyAuthHandler = (req: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<FastifyLikeReply | void>

/** Convert the loose Fastify header bag into a Web Fetch Headers object. */
function toFetchHeaders(headers: FastifyLikeRequest['headers']): Headers {
  const h = new Headers()
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const item of v) h.append(k, String(item))
    } else {
      h.set(k, String(v))
    }
  }
  return h
}

/**
 * Forward the Web Fetch `Response` produced by `executeIntents` onto
 * the Fastify reply. Handles Set-Cookie multiplicity correctly (one
 * header per cookie). Returns the reply so the caller can `return`
 * straight from the handler.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
async function forward(response: Response, reply: FastifyLikeReply): Promise<FastifyLikeReply> {
  reply.status(response.status)
  // Use getSetCookie() when available so multiple Set-Cookie headers
  // each land separately; fall back to the iterator for older runtimes.
  const getSetCookie = (response.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie
  if (getSetCookie) {
    for (const cookie of getSetCookie.call(response.headers)) {
      reply.header('set-cookie', cookie)
    }
  }
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') return // already handled
    reply.header(key, value)
  })
  const body = response.body ? await response.text() : ''
  reply.send(body)
  return reply
}

function handleError(err: unknown, reply: FastifyLikeReply): FastifyLikeReply {
  if (err instanceof AuthErrorObject) {
    reply.status(err.status)
    reply.header('content-type', 'application/json; charset=utf-8')
    reply.send(JSON.stringify(err.toJSON()))
    return reply
  }
  reply.status(500)
  reply.header('content-type', 'application/json; charset=utf-8')
  reply.send(JSON.stringify({ code: 'AUTH/MISCONFIGURED', detail: 'internal error' }))
  return reply
}

/**
 * Fastify handler for the sign-in route.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function fastifySignIn(auth: AuthRoot): FastifyAuthHandler {
  return async (req, reply) => {
    try {
      const body = (req.body ?? {}) as { providerId?: string; input?: unknown }
      if (!body.providerId) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const result = await auth.flows.signIn({
        providerId: body.providerId,
        input: body.input ?? {},
      })
      return forward(executeIntents(result.intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Fastify handler for sign-out.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function fastifySignOut(auth: AuthRoot): FastifyAuthHandler {
  return async (req, reply) => {
    try {
      const sid = auth.transport.extract({ headers: toFetchHeaders(req.headers) })
      if (!sid) return forward(executeIntents(auth.transport.revoke()), reply)
      const { intents } = await auth.flows.signOut(sid)
      return forward(executeIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Fastify handler for the session-introspection route.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function fastifySession(auth: AuthRoot): FastifyAuthHandler {
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
 * Fastify handler for the per-provider begin step (OAuth start /
 * passkey-options / etc.).
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function fastifyProviderBegin(auth: AuthRoot): FastifyAuthHandler {
  return async (req, reply) => {
    try {
      const id = req.params?.id
      if (!id) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }]), reply)
      }
      const intents = await auth.flows.beginProvider(id, (req.body ?? {}) as unknown)
      return forward(executeIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Convenience plugin function that mounts every handler under
 * `/auth/*` in one call. Apps that want a custom path layout can
 * skip this and wire each handler directly.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function registerFastifyAuth(
  fastify: {
    post: (path: string, handler: FastifyAuthHandler) => void
    get: (path: string, handler: FastifyAuthHandler) => void
  },
  auth: AuthRoot,
  opts: { prefix?: string } = {},
): void {
  const prefix = opts.prefix ?? '/auth'
  fastify.post(`${prefix}/signin`, fastifySignIn(auth))
  fastify.post(`${prefix}/signout`, fastifySignOut(auth))
  fastify.get(`${prefix}/session`, fastifySession(auth))
  fastify.post(`${prefix}/providers/:id/begin`, fastifyProviderBegin(auth))
}

/**
 * Namespace merge for `FastifyAdapter`. Co-locates the loose handler
 * + request / reply shapes alongside the factories.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace FastifyAdapter {
  /** Alias for `FastifyAuthHandler`. */
  export type IHandler = FastifyAuthHandler
  /** Alias for `FastifyLikeRequest`. */
  export type IRequest = FastifyLikeRequest
  /** Alias for `FastifyLikeReply`. */
  export type IReply = FastifyLikeReply
}
