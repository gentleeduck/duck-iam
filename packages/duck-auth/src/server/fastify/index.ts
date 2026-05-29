/**
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
 */

import type { AuthRoot } from '../../core/auth'
import {
  errorToHttp,
  executeIntents,
  extractSetCookies,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
} from '../generic'

/** Convert the loose Fastify header bag into a Web Fetch Headers object. */
const toFetchHeaders: (headers: FastifyAdapter.IRequest['headers']) => Headers = nodeHeadersToFetch

/**
 * Forward the Web Fetch `Response` produced by `executeIntents` onto
 * the Fastify reply. Handles Set-Cookie multiplicity correctly (one
 * header per cookie). Returns the reply so the caller can `return`
 * straight from the handler.
 */
async function forward(response: Response, reply: FastifyAdapter.IReply): Promise<FastifyAdapter.IReply> {
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

function handleError(err: unknown, reply: FastifyAdapter.IReply): FastifyAdapter.IReply {
  const { status, body } = errorToHttp(err)
  reply.status(status)
  reply.header('content-type', 'application/json; charset=utf-8')
  reply.send(JSON.stringify(body))
  return reply
}

/**
 * Fastify handler for the sign-in route.
 */
export function fastifySignIn(auth: AuthRoot): FastifyAdapter.IHandler {
  return async (req, reply) => {
    try {
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const result = await auth.flows.signIn(parsed)
      return forward(executeIntents(result.intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Fastify handler for sign-out.
 */
export function fastifySignOut(auth: AuthRoot): FastifyAdapter.IHandler {
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
 */
export function fastifySession(auth: AuthRoot): FastifyAdapter.IHandler {
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
 */
export function fastifyProviderBegin(auth: AuthRoot): FastifyAdapter.IHandler {
  return async (req, reply) => {
    try {
      const id = req.params?.id
      if (!id) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }]), reply)
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
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
 * `/auth/*` in one call. Apps that want a custom path layout can
 * skip this and wire each handler directly.
 */
export function registerFastifyAuth(
  fastify: {
    post: (path: string, handler: FastifyAdapter.IHandler) => void
    get: (path: string, handler: FastifyAdapter.IHandler) => void
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
 */
export namespace FastifyAdapter {
  export type IHandler = (
    req: FastifyAdapter.IRequest,
    reply: FastifyAdapter.IReply,
  ) => Promise<FastifyAdapter.IReply | undefined>

  export interface IRequest {
    method: string
    url: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
    params?: Record<string, string>
  }

  export interface IReply {
    status(code: number): FastifyAdapter.IReply
    header(key: string, value: string): FastifyAdapter.IReply
    send(payload: unknown): FastifyAdapter.IReply | undefined | Promise<unknown>
  }
}
