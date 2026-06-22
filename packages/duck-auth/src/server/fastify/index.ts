/**
 * Fastify adapter. Fastify is Node-native (req/reply rather than
 * Web-Fetch), so the adapter translates between the Web Fetch
 * `Response` that `authExecuteIntents` returns and Fastify's reply API.
 *
 * Mount each handler on your Fastify instance:
 *
 *   fastify.post('/auth/signin',  authFastifySignIn(auth))
 *   fastify.post('/auth/signout', authFastifySignOut(auth))
 *   fastify.get('/auth/session',  authFastifySession(auth))
 *   fastify.post('/auth/providers/:id/begin', authFastifyProviderBegin(auth))
 */

import type { AuthEngine } from '../../core/auth'
import {
  authErrorToHttp,
  authExecuteIntents,
  authExtractSetCookies,
  authIsValidProviderId,
  authNodeHeadersToFetch,
  authParseProviderBeginBody,
  authParseSignInBody,
} from '../generic'

/** Convert the loose Fastify header bag into a Web Fetch Headers object. */
const toFetchHeaders: (headers: AuthFastifyAdapter.IRequest['headers']) => Headers = authNodeHeadersToFetch

/**
 * Forward the Web Fetch `Response` produced by `authExecuteIntents` onto
 * the Fastify reply. Handles Set-Cookie multiplicity correctly (one
 * header per cookie). Returns the reply so the caller can `return`
 * straight from the handler.
 */
async function forward(response: Response, reply: AuthFastifyAdapter.IReply): Promise<AuthFastifyAdapter.IReply> {
  reply.status(response.status)
  for (const cookie of authExtractSetCookies(response)) {
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

function handleError(err: unknown, reply: AuthFastifyAdapter.IReply): AuthFastifyAdapter.IReply {
  const { status, body } = authErrorToHttp(err)
  reply.status(status)
  reply.header('content-type', 'application/json; charset=utf-8')
  reply.send(JSON.stringify(body))
  return reply
}

/** Fastify handler for the sign-in route. */
export function authFastifySignIn(auth: AuthEngine): AuthFastifyAdapter.IHandler {
  return async (req, reply) => {
    try {
      const parsed = authParseSignInBody(req.body)
      if (!parsed) {
        return forward(authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const result = await auth.flows.signIn(parsed)
      return forward(authExecuteIntents(result.intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** Fastify handler for sign-out. */
export function authFastifySignOut(auth: AuthEngine): AuthFastifyAdapter.IHandler {
  return async (req, reply) => {
    try {
      const sid = auth.transport.extract({ headers: toFetchHeaders(req.headers) })
      if (!sid) return forward(authExecuteIntents(auth.transport.revoke()), reply)
      const { intents } = await auth.flows.signOut(sid)
      return forward(authExecuteIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** Fastify handler for the session-introspection route. */
export function authFastifySession(auth: AuthEngine): AuthFastifyAdapter.IHandler {
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
export function authFastifyProviderBegin(auth: AuthEngine): AuthFastifyAdapter.IHandler {
  return async (req, reply) => {
    try {
      const id = req.params?.id
      if (!authIsValidProviderId(id)) {
        return forward(authExecuteIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }]), reply)
      }
      const body = authParseProviderBeginBody(req.body)
      if (body === null) {
        return forward(authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const intents = await auth.flows.beginProvider(id, body)
      return forward(authExecuteIntents(intents), reply)
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
export function authRegisterFastify(
  fastify: {
    post: (path: string, handler: AuthFastifyAdapter.IHandler) => void
    get: (path: string, handler: AuthFastifyAdapter.IHandler) => void
  },
  auth: AuthEngine,
  opts: { prefix?: string } = {},
): void {
  const prefix = opts.prefix ?? '/auth'
  fastify.post(`${prefix}/signin`, authFastifySignIn(auth))
  fastify.post(`${prefix}/signout`, authFastifySignOut(auth))
  fastify.get(`${prefix}/session`, authFastifySession(auth))
  fastify.post(`${prefix}/providers/:id/begin`, authFastifyProviderBegin(auth))
}

export namespace AuthFastifyAdapter {
  export type IHandler = (
    req: AuthFastifyAdapter.IRequest,
    reply: AuthFastifyAdapter.IReply,
  ) => Promise<AuthFastifyAdapter.IReply | undefined>

  export interface IRequest {
    method: string
    url: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
    params?: Record<string, string>
  }

  export interface IReply {
    status(code: number): AuthFastifyAdapter.IReply
    header(key: string, value: string): AuthFastifyAdapter.IReply
    send(payload: unknown): AuthFastifyAdapter.IReply | undefined | Promise<unknown>
  }
}
