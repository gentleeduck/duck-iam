/**
 * @packageDocumentation
 * Elysia adapter. Elysia is Web-Fetch native; the adapter is a thin
 * wrapper around `server/generic.executeIntents` that pulls
 * `Headers` straight from `context.request`.
 *
 * Mount on an Elysia instance:
 *
 *   app.post('/auth/signin',  elysiaSignIn(auth))
 *   app.post('/auth/signout', elysiaSignOut(auth))
 *   app.get('/auth/session',  elysiaSession(auth))
 *   app.post('/auth/providers/:id/begin', elysiaProviderBegin(auth))
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { AuthRoot } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import { executeIntents } from '../generic'

/**
 * Narrow subset of Elysia's `Context` we depend on. Lets us accept
 * Elysia contexts without importing the `elysia` package as a hard
 * dep.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface ElysiaLikeContext {
  request: Request
  /** Pre-parsed JSON body (Elysia parses by default when content-type is application/json). */
  body?: unknown
  /** Route params; populated when the route definition declares `:id` etc. */
  params?: Record<string, string>
}

/**
 * Elysia route-handler shape. Returns `Response` so Elysia drains it
 * directly.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type ElysiaAuthHandler = (ctx: ElysiaLikeContext) => Promise<Response>

function handleError(err: unknown): Response {
  if (err instanceof AuthErrorObject) {
    return new Response(JSON.stringify(err.toJSON()), {
      status: err.status,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    })
  }
  return new Response(JSON.stringify({ code: 'AUTH/MISCONFIGURED', detail: 'internal error' }), {
    status: 500,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

/**
 * Elysia handler for the sign-in route.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function elysiaSignIn(auth: AuthRoot): ElysiaAuthHandler {
  return async (ctx) => {
    try {
      const body = (ctx.body ?? {}) as { providerId?: string; input?: unknown }
      if (!body.providerId) {
        return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn({
        providerId: body.providerId,
        input: body.input ?? {},
      })
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * Elysia handler for sign-out.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function elysiaSignOut(auth: AuthRoot): ElysiaAuthHandler {
  return async (ctx) => {
    try {
      const sid = auth.transport.extract({ headers: ctx.request.headers })
      if (!sid) return executeIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * Elysia handler for the session-introspection route.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function elysiaSession(auth: AuthRoot): ElysiaAuthHandler {
  return async (ctx) => {
    try {
      const resolved = await auth.resolveSession({ headers: ctx.request.headers })
      const body = resolved
        ? { session: resolved.session, identity: resolved.identity }
        : { session: null, identity: null }
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
      })
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * Elysia handler for the per-provider begin step.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function elysiaProviderBegin(auth: AuthRoot): ElysiaAuthHandler {
  return async (ctx) => {
    try {
      const id = ctx.params?.id
      if (!id) {
        return executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      const intents = await auth.flows.beginProvider(id, (ctx.body ?? {}) as unknown)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * Namespace merge for `ElysiaAdapter`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace ElysiaAdapter {
  /** Alias for `ElysiaAuthHandler`. */
  export type IHandler = ElysiaAuthHandler
  /** Alias for `ElysiaLikeContext`. */
  export type IContext = ElysiaLikeContext
}
