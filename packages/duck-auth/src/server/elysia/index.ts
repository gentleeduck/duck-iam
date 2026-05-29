/**
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
 */

import type { AuthRoot } from '../../core/auth'
import { errorToHttp, executeIntents, parseProviderBeginBody, parseSignInBody } from '../generic'

function handleError(err: unknown): Response {
  const { status, body } = errorToHttp(err)
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

/**
 * Elysia handler for the sign-in route.
 */
export function elysiaSignIn(auth: AuthRoot): ElysiaAdapter.IHandler {
  return async (ctx) => {
    try {
      const parsed = parseSignInBody(ctx.body)
      if (!parsed) {
        return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn(parsed)
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * Elysia handler for sign-out.
 */
export function elysiaSignOut(auth: AuthRoot): ElysiaAdapter.IHandler {
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
 */
export function elysiaSession(auth: AuthRoot): ElysiaAdapter.IHandler {
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
 */
export function elysiaProviderBegin(auth: AuthRoot): ElysiaAdapter.IHandler {
  return async (ctx) => {
    try {
      const id = ctx.params?.id
      if (!id) {
        return executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      const body = parseProviderBeginBody(ctx.body)
      if (body === null) {
        return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const intents = await auth.flows.beginProvider(id, body)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * Namespace merge for `ElysiaAdapter`.
 */
export namespace ElysiaAdapter {
  export type IHandler = (ctx: ElysiaAdapter.IContext) => Promise<Response>

  export interface IContext {
    request: Request
    /** Pre-parsed JSON body (Elysia parses by default when content-type is application/json). */
    body?: unknown
    /** Route params; populated when the route definition declares `:id` etc. */
    params?: Record<string, string>
  }
}
