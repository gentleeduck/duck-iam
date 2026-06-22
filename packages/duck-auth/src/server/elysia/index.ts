/**
 * Elysia adapter. Elysia is Web-Fetch native; the adapter is a thin
 * wrapper around `server/generic.authExecuteIntents` that pulls
 * `Headers` straight from `context.request`.
 *
 * Mount on an Elysia instance:
 *
 *   app.post('/auth/signin',  authElysiaSignIn(auth))
 *   app.post('/auth/signout', authElysiaSignOut(auth))
 *   app.get('/auth/session',  authElysiaSession(auth))
 *   app.post('/auth/providers/:id/begin', authElysiaProviderBegin(auth))
 */

import type { AuthEngine } from '../../core/engine'
import {
  authErrorToHttp,
  authExecuteIntents,
  authIsValidProviderId,
  authParseProviderBeginBody,
  authParseSignInBody,
} from '../generic'

function handleError(err: unknown): Response {
  const { status, body } = authErrorToHttp(err)
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

/** Elysia handler for the sign-in route. */
export function authElysiaSignIn(auth: AuthEngine): AuthElysiaAdapter.IHandler {
  return async (ctx) => {
    try {
      const parsed = authParseSignInBody(ctx.body)
      if (!parsed) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn(parsed)
      return authExecuteIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** Elysia handler for sign-out. */
export function authElysiaSignOut(auth: AuthEngine): AuthElysiaAdapter.IHandler {
  return async (ctx) => {
    try {
      const sid = auth.transport.extract({ headers: ctx.request.headers })
      if (!sid) return authExecuteIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return authExecuteIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** Elysia handler for the session-introspection route. */
export function authElysiaSession(auth: AuthEngine): AuthElysiaAdapter.IHandler {
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

/** Elysia handler for the per-provider begin step. */
export function authElysiaProviderBegin(auth: AuthEngine): AuthElysiaAdapter.IHandler {
  return async (ctx) => {
    try {
      const id = ctx.params?.id
      if (!authIsValidProviderId(id)) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      const body = authParseProviderBeginBody(ctx.body)
      if (body === null) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const intents = await auth.flows.beginProvider(id, body)
      return authExecuteIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

export namespace AuthElysiaAdapter {
  export type IHandler = (ctx: AuthElysiaAdapter.IContext) => Promise<Response>

  export interface IContext {
    request: Request
    /** Pre-parsed JSON body (Elysia parses by default when content-type is application/json). */
    body?: unknown
    /** Route params; populated when the route definition declares `:id` etc. */
    params?: Record<string, string>
  }
}
