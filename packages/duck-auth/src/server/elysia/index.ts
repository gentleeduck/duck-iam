/**
 * Elysia adapter. Elysia is Web-Fetch native; the adapter is a thin
 * wrapper around `server/generic.executeIntents` that pulls
 * `Headers` straight from `context.request`.
 *
 * Mount on an Elysia instance:
 *
 *   app.post('/AUTH/signin',  elysiaSignIn(auth))
 *   app.post('/AUTH/signout', elysiaSignOut(auth))
 *   app.get('/AUTH/session',  elysiaSession(auth))
 *   app.post('/AUTH/providers/:id/begin', elysiaProviderBegin(auth))
 */

import type { AuthEngine } from '../../core/engine'
import { errorToHttp, executeIntents, isValidProviderId, parseProviderBeginBody, parseSignInBody } from '../generic'

import type { ElysiaAdapter } from './elysia.types'

function handleError(err: unknown): Response {
  const { status, body } = errorToHttp(err)
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

/** Elysia handler for the sign-in route. */
export function elysiaSignIn(auth: AuthEngine): ElysiaAdapter.Handler {
  return async (ctx) => {
    try {
      const parsed = parseSignInBody(ctx.body)
      if (!parsed) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn(parsed)
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** Elysia handler for sign-out. */
export function elysiaSignOut(auth: AuthEngine): ElysiaAdapter.Handler {
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

/** Elysia handler for the session-introspection route. */
export function elysiaSession(auth: AuthEngine): ElysiaAdapter.Handler {
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
export function elysiaProviderBegin(auth: AuthEngine): ElysiaAdapter.Handler {
  return async (ctx) => {
    try {
      const id = ctx.params?.id
      if (!isValidProviderId(id)) {
        return executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }])
      }
      const body = parseProviderBeginBody(ctx.body)
      if (body === null) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      const intents = await auth.flows.beginProvider(id, body)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

export type { ElysiaAdapter } from './elysia.types'
