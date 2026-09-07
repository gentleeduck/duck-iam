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

import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import {
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  executeIntents,
  isValidProviderId,
  parseProviderBeginBody,
  parseSignInBody,
  type RequestSecurityOptions,
  requestSecurity,
} from '../generic'

import type { ElysiaAdapter } from './elysia.types'

function handleError(err: unknown): Response {
  const { status, body } = errorToHttp(err)
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

/** Elysia handler for the sign-in route. CSRF-guarded. */
export function elysiaSignIn(auth: AuthEngine): ElysiaAdapter.Handler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, ctx.request)
      const parsed = parseSignInBody(ctx.body)
      if (!parsed) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn({
        ...parsed,
        ...elysiaCaller(ctx),
      })
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** Elysia handler for sign-out. CSRF-guarded. */
export function elysiaSignOut(auth: AuthEngine): ElysiaAdapter.Handler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, ctx.request)
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

/** Elysia handler for the per-provider begin step. CSRF-guarded. */
export function elysiaProviderBegin(auth: AuthEngine): ElysiaAdapter.Handler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, ctx.request)
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

/** CSRF guard for your own routes: `app.onBeforeHandle(elysiaCsrf(auth))`. */
/**
 * Wrap one handler so its writes carry the request's actor. `Elysia` composes no
 * `next`, so the binding is per-handler rather than a middleware: without it a
 * write records `created_by` / `updated_by` / `deleted_by` as `null`, because
 * nothing else in the package opens the scope the stores read.
 *
 * Anonymous requests and unresolvable sessions run unbound, which is the honest
 * `null`; while impersonating, the operator behind `actingAs` is the actor, not
 * the account being acted on.
 */
/** The fingerprint Elysia resolved, the same pair {@link elysiaSignIn} stamps at sign-in. */
export function elysiaCaller(ctx: ElysiaAdapter.Context): CallerFingerprint {
  return callerContext({ ip: ctx.ip, userAgent: ctx.request.headers.get('user-agent') ?? undefined })
}

/**
 * Options for the actor-context wrapper.
 *
 * `getCaller` is the opt-in: omit it and the wrapper is what it has always been, an attribution
 * scope that refuses nothing. Supply it - {@link elysiaCaller} reads the same values the sign-in
 * route already stamps onto the session - and every request's fingerprint is compared with the
 * session's, running the anomaly detectors and the hijack policy. Switching that on in a live
 * deployment starts acting on IP and User-Agent drift for sessions already issued.
 */
export type ElysiaActorOptions = {
  /** Read the request fingerprint. Never from a forwarded header: see `callerContext`. */
  getCaller?: (ctx: ElysiaAdapter.Context) => CallerFingerprint
  /** Handle drift yourself, including the `'rotate'` reaction the wrapper cannot perform. */
  onHijack?: RequestSecurityOptions['onHijack']
}

export function elysiaWithActor(
  auth: AuthEngine,
  handler: ElysiaAdapter.Handler,
  opts: ElysiaActorOptions = {},
): ElysiaAdapter.Handler {
  return (ctx) =>
    withRequestActor(
      auth,
      { headers: ctx.request.headers },
      () => handler(ctx),
      requestSecurity(auth, { ...(opts.onHijack && { onHijack: opts.onHijack }), caller: opts.getCaller?.(ctx) ?? {} }),
    )
}

export function elysiaCsrf(auth: AuthEngine, opts: Csrf.GuardOptions = {}): ElysiaAdapter.Middleware {
  return async (ctx) => {
    try {
      await csrfGuard(auth, ctx.request, opts)
      return undefined
    } catch (err) {
      return handleError(err)
    }
  }
}

export type { ElysiaAdapter } from './elysia.types'
