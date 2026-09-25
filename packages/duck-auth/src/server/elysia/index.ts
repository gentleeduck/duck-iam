/**
 * Elysia adapter. Elysia is Web-Fetch native; the adapter is a thin
 * wrapper around `server/generic.executeIntents` that pulls
 * `Headers` straight from `context.request`.
 */

import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorResponse,
  executeIntents,
  isValidProviderId,
  jsonResponse,
  parseProviderBeginBody,
  parseSignInBody,
  requestSecurity,
} from '../generic'

import type { ElysiaAdapter } from './elysia.types'

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
      return errorResponse(err)
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
      return errorResponse(err)
    }
  }
}

/** Elysia handler for the session-introspection route. */
export function elysiaSession(auth: AuthEngine): ElysiaAdapter.Handler {
  return async (ctx) => {
    try {
      const resolved = await auth.resolveSession({ headers: ctx.request.headers }).orNull()
      // `csrfHash` is server-side state: the browser holds the plaintext in its cookie and never needs the hash.
      const { csrfHash: _csrfHash, ...session } = resolved?.session ?? { csrfHash: null }
      const body = resolved ? { session, identity: resolved.identity } : { session: null, identity: null }
      return jsonResponse(200, body)
    } catch (err) {
      return errorResponse(err)
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
      return errorResponse(err)
    }
  }
}

/** The fingerprint Elysia resolved, the same pair {@link elysiaSignIn} stamps at sign-in. */
export function elysiaCaller(ctx: ElysiaAdapter.Context): CallerFingerprint {
  return callerContext({ ip: ctx.ip, userAgent: ctx.request.headers.get('user-agent') ?? undefined })
}

export type ElysiaActorOptions = ActorOptions<ElysiaAdapter.Context>

/** Wrap one handler so its writes carry the request's actor; per-handler, since Elysia composes no
 *  `next`. See `core/actor/README.md` for what runs unbound and what raises. */
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
      requestSecurity(auth, { caller: opts.getCaller?.(ctx), onAnomaly: opts.onAnomaly, onHijack: opts.onHijack }),
    )
}

/** CSRF guard for your own routes: `app.onBeforeHandle(elysiaCsrf(auth))`. */
export function elysiaCsrf(auth: AuthEngine, opts: Csrf.GuardOptions = {}): ElysiaAdapter.Middleware {
  return async (ctx) => {
    try {
      await csrfGuard(auth, ctx.request, opts)
      return undefined
    } catch (err) {
      return errorResponse(err)
    }
  }
}

export type { ElysiaAdapter } from './elysia.types'
