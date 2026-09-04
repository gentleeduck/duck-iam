/**
 * Koa adapter. Koa is Node-native and uses ctx.req / ctx.request, so
 * the adapter translates between Web-Fetch responses (from
 * executeIntents) and Koa's ctx response API.
 *
 * Mount each handler:
 *
 *   router.post('/AUTH/signin',  koaSignIn(auth))
 *   router.post('/AUTH/signout', koaSignOut(auth))
 *   router.get('/AUTH/session',  koaSession(auth))
 *   router.post('/AUTH/providers/:id/begin', koaProviderBegin(auth))
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
  extractSetCookies,
  isValidProviderId,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
  type RequestSecurityOptions,
  requestSecurity,
} from '../generic'

import type { KoaAdapter } from './koa.types'

const toFetchHeaders: (headers: KoaAdapter.Context['request']['headers']) => Headers = nodeHeadersToFetch

/** Koa keeps method + headers on `ctx.request`; csrfGuard wants them flat. */
function toCsrfRequest(ctx: KoaAdapter.Context): { method: string; headers: Headers } {
  return { headers: toFetchHeaders(ctx.request.headers), method: ctx.request.method }
}

/**
 * Forward a Web Fetch `Response` (from executeIntents) onto a Koa
 * ctx. Set-Cookie multiplicity preserved by using `append()` when the
 * Koa version supports it; falls back to `set()` with a string-array.
 */
async function forward(response: Response, ctx: KoaAdapter.Context): Promise<void> {
  ctx.status = response.status
  const cookies = extractSetCookies(response)
  if (cookies.length > 0) {
    if (ctx.append) {
      for (const c of cookies) ctx.append('set-cookie', c)
    } else {
      ctx.set('set-cookie', cookies)
    }
  }
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') return
    ctx.set(key, value)
  })
  ctx.body = response.body ? await response.text() : ''
}

function handleError(err: unknown, ctx: KoaAdapter.Context): void {
  const { status, body } = errorToHttp(err)
  ctx.status = status
  ctx.set('content-type', 'application/json; charset=utf-8')
  ctx.body = JSON.stringify(body)
}

/** Koa handler for the sign-in route. CSRF-guarded. */
export function koaSignIn(auth: AuthEngine): KoaAdapter.Handler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, toCsrfRequest(ctx))
      const parsed = parseSignInBody(ctx.request.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), ctx)
      }
      const result = await auth.flows.signIn({
        ...parsed,
        ...koaCaller(ctx),
      })
      await forward(executeIntents(result.intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/** Koa handler for sign-out. CSRF-guarded. */
export function koaSignOut(auth: AuthEngine): KoaAdapter.Handler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, toCsrfRequest(ctx))
      const sid = auth.transport.extract({ headers: toFetchHeaders(ctx.request.headers) })
      if (!sid) {
        await forward(executeIntents(auth.transport.revoke()), ctx)
        return
      }
      const { intents } = await auth.flows.signOut(sid)
      await forward(executeIntents(intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/** Koa handler for the session-introspection route. */
export function koaSession(auth: AuthEngine): KoaAdapter.Handler {
  return async (ctx) => {
    try {
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(ctx.request.headers) })
      ctx.status = 200
      ctx.set('content-type', 'application/json; charset=utf-8')
      ctx.body = JSON.stringify(
        resolved ? { session: resolved.session, identity: resolved.identity } : { session: null, identity: null },
      )
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/** Koa handler for the per-provider begin step. CSRF-guarded. */
export function koaProviderBegin(auth: AuthEngine): KoaAdapter.Handler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, toCsrfRequest(ctx))
      const id = ctx.params?.id
      if (!isValidProviderId(id)) {
        await forward(executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }]), ctx)
        return
      }
      const body = parseProviderBeginBody(ctx.request.body)
      if (body === null) {
        await forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), ctx)
        return
      }
      const intents = await auth.flows.beginProvider(id, body)
      await forward(executeIntents(intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/** CSRF guard for your own routes: `app.use(koaCsrf(auth))`. Skips `next` on failure. */
/**
 * Bind the request's actor scope for everything downstream. Without it a write
 * a request drives records `created_by` / `updated_by` / `deleted_by` as `null`,
 * because nothing else in the package opens the scope the stores read.
 *
 * Install it above your own routes, alongside the CSRF guard. Anonymous
 * requests and unresolvable sessions run unbound, which is the honest `null`;
 * while impersonating, the operator behind `actingAs` is the actor, not the
 * account being acted on.
 */
/** The fingerprint Koa resolved, the same pair {@link koaSignIn} stamps at sign-in. */
export function koaCaller(ctx: KoaAdapter.Context): CallerFingerprint {
  return callerContext({ ip: ctx.request.ip, userAgent: ctx.request.headers['user-agent'] })
}

/**
 * Options for the actor-context wrapper.
 *
 * `getCaller` is the opt-in: omit it and the wrapper is what it has always been, an attribution
 * scope that refuses nothing. Supply it - {@link koaCaller} reads the same values the sign-in
 * route already stamps onto the session - and every request's fingerprint is compared with the
 * session's, running the anomaly detectors and the hijack policy. Switching that on in a live
 * deployment starts acting on IP and User-Agent drift for sessions already issued.
 */
export type KoaActorOptions = {
  /** Read the request fingerprint. Never from a forwarded header: see `callerContext`. */
  getCaller?: (ctx: KoaAdapter.Context) => CallerFingerprint
  /** Handle drift yourself, including the `'rotate'` reaction the wrapper cannot perform. */
  onHijack?: RequestSecurityOptions['onHijack']
}

export function koaActorContext(auth: AuthEngine, opts: KoaActorOptions = {}): KoaAdapter.Middleware {
  return async (ctx, next) => {
    await withRequestActor(
      auth,
      { headers: toFetchHeaders(ctx.request.headers) },
      () => next(),
      requestSecurity(auth, { ...(opts.onHijack && { onHijack: opts.onHijack }), caller: opts.getCaller?.(ctx) ?? {} }),
    )
  }
}

export function koaCsrf(auth: AuthEngine, opts: Csrf.GuardOptions = {}): KoaAdapter.Middleware {
  return async (ctx, next) => {
    try {
      await csrfGuard(auth, toCsrfRequest(ctx), opts)
    } catch (err) {
      handleError(err, ctx)
      return
    }
    await next()
  }
}

export type { KoaAdapter } from './koa.types'
