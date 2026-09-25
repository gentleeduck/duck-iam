/** Koa adapter. Koa is Node-native and uses `ctx.req` / `ctx.request`, so this translates between
 *  the Web Fetch responses `executeIntents` returns and Koa's ctx response API. */

import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  executeIntents,
  extractSetCookies,
  isValidProviderId,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
  requestSecurity,
} from '../generic'

import type { KoaAdapter } from './koa.types'

const toFetchHeaders: (headers: KoaAdapter.Context['request']['headers']) => Headers = nodeHeadersToFetch

/** Koa keeps method + headers on `ctx.request`; csrfGuard wants them flat. */
function toCsrfRequest(ctx: KoaAdapter.Context): { method: string; headers: Headers } {
  return { headers: toFetchHeaders(ctx.request.headers), method: ctx.request.method }
}

/** Forward `executeIntents`' `Response` onto a Koa ctx, keeping Set-Cookie multiplicity through
 *  `append()` where the Koa version has it and a string array otherwise. */
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
  ctx.set('cache-control', 'no-store')
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
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(ctx.request.headers) }).orNull()
      // `csrfHash` is server-side state: the browser holds the plaintext in its cookie and never needs the hash.
      const { csrfHash: _csrfHash, ...session } = resolved?.session ?? { csrfHash: null }
      ctx.status = 200
      ctx.set('cache-control', 'no-store')
      ctx.set('content-type', 'application/json; charset=utf-8')
      ctx.body = JSON.stringify(resolved ? { session, identity: resolved.identity } : { session: null, identity: null })
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

/** The fingerprint Koa resolved, the same pair {@link koaSignIn} stamps at sign-in. */
export function koaCaller(ctx: KoaAdapter.Context): CallerFingerprint {
  return callerContext({ ip: ctx.request.ip, userAgent: ctx.request.headers['user-agent'] })
}

export type KoaActorOptions = ActorOptions<KoaAdapter.Context>

/** Bind the request's actor scope for everything downstream; install it above your own routes,
 *  alongside the CSRF guard. See `core/actor/README.md` for what runs unbound and what raises. */
export function koaActorContext(auth: AuthEngine, opts: KoaActorOptions = {}): KoaAdapter.Middleware {
  return async (ctx, next) => {
    await withRequestActor(
      auth,
      { headers: toFetchHeaders(ctx.request.headers) },
      () => next(),
      requestSecurity(auth, { caller: opts.getCaller?.(ctx), onAnomaly: opts.onAnomaly, onHijack: opts.onHijack }),
    )
  }
}

/** CSRF guard for your own routes: `app.use(koaCsrf(auth))`. Skips `next` on failure. */
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
