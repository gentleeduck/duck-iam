/** Koa adapter. Koa is Node-native and uses `ctx.req` / `ctx.request`, so this translates between
 *  the Web Fetch responses `executeIntents` returns and Koa's ctx response API. */

import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import type { Provider } from '~/core/provider/provider.types'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  executeIntents,
  nodeHeadersToFetch,
  requestSecurity,
} from '../generic'

import type { KoaAdapter } from './koa.types'

const toFetchHeaders: (headers: KoaAdapter.Context['request']['headers']) => Headers = nodeHeadersToFetch

/** Koa keeps method + headers on `ctx.request`; csrfGuard wants them flat. */
function toCsrfRequest(ctx: KoaAdapter.Context): { method: string; headers: Headers } {
  return { headers: toFetchHeaders(ctx.request.headers), method: ctx.request.method }
}

/** Write the intents a flow returned onto a Koa ctx, for a host's own routes. Set-Cookie keeps one header
 *  per cookie, through `append()` where the Koa version has it and a string array otherwise. */
export async function koaApplyIntents(intents: Provider.Intent[], ctx: KoaAdapter.Context): Promise<void> {
  const response = executeIntents(intents)
  ctx.status = response.status
  const cookies = response.headers.getSetCookie()
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

/** The fingerprint Koa resolved, for `flows.signIn` to stamp onto the session. */
export function koaCaller(ctx: KoaAdapter.Context): CallerFingerprint {
  return callerContext({ ip: ctx.request.ip, userAgent: ctx.request.headers['user-agent'] })
}

/** {@link ActorOptions} over Koa's context. */
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
