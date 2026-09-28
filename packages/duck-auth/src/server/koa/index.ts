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
  isValidProviderId,
  nodeHeadersToFetch,
  oauthCallback,
  parseProviderBeginBody,
  parseSignInBody,
  redirectForScript,
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

/** Koa handler for the sign-in route. CSRF-guarded. */
export function koaSignIn(auth: AuthEngine): KoaAdapter.Handler {
  return async (ctx) => {
    try {
      const req = toCsrfRequest(ctx)
      await csrfGuard(auth, req)
      const parsed = parseSignInBody(ctx.request.body)
      if (!parsed) {
        return koaApplyIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }], ctx)
      }
      const result = await auth.flows.signIn({
        ...parsed,
        ...koaCaller(ctx),
        previousSid: auth.transport.extract(req) ?? undefined,
      })
      await koaApplyIntents(result.intents, ctx)
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
        await koaApplyIntents(auth.transport.revoke(), ctx)
        return
      }
      const { intents } = await auth.flows.signOut(sid)
      await koaApplyIntents(intents, ctx)
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
      const req = toCsrfRequest(ctx)
      await csrfGuard(auth, req)
      const id = ctx.params?.id
      if (!isValidProviderId(id)) {
        await koaApplyIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }], ctx)
        return
      }
      const body = parseProviderBeginBody(ctx.request.body)
      if (body === null) {
        await koaApplyIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }], ctx)
        return
      }
      await koaApplyIntents(redirectForScript(await auth.flows.beginProvider(id, body), req.headers), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/** Koa handler for the oauth callback, GET and POST. A form post needs a body parser that reads forms, as
 *  `koa-bodyparser` does by default. See {@link oauthCallback}. */
export function koaProviderCallback(auth: AuthEngine): KoaAdapter.Handler {
  return async (ctx) => {
    try {
      const { body, headers, method, url } = ctx.request
      await koaApplyIntents(
        await oauthCallback(auth, ctx.params?.id, { body, cookie: headers.cookie, method, url }, koaCaller(ctx)),
        ctx,
      )
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/** The fingerprint Koa resolved, the same pair {@link koaSignIn} stamps at sign-in. */
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
