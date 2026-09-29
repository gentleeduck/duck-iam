import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { type ActorOptions, type CallerFingerprint, callerContext, errorResponse, requestSecurity } from '../generic'
import type { HonoAdapter } from './hono.types'

/** Hono exposes no resolved address, so `ctx.ip` is whatever the app chose to put there. */
export function honoCaller(ctx: { ip?: string; req: { header: (n?: string) => unknown } }): CallerFingerprint {
  const ua = ctx.req.header('user-agent')
  return callerContext({ ip: ctx.ip, userAgent: typeof ua === 'string' ? ua : undefined })
}

function reqHeaders(ctx: HonoAdapter.Context): Headers {
  return ctx.req.raw.headers
}

function reqMethod(ctx: HonoAdapter.Context): string {
  return ctx.req.raw.method
}

/** Convert a native Hono Context into the structural {@link HonoAdapter.Context}. */
export function toHonoAdapterCtx(c: HonoAdapter.HonoCtx): HonoAdapter.Context {
  return {
    req: {
      header: (name?: string) => {
        if (name === undefined) {
          const out: Record<string, string> = {}
          c.req.raw.headers.forEach((v, k) => {
            out[k] = v
          })
          return out
        }
        const value = c.req.header(name)
        return typeof value === 'string' ? value : undefined
      },
      raw: c.req.raw,
    },
  }
}

/** {@link ActorOptions} over Hono's context. */
export type HonoActorOptions = ActorOptions<HonoAdapter.Context>

/** Bind the request's actor scope for everything downstream; install it above your own routes,
 *  alongside the CSRF guard. See `core/actor/README.md` for what runs unbound and what raises. */
export function honoActorContext(auth: AuthEngine, opts: HonoActorOptions = {}): HonoAdapter.Middleware {
  return async (ctx, next) => {
    try {
      await withRequestActor(
        auth,
        { headers: ctx.req.raw.headers },
        () => next(),
        requestSecurity(auth, { caller: opts.getCaller?.(ctx), onAnomaly: opts.onAnomaly, onHijack: opts.onHijack }),
      )
    } catch (err) {
      // A refusal is answered here, since Hono's default `onError` answers any throw with a 500. A
      // failure is still raised to it.
      if (err instanceof AuthError && err.status < 500) return errorResponse(err)
      throw err
    }
    return undefined
  }
}

/** CSRF guard for your own routes: `app.use('*', honoCsrf(auth))`. */
export function honoCsrf(auth: AuthEngine, opts: Csrf.GuardOptions = {}): HonoAdapter.Middleware {
  return async (ctx, next) => {
    try {
      await csrfGuard(auth, { headers: reqHeaders(ctx), method: reqMethod(ctx) }, opts)
    } catch (err) {
      return errorResponse(err)
    }
    await next()
    return undefined
  }
}

export type { HonoAdapter } from './hono.types'
