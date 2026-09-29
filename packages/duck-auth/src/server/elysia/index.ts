/** Elysia adapter: the CSRF guard, the actor wrapper and the caller fingerprint for your own routes. Elysia is
 *  Web-Fetch native, so a route answers a flow's intents with `executeIntents(intents)`. */

import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import { type ActorOptions, type CallerFingerprint, callerContext, errorResponse, requestSecurity } from '../generic'

import type { ElysiaAdapter } from './elysia.types'

/** The fingerprint Elysia resolved, for `flows.signIn` to stamp onto the session. */
export function elysiaCaller(ctx: ElysiaAdapter.Context): CallerFingerprint {
  return callerContext({ ip: ctx.ip, userAgent: ctx.request.headers.get('user-agent') ?? undefined })
}

/** {@link ActorOptions} over Elysia's context. */
export type ElysiaActorOptions<Ctx extends ElysiaAdapter.Context = ElysiaAdapter.Context> = ActorOptions<Ctx>

/** Wrap one handler so its writes carry the request's actor; per-handler, since Elysia composes no
 *  `next`. A handler annotated with Elysia's own `Context` keeps it. See `core/actor/README.md` for
 *  what runs unbound and what raises. */
export function elysiaWithActor<Ctx extends ElysiaAdapter.Context, Out>(
  auth: AuthEngine,
  handler: (ctx: Ctx) => Promise<Out>,
  opts: ElysiaActorOptions<Ctx> = {},
): (ctx: Ctx) => Promise<Out> {
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
