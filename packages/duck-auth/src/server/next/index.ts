import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { type ActorOptions, type CallerFingerprint, callerContext, errorResponse, requestSecurity } from '../generic'

/**
 * CSRF guard for your own routes. A wrapper rather than middleware because the
 * App Router gives the adapter no chain to hook:
 * `export const POST = withNextCsrf(auth, handler)`. Every argument is passed on, the route's `{ params }` included.
 */
export function withNextCsrf<Args extends [Request, ...unknown[]]>(
  auth: AuthEngine,
  handler: (...args: Args) => Promise<Response>,
  opts: Csrf.GuardOptions = {},
): (...args: Args) => Promise<Response> {
  return async (...args) => {
    const [req] = args
    try {
      await csrfGuard(auth, { headers: req.headers, method: req.method }, opts)
    } catch (err) {
      return errorResponse(err)
    }
    return handler(...args)
  }
}

/**
 * The fingerprint Next exposes, for `flows.signIn` to stamp onto the session: User-Agent only. A Web
 * `Request` carries no resolved peer address, and the forwarded header that would stand in for one is
 * written by the caller.
 */
export function nextCaller(req: Request): CallerFingerprint {
  return callerContext({ userAgent: req.headers.get('user-agent') ?? undefined })
}

/** Options for the actor-context wrapper. */
export type NextActorOptions<Req extends Request = Request> = ActorOptions<Req>

/** Wrap one route handler so its writes carry the request's actor; per-handler, since a route handler
 *  composes no `next`. Every argument is passed on, the route's `{ params }` included. See
 *  `core/actor/README.md` for what runs unbound and what raises. */
export function nextWithActor<Args extends [Request, ...unknown[]]>(
  auth: AuthEngine,
  handler: (...args: Args) => Promise<Response>,
  opts: NextActorOptions<Args[0]> = {},
): (...args: Args) => Promise<Response> {
  return async (...args) => {
    const [req] = args
    try {
      return await withRequestActor(
        auth,
        { headers: req.headers },
        () => handler(...args),
        requestSecurity(auth, { caller: opts.getCaller?.(req), onAnomaly: opts.onAnomaly, onHijack: opts.onHijack }),
      )
    } catch (err) {
      // A refusal is answered here, since Next answers any throw from a route with a 500. A failure is
      // still raised to it.
      if (err instanceof AuthError && err.status < 500) return errorResponse(err)
      throw err
    }
  }
}
