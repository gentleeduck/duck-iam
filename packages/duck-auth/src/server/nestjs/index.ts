import type { ArgumentsHost, ExceptionFilter, ExecutionContext } from '@nestjs/common'
import { Catch, createParamDecorator } from '@nestjs/common'
import { withResolvedActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard, verifyCsrf } from '~/core/csrf'
import type { AuthEngine, Engine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  nodeHeadersToFetch,
  requestSecurity,
} from '../generic'

import type { NestAdapter } from './nestjs.types'

const toFetchHeaders: (headers: NestAdapter.Request['headers']) => Headers = nodeHeadersToFetch

/** What duck-auth resolved for a request, shared by the middleware, the guard and the param decorators.
 *  Held here rather than on `req.session`, which is the host's session middleware's: express-session fills it
 *  on every request, and skips itself on finding it filled. */
const resolvedByRequest = new WeakMap<object, Engine.ResolveResult<Identities.ProfileMetadataBase> | null>()

/** Auth guard for your own routes. CSRF is checked by default, since an app mounting only this guard
 *  would otherwise have no CSRF defence; pass `csrf: false` only if something upstream did it. */
export function makeGuard(
  auth: AuthEngine,
  opts: { required?: boolean; csrf?: boolean; cfg?: Csrf.Cfg } = {},
): NestAdapter.Guard {
  const required = opts.required ?? true
  const csrf = opts.csrf ?? true
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest()
      // Nest runs middleware before guards, so `nestActorContext` has usually resolved it already.
      const resolved = resolvedByRequest.has(req)
        ? (resolvedByRequest.get(req) ?? null)
        : await auth.resolveSession({ headers: toFetchHeaders(req.headers) }).orNull()
      resolvedByRequest.set(req, resolved)
      if (csrf) {
        // Reuse the session just resolved rather than paying a second
        // resolveSession inside csrfGuard.
        verifyCsrf({
          headers: toFetchHeaders(req.headers),
          method: req.method,
          ...(opts.cfg !== undefined && { cfg: opts.cfg }),
          ...(resolved?.session.csrfHash != null && { sessionCsrfHash: resolved.session.csrfHash }),
        })
      }
      if (!resolved) {
        if (required) {
          throw new AuthError('AUTH_UNAUTHENTICATED')
        }
        return true
      }
      req.identity = resolved.identity
      return true
    },
  }
}

/** The fingerprint Nest resolved, for `flows.signIn` to stamp onto the session.
 *  SECURITY: `req.ip` and nothing else, the host resolving that against its own proxy trust, while a
 *  forwarded header here would take the value the caller wrote. */
export function nestCaller(req: NestAdapter.Request): CallerFingerprint {
  return callerContext({ ip: req.ip, userAgent: req.headers?.['user-agent'] })
}

/** {@link ActorOptions} over Nest's request. */
export type NestActorOptions = ActorOptions<NestAdapter.Request>

/** Bind the request's actor scope for everything downstream:
 *  `consumer.apply(nestActorContext(auth)).forRoutes('*')`. Middleware, since it runs ahead of the guards,
 *  which an interceptor would leave unbound. `makeGuard` reuses what it resolved, so the pair costs one
 *  `resolveSession`. */
export function nestActorContext(
  auth: AuthEngine,
  opts: NestActorOptions = {},
): (req: NestAdapter.Request, res: unknown, next: (err?: unknown) => void) => Promise<void> {
  return async (req, _res, next) => {
    // SECURITY: all of it inside the try. Mounted with `app.use` on Nest 10, whose Express 4 forwards no
    // rejected middleware, a refusal or a store outage would hold the request open instead of answering it.
    try {
      const security = requestSecurity(auth, {
        caller: opts.getCaller?.(req),
        onAnomaly: opts.onAnomaly,
        onHijack: opts.onHijack,
      })
      // Resolved here rather than by `withRequestActor`, which drops the identity the guard reuses.
      const resolved = await auth
        .resolveSession({ headers: toFetchHeaders(req.headers) }, { requestSnapshot: security.requestSnapshot })
        // `.orNull()` answers null for "no session" alone, so a store outage still throws.
        .orNull()
      resolvedByRequest.set(req, resolved)
      if (resolved) req.identity = resolved.identity
      // `next()` is synchronous, so the downstream chain starts inside the scope.
      await withResolvedActor(resolved?.session ?? null, async () => next(), security, resolved?.anomaly)
    } catch (err) {
      next(err)
    }
  }
}

/** CSRF-only guard, for routes that need the check without the auth gate. */
export function makeCsrfGuard(auth: AuthEngine, opts: Csrf.GuardOptions = {}): NestAdapter.Guard {
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest()
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method }, opts)
      return true
    },
  }
}

/** Injection token the Nest module binds the engine under. */
export const DUCK_AUTH_TOKEN = 'DUCK_AUTH'

/** Turns an `AuthError` into the Nest response its status and code describe. */
@Catch(AuthError)
export class NestExceptionFilter implements ExceptionFilter {
  /** Writes the error's status and JSON body onto the Nest response, unless it was already answered: a second
   *  write throws ERR_HTTP_HEADERS_SENT, which Nest then logs in place of this error. */
  catch(err: AuthError, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<{
      headersSent: boolean
      setHeader(name: string, value: string): void
      status(code: number): { json(body: unknown): void }
    }>()
    if (res.headersSent) return
    const { status, body } = errorToHttp(err)
    res.setHeader('cache-control', 'no-store')
    res.status(status).json(body)
  }
}

/** Parameter decorator supplying the session `makeGuard` or `nestActorContext` resolved. */
export const CurrentSession = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): Sessions.Me | undefined =>
    resolvedByRequest.get(ctx.switchToHttp().getRequest<object>())?.session,
)

/** Parameter decorator supplying the identity `makeGuard` or `nestActorContext` resolved. */
export const CurrentIdentity = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): Identities.Me | null | undefined =>
    resolvedByRequest.get(ctx.switchToHttp().getRequest<object>())?.identity,
)

export type { NestAdapter } from './nestjs.types'

/** Constructs a {@link NestExceptionFilter}. */
export function nestExceptionFilter(...args: ConstructorParameters<typeof NestExceptionFilter>): NestExceptionFilter {
  return new NestExceptionFilter(...args)
}
