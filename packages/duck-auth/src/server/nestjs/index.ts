import type { ArgumentsHost, ExceptionFilter, ExecutionContext } from '@nestjs/common'
import { Catch, createParamDecorator } from '@nestjs/common'
import { withResolvedActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard, verifyCsrf } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import type { Flows } from '~/core/flows'
import type { Identities } from '~/core/identities/identities.types'
import type { Provider } from '~/core/provider'
import type { Sessions } from '~/core/sessions/sessions.types'
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

import type { NestAdapter } from './nestjs.types'

const toFetchHeaders: (headers: NestAdapter.Request['headers']) => Headers = nodeHeadersToFetch

async function forward(response: Response, reply: NestAdapter.Response): Promise<unknown> {
  reply.status(response.status)
  const cookies = extractSetCookies(response)
  if (cookies.length > 0) {
    if (reply.setHeader) reply.setHeader('set-cookie', cookies)
    else if (reply.set) reply.set('set-cookie', cookies)
  }
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') return
    if (reply.setHeader) reply.setHeader(key, value)
    else if (reply.set) reply.set(key, value)
  })
  const body = response.body ? await response.text() : ''
  return reply.send(body)
}

function handleError(err: unknown, reply: NestAdapter.Response): never {
  const { status, body } = errorToHttp(err)
  reply.status(status)
  if (reply.setHeader) reply.setHeader('content-type', 'application/json; charset=utf-8')
  reply.send(JSON.stringify(body))
  // rethrow so NestJS exception filter can log to Loki; filter's res.headersSent
  // check prevents double-send
  throw err
}

/**
 * A refusal returned by {@link NestSignInOptions.onAuthenticated}.
 *
 * `detail` and not `message`: it is forwarded verbatim as the response body's `error.detail`,
 * the field every other duck-auth error already uses.
 */
export type NestSignInDenial = {
  /** Machine-readable code, e.g. `'AUTH_NOT_PERMITTED_ON_HOST'`. Free-form - it is your vocabulary, not the engine's. */
  code: string
  /** HTTP status. Must be 4xx or 5xx; anything else is coerced to 403 (see {@link denialIntent}). */
  status: number
  detail?: string
}

export type NestSignInOptions = {
  /**
   * Runs after the credentials verify and the session row exists, before any intent reaches
   * the response. Returning a denial revokes the session that was just created and replaces
   * the session intents with the error, so the client never receives the SID.
   *
   * Gating here rather than in front of `signIn` is deliberate: a caller has to prove the
   * password before it learns anything, so the denial is not an enumeration oracle.
   *
   * `outcome.session` is null when the provider stopped short of a session - an MFA challenge,
   * typically. The hook still runs so it can refuse at that point too; there is simply nothing
   * to revoke.
   */
  onAuthenticated?: (
    outcome: Flows.SignInOutcome,
    req: NestAdapter.Request,
  ) => Promise<NestSignInDenial | undefined> | NestSignInDenial | undefined
}

/**
 * Normalise a hook's denial into an error intent, failing closed.
 *
 * A hook that returns `status: 200`, `NaN`, or a blank code would otherwise render a refusal
 * as a success status - which is the exact bypass this hook exists to prevent - so a denial
 * the adapter cannot read is still a denial, at 403.
 */
function denialIntent(denial: NestSignInDenial): Provider.Intent {
  const code = typeof denial.code === 'string' && denial.code.trim().length > 0 ? denial.code : 'AUTH_DENIED'
  const status = Number.isInteger(denial.status) && denial.status >= 400 && denial.status <= 599 ? denial.status : 403
  return { code, status, type: 'error', ...(typeof denial.detail === 'string' && { detail: denial.detail }) }
}

/**
 * Drop the session `signIn` just issued. Empty when the provider issued none (MFA challenge),
 * in which case `sid` is empty and there is nothing to revoke.
 */
async function revokeIssuedSession(auth: AuthEngine, outcome: Flows.SignInOutcome): Promise<Provider.Intent[]> {
  if (!outcome.sid) return []
  const { intents } = await auth.flows.signOut(outcome.sid)
  return intents
}

/**
 * POST sign-in. CSRF-guarded.
 *
 * Pass `onAuthenticated` to gate the sign-in on something the engine cannot know - host
 * allow-lists, tenant suspension, a per-identity block. See {@link NestSignInOptions}.
 */
export function nestSignIn(auth: AuthEngine, opts: NestSignInOptions = {}): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method })
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      // The flow, the store and the columns all take these and the adapter was dropping
      // them, so every session row recorded a device it could not name.
      const outcome = await auth.flows.signIn({ ...parsed, ...nestCaller(req) })
      if (!opts.onAuthenticated) return forward(executeIntents(outcome.intents), reply)

      let denial: NestSignInDenial | undefined
      try {
        denial = await opts.onAuthenticated(outcome, req)
      } catch (hookErr) {
        // The row is already live at this point. Drop it before the error propagates, or a
        // hook that throws leaves behind exactly the session a denial would have revoked.
        await revokeIssuedSession(auth, outcome)
        throw hookErr
      }
      if (!denial) return forward(executeIntents(outcome.intents), reply)

      // Revoke inside the library: it owns the sid, and a consumer would forget - forgetting
      // leaves a live session behind a 403, a silent auth bypass. The revoke intents come
      // first so the Set-Cookie is cleared rather than left pointing at a dead session.
      const revoked = await revokeIssuedSession(auth, outcome)
      return forward(executeIntents([...revoked, denialIntent(denial)]), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** POST sign-out. CSRF-guarded. */
export function nestSignOut(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method })
      const sid = auth.transport.extract({ headers: toFetchHeaders(req.headers) })
      if (!sid) return forward(executeIntents(auth.transport.revoke()), reply)
      const { intents } = await auth.flows.signOut(sid)
      return forward(executeIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

export function nestSession(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(req.headers) })
      reply.status(200)
      if (reply.setHeader) reply.setHeader('content-type', 'application/json; charset=utf-8')
      return reply.send(
        JSON.stringify(
          resolved ? { session: resolved.session, identity: resolved.identity } : { session: null, identity: null },
        ),
      )
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** POST provider-begin. CSRF-guarded. */
export function nestProviderBegin(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method })
      const id = req.params?.id
      if (!isValidProviderId(id)) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }]), reply)
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const intents = await auth.flows.beginProvider(id, body)
      return forward(executeIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Auth guard for your own routes. CSRF is checked by default because a
 * cookie-session app mounting only this guard would otherwise have no CSRF
 * defence at all. Pass `csrf: false` only if something upstream already did it.
 */
export function makeGuard(auth: AuthEngine, opts: { required?: boolean; csrf?: boolean } = {}): NestAdapter.Guard {
  const required = opts.required ?? true
  const csrf = opts.csrf ?? true
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest<NestAdapter.Request>()
      // What `nestActorContext` already resolved, when it ran first. Nest runs middleware before
      // guards, so resolving again is the session store read twice for one request.
      const resolved = req.session
        ? { identity: req.identity ?? null, session: req.session }
        : await auth.resolveSession({ headers: toFetchHeaders(req.headers) })
      if (csrf) {
        // Reuse the session we just resolved rather than paying a second
        // resolveSession inside csrfGuard.
        verifyCsrf({
          headers: toFetchHeaders(req.headers),
          method: req.method,
          ...(resolved?.session.csrfHash != null && { sessionCsrfHash: resolved.session.csrfHash }),
        })
      }
      if (!resolved) {
        if (required) {
          throw new AuthError('AUTH_UNAUTHENTICATED')
        }
        return true
      }
      req.session = resolved.session
      // Adapter is profile-agnostic; store the resolved identity opaquely.
      req.identity = resolved.identity as NestAdapter.Request['identity']
      return true
    },
  }
}

/**
 * Bind the request's actor scope for everything downstream:
 * `consumer.apply(nestActorContext(auth)).forRoutes('*')`.
 *
 * A middleware and not a guard or an interceptor. `canActivate` returns before
 * the handler runs, so a scope opened there is already closed by the time a
 * write happens; an interceptor would have to hold the scope across the
 * `Observable` its handler is subscribed on, which is not where it is opened.
 * Middleware is the one Nest hook that wraps handler execution directly.
 *
 * Reuses the session `makeGuard` resolved when it ran first, so the pair costs
 * one `resolveSession`, not two.
 */
/**
 * The fingerprint Nest resolved, the same pair the sign-in handler stamps onto the session.
 *
 * `req.ip` and nothing else: the host resolves it against its own proxy trust, and reading a
 * forwarded header here would take the value the caller wrote.
 */
export function nestCaller(req: NestAdapter.Request): CallerFingerprint {
  return callerContext({ ip: req.ip, userAgent: req.headers?.['user-agent'] })
}

/**
 * Options for the actor-context wrapper.
 *
 * `getCaller` is the opt-in: omit it and the wrapper is what it has always been, an attribution
 * scope that refuses nothing. Supply it - {@link nestCaller} reads the same values the sign-in
 * route already stamps onto the session - and every request's fingerprint is compared with the
 * session's, running the anomaly detectors and the hijack policy. Switching that on in a live
 * deployment starts acting on IP and User-Agent drift for sessions already issued.
 */
export type NestActorOptions = {
  /** Read the request fingerprint. Never from a forwarded header: see `callerContext`. */
  getCaller?: (req: NestAdapter.Request) => CallerFingerprint
  /** Handle drift yourself, including the `'rotate'` reaction the wrapper cannot perform. */
  onHijack?: RequestSecurityOptions['onHijack']
}

export function nestActorContext(
  auth: AuthEngine,
  opts: NestActorOptions = {},
): {
  use(req: NestAdapter.Request, res: unknown, next: () => void): Promise<void>
} {
  return {
    async use(req, _res, next) {
      const bound = async (): Promise<void> => {
        next()
      }
      const security = requestSecurity(auth, {
        ...(opts.onHijack && { onHijack: opts.onHijack }),
        caller: opts.getCaller?.(req) ?? {},
      })
      // Resolved here rather than by `withRequestActor`, which keeps the session and drops the
      // identity: both are stashed on the request so `makeGuard` reuses them instead of paying a
      // second resolveSession. A session that will not resolve leaves the request unattributed,
      // which is what the wrapper did too.
      if (!req.session) {
        const resolved = await auth
          .resolveSession(
            { headers: toFetchHeaders(req.headers) },
            security.requestSnapshot ? { requestSnapshot: security.requestSnapshot } : undefined,
          )
          .catch(() => null)
        if (resolved) {
          req.session = resolved.session
          req.identity = resolved.identity as NestAdapter.Request['identity']
        }
      }
      // `next()` is synchronous, so the downstream chain starts inside the
      // scope and every async continuation of it inherits the binding.
      if (req.session) await withResolvedActor(req.session, bound, security)
      else await bound()
    },
  }
}

/** CSRF-only guard, for routes that need the check without the auth gate. */
export function makeCsrfGuard(auth: AuthEngine, opts: Csrf.GuardOptions = {}): NestAdapter.Guard {
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest<NestAdapter.Request>()
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method }, opts)
      return true
    },
  }
}

export const DUCK_AUTH_TOKEN = 'DUCK_AUTH'

@Catch(AuthError)
export class NestExceptionFilter implements ExceptionFilter {
  catch(err: AuthError, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<{ status(code: number): { json(body: unknown): void } }>()
    res.status(err.status).json(err.toJSON())
  }
}

export const CurrentSession = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): Sessions.Me | undefined =>
    ctx.switchToHttp().getRequest<{ session?: Sessions.Me }>().session,
)

export const CurrentIdentity = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): Identities.Me | null | undefined =>
    ctx.switchToHttp().getRequest<{ identity?: Identities.Me | null }>().identity,
)

export type { NestAdapter } from './nestjs.types'

/** Factory around {@link NestExceptionFilter}, for callers who prefer functions to `new`. */
export function nestExceptionFilter(...args: ConstructorParameters<typeof NestExceptionFilter>): NestExceptionFilter {
  return new NestExceptionFilter(...args)
}
