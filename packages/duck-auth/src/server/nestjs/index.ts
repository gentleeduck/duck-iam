import type { ArgumentsHost, ExceptionFilter, ExecutionContext } from '@nestjs/common'
import { Catch, createParamDecorator } from '@nestjs/common'
import { withResolvedActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard, verifyCsrf } from '~/core/csrf'
import type { AuthEngine, Engine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import type { Flows } from '~/core/flows'
import type { Identities } from '~/core/identities/identities.types'
import type { Provider } from '~/core/provider'
import type { Sessions } from '~/core/sessions/sessions.types'
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

import type { NestAdapter } from './nestjs.types'

const toFetchHeaders: (headers: NestAdapter.Request['headers']) => Headers = nodeHeadersToFetch

/** What duck-auth resolved for a request, shared by the middleware, the guard and the param decorators.
 *  Held here rather than on `req.session`, which is the host's session middleware's: express-session fills it
 *  on every request, and skips itself on finding it filled. */
const resolvedByRequest = new WeakMap<object, Engine.ResolveResult<Identities.ProfileMetadataBase> | null>()

async function forward(response: Response, reply: NestAdapter.Response): Promise<unknown> {
  reply.status(response.status)
  const cookies = response.headers.getSetCookie()
  if (cookies.length > 0) reply.setHeader('set-cookie', cookies)
  response.headers.forEach((value, key) => {
    if (key !== 'set-cookie') reply.setHeader(key, value)
  })
  const body = response.body ? await response.text() : ''
  return reply.send(body)
}

function handleError(err: unknown, reply: NestAdapter.Response): never {
  const { status, body } = errorToHttp(err)
  reply.status(status)
  reply.setHeader('cache-control', 'no-store')
  reply.setHeader('content-type', 'application/json; charset=utf-8')
  reply.send(JSON.stringify(body))
  // Rethrown for the host's exception filters to see; `NestExceptionFilter` leaves the answered response alone.
  throw err
}

/** A refusal from {@link NestSignInOptions.onAuthenticated}. `detail`, not `message`: it is forwarded
 *  verbatim as the body's `error.detail`, the field every other duck-auth error uses. */
export type NestSignInDenial = {
  /** Machine-readable code such as `'AUTH_NOT_PERMITTED_ON_HOST'`. Free-form: your vocabulary, not the engine's. */
  code: string
  /** HTTP status. Must be 4xx or 5xx; anything else is coerced to 403. */
  status: number
  detail?: string
}

/** Options for the Nest sign-in handler. */
export type NestSignInOptions = {
  /**
   * Runs once the credentials verify and the session row exists, before any intent reaches the
   * response: a denial revokes that session and replaces its intents, so the client never sees the
   * SID. `outcome.session` is null when the provider stopped short of one, typically an MFA
   * challenge; the hook still runs, with nothing to revoke.
   *
   * SECURITY: gated here rather than in front of `signIn`, so a caller proves the password before it
   * learns anything and the denial is not an enumeration oracle.
   */
  onAuthenticated?: (
    outcome: Flows.SignInOutcome,
    req: NestAdapter.Request,
  ) => Promise<NestSignInDenial | undefined> | NestSignInDenial | undefined
}

/** Normalise a hook's denial into an error intent, failing closed: a `status: 200`, a `NaN` or a
 *  blank code would otherwise render a refusal as a success, so an unreadable denial is still one, at 403. */
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

/** POST sign-in, CSRF-guarded. Pass `onAuthenticated` to gate it on something the engine cannot
 *  know, such as an allow-list, a suspended tenant or a per-identity block. */
export function nestSignIn(auth: AuthEngine, opts: NestSignInOptions = {}): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      const headers = toFetchHeaders(req.headers)
      await csrfGuard(auth, { headers, method: req.method })
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      // The flow, the store and the columns all take these and the adapter was dropping
      // them, so every session row recorded a device it could not name.
      const outcome = await auth.flows.signIn({
        ...parsed,
        ...nestCaller(req),
        previousSid: auth.transport.extract({ headers }) ?? undefined,
      })
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

      // Revoke inside the library: it owns the sid, and a consumer would forget, which
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

/** Nest handler answering the current session. */
export function nestSession(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(req.headers) }).orNull()
      // `csrfHash` is server-side state: the browser holds the plaintext in its cookie and never needs the hash.
      const { csrfHash: _csrfHash, ...session } = resolved?.session ?? { csrfHash: null }
      reply.status(200)
      reply.setHeader('cache-control', 'no-store')
      reply.setHeader('content-type', 'application/json; charset=utf-8')
      return reply.send(
        JSON.stringify(resolved ? { session, identity: resolved.identity } : { session: null, identity: null }),
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
      const headers = toFetchHeaders(req.headers)
      await csrfGuard(auth, { headers, method: req.method })
      const id = req.params?.id
      if (!isValidProviderId(id)) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }]), reply)
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      return forward(executeIntents(redirectForScript(await auth.flows.beginProvider(id, body), headers)), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** GET and POST provider-callback, where the IdP returns the browser. See {@link oauthCallback}. */
export function nestProviderCallback(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      const request = { body: req.body, cookie: req.headers.cookie, method: req.method, url: req.url ?? '' }
      return forward(executeIntents(await oauthCallback(auth, req.params?.id, request, nestCaller(req))), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

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

/** The fingerprint Nest resolved, the same pair the sign-in handler stamps onto the session.
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
  /** Writes the error's status and JSON body onto the Nest response, unless a duck-auth handler already answered
   *  it: a second write throws ERR_HTTP_HEADERS_SENT, which Nest then logs in place of this error. */
  catch(err: AuthError, host: ArgumentsHost): void {
    const res = host
      .switchToHttp()
      .getResponse<{ headersSent: boolean; status(code: number): { json(body: unknown): void } }>()
    if (res.headersSent) return
    const { status, body } = errorToHttp(err)
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
