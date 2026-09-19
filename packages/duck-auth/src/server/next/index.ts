import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import {
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  executeIntents,
  isValidProviderId,
  parseProviderBeginBody,
  parseSignInBody,
  type RequestSecurityOptions,
  requestSecurity,
} from '../generic'

/** CSRF-guarded. */
export function nextSignIn(auth: AuthEngine): NextAdapter.Handler {
  return async (req) => {
    try {
      await csrfGuard(auth, { method: req.method, headers: req.headers })
      const parsed = parseSignInBody(await req.json().catch(() => null))
      if (!parsed) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn({
        ...parsed,
        ...nextCaller(req),
      })
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** CSRF-guarded. */
export function nextSignOut(auth: AuthEngine): NextAdapter.Handler {
  return async (req) => {
    try {
      await csrfGuard(auth, { method: req.method, headers: req.headers })
      const sid = auth.transport.extract({ headers: req.headers })
      if (!sid) return executeIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** Next.js route handler answering the current session. */
export function nextSession(auth: AuthEngine): NextAdapter.Handler {
  return async (req) => {
    try {
      const resolved = await auth.resolveSession({ headers: req.headers }).orNull()
      // `csrfHash` is server-side state: the browser holds the plaintext in its cookie and never needs the hash.
      const { csrfHash: _csrfHash, ...session } = resolved?.session ?? { csrfHash: null }
      const body = resolved ? { session, identity: resolved.identity } : { session: null, identity: null }
      return Response.json(body, { headers: { 'cache-control': 'no-store' } })
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * Provider begin handler. Extract the provider id from the URL path or pass
 * via the second arg; both flows fit the App Router shape.
 */
export function nextProviderBegin(auth: AuthEngine, providerId: string): NextAdapter.Handler {
  return async (req) => {
    try {
      if (!isValidProviderId(providerId)) {
        return executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }])
      }
      await csrfGuard(auth, { method: req.method, headers: req.headers })
      const body = parseProviderBeginBody(await req.json().catch(() => null))
      if (body === null) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      const intents = await auth.flows.beginProvider(providerId, body)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * Catch-all router for `app/api/auth/[...auth]/route.ts`. Returns `{ GET, POST }`
 * tied to the configured AuthEngine. Apps map the parsed path segments to
 * provider/flow handlers.
 */
export function mountNext(
  auth: AuthEngine,
  opts: { signin?: boolean; signout?: boolean; session?: boolean; providerBegin?: boolean } = {},
): {
  POST: NextAdapter.Handler
  GET: NextAdapter.Handler
} {
  const enabled = {
    signin: opts.signin ?? true,
    signout: opts.signout ?? true,
    session: opts.session ?? true,
    providerBegin: opts.providerBegin ?? true,
  }
  return {
    async POST(req) {
      const url = new URL(req.url)
      const segments = url.pathname.split('/').filter(Boolean)
      const last = segments[segments.length - 1] ?? ''
      const second = segments[segments.length - 2] ?? ''
      if (enabled.signin && last === 'signin') return nextSignIn(auth)(req)
      if (enabled.signout && last === 'signout') return nextSignOut(auth)(req)
      if (enabled.providerBegin && last === 'begin' && second) {
        return nextProviderBegin(auth, second)(req)
      }
      return executeIntents([
        { type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 404, detail: 'unknown auth route' },
      ])
    },
    async GET(req) {
      const url = new URL(req.url)
      const segments = url.pathname.split('/').filter(Boolean)
      const last = segments[segments.length - 1] ?? ''
      if (enabled.session && last === 'session') return nextSession(auth)(req)
      return executeIntents([
        { type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 404, detail: 'unknown auth route' },
      ])
    },
  }
}

function handleError(err: unknown): Response {
  const { status, body } = errorToHttp(err)
  return Response.json(body, { headers: { 'cache-control': 'no-store' }, status })
}

/**
 * CSRF guard for your own routes. A wrapper rather than middleware because the
 * App Router gives the adapter no chain to hook:
 * `export const POST = withNextCsrf(auth, handler)`.
 */
export function withNextCsrf(
  auth: AuthEngine,
  handler: NextAdapter.Handler,
  opts: Csrf.GuardOptions = {},
): NextAdapter.Handler {
  return async (req) => {
    try {
      await csrfGuard(auth, { headers: req.headers, method: req.method }, opts)
    } catch (err) {
      return handleError(err)
    }
    return handler(req)
  }
}

/**
 * The fingerprint Next exposes, the same pair {@link nextSignIn} stamps at sign-in: User-Agent
 * only. A Web `Request` carries no resolved peer address, and the forwarded header that would
 * stand in for one is written by the caller.
 */
export function nextCaller(req: Request): CallerFingerprint {
  return callerContext({ userAgent: req.headers.get('user-agent') ?? undefined })
}

/** Options for the actor-context wrapper. */
export type NextActorOptions = {
  /** Read the request fingerprint. Never from a forwarded header: see `callerContext`. */
  getCaller?: (req: Request) => CallerFingerprint
  /** Handle drift yourself, including the `'rotate'` reaction the wrapper cannot perform. */
  onHijack?: RequestSecurityOptions['onHijack']
}

/** Wrap one handler so its writes carry the request's actor. Per-handler rather than middleware,
 *  since a route handler composes no `next`. Anonymous and unresolvable sessions run unbound, which is the
 *  honest `null`; while impersonating the actor is the operator behind `actingAs`. */
export function nextWithActor(
  auth: AuthEngine,
  handler: NextAdapter.Handler,
  opts: NextActorOptions = {},
): NextAdapter.Handler {
  return (req) =>
    withRequestActor(
      auth,
      { headers: req.headers },
      () => handler(req),
      requestSecurity(auth, {
        ...(opts.onHijack && { onHijack: opts.onHijack }),
        ...(opts.getCaller && { caller: opts.getCaller(req) }),
      }),
    )
}

/** The Next.js request and response surface the adapter touches. */
export namespace NextAdapter {
  export type Handler = (req: Request) => Promise<Response>
}
