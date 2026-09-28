import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorResponse,
  executeIntents,
  isValidProviderId,
  jsonResponse,
  oauthCallback,
  parseProviderBeginBody,
  parseSignInBody,
  readBodyJson,
  readBodyText,
  redirectForScript,
  requestSecurity,
} from '../generic'

/** CSRF-guarded. */
export function nextSignIn(auth: AuthEngine): NextAdapter.Handler {
  return async (req) => {
    try {
      await csrfGuard(auth, { method: req.method, headers: req.headers })
      const parsed = parseSignInBody(await readBodyJson(req))
      if (!parsed) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn({
        ...parsed,
        ...nextCaller(req),
        previousSid: auth.transport.extract(req) ?? undefined,
      })
      return executeIntents(result.intents)
    } catch (err) {
      return errorResponse(err)
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
      return errorResponse(err)
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
      return jsonResponse(200, body)
    } catch (err) {
      return errorResponse(err)
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
      const body = parseProviderBeginBody(await readBodyJson(req))
      if (body === null) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      return executeIntents(redirectForScript(await auth.flows.beginProvider(providerId, body), req.headers))
    } catch (err) {
      return errorResponse(err)
    }
  }
}

/** The oauth callback, GET and POST. See {@link oauthCallback}. */
export function nextProviderCallback(auth: AuthEngine, providerId: string): NextAdapter.Handler {
  return async (req) => {
    try {
      const body = req.method === 'POST' ? ((await readBodyText(req)) ?? '') : undefined
      const request = { body, cookie: req.headers.get('cookie'), method: req.method, url: req.url }
      return executeIntents(await oauthCallback(auth, providerId, request, nextCaller(req)))
    } catch (err) {
      return errorResponse(err)
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
  opts: {
    signin?: boolean
    signout?: boolean
    session?: boolean
    providerBegin?: boolean
    providerCallback?: boolean
  } = {},
): {
  POST: NextAdapter.Handler
  GET: NextAdapter.Handler
} {
  const enabled = {
    signin: opts.signin ?? true,
    signout: opts.signout ?? true,
    session: opts.session ?? true,
    providerBegin: opts.providerBegin ?? true,
    providerCallback: opts.providerCallback ?? true,
  }
  // `pathname` keeps its escapes, and a client encodes the `:` of every `oauth:` id.
  const providerId = (segment: string): string | null => {
    try {
      return decodeURIComponent(segment)
    } catch {
      return null
    }
  }
  const malformed = () => executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }])
  return {
    async POST(req) {
      const url = new URL(req.url)
      const segments = url.pathname.split('/').filter(Boolean)
      const last = segments[segments.length - 1] ?? ''
      const second = segments[segments.length - 2] ?? ''
      if (enabled.signin && last === 'signin') return nextSignIn(auth)(req)
      if (enabled.signout && last === 'signout') return nextSignOut(auth)(req)
      if (enabled.providerBegin && last === 'begin' && second) {
        const id = providerId(second)
        return id === null ? malformed() : nextProviderBegin(auth, id)(req)
      }
      if (enabled.providerCallback && last === 'callback' && second) {
        const id = providerId(second)
        return id === null ? malformed() : nextProviderCallback(auth, id)(req)
      }
      return executeIntents([
        { type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 404, detail: 'unknown auth route' },
      ])
    },
    async GET(req) {
      const url = new URL(req.url)
      const segments = url.pathname.split('/').filter(Boolean)
      const last = segments[segments.length - 1] ?? ''
      const second = segments[segments.length - 2] ?? ''
      if (enabled.session && last === 'session') return nextSession(auth)(req)
      if (enabled.providerCallback && last === 'callback' && second) {
        const id = providerId(second)
        return id === null ? malformed() : nextProviderCallback(auth, id)(req)
      }
      return executeIntents([
        { type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 404, detail: 'unknown auth route' },
      ])
    },
  }
}

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
 * The fingerprint Next exposes, the same pair {@link nextSignIn} stamps at sign-in: User-Agent
 * only. A Web `Request` carries no resolved peer address, and the forwarded header that would
 * stand in for one is written by the caller.
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

/** The Next.js request and response surface the adapter touches. */
export namespace NextAdapter {
  /** A route handler. */
  export type Handler = (req: Request) => Promise<Response>
}
