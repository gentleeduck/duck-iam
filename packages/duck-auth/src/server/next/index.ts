import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import {
  callerContext,
  errorToHttp,
  executeIntents,
  isValidProviderId,
  parseProviderBeginBody,
  parseSignInBody,
} from '../generic'

/** `nextSignIn`. CSRF-guarded. */
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
        ...callerContext({ userAgent: req.headers.get('user-agent') ?? undefined }),
      })
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** `nextSignOut`. CSRF-guarded. */
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

/** `nextSession`. */
export function nextSession(auth: AuthEngine): NextAdapter.Handler {
  return async (req) => {
    try {
      const resolved = await auth.resolveSession({ headers: req.headers })
      const body = resolved
        ? { session: resolved.session, identity: resolved.identity }
        : { session: null, identity: null }
      return Response.json(body)
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
 * Catch-all router for `app/api/AUTH/[...auth]/route.ts`. Returns `{ GET, POST }`
 * tied to the configured AuthEngine. Apps map the parsed path segments to
 * provider/flow handlers.
 *
 * Apps can also wire the individual nextSignIn / nextSignOut / etc. directly
 * - `mountNext` is an ergonomic helper.
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
      // last segments after '/AUTH/'
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
  return Response.json(body, { status })
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

export namespace NextAdapter {
  export type Handler = (req: Request) => Promise<Response>
}
