import type { AuthRoot } from '../../core/auth'
import { csrfGuard } from '../../core/csrf'
import { errorToHttp, executeIntents, isValidProviderId, parseProviderBeginBody, parseSignInBody } from '../generic'

/** `nextSignIn`. CSRF-guarded. */
export function nextSignIn(auth: AuthRoot): NextAdapter.IHandler {
  return async (req) => {
    try {
      await csrfGuard(auth, { method: req.method, headers: req.headers })
      const parsed = parseSignInBody(await req.json().catch(() => null))
      if (!parsed) {
        return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn(parsed)
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** `nextSignOut`. CSRF-guarded. */
export function nextSignOut(auth: AuthRoot): NextAdapter.IHandler {
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
export function nextSession(auth: AuthRoot): NextAdapter.IHandler {
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
export function nextProviderBegin(auth: AuthRoot, providerId: string): NextAdapter.IHandler {
  return async (req) => {
    try {
      if (!isValidProviderId(providerId)) {
        return executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      await csrfGuard(auth, { method: req.method, headers: req.headers })
      const body = parseProviderBeginBody(await req.json().catch(() => null))
      if (body === null) {
        return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
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
 * tied to the configured AuthRoot. Apps map the parsed path segments to
 * provider/flow handlers.
 *
 * Apps can also wire the individual nextSignIn / nextSignOut / etc. directly
 * - `mountNext` is an ergonomic helper.
 */
export function mountNext(
  auth: AuthRoot,
  opts: { signin?: boolean; signout?: boolean; session?: boolean; providerBegin?: boolean } = {},
): {
  POST: NextAdapter.IHandler
  GET: NextAdapter.IHandler
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
      // last segments after '/auth/'
      const last = segments[segments.length - 1] ?? ''
      const second = segments[segments.length - 2] ?? ''
      if (enabled.signin && last === 'signin') return nextSignIn(auth)(req)
      if (enabled.signout && last === 'signout') return nextSignOut(auth)(req)
      if (enabled.providerBegin && last === 'begin' && second) {
        return nextProviderBegin(auth, second)(req)
      }
      return executeIntents([
        { type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 404, detail: 'unknown auth route' },
      ])
    },
    async GET(req) {
      const url = new URL(req.url)
      const segments = url.pathname.split('/').filter(Boolean)
      const last = segments[segments.length - 1] ?? ''
      if (enabled.session && last === 'session') return nextSession(auth)(req)
      return executeIntents([
        { type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 404, detail: 'unknown auth route' },
      ])
    },
  }
}

function handleError(err: unknown): Response {
  const { status, body } = errorToHttp(err)
  return Response.json(body, { status })
}

export namespace NextAdapter {
  export type IHandler = (req: Request) => Promise<Response>
}
