import type { AuthEngine } from '../../core/auth'
import { authCsrfGuard } from '../../core/csrf'
import { authErrorToHttp, authExecuteIntents, authIsValidProviderId, authParseProviderBeginBody, authParseSignInBody } from '../generic'

/** `authNextSignIn`. CSRF-guarded. */
export function authNextSignIn(auth: AuthEngine): AuthNextAdapter.IHandler {
  return async (req) => {
    try {
      await authCsrfGuard(auth, { method: req.method, headers: req.headers })
      const parsed = authParseSignInBody(await req.json().catch(() => null))
      if (!parsed) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn(parsed)
      return authExecuteIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** `authNextSignOut`. CSRF-guarded. */
export function authNextSignOut(auth: AuthEngine): AuthNextAdapter.IHandler {
  return async (req) => {
    try {
      await authCsrfGuard(auth, { method: req.method, headers: req.headers })
      const sid = auth.transport.extract({ headers: req.headers })
      if (!sid) return authExecuteIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return authExecuteIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** `authNextSession`. */
export function authNextSession(auth: AuthEngine): AuthNextAdapter.IHandler {
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
 * AuthProvider begin handler. Extract the provider id from the URL path or pass
 * via the second arg; both flows fit the App Router shape.
 */
export function authNextProviderBegin(auth: AuthEngine, providerId: string): AuthNextAdapter.IHandler {
  return async (req) => {
    try {
      if (!authIsValidProviderId(providerId)) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      await authCsrfGuard(auth, { method: req.method, headers: req.headers })
      const body = authParseProviderBeginBody(await req.json().catch(() => null))
      if (body === null) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const intents = await auth.flows.beginProvider(providerId, body)
      return authExecuteIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * Catch-all router for `app/api/auth/[...auth]/route.ts`. Returns `{ GET, POST }`
 * tied to the configured AuthEngine. Apps map the parsed path segments to
 * provider/flow handlers.
 *
 * Apps can also wire the individual authNextSignIn / authNextSignOut / etc. directly
 * - `authMountNext` is an ergonomic helper.
 */
export function authMountNext(
  auth: AuthEngine,
  opts: { signin?: boolean; signout?: boolean; session?: boolean; providerBegin?: boolean } = {},
): {
  POST: AuthNextAdapter.IHandler
  GET: AuthNextAdapter.IHandler
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
      if (enabled.signin && last === 'signin') return authNextSignIn(auth)(req)
      if (enabled.signout && last === 'signout') return authNextSignOut(auth)(req)
      if (enabled.providerBegin && last === 'begin' && second) {
        return authNextProviderBegin(auth, second)(req)
      }
      return authExecuteIntents([
        { type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 404, detail: 'unknown auth route' },
      ])
    },
    async GET(req) {
      const url = new URL(req.url)
      const segments = url.pathname.split('/').filter(Boolean)
      const last = segments[segments.length - 1] ?? ''
      if (enabled.session && last === 'session') return authNextSession(auth)(req)
      return authExecuteIntents([
        { type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 404, detail: 'unknown auth route' },
      ])
    },
  }
}

function handleError(err: unknown): Response {
  const { status, body } = authErrorToHttp(err)
  return Response.json(body, { status })
}

export namespace AuthNextAdapter {
  export type IHandler = (req: Request) => Promise<Response>
}
