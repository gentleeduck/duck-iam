/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { AuthRoot } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import { executeIntents } from '../generic'

/**
 * Next.js App Router adapter. Handlers consume the Web-Fetch `Request`
 * Next provides to route handlers + Server Actions and return a `Response`.
 *
 * Example routing under `app/api/auth/[...auth]/route.ts`:
 *
 *   export const POST = async (req: Request, { params }) => {
 *     const [path] = (await params).auth ?? []
 *     switch (path) {
 *       case 'signin':  return nextSignIn(auth)(req)
 *       case 'signout': return nextSignOut(auth)(req)
 *       case 'providers': return nextProviderBegin(auth)(req, params)
 *     }
 *   }
 *
 * Or one-shot via `mountNext(auth)` which wires the catch-all routes.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

export type NextHandler = (req: Request) => Promise<Response>

/**
 * `nextSignIn`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function nextSignIn(auth: AuthRoot): NextHandler {
  return async (req) => {
    try {
      const body = (await req.json().catch(() => ({}))) as {
        providerId?: string
        input?: unknown
      }
      if (!body.providerId) {
        return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn({
        providerId: body.providerId,
        input: body.input ?? {},
      })
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * `nextSignOut`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function nextSignOut(auth: AuthRoot): NextHandler {
  return async (req) => {
    try {
      const sid = auth.transport.extract({ headers: req.headers })
      if (!sid) return executeIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * `nextSession`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function nextSession(auth: AuthRoot): NextHandler {
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function nextProviderBegin(auth: AuthRoot, providerId: string): NextHandler {
  return async (req) => {
    try {
      const body = (await req.json().catch(() => ({}))) as unknown
      const intents = await auth.flows.beginProvider(providerId, body ?? {})
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function mountNext(
  auth: AuthRoot,
  opts: { signin?: boolean; signout?: boolean; session?: boolean; providerBegin?: boolean } = {},
): {
  POST: NextHandler
  GET: NextHandler
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
  if (err instanceof AuthErrorObject) {
    return Response.json(err.toJSON(), { status: err.status })
  }
  return Response.json({ code: 'AUTH/MISCONFIGURED', detail: 'internal error' }, { status: 500 })
}

/**
 * Namespace merge for NextAdapter. Co-locates the config + input +
 * output shapes via TS namespace declaration. Consumers can write either
 * the flat name (NextHandler) or the namespaced form
 * (NextAdapter.IHandler); both resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace NextAdapter {
  /** Alias for the flat `NextHandler` type. */
  export type IHandler = NextHandler
}
