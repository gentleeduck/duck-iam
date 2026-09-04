import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import type { Provider } from '~/core/provider/provider.types'
import {
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  isSafeRedirectUrl,
  isValidProviderId,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
  type RequestSecurityOptions,
  requestSecurity,
  serializeCookie,
} from '../generic'

import type { ExpressAdapter } from './express.types'
/** Convert Express's flat `req.headers` object into a `Headers` instance. */
export const toHeaders: (headers: ExpressAdapter.Request['headers']) => Headers = nodeHeadersToFetch

/**
 * Execute an Intent[] against an ExpressAdapter.Response. Mirrors the
 * Web-Fetch executor in `server/generic` but writes directly into
 * Express's mutable response object.
 */
export function applyIntents(intents: Provider.Intent[], res: ExpressAdapter.Response, baseStatus = 200): void {
  let status = baseStatus
  let body: unknown = null
  let hasBody = false

  for (const intent of intents) {
    switch (intent.type) {
      case 'setCookie':
      case 'clearCookie': {
        res.append(
          'Set-Cookie',
          serializeCookie(intent.name, intent.type === 'clearCookie' ? '' : intent.value, intent.options ?? {}),
        )
        break
      }
      case 'redirect': {
        // see isSafeRedirectUrl in server/generic for rationale.
        if (!isSafeRedirectUrl(intent.url)) {
          res.status(500).json({ code: 'AUTH_MISCONFIGURED', detail: 'unsafe redirect URL rejected' })
          return
        }
        res.redirect(intent.status ?? 302, intent.url)
        return
      }
      case 'json': {
        status = intent.status
        body = intent.body
        hasBody = true
        break
      }
      case 'error': {
        status = intent.status
        body = { code: intent.code, detail: intent.detail }
        hasBody = true
        break
      }
    }
  }
  res.status(status)
  if (hasBody) res.json(body)
  else res.end()
}

/** POST /AUTH/signin - `{ providerId, input }` body. CSRF-guarded
 * (Layer-1 Sec-Fetch-Site for the no-session case; Layer-2 double-submit
 * for the post-rotation case if the route is re-entered with a stale
 * SID). */
export function mountSignIn(auth: AuthEngine): ExpressAdapter.Handler {
  return async (req, res) => {
    try {
      const headers = toHeaders(req.headers)
      await csrfGuard(auth, { method: req.method ?? 'POST', headers })
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        applyIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }], res)
        return
      }
      const result = await auth.flows.signIn({
        ...parsed,
        ...expressCaller(req),
      })
      applyIntents(result.intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** POST /AUTH/signout - reads the SID from the transport. CSRF-guarded. */
export function mountSignOut(auth: AuthEngine): ExpressAdapter.Handler {
  return async (req, res) => {
    try {
      const headers = toHeaders(req.headers)
      await csrfGuard(auth, { method: req.method ?? 'POST', headers })
      const sid = auth.transport.extract({ headers })
      if (!sid) {
        applyIntents(auth.transport.revoke(), res, 200)
        return
      }
      const { intents } = await auth.flows.signOut(sid)
      applyIntents(intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** POST /AUTH/providers/:id/begin - driver for two-step flows. CSRF-guarded. */
export function mountProviderBegin(auth: AuthEngine): ExpressAdapter.Handler {
  return async (req, res) => {
    try {
      const headers = toHeaders(req.headers)
      await csrfGuard(auth, { method: req.method ?? 'POST', headers })
      const id = providerIdFromUrl(req.url, 'begin')
      if (!isValidProviderId(id)) {
        applyIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }], res)
        return
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        applyIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }], res)
        return
      }
      const intents = await auth.flows.beginProvider(id, body)
      applyIntents(intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** GET /AUTH/session - returns the resolved session as JSON. */
export function mountSession(auth: AuthEngine): ExpressAdapter.Handler {
  return async (req, res) => {
    try {
      const resolved = await auth.resolveSession({ headers: toHeaders(req.headers) })
      if (!resolved) {
        res.status(200).json({ session: null, identity: null })
        return
      }
      res.status(200).json({ session: resolved.session, identity: resolved.identity })
    } catch (err) {
      handleError(err, res)
    }
  }
}

function handleError(err: unknown, res: ExpressAdapter.Response): void {
  const { status, body } = errorToHttp(err)
  res.status(status).json(body)
}

function providerIdFromUrl(url: string, suffix: string): string | null {
  const path = url.split('?')[0] ?? ''
  const parts = path.split('/').filter(Boolean)
  if (parts.length < 4) return null
  if (parts[parts.length - 1] !== suffix) return null
  return parts[parts.length - 2] ?? null
}

/**
 * Bind the request's actor scope for everything downstream. Without it a write
 * a request drives records `created_by` / `updated_by` / `deleted_by` as `null`,
 * because nothing else in the package opens the scope the stores read.
 *
 * Install it above your own routes, alongside the CSRF guard. Anonymous
 * requests and unresolvable sessions run unbound, which is the honest `null`;
 * while impersonating, the operator behind `actingAs` is the actor, not the
 * account being acted on.
 */
/** The fingerprint Express resolved, the same pair {@link expressSignIn} stamps at sign-in. */
export function expressCaller(req: ExpressAdapter.Request): CallerFingerprint {
  return callerContext({ ip: req.ip, userAgent: req.headers['user-agent'] })
}

/**
 * Options for the actor-context wrapper.
 *
 * `getCaller` is the opt-in: omit it and the wrapper is what it has always been, an attribution
 * scope that refuses nothing. Supply it - {@link expressCaller} reads the same values the sign-in
 * route already stamps onto the session - and every request's fingerprint is compared with the
 * session's, running the anomaly detectors and the hijack policy. Switching that on in a live
 * deployment starts acting on IP and User-Agent drift for sessions already issued.
 */
export type ExpressActorOptions = {
  /** Read the request fingerprint. Never from a forwarded header: see `callerContext`. */
  getCaller?: (req: ExpressAdapter.Request) => CallerFingerprint
  /** Handle drift yourself, including the `'rotate'` reaction the wrapper cannot perform. */
  onHijack?: RequestSecurityOptions['onHijack']
}

export function expressActorContext(auth: AuthEngine, opts: ExpressActorOptions = {}): ExpressAdapter.Middleware {
  return async (req, _res, next) => {
    // `next()` is synchronous, so the downstream chain starts inside the scope
    // and every async continuation of it inherits the binding.
    await withRequestActor(
      auth,
      { headers: toHeaders(req.headers) },
      async () => {
        next()
      },
      requestSecurity(auth, { ...(opts.onHijack && { onHijack: opts.onHijack }), caller: opts.getCaller?.(req) ?? {} }),
    )
  }
}

/**
 * CSRF guard for your own routes: `app.use(expressCsrf(auth))`. Writes the 403
 * itself rather than passing the error to `next`, so protection doesn't depend
 * on the app having an AuthError-aware error handler.
 */
export function expressCsrf(auth: AuthEngine, opts: Csrf.GuardOptions = {}): ExpressAdapter.Middleware {
  return async (req, res, next) => {
    try {
      await csrfGuard(auth, { headers: toHeaders(req.headers), method: req.method ?? 'POST' }, opts)
    } catch (err) {
      handleError(err, res)
      return
    }
    next()
  }
}

export type { ExpressAdapter } from './express.types'
