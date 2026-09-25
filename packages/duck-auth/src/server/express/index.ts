import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import type { Provider } from '~/core/provider/provider.types'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorToHttp,
  isSafeRedirectUrl,
  isValidProviderId,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
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
  // Auth responses vary by cookie on a URL that does not: a shared cache holding one would answer
  // the next caller with it.
  res.setHeader('cache-control', 'no-store')
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

/** POST /auth/signin, taking a `{ providerId, input }` body. CSRF-guarded by Sec-Fetch-Site for the
 *  no-session case, and by double-submit when the route is re-entered with a stale SID. */
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

/** POST /auth/signout, reading the SID from the transport. CSRF-guarded. */
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

/** POST /auth/providers/:id/begin, the driver for two-step flows. CSRF-guarded. */
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

/** GET /auth/session, answering the resolved session as JSON. */
export function mountSession(auth: AuthEngine): ExpressAdapter.Handler {
  return async (req, res) => {
    try {
      const resolved = await auth.resolveSession({ headers: toHeaders(req.headers) }).orNull()
      res.setHeader('cache-control', 'no-store')
      if (!resolved) {
        res.status(200).json({ session: null, identity: null })
        return
      }
      // `csrfHash` is server-side state: the browser holds the plaintext in its cookie and never needs the hash.
      const { csrfHash: _csrfHash, ...session } = resolved.session
      res.status(200).json({ session, identity: resolved.identity })
    } catch (err) {
      handleError(err, res)
    }
  }
}

function handleError(err: unknown, res: ExpressAdapter.Response): void {
  const { status, body } = errorToHttp(err)
  res.setHeader('cache-control', 'no-store')
  res.status(status).json(body)
}

function providerIdFromUrl(url: string, suffix: string): string | null {
  const path = url.split('?')[0] ?? ''
  const parts = path.split('/').filter(Boolean)
  if (parts.length < 4) return null
  if (parts[parts.length - 1] !== suffix) return null
  return parts[parts.length - 2] ?? null
}

/** The fingerprint Express resolved, the same pair {@link mountSignIn} stamps at sign-in. */
export function expressCaller(req: ExpressAdapter.Request): CallerFingerprint {
  return callerContext({ ip: req.ip, userAgent: req.headers['user-agent'] })
}

export type ExpressActorOptions = ActorOptions<ExpressAdapter.Request>

/** Bind the request's actor scope for everything downstream; install it above your own routes,
 *  alongside the CSRF guard. See `core/actor/README.md` for what runs unbound and what raises. */
export function expressActorContext(auth: AuthEngine, opts: ExpressActorOptions = {}): ExpressAdapter.Middleware {
  return async (req, _res, next) => {
    try {
      // `next()` is synchronous, so the downstream chain starts inside the scope
      // and every async continuation of it inherits the binding.
      await withRequestActor(
        auth,
        { headers: toHeaders(req.headers) },
        async () => {
          next()
        },
        requestSecurity(auth, { caller: opts.getCaller?.(req), onAnomaly: opts.onAnomaly, onHijack: opts.onHijack }),
      )
    } catch (err) {
      // SECURITY: Express 4 does not forward a rejected async middleware anywhere - the socket is simply
      // held until something times out. `onHijack` and the `revoke` reaction refuse by throwing, so on
      // Express 4 that refusal reached neither the error handler nor the client. Only errors raised before
      // `next()` arrive here: a downstream throw is caught by its own layer, so this cannot double-dispatch.
      next(err)
    }
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
