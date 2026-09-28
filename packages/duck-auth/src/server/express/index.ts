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
  oauthCallback,
  parseProviderBeginBody,
  parseSignInBody,
  redirectForScript,
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
          const error = { code: 'AUTH_MISCONFIGURED', detail: 'unsafe redirect URL rejected', status: 500 }
          res.status(500).json({ error, ok: false })
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
        const { code, detail } = intent
        body = { error: { code, status, ...(detail !== undefined && { detail }) }, ok: false }
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
        previousSid: auth.transport.extract({ headers }) ?? undefined,
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
      const id = req.params?.id
      if (!isValidProviderId(id)) {
        applyIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }], res)
        return
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        applyIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }], res)
        return
      }
      applyIntents(redirectForScript(await auth.flows.beginProvider(id, body), headers), res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** GET and POST /auth/providers/:id/callback, where the IdP returns the browser. A form post needs
 *  `express.urlencoded()` ahead of it. See {@link oauthCallback}. */
export function mountProviderCallback(auth: AuthEngine): ExpressAdapter.Handler {
  return async (req, res) => {
    try {
      const request = { body: req.body, cookie: req.headers.cookie, method: req.method, url: req.url }
      applyIntents(await oauthCallback(auth, req.params?.id, request, expressCaller(req)), res, 200)
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

/** The fingerprint Express resolved, the same pair {@link mountSignIn} stamps at sign-in. */
export function expressCaller(req: ExpressAdapter.Request): CallerFingerprint {
  return callerContext({ ip: req.ip, userAgent: req.headers['user-agent'] })
}

/** {@link ActorOptions} over Express's request. */
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
      // SECURITY: Express 4 holds the socket on a rejected async middleware, so every raise is passed on.
      // Only one from before `next()` lands here: a downstream throw is caught by its own layer.
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
