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
  nodeHeadersToFetch,
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

function handleError(err: unknown, res: ExpressAdapter.Response): void {
  const { status, body } = errorToHttp(err)
  res.setHeader('cache-control', 'no-store')
  res.status(status).json(body)
}

/** The fingerprint Express resolved, for `flows.signIn` to stamp onto the session. */
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
