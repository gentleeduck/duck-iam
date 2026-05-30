import type { AuthRoot } from '../../core/auth'
import { csrfGuard } from '../../core/csrf'
import type { Provider } from '../../core/types/provider'
import {
  errorToHttp,
  isSafeRedirectUrl,
  isValidProviderId,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
  serializeCookie,
} from '../generic'

export namespace ExpressAdapter {
  /** Minimal duck-typed Express request subset. */
  export interface IRequest {
    method: string
    url: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
  }

  /** Minimal duck-typed Express response subset. */
  export interface IResponse {
    status(code: number): IResponse
    setHeader(name: string, value: string | number | string[]): IResponse
    append(name: string, value: string): IResponse
    json(body: unknown): IResponse
    redirect(status: number, location: string): void
    end(body?: string): void
  }

  /** Express handler signature `(req, res) => Promise<void>`. */
  export type IHandler = (req: IRequest, res: IResponse) => Promise<void>
}

/** Convert Express's flat `req.headers` object into a `Headers` instance. */
export const toHeaders: (headers: ExpressAdapter.IRequest['headers']) => Headers = nodeHeadersToFetch

/**
 * Execute an Intent[] against an ExpressAdapter.IResponse. Mirrors the
 * Web-Fetch executor in `server/generic` but writes directly into
 * Express's mutable response object.
 */
export function applyIntents(intents: Provider.Intent[], res: ExpressAdapter.IResponse, baseStatus = 200): void {
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
          res.status(500).json({ code: 'AUTH/MISCONFIGURED', detail: 'unsafe redirect URL rejected' })
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
      case 'startSession':
      case 'requireMfa': {
        status = 500
        body = { code: 'AUTH/MISCONFIGURED', detail: `unhandled intent type: ${intent.type}` }
        hasBody = true
        break
      }
    }
  }
  res.status(status)
  if (hasBody) res.json(body)
  else res.end()
}

/** POST /auth/signin - `{ providerId, input }` body. CSRF-guarded
 * (Layer-1 Sec-Fetch-Site for the no-session case; Layer-2 double-submit
 * for the post-rotation case if the route is re-entered with a stale
 * SID). */
export function mountSignIn(auth: AuthRoot): ExpressAdapter.IHandler {
  return async (req, res) => {
    try {
      const headers = toHeaders(req.headers)
      await csrfGuard(auth, { method: req.method ?? 'POST', headers })
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        applyIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }], res)
        return
      }
      const result = await auth.flows.signIn(parsed)
      applyIntents(result.intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** POST /auth/signout - reads the SID from the transport. CSRF-guarded. */
export function mountSignOut(auth: AuthRoot): ExpressAdapter.IHandler {
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

/** POST /auth/providers/:id/begin - driver for two-step flows. CSRF-guarded. */
export function mountProviderBegin(auth: AuthRoot): ExpressAdapter.IHandler {
  return async (req, res) => {
    try {
      const headers = toHeaders(req.headers)
      await csrfGuard(auth, { method: req.method ?? 'POST', headers })
      const id = providerIdFromUrl(req.url, 'begin')
      if (!isValidProviderId(id)) {
        applyIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }], res)
        return
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        applyIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }], res)
        return
      }
      const intents = await auth.flows.beginProvider(id, body)
      applyIntents(intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** GET /auth/session - returns the resolved session as JSON. */
export function mountSession(auth: AuthRoot): ExpressAdapter.IHandler {
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

function handleError(err: unknown, res: ExpressAdapter.IResponse): void {
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
