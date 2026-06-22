import type { AuthEngine } from '../../core/auth'
import { authCsrfGuard } from '../../core/csrf'
import type { AuthProvider } from '../../core/types/provider'
import {
  authErrorToHttp,
  authIsSafeRedirectUrl,
  authIsValidProviderId,
  authNodeHeadersToFetch,
  authParseProviderBeginBody,
  authParseSignInBody,
  authSerializeCookie,
} from '../generic'

export namespace AuthExpressAdapter {
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
export const authToHeaders: (headers: AuthExpressAdapter.IRequest['headers']) => Headers = authNodeHeadersToFetch

/**
 * Execute an Intent[] against an AuthExpressAdapter.IResponse. Mirrors the
 * Web-Fetch executor in `server/generic` but writes directly into
 * Express's mutable response object.
 */
export function authApplyIntents(intents: AuthProvider.Intent[], res: AuthExpressAdapter.IResponse, baseStatus = 200): void {
  let status = baseStatus
  let body: unknown = null
  let hasBody = false

  for (const intent of intents) {
    switch (intent.type) {
      case 'setCookie':
      case 'clearCookie': {
        res.append(
          'Set-Cookie',
          authSerializeCookie(intent.name, intent.type === 'clearCookie' ? '' : intent.value, intent.options ?? {}),
        )
        break
      }
      case 'redirect': {
        // see authIsSafeRedirectUrl in server/generic for rationale.
        if (!authIsSafeRedirectUrl(intent.url)) {
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
export function authMountSignIn(auth: AuthEngine): AuthExpressAdapter.IHandler {
  return async (req, res) => {
    try {
      const headers = authToHeaders(req.headers)
      await authCsrfGuard(auth, { method: req.method ?? 'POST', headers })
      const parsed = authParseSignInBody(req.body)
      if (!parsed) {
        authApplyIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }], res)
        return
      }
      const result = await auth.flows.signIn(parsed)
      authApplyIntents(result.intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** POST /auth/signout - reads the SID from the transport. CSRF-guarded. */
export function authMountSignOut(auth: AuthEngine): AuthExpressAdapter.IHandler {
  return async (req, res) => {
    try {
      const headers = authToHeaders(req.headers)
      await authCsrfGuard(auth, { method: req.method ?? 'POST', headers })
      const sid = auth.transport.extract({ headers })
      if (!sid) {
        authApplyIntents(auth.transport.revoke(), res, 200)
        return
      }
      const { intents } = await auth.flows.signOut(sid)
      authApplyIntents(intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** POST /auth/providers/:id/begin - driver for two-step flows. CSRF-guarded. */
export function authMountProviderBegin(auth: AuthEngine): AuthExpressAdapter.IHandler {
  return async (req, res) => {
    try {
      const headers = authToHeaders(req.headers)
      await authCsrfGuard(auth, { method: req.method ?? 'POST', headers })
      const id = providerIdFromUrl(req.url, 'begin')
      if (!authIsValidProviderId(id)) {
        authApplyIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }], res)
        return
      }
      const body = authParseProviderBeginBody(req.body)
      if (body === null) {
        authApplyIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }], res)
        return
      }
      const intents = await auth.flows.beginProvider(id, body)
      authApplyIntents(intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** GET /auth/session - returns the resolved session as JSON. */
export function authMountSession(auth: AuthEngine): AuthExpressAdapter.IHandler {
  return async (req, res) => {
    try {
      const resolved = await auth.resolveSession({ headers: authToHeaders(req.headers) })
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

function handleError(err: unknown, res: AuthExpressAdapter.IResponse): void {
  const { status, body } = authErrorToHttp(err)
  res.status(status).json(body)
}

function providerIdFromUrl(url: string, suffix: string): string | null {
  const path = url.split('?')[0] ?? ''
  const parts = path.split('/').filter(Boolean)
  if (parts.length < 4) return null
  if (parts[parts.length - 1] !== suffix) return null
  return parts[parts.length - 2] ?? null
}
