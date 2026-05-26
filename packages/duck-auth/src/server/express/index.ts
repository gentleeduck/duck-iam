/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { AuthRoot } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import type { Provider } from '../../core/types/provider'

/**
 * Express request shape - minimal duck-typed subset to avoid pulling the
 * Express type-graph into duck-auth. Apps providing their own type narrowing
 * to `Express.Request` / `Express.Response` get full inference at the call site.
 */
export interface ExpressLikeRequest {
  method: string
  url: string
  headers: Record<string, string | string[] | undefined>
  body?: unknown
}

export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse
  setHeader(name: string, value: string | number | string[]): ExpressLikeResponse
  append(name: string, value: string): ExpressLikeResponse
  json(body: unknown): ExpressLikeResponse
  redirect(status: number, location: string): void
  end(body?: string): void
}

export type Handler = (req: ExpressLikeRequest, res: ExpressLikeResponse) => Promise<void>

/** Convert Express's flat `req.headers` object into a `Headers` instance. */
export function toHeaders(headers: ExpressLikeRequest['headers']): Headers {
  const h = new Headers()
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const item of v) h.append(k, item)
    } else {
      h.set(k, v)
    }
  }
  return h
}

/**
 * Execute an Intent[] against an ExpressLikeResponse. Mirrors the Web-Fetch
 * executor in `server/generic` but writes directly into Express's mutable
 * response object, since Express handlers don't return a `Response`.
 */
export function applyIntents(intents: Provider.Intent[], res: ExpressLikeResponse, baseStatus = 200): void {
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

function serializeCookie(
  name: string,
  value: string,
  opts: {
    httpOnly?: boolean
    secure?: boolean
    sameSite?: 'strict' | 'lax' | 'none'
    path?: string
    domain?: string
    maxAge?: number
    expires?: Date
  },
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`]
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`)
  if (opts.expires) parts.push(`Expires=${opts.expires.toUTCString()}`)
  if (opts.path) parts.push(`Path=${opts.path}`)
  if (opts.domain) parts.push(`Domain=${opts.domain}`)
  if (opts.httpOnly) parts.push('HttpOnly')
  if (opts.secure) parts.push('Secure')
  if (opts.sameSite) {
    const cap = opts.sameSite.charAt(0).toUpperCase() + opts.sameSite.slice(1)
    parts.push(`SameSite=${cap}`)
  }
  return parts.join('; ')
}

/** POST /auth/signin - `{ providerId, input }` body. */
export function mountSignIn(auth: AuthRoot): Handler {
  return async (req, res) => {
    try {
      const body = (req.body ?? {}) as { providerId?: string; input?: unknown }
      if (!body.providerId) {
        applyIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }], res)
        return
      }
      const result = await auth.flows.signIn({ providerId: body.providerId, input: body.input ?? {} })
      applyIntents(result.intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** POST /auth/signout - reads the SID from the transport. */
export function mountSignOut(auth: AuthRoot): Handler {
  return async (req, res) => {
    try {
      const sid = auth.transport.extract({ headers: toHeaders(req.headers) })
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

/** POST /auth/providers/:id/begin - driver for two-step flows (magic-link, oauth begin, etc.). */
export function mountProviderBegin(auth: AuthRoot): Handler {
  return async (req, res) => {
    try {
      const id = providerIdFromUrl(req.url, 'begin')
      if (!id) {
        applyIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }], res)
        return
      }
      const intents = await auth.flows.beginProvider(id, req.body ?? {})
      applyIntents(intents, res, 200)
    } catch (err) {
      handleError(err, res)
    }
  }
}

/** GET /auth/session - returns the resolved session as JSON. */
export function mountSession(auth: AuthRoot): Handler {
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

function handleError(err: unknown, res: ExpressLikeResponse): void {
  if (err instanceof AuthErrorObject) {
    res.status(err.status).json(err.toJSON())
    return
  }
  // Unexpected: fail-closed so an unexpected throw never leaks internal state.
  res.status(500).json({ code: 'AUTH/MISCONFIGURED', detail: 'internal error' })
}

function providerIdFromUrl(url: string, suffix: string): string | null {
  // /auth/providers/<id>/<suffix> - trivial parser, no regex backtracking.
  const path = url.split('?')[0] ?? ''
  const parts = path.split('/').filter(Boolean)
  // Expect ['auth', 'providers', '<id>', '<suffix>']
  if (parts.length < 4) return null
  if (parts[parts.length - 1] !== suffix) return null
  return parts[parts.length - 2] ?? null
}
