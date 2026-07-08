import { AuthError } from '~/core/errors'
import type { Provider } from '~/core/types/provider'

/** Web-Fetch executor: turn `Provider.Intent[]` into a `Response`. */
export function executeIntents(intents: Provider.Intent[], baseStatus = 200): Response {
  let status = baseStatus
  let body: string | null = null
  const headers = new Headers()
  let bodyContentType: string | undefined

  for (const intent of intents) {
    switch (intent.type) {
      case 'setCookie':
      case 'clearCookie': {
        headers.append(
          'set-cookie',
          serializeCookie(intent.name, intent.type === 'clearCookie' ? '' : intent.value, intent.options ?? {}),
        )
        break
      }
      case 'redirect': {
        if (!isSafeRedirectUrl(intent.url)) {
          status = 500
          body = JSON.stringify({ code: 'AUTH_MISCONFIGURED', detail: 'unsafe redirect URL rejected' })
          bodyContentType = 'application/json; charset=utf-8'
          break
        }
        status = intent.status ?? 302
        headers.set('location', intent.url)
        break
      }
      case 'json': {
        status = intent.status
        body = JSON.stringify(intent.body)
        bodyContentType = 'application/json; charset=utf-8'
        break
      }
      case 'error': {
        status = intent.status
        const errBody: Record<string, unknown> = { code: intent.code, status: intent.status }
        if (intent.detail !== undefined) errBody.detail = intent.detail
        body = JSON.stringify({ ok: false, error: errBody })
        bodyContentType = 'application/json; charset=utf-8'
        break
      }
    }
  }

  if (bodyContentType) headers.set('content-type', bodyContentType)
  return new Response(body, { status, headers })
}

/** Validate the HTTP sign-in body shape. */
export function parseSignInBody(raw: unknown): { providerId: string; input: unknown } | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
  if (!('providerId' in raw)) return null
  if (!isValidProviderId(raw.providerId)) return null
  const input = 'input' in raw ? raw.input : {}
  return { providerId: raw.providerId, input: input ?? {} }
}

/** Validate the HTTP provider-begin body; `null`/`undefined` normalize to `{}`. */
export function parseProviderBeginBody(raw: unknown): object | null {
  if (raw === undefined || raw === null) return {}
  if (typeof raw !== 'object' || Array.isArray(raw)) return null
  return raw
}

const PROVIDER_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/
export function isValidProviderId(value: unknown): value is string {
  return typeof value === 'string' && PROVIDER_ID_RE.test(value)
}

/** Extract a non-empty bounded string field from a JSON body. */
export function parseBodyStringField(raw: unknown, field: string, maxLength = 256): string | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
  if (!(field in raw)) return null
  const value: unknown = Reflect.get(raw, field)
  if (typeof value !== 'string' || value.length === 0) return null
  if (value.length > maxLength) return null
  return value
}

/** Validate a redirect URL: http(s) absolute or same-origin path; rejects CTL, protocol-relative, oversize. */
export function isSafeRedirectUrl(url: unknown): boolean {
  if (typeof url !== 'string') return false
  if (url.length === 0 || url.length > 2048) return false
  if (hasControlChar(url)) return false
  if (url.startsWith('/')) {
    if (url.startsWith('//')) return false
    if (url.startsWith('/\\')) return false
    return true
  }
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }
  return parsed.protocol === 'https:' || parsed.protocol === 'http:'
}
function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c <= 0x1f || c === 0x7f) return true
  }
  return false
}

/** Extract `Set-Cookie` headers preserving multiplicity; `[]` on runtimes without `getSetCookie`. */
export function extractSetCookies(response: Response): string[] {
  const headers: Headers = response.headers
  const candidate: unknown = Reflect.get(headers, 'getSetCookie')
  if (typeof candidate !== 'function') return []
  const result: unknown = Reflect.apply(candidate, headers, [])
  if (!Array.isArray(result)) return []
  const out: string[] = []
  for (const v of result) {
    if (typeof v === 'string') out.push(v)
  }
  return out
}

/** Convert a Node header bag to a Web Fetch `Headers`; arrays expand to one `append` per item. */
export function nodeHeadersToFetch(raw: Record<string, string | string[] | undefined>): Headers {
  const h = new Headers()
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const item of v) h.append(k, String(item))
    } else {
      h.set(k, String(v))
    }
  }
  return h
}

/** Convert any thrown error into a wire-safe `{ status, body }`. */
export function errorToHttp(err: unknown): { status: number; body: object } {
  if (err instanceof AuthError) {
    return { status: err.status, body: err.toJSON() }
  }
  return {
    status: 500,
    body: { ok: false, error: { code: 'AUTH_MISCONFIGURED', status: 500, detail: 'internal error' } },
  }
}

/** RFC 6265 cookie serializer (zero deps; subset sufficient for auth use). */
export function serializeCookie(
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
  if (hasControlChar(name) || /[;=]/.test(name)) throw new Error('serializeCookie: invalid cookie name')
  if (opts.path !== undefined && (hasControlChar(opts.path) || opts.path.includes(';')))
    throw new Error('serializeCookie: invalid cookie Path')
  if (opts.domain !== undefined && (hasControlChar(opts.domain) || opts.domain.includes(';')))
    throw new Error('serializeCookie: invalid cookie Domain')
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
