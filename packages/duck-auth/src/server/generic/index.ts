import { AuthErrorObject } from '../../core/errors'
import type { Provider } from '../../core/types/provider'

/**
 * Generic Web-Fetch executor. Converts a list of provider Intents into a
 * `Response` (one `Set-Cookie` header per setCookie/clearCookie intent,
 * `Location` for redirect, `Content-Type: application/json` for json).
 *
 * Framework adapters (express, hono, next, elysia) build on this; they
 * extract a `Headers`-shaped object from the incoming request, hand it to
 * AuthRoot, then call this executor on the returned Intent[] to emit a
 * native response in the framework's shape.
 */
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
          body = JSON.stringify({ code: 'AUTH/MISCONFIGURED', detail: 'unsafe redirect URL rejected' })
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
        body = JSON.stringify({ code: intent.code, detail: intent.detail })
        bodyContentType = 'application/json; charset=utf-8'
        break
      }
      case 'startSession':
      case 'requireMfa':
        // Lifecycle intents - already interpreted by FlowsFacet; if one reaches
        // this executor it's a logic error in the caller. Surface a 500 rather
        // than silently dropping.
        status = 500
        body = JSON.stringify({ code: 'AUTH/MISCONFIGURED', detail: `unhandled intent type: ${intent.type}` })
        bodyContentType = 'application/json; charset=utf-8'
        break
    }
  }

  if (bodyContentType) headers.set('content-type', bodyContentType)
  return new Response(body, { status, headers })
}

/**
 * validate the HTTP-supplied sign-in body shape. The body is
 * attacker-controlled JSON; prior `(req.body ?? {}) as { providerId?:
 * string; input?: unknown }` casts across every server adapter were
 * trusting the cast. Bad shapes (top-level string, array, number,
 * non-string `providerId`) would have surfaced as `body.providerId
 * === undefined` and reached the `!providerId` check - accidentally
 * safe but still wrong style. This validator centralizes the parse
 * with an explicit shape check.
 */
export function parseSignInBody(raw: unknown): { providerId: string; input: unknown } | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
  if (!('providerId' in raw)) return null
  const providerId = raw.providerId
  if (typeof providerId !== 'string' || providerId.length === 0) return null
  // 128-char cap; reflects into AUTH/PROVIDER_FAILED meta + events otherwise.
  if (providerId.length > 128) return null
  const input = 'input' in raw ? raw.input : {}
  return { providerId, input: input ?? {} }
}

/**
 * validate the HTTP-supplied provider-begin body. Each provider's
 * `begin(input)` is contractually an *object* (passkey opts, oauth
 * `{ returnTo }`, etc.). Adapters previously passed `req.body ?? {}`
 * untouched - a JSON-typed payload like a top-level string, array, or
 * number would have flowed straight into the provider, where various
 * `input.foo` accesses would have either thrown an unhelpful TypeError
 * or silently mis-coerced. Returning `null` signals to the adapter to
 * reply 400 INVALID_CREDENTIALS rather than entering the provider with
 * a malformed body. `undefined`/`null` are accepted and normalized to
 * `{}` (matches the legacy `?? {}` default for providers that don't
 * require any input - e.g. passkey discovery).
 */
export function parseProviderBeginBody(raw: unknown): object | null {
  if (raw === undefined || raw === null) return {}
  if (typeof raw !== 'object' || Array.isArray(raw)) return null
  return raw
}

/**
 * extract a single non-empty string field from a JSON body. Used
 * by MFA endpoints that previously did `(await c.req.json()) as {
 * label: string }` - the cast lied. A missing/non-string value would
 * have turned into `body.label === undefined`, then `auth.mfa.beginTotpEnrollment(id, undefined)`,
 * surfacing as a downstream TypeError. Returns the value as a string
 * or `null` on any malformed shape (top-level non-object, missing key,
 * non-string value, empty string).
 *
 * The `maxLength` cap matches the per-field DoS defense applied
 * throughout duck-auth (see `[[duck-auth-security-sweep-2026-05]]`):
 * cap at the entry point so downstream sha256 / database storage
 * never sees a multi-MB payload.
 */
export function parseBodyStringField(raw: unknown, field: string, maxLength = 256): string | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
  if (!(field in raw)) return null
  // Reflect.get returns `unknown` - no cast needed (vs.
  // `(raw as Record<string, unknown>)[field]`).
  const value: unknown = Reflect.get(raw, field)
  if (typeof value !== 'string' || value.length === 0) return null
  if (value.length > maxLength) return null
  return value
}

/**
 * validate a redirect URL before it leaves duck-auth on a
 * `Location` header. Defense in depth - built-in providers (OAuth,
 * SAML) construct their `url` from server-side config, but a custom
 * provider, a misconfigured client, or a future regression could emit
 * an attacker-controlled string.
 *
 * Accepted:
 *  - `https://...` (full URLs)
 *  - `http://...` (allowed; some self-hosted setups still use it)
 *  - `/path...` (same-origin paths; allowed for in-app navigation)
 *
 * Rejected:
 *  - `javascript:` / `data:` / `vbscript:` / `file:` schemes (XSS surface)
 *  - protocol-relative `//evil.example.com` (browsers resolve under
 *    current scheme; an attacker can hop to an external origin)
 *  - URLs containing CR/LF (HTTP response splitting - `Headers.set`
 *    rejects them on most runtimes, but be explicit)
 *  - non-string / empty
 *  - oversize (cap at 2048 to match RFC 7230 §3.1.1 practical limits)
 */
export function isSafeRedirectUrl(url: unknown): boolean {
  if (typeof url !== 'string') return false
  if (url.length === 0 || url.length > 2048) return false
  if (url.includes('\r') || url.includes('\n')) return false
  // Same-origin path: must be a single leading `/` and not `//` (the
  // latter is protocol-relative and resolves cross-origin).
  if (url.startsWith('/')) {
    if (url.startsWith('//')) return false
    if (url.startsWith('/\\')) return false
    return true
  }
  // Require http(s); `javascript:` parses but the allowlist rejects it.
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }
  return parsed.protocol === 'https:' || parsed.protocol === 'http:'
}

/**
 * Extract the list of `Set-Cookie` header values from a Web Fetch
 * `Response` while preserving multiplicity (one entry per cookie).
 * Web Fetch's `headers.get('set-cookie')` flattens duplicates into a
 * comma-separated string - broken for cookies whose value contains
 * commas. `getSetCookie()` (RFC 7230 - added later to the spec) is
 * the correct API; this helper centralizes the
 * runtime-feature-detected fallback so per-adapter forwarders don't
 * each carry the `(headers as Headers & { getSetCookie?: () => string[] })`
 * cast. Returns `[]` on runtimes without `getSetCookie`.
 */
export function extractSetCookies(response: Response): string[] {
  const headers: Headers = response.headers
  // Avoid an `as` cast by reading the optional method off the prototype
  // via a type predicate: defined-and-callable means we use it.
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

/**
 * Convert a Node-style header bag (`Record<string, string | string[] |
 * undefined>` - the shape emitted by express/fastify/koa/nestjs) into
 * a Web Fetch `Headers` instance. Multi-value arrays expand to one
 * `append` per item so RFC 7230 multi-value headers (e.g. multiple
 * `Set-Cookie`) survive the conversion.
 *
 * Centralizes the verbatim per-adapter implementations under
 * `server/express/index.ts:toHeaders` + `server/{fastify,koa,nestjs}/index.ts:toFetchHeaders`.
 */
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

/**
 * Convert any error thrown by the auth flow into a `{ status, body }`
 * shape suitable for any HTTP response abstraction. Centralizes the
 * `instanceof AuthErrorObject ? toJSON : 500-MISCONFIGURED` decision
 * that was duplicated across every server adapter's local
 * `handleError`. Adapters become thin wrappers that copy `status` +
 * `body` into their native response API.
 */
export function errorToHttp(err: unknown): { status: number; body: object } {
  if (err instanceof AuthErrorObject) {
    return { status: err.status, body: err.toJSON() }
  }
  return { status: 500, body: { code: 'AUTH/MISCONFIGURED', detail: 'internal error' } }
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
