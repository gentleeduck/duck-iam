/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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

/** RFC 6265 cookie serializer (zero deps; subset sufficient for auth use). */
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
