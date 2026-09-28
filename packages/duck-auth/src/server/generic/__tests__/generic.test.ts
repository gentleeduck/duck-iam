import { describe, expect, it, vi } from 'vitest'
import { AuthError } from '~/core/errors'
import type { Provider } from '~/core/provider/provider.types'
import { postRequest, streamedMiB } from '~/test/adapter-fakes'
import {
  errorToHttp,
  executeIntents,
  isSafeRedirectUrl,
  isValidProviderId,
  parseBodyStringField,
  parseProviderBeginBody,
  parseSignInBody,
  readBodyJson,
  readBodyText,
  serializeCookie,
} from '../index'

describe('isValidProviderId', () => {
  it('accepts the ids providers register under, namespaced oauth ids included', () => {
    expect(isValidProviderId('password')).toBe(true)
    expect(isValidProviderId('magic-link')).toBe(true)
    expect(isValidProviderId('oauth:google')).toBe(true)
    expect(isValidProviderId('Google-OAuth2')).toBe(true)
  })
  it('rejects empty and over-length', () => {
    expect(isValidProviderId('')).toBe(false)
    expect(isValidProviderId('a'.repeat(128))).toBe(true)
    expect(isValidProviderId('a'.repeat(129))).toBe(false)
  })
  it('rejects path traversal / separator chars', () => {
    expect(isValidProviderId('..')).toBe(false)
    expect(isValidProviderId('a/b')).toBe(false)
    expect(isValidProviderId('a b')).toBe(false)
    expect(isValidProviderId('oauth%3Agoogle')).toBe(false)
  })
  it('rejects control / unicode / null-byte / CRLF injection', () => {
    expect(isValidProviderId('a\u0000b')).toBe(false)
    expect(isValidProviderId('a\nb')).toBe(false)
    expect(isValidProviderId('a\rb')).toBe(false)
    expect(isValidProviderId('a‮b')).toBe(false)
    expect(isValidProviderId('café')).toBe(false)
  })
  it('rejects non-strings', () => {
    expect(isValidProviderId(undefined)).toBe(false)
    expect(isValidProviderId(null)).toBe(false)
    expect(isValidProviderId(123)).toBe(false)
    expect(isValidProviderId({})).toBe(false)
  })
})

describe('parseSignInBody', () => {
  it('accepts a well-formed body', () => {
    expect(parseSignInBody({ providerId: 'password', input: { email: 'a@x.com' } })).toEqual({
      providerId: 'password',
      input: { email: 'a@x.com' },
    })
  })

  it('defaults missing input to {}', () => {
    expect(parseSignInBody({ providerId: 'magic-link' })).toEqual({ providerId: 'magic-link', input: {} })
  })

  it('normalizes null input to {}', () => {
    expect(parseSignInBody({ providerId: 'password', input: null })).toEqual({ providerId: 'password', input: {} })
  })

  it('rejects a top-level non-object body', () => {
    expect(parseSignInBody('string')).toBeNull()
    expect(parseSignInBody(42)).toBeNull()
    expect(parseSignInBody(null)).toBeNull()
    expect(parseSignInBody(undefined)).toBeNull()
    expect(parseSignInBody(true)).toBeNull()
  })

  it('rejects an array body (typeof === object but Array.isArray catches it)', () => {
    expect(parseSignInBody(['password', { email: 'a@x.com' }])).toBeNull()
  })

  it('rejects a missing providerId', () => {
    expect(parseSignInBody({})).toBeNull()
    expect(parseSignInBody({ input: { x: 1 } })).toBeNull()
  })

  it('rejects a non-string providerId', () => {
    expect(parseSignInBody({ providerId: 42, input: {} })).toBeNull()
    expect(parseSignInBody({ providerId: null, input: {} })).toBeNull()
    expect(parseSignInBody({ providerId: {}, input: {} })).toBeNull()
  })

  it('rejects an empty-string providerId', () => {
    expect(parseSignInBody({ providerId: '', input: {} })).toBeNull()
  })

  it('rejects an oversized providerId (reflection-DoS defense via AUTH_PROVIDER_FAILED echo)', () => {
    expect(parseSignInBody({ providerId: 'a'.repeat(129), input: {} })).toBeNull()
    expect(parseSignInBody({ providerId: 'a'.repeat(128), input: {} })).toEqual({
      providerId: 'a'.repeat(128),
      input: {},
    })
  })

  it('rejects a providerId with CTL chars / path separators', () => {
    expect(parseSignInBody({ providerId: '..', input: {} })).toBeNull()
    expect(parseSignInBody({ providerId: 'a/b', input: {} })).toBeNull()
    expect(parseSignInBody({ providerId: 'a\nb', input: {} })).toBeNull()
  })
})

describe('parseProviderBeginBody', () => {
  it('accepts a plain object', () => {
    expect(parseProviderBeginBody({ returnTo: '/dash' })).toEqual({ returnTo: '/dash' })
  })

  it('normalizes undefined to {} (legacy `?? {}` parity)', () => {
    expect(parseProviderBeginBody(undefined)).toEqual({})
  })

  it('normalizes null to {} (legacy `?? {}` parity)', () => {
    expect(parseProviderBeginBody(null)).toEqual({})
  })

  it('rejects a top-level string (would have flowed through to provider.begin as input.foo access target)', () => {
    expect(parseProviderBeginBody('attacker-controlled')).toBeNull()
  })

  it('rejects a number / boolean (defends against primitives being passed to provider.begin)', () => {
    expect(parseProviderBeginBody(42)).toBeNull()
    expect(parseProviderBeginBody(true)).toBeNull()
  })

  it('rejects an array (typeof === object catches arrays too)', () => {
    expect(parseProviderBeginBody(['a', 'b'])).toBeNull()
  })
})

describe('parseBodyStringField', () => {
  it('returns the value when present and well-formed', () => {
    expect(parseBodyStringField({ code: '123456' }, 'code')).toBe('123456')
    expect(parseBodyStringField({ label: 'MyApp' }, 'label')).toBe('MyApp')
  })

  it('honors the configured max length cap (default 256)', () => {
    const atCap = 'x'.repeat(256)
    const overCap = 'x'.repeat(257)
    expect(parseBodyStringField({ v: atCap }, 'v')).toBe(atCap)
    expect(parseBodyStringField({ v: overCap }, 'v')).toBeNull()
  })

  it('honors a custom max length', () => {
    expect(parseBodyStringField({ v: 'x'.repeat(65) }, 'v', 64)).toBeNull()
    expect(parseBodyStringField({ v: 'x'.repeat(64) }, 'v', 64)).toBe('x'.repeat(64))
  })

  it('rejects a top-level non-object body', () => {
    expect(parseBodyStringField('plain-string', 'code')).toBeNull()
    expect(parseBodyStringField(42, 'code')).toBeNull()
    expect(parseBodyStringField(null, 'code')).toBeNull()
    expect(parseBodyStringField(undefined, 'code')).toBeNull()
    expect(parseBodyStringField(true, 'code')).toBeNull()
  })

  it('rejects an array body', () => {
    expect(parseBodyStringField(['code', '123456'], 'code')).toBeNull()
  })

  it('rejects a missing field', () => {
    expect(parseBodyStringField({}, 'code')).toBeNull()
    expect(parseBodyStringField({ otherKey: 'x' }, 'code')).toBeNull()
  })

  it('rejects a non-string field value (e.g. number, object - guards against type confusion)', () => {
    expect(parseBodyStringField({ code: 42 }, 'code')).toBeNull()
    expect(parseBodyStringField({ code: { nested: 'x' } }, 'code')).toBeNull()
    expect(parseBodyStringField({ code: null }, 'code')).toBeNull()
    expect(parseBodyStringField({ code: true }, 'code')).toBeNull()
  })

  it('rejects empty string (downstream sha256 over empty would still be wasted work)', () => {
    expect(parseBodyStringField({ code: '' }, 'code')).toBeNull()
  })

  it('own-property check uses `in` (catches inherited props too - but that is the safer default for adversarial JSON)', () => {
    // `JSON.parse` produces a plain object - no prototype pollution risk
    // via Object.prototype unless the parser was a custom reviver. The
    // `in` check accepts inherited too; the typeof-string guard catches
    // any function/proto-chain prop that isn't a string.
    expect(parseBodyStringField(Object.create({ inherited: 'x' }), 'inherited')).toBe('x')
  })
})

describe('isSafeRedirectUrl', () => {
  it('accepts a full https URL', () => {
    expect(isSafeRedirectUrl('https://accounts.google.com/o/oauth2/v2/auth?client_id=x')).toBe(true)
  })

  it('accepts a full http URL (self-hosted setups)', () => {
    expect(isSafeRedirectUrl('http://localhost:3000/callback')).toBe(true)
  })

  it('accepts a same-origin path', () => {
    expect(isSafeRedirectUrl('/dashboard')).toBe(true)
    expect(isSafeRedirectUrl('/auth/callback?code=abc')).toBe(true)
    expect(isSafeRedirectUrl('/')).toBe(true)
  })

  it('rejects `javascript:` (XSS via Location header on some browsers)', () => {
    expect(isSafeRedirectUrl('javascript:alert(1)')).toBe(false)
    expect(isSafeRedirectUrl('JavaScript:alert(1)')).toBe(false)
  })

  it('rejects `data:` and other unsafe schemes', () => {
    expect(isSafeRedirectUrl('data:text/html,<script>alert(1)</script>')).toBe(false)
    expect(isSafeRedirectUrl('vbscript:msgbox(1)')).toBe(false)
    expect(isSafeRedirectUrl('file:///etc/passwd')).toBe(false)
  })

  it('rejects protocol-relative `//evil.com` (browsers resolve cross-origin under current scheme)', () => {
    expect(isSafeRedirectUrl('//evil.example.com/phishing')).toBe(false)
  })

  it('rejects path that begins `/\\` (some browsers treat as protocol-relative)', () => {
    expect(isSafeRedirectUrl('/\\evil.example.com/phishing')).toBe(false)
  })

  it('rejects URLs containing CR/LF (HTTP response splitting)', () => {
    expect(isSafeRedirectUrl('https://x.com/\r\nSet-Cookie: foo=bar')).toBe(false)
    expect(isSafeRedirectUrl('/path\rcrlf')).toBe(false)
    expect(isSafeRedirectUrl('/path\nlf')).toBe(false)
  })

  it('rejects URLs containing any C0 control or DEL (tab, NUL, ESC, ...)', () => {
    expect(isSafeRedirectUrl('https://x.com/\tHost: evil')).toBe(false)
    expect(isSafeRedirectUrl('/path\x00trunc')).toBe(false)
    expect(isSafeRedirectUrl('/path\x1bbell')).toBe(false)
    expect(isSafeRedirectUrl('/path\x7fdel')).toBe(false)
  })

  it('rejects oversize URL (RFC 7230 practical-limit defense)', () => {
    const huge = `https://x.com/${'a'.repeat(2048)}`
    expect(isSafeRedirectUrl(huge)).toBe(false)
  })

  it('rejects non-string and empty', () => {
    expect(isSafeRedirectUrl(undefined)).toBe(false)
    expect(isSafeRedirectUrl(null)).toBe(false)
    expect(isSafeRedirectUrl(42)).toBe(false)
    expect(isSafeRedirectUrl('')).toBe(false)
  })

  it('rejects malformed URL strings (URL() throws)', () => {
    expect(isSafeRedirectUrl('not a url')).toBe(false)
    expect(isSafeRedirectUrl('http://')).toBe(false)
  })
})

describe('serializeCookie - header injection guards', () => {
  it('rejects a cookie name containing CRLF', () => {
    expect(() => serializeCookie('bad\r\nname', 'v', {})).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: 'serializeCookie: invalid cookie name' } }),
    )
  })
  it('rejects a cookie name containing `;` or `=`', () => {
    expect(() => serializeCookie('na;me', 'v', {})).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: 'serializeCookie: invalid cookie name' } }),
    )
    expect(() => serializeCookie('na=me', 'v', {})).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: 'serializeCookie: invalid cookie name' } }),
    )
  })
  it('rejects a Path containing CTL', () => {
    expect(() => serializeCookie('sid', 'v', { path: '/bad\r\nLocation: x' })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: 'serializeCookie: invalid cookie Path' } }),
    )
  })
  it('rejects a Path containing `;` (attribute splicing)', () => {
    expect(() => serializeCookie('sid', 'v', { path: '/; Domain=evil.com' })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: 'serializeCookie: invalid cookie Path' } }),
    )
  })
  it('rejects a Domain containing CTL', () => {
    expect(() => serializeCookie('sid', 'v', { domain: 'x.com\r\nLocation: y' })).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: 'serializeCookie: invalid cookie Domain' },
      }),
    )
  })
  it('rejects a Domain containing `;` (attribute splicing)', () => {
    expect(() => serializeCookie('sid', 'v', { domain: 'x.com; Secure' })).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: 'serializeCookie: invalid cookie Domain' },
      }),
    )
  })
})

describe('executeIntents refusing an unsafe redirect', () => {
  const unsafe: Provider.Intent = { type: 'redirect', url: 'javascript:alert(1)' }

  it('answers AUTH_MISCONFIGURED in the error envelope and sets no location', async () => {
    const res = executeIntents([unsafe])
    expect(res.status).toBe(500)
    expect(res.headers.get('location')).toBeNull()
    expect(await res.json()).toEqual({
      error: { code: 'AUTH_MISCONFIGURED', detail: 'unsafe redirect URL rejected', status: 500 },
      ok: false,
    })
  })

  it('stays refused when another intent follows, rather than being overwritten by it', async () => {
    // The refusal used to `break` the switch and let the loop run on, so the next intent reassigned
    // `status` and `body` and the caller got a 200 success for a flow that never redirected - the
    // operator's one signal that their redirect config is broken, gone. The express executor returns
    // here, so the two disagreed on the same intent list.
    const res = executeIntents([unsafe, { body: { ok: true }, status: 200, type: 'json' }])
    expect(res.status).toBe(500)
    expect(await res.json()).toMatchObject({ error: { code: 'AUTH_MISCONFIGURED' }, ok: false })
  })

  it('does not let a safe redirect later in the list carry the response', async () => {
    const res = executeIntents([unsafe, { type: 'redirect', url: 'https://example.com/after' }])
    expect(res.status).toBe(500)
    expect(res.headers.get('location')).toBeNull()
  })

  it('answers a safe redirect with its location, and a json intent with its body', async () => {
    const redirect = executeIntents([{ type: 'redirect', url: 'https://example.com/after' }])
    expect(redirect.status).toBe(302)
    expect(redirect.headers.get('location')).toBe('https://example.com/after')
    const json = executeIntents([{ body: { ok: true }, status: 201, type: 'json' }])
    expect(json.status).toBe(201)
    expect(await json.json()).toEqual({ ok: true })
  })
})

describe('readBodyText', () => {
  const post = (body: BodyInit, headers?: HeadersInit) => postRequest('http://x/', body, headers)

  it('reads a body of exactly 100 KiB, and refuses one byte more', async () => {
    const cap = 100 * 1024
    expect(await readBodyText(post('a'.repeat(cap)))).toHaveLength(cap)
    expect(await readBodyText(post('a'.repeat(cap + 1)))).toBeNull()
  })

  it('stops pulling a streamed body once it passes the cap, and cancels the rest', async () => {
    const { body, cancelled, pulled } = streamedMiB()
    expect(await readBodyText(post(body))).toBeNull()
    expect(pulled()).toBeLessThanOrEqual(7)
    expect(cancelled()).toBe(true)
  })

  it('refuses a declared length past the cap without reading', async () => {
    const { body, pulled } = streamedMiB()
    expect(await readBodyText(post(body, { 'content-length': String(1024 * 1024) }))).toBeNull()
    expect(pulled()).toBe(0)
  })

  it('decodes a character split across two chunks', async () => {
    const [a, b] = [new Uint8Array([0xc3]), new Uint8Array([0xa9])]
    const body = new ReadableStream<Uint8Array>({
      start: (c) => {
        c.enqueue(a)
        c.enqueue(b)
        c.close()
      },
    })
    expect(await readBodyText(post(body))).toBe('\u00e9')
  })

  it('parses JSON, and answers null for a body that is not', async () => {
    expect(await readBodyJson(post('{"a":1}'))).toEqual({ a: 1 })
    expect(await readBodyJson(post('{"a":'))).toBeNull()
  })
})

describe('errorToHttp', () => {
  it('logs the cause of a 5xx, which the body withholds, and nothing for a refusal', () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const crash = new Error('relation "auth_identities" does not exist')
      const misconfigured = new AuthError('AUTH_MISCONFIGURED', { detail: 'the database is missing the auth schema' })
      const unavailable = new AuthError('AUTH_ADAPTER_UNAVAILABLE')
      expect(errorToHttp(crash).status).toBe(500)
      expect(errorToHttp(misconfigured).status).toBe(500)
      expect(errorToHttp(unavailable).status).toBe(503)
      expect(errorToHttp(new AuthError('AUTH_UNAUTHENTICATED')).status).toBe(401)
      expect(logged.mock.calls).toEqual([
        ['[@gentleduck/auth] request failed:', crash],
        ['[@gentleduck/auth] request failed:', misconfigured],
        ['[@gentleduck/auth] request failed:', unavailable],
      ])
    } finally {
      logged.mockRestore()
    }
  })
})
