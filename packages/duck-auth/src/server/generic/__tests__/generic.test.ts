import { describe, expect, it } from 'vitest'
import {
  extractSetCookies,
  isSafeRedirectUrl,
  parseBodyStringField,
  parseProviderBeginBody,
  parseSignInBody,
} from '../index'

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

  it('rejects an oversized providerId (reflection-DoS defense via AUTH/PROVIDER_FAILED echo)', () => {
    expect(parseSignInBody({ providerId: 'a'.repeat(129), input: {} })).toBeNull()
    expect(parseSignInBody({ providerId: 'a'.repeat(128), input: {} })).toEqual({
      providerId: 'a'.repeat(128),
      input: {},
    })
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

describe('extractSetCookies', () => {
  it('preserves multiplicity when getSetCookie() is available', () => {
    const headers = new Headers()
    headers.append('set-cookie', 'a=1; Path=/')
    headers.append('set-cookie', 'b=2; Path=/')
    const response = new Response(null, { headers })
    expect(extractSetCookies(response)).toEqual(['a=1; Path=/', 'b=2; Path=/'])
  })

  it('returns [] when no set-cookie present', () => {
    const response = new Response(null, { headers: new Headers({ 'content-type': 'text/plain' }) })
    expect(extractSetCookies(response)).toEqual([])
  })

  it('returns [] on runtimes without getSetCookie (graceful degradation)', () => {
    // Simulate an older runtime by handing in a header-bag shape that
    // lacks getSetCookie. The helper must not throw.
    const fake: Response = {
      headers: { forEach() {} },
      // ...other Response fields not used by extractSetCookies.
    } as unknown as Response
    expect(extractSetCookies(fake)).toEqual([])
  })
})
