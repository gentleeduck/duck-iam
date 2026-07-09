import { describe, expect, it } from 'vitest'
import { CookieTransport } from '../cookie.transport'

function withCookie(value: string): { headers: Headers } {
  return { headers: new Headers({ cookie: value }) }
}

describe('AuthCookieTransport - construction invariants', () => {
  it('defaults cookie name to `__Host-duck-sid` when no domain is set', () => {
    const t = new CookieTransport({})
    expect(t.cookieName).toBe('__Host-duck-sid')
  })

  it('defaults to `duck-sid` when a domain is supplied', () => {
    const t = new CookieTransport({ domain: 'app.example.com' })
    expect(t.cookieName).toBe('duck-sid')
  })

  it('rejects __Host- prefix with a Domain attribute', () => {
    expect(() => new CookieTransport({ name: '__Host-mine', domain: 'x.com' })).toThrow(/__Host-/)
  })

  it('rejects __Host- prefix with non-root Path', () => {
    expect(() => new CookieTransport({ name: '__Host-mine', path: '/api' })).toThrow(/Path=\//)
  })

  it('rejects __Host- prefix with secure:false', () => {
    expect(() => new CookieTransport({ name: '__Host-mine', secure: false })).toThrow(/Secure=true/)
  })
})

describe('AuthCookieTransport.extract - happy path', () => {
  const t = new CookieTransport({ secure: false, name: 'duck-sid' })

  it('returns the cookie value when present', () => {
    expect(t.extract(withCookie('duck-sid=abc123'))).toBe('abc123')
  })

  it('returns null when no cookie header present', () => {
    expect(t.extract({ headers: new Headers() })).toBeNull()
  })

  it('returns null when cookie not found in header', () => {
    expect(t.extract(withCookie('other=value; another=thing'))).toBeNull()
  })

  it('ignores surrounding whitespace in cookie pairs', () => {
    expect(t.extract(withCookie('  other=x ;  duck-sid=abc  '))).toBe('abc')
  })

  it('URL-decodes the cookie value', () => {
    // RFC 6265 doesn't mandate URL encoding, but many issuers do; the
    // parser round-trips encoded values.
    expect(t.extract(withCookie('duck-sid=abc%20def'))).toBe('abc def')
  })
})

describe('AuthCookieTransport.extract - SEC: hardened parser', () => {
  const t = new CookieTransport({ secure: false, name: 'duck-sid' })

  it('returns null on malformed percent-encoding (would otherwise throw URIError -> DoS crash)', () => {
    // `decodeURIComponent('%g0')` throws URIError. Previously this
    // crashed the auth pipeline; now it falls through as a missing
    // cookie, fail-closed.
    expect(t.extract(withCookie('duck-sid=%g0'))).toBeNull()
    expect(t.extract(withCookie('duck-sid=%'))).toBeNull()
    expect(t.extract(withCookie('duck-sid=%E0%A4%A'))).toBeNull()
  })

  it('returns null when the cookie name appears twice (path/domain shadowing defense)', () => {
    // Browsers send multiple cookies of the same name when the writer's
    // path/domain scope overlapped. First-match-wins let an attacker who
    // could plant a cookie at a broader scope shadow the legitimate
    // session. Now refuses to choose.
    expect(t.extract(withCookie('duck-sid=attacker; duck-sid=legit'))).toBeNull()
    expect(t.extract(withCookie('duck-sid=legit; other=x; duck-sid=attacker'))).toBeNull()
  })

  it('returns null on malformed percent-encoding in a value even when other cookies are valid', () => {
    // Mixed: a valid `other` cookie + a malformed `duck-sid`. We're
    // looking up `duck-sid`; that's the one with the bad encoding.
    expect(t.extract(withCookie('other=ok; duck-sid=%zz'))).toBeNull()
  })

  it('skips pairs with no `=` separator instead of crashing', () => {
    expect(t.extract(withCookie('bare-flag; duck-sid=abc; another'))).toBe('abc')
  })

  it('a single occurrence is still accepted (regression guard for the duplicate check)', () => {
    expect(t.extract(withCookie('duck-sid=only-one'))).toBe('only-one')
  })

  it('rejects an oversize cookie value (decode-then-authSha256 DoS defense)', () => {
    // Real opaque SIDs are 64 chars; JWTs run a few hundred. 1024 cap
    // is generous. Without it, an attacker who fits a large cookie
    // under the HTTP-server header limit (typically 8-16k) can force
    // a multi-KB decodeURIComponent + downstream sha256 per request.
    const huge = 'x'.repeat(1025)
    expect(t.extract(withCookie(`duck-sid=${huge}`))).toBeNull()
  })

  it('accepts a value at the exact cap (1024 chars)', () => {
    const atCap = 'x'.repeat(1024)
    expect(t.extract(withCookie(`duck-sid=${atCap}`))).toBe(atCap)
  })

  describe('cookie name validation at construction', () => {
    it('rejects a cookie name with whitespace (RFC 6265 token)', () => {
      expect(() => new CookieTransport({ secure: false, name: 'duck sid' })).toThrow(/RFC 6265/)
    })
    it('rejects a cookie name with semicolon', () => {
      expect(() => new CookieTransport({ secure: false, name: 'duck;sid' })).toThrow(/RFC 6265/)
    })
    it('rejects a cookie name with equals sign', () => {
      expect(() => new CookieTransport({ secure: false, name: 'duck=sid' })).toThrow(/RFC 6265/)
    })
    it('rejects an empty cookie name', () => {
      expect(() => new CookieTransport({ secure: false, name: '' })).toThrow(/non-empty string/)
    })
    it('accepts the default duck-sid name', () => {
      expect(() => new CookieTransport({ secure: false, name: 'duck-sid' })).not.toThrow()
    })
    it('accepts the __Host-duck-sid name', () => {
      expect(() => new CookieTransport({ secure: true, name: '__Host-duck-sid' })).not.toThrow()
    })
  })
})
