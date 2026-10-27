import { describe, expect, it, vi } from 'vitest'
import { makeSession } from '~/test/store-inputs'
import { CookieTransport } from '../cookie.transport'

function withCookie(value: string): { headers: Headers } {
  return { headers: new Headers({ cookie: value }) }
}

describe('AuthCookieTransport - construction invariants', () => {
  it('defaults cookie name to `__Host-duck-sid` when no domain is set', () => {
    vi.stubEnv('NODE_ENV', 'production')
    const t = new CookieTransport({})
    expect(t.cookieName).toBe('__Host-duck-sid')
  })

  it('defaults to `duck-sid` when a domain is supplied', () => {
    const t = new CookieTransport({ domain: 'app.example.com' })
    expect(t.cookieName).toBe('duck-sid')
  })

  it('rejects __Host- prefix with a Domain attribute', () => {
    expect(() => new CookieTransport({ name: '__Host-mine', domain: 'x.com' })).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: expect.stringContaining('__Host- prefix forbids the Domain attribute') },
      }),
    )
  })

  it('rejects __Host- prefix with non-root Path', () => {
    expect(() => new CookieTransport({ name: '__Host-mine', path: '/api' })).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: expect.stringContaining('__Host- prefix requires Path=/') },
      }),
    )
  })

  it.each([0, -60, Number.NaN, 90.5, Number.POSITIVE_INFINITY])('rejects maxAgeSec %s', (maxAgeSec) => {
    expect(() => new CookieTransport({ maxAgeSec })).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: '@gentleduck/auth CookieTransport: maxAgeSec must be a positive whole number of seconds' },
      }),
    )
  })

  it.each([1, 90])('issues maxAgeSec %s as the Max-Age of a session that outlives it', (maxAgeSec) => {
    const session = makeSession({ absoluteExpiresAt: new Date(Date.now() + 3_600_000) })
    const [cookie] = new CookieTransport({ maxAgeSec }).issue('sid', session, { absolute: false, fresh: true })
    expect(cookie).toMatchObject({ options: { maxAge: maxAgeSec }, type: 'setCookie' })
  })

  it('lives to the absolute deadline, not the idle one, so a slid session keeps its cookies', () => {
    vi.useFakeTimers()
    const session = makeSession({
      expiresAt: new Date(Date.now() + 60_000),
      absoluteExpiresAt: new Date(Date.now() + 3_600_000),
    })
    const issued = new CookieTransport().issue('sid', session, { absolute: false, fresh: true, csrfToken: 'c' })
    vi.useRealTimers()
    expect(issued.map((i) => i.type === 'setCookie' && i.options.maxAge)).toEqual([3600, 3600])
  })

  it('refuses a path or domain the browser would replace or drop', () => {
    const misconfigured = expect.objectContaining({ code: 'AUTH_MISCONFIGURED' })
    for (const path of ['', 'app', 'app/', '/a;b']) {
      expect(() => new CookieTransport({ domain: 'example.com', path })).toThrow(misconfigured)
    }
    for (const domain of ['https://example.com', 'example.com:3000', 'example.com/', ' example.com']) {
      expect(() => new CookieTransport({ domain })).toThrow(misconfigured)
    }
    expect(new CookieTransport({ domain: '.example.com', path: '/app' }).cookieName).toBe('duck-sid')
    vi.stubEnv('NODE_ENV', 'production')
    expect(new CookieTransport({ domain: '' }).cookieName).toBe('__Host-duck-sid')
  })
})

describe('AuthCookieTransport - Secure follows NODE_ENV', () => {
  const session = makeSession({ absoluteExpiresAt: new Date(Date.now() + 3_600_000) })
  const issue = (t: CookieTransport) => t.issue('sid', session, { absolute: false, fresh: true, csrfToken: 'c' })

  it('sets both cookies Secure, under the __Host- prefix, in production', () => {
    vi.stubEnv('NODE_ENV', 'production')
    const t = new CookieTransport()
    expect([t.cookieName, t.csrfCookieName]).toEqual(['__Host-duck-sid', '__Host-duck-csrf'])
    expect(issue(t)).toMatchObject([
      { name: '__Host-duck-sid', options: { secure: true } },
      { name: '__Host-duck-csrf', options: { secure: true } },
    ])
    expect(t.revoke()).toMatchObject([
      { name: '__Host-duck-sid', options: { secure: true } },
      { name: '__Host-duck-csrf', options: { secure: true } },
    ])
  })

  // Over plain http, which is how a dev server runs, a browser drops a Secure cookie and any `__Host-` one.
  it.each(['development', 'test'])('drops Secure and the __Host- prefix under NODE_ENV=%s', (value) => {
    vi.stubEnv('NODE_ENV', value)
    const t = new CookieTransport()
    expect([t.cookieName, t.csrfCookieName]).toEqual(['duck-sid', 'duck-csrf'])
    expect(issue(t)).toMatchObject([
      { name: 'duck-sid', options: { secure: false } },
      { name: 'duck-csrf', options: { secure: false } },
    ])
    expect(t.revoke()).toMatchObject([
      { name: 'duck-sid', options: { secure: false } },
      { name: 'duck-csrf', options: { secure: false } },
    ])
  })

  it('drops a __Secure- prefix the caller named, outside production', () => {
    vi.stubEnv('NODE_ENV', 'development')
    expect(new CookieTransport({ name: '__Secure-sid' }).cookieName).toBe('sid')
    vi.stubEnv('NODE_ENV', 'production')
    expect(new CookieTransport({ name: '__Secure-sid' }).cookieName).toBe('__Secure-sid')
  })

  // A browser drops a SameSite=None cookie that is not Secure, so None keeps it in every environment.
  it('keeps Secure and the prefix under SameSite=None outside production', () => {
    vi.stubEnv('NODE_ENV', 'development')
    const t = new CookieTransport({ sameSite: 'none' })
    expect([t.cookieName, t.csrfCookieName]).toEqual(['__Host-duck-sid', '__Host-duck-csrf'])
    expect(issue(t)).toMatchObject([
      { options: { secure: true, sameSite: 'none' } },
      { options: { secure: true, sameSite: 'none' } },
    ])
  })

  // Refused where it is written, rather than first on the production deploy.
  it.each(['development', 'production'])(
    'refuses a __Host- name with a domain or a path under NODE_ENV=%s',
    (value) => {
      vi.stubEnv('NODE_ENV', value)
      expect(() => new CookieTransport({ name: '__Host-mine', domain: 'x.com' })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
      expect(() => new CookieTransport({ name: '__Host-mine', path: '/api' })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    },
  )
})

describe('AuthCookieTransport.extract - happy path', () => {
  const t = new CookieTransport({ name: 'duck-sid' })

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
  const t = new CookieTransport({ name: 'duck-sid' })

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

  it('rejects an oversize cookie value (decode-then-sha256 DoS defense)', () => {
    // Real opaque SIDs are 64 chars; JWTs run a few hundred. 1024 cap
    // is generous.
    const huge = 'x'.repeat(1025)
    expect(t.extract(withCookie(`duck-sid=${huge}`))).toBeNull()
  })

  it('accepts a value at the exact cap (1024 chars)', () => {
    const atCap = 'x'.repeat(1024)
    expect(t.extract(withCookie(`duck-sid=${atCap}`))).toBe(atCap)
  })

  describe('cookie name validation at construction', () => {
    it('rejects a cookie name with whitespace (RFC 6265 token)', () => {
      expect(() => new CookieTransport({ name: 'duck sid' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: { detail: '@gentleduck/auth CookieTransport: name contains an RFC 6265-forbidden character' },
        }),
      )
    })
    it('rejects a cookie name with semicolon', () => {
      expect(() => new CookieTransport({ name: 'duck;sid' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: { detail: '@gentleduck/auth CookieTransport: name contains an RFC 6265-forbidden character' },
        }),
      )
    })
    it('rejects a cookie name with equals sign', () => {
      expect(() => new CookieTransport({ name: 'duck=sid' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: { detail: '@gentleduck/auth CookieTransport: name contains an RFC 6265-forbidden character' },
        }),
      )
    })
    it('rejects an empty cookie name', () => {
      expect(() => new CookieTransport({ name: '' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: { detail: '@gentleduck/auth CookieTransport: name must be a non-empty string <=256 chars' },
        }),
      )
    })
    it('accepts the default duck-sid name', () => {
      expect(() => new CookieTransport({ name: 'duck-sid' })).not.toThrow()
    })
    it('accepts the __Host-duck-sid name', () => {
      expect(() => new CookieTransport({ name: '__Host-duck-sid' })).not.toThrow()
    })
  })
})
