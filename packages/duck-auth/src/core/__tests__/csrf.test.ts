import { describe, expect, it } from 'vitest'
import { sha256 } from '../crypto'
import { buildCsrfCookieOptions, csrfGuard, DEFAULT_CSRF_CONFIG, issueCsrfToken, verifyCsrf } from '../csrf'

describe('CSRF', () => {
  describe('issueCsrfToken / buildCsrfCookieOptions', () => {
    it('issues a base64url token and its sha256 hash', () => {
      const { token, hash } = issueCsrfToken()
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/)
      expect(hash).toBe(sha256(token))
    })

    it('cookie defaults: __Host-duck-csrf, HttpOnly=false, Secure, SameSite=Lax, Path=/', () => {
      const c = buildCsrfCookieOptions('abc')
      expect(c.name).toBe('__Host-duck-csrf')
      expect(c.value).toBe('abc')
      expect(c.options.httpOnly).toBe(false)
      expect(c.options.secure).toBe(true)
      expect(c.options.sameSite).toBe('lax')
      expect(c.options.path).toBe('/')
    })
  })

  describe('verifyCsrf - safe methods + bearer exemption', () => {
    it.each(['GET', 'HEAD', 'OPTIONS', 'TRACE'])('exempts %s', (method) => {
      expect(() =>
        verifyCsrf({
          method,
          headers: new Headers(),
        }),
      ).not.toThrow()
    })

    it('exempts bearer-authed requests regardless of mutating method', () => {
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers(),
          isBearer: true,
        }),
      ).not.toThrow()
    })
  })

  describe('verifyCsrf - Sec-Fetch-Site layer', () => {
    it('rejects cross-site requests', () => {
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({ 'sec-fetch-site': 'cross-site' }),
          sessionCsrfHash: sha256('x'),
        }),
      ).toThrow(/AUTH\/CSRF/)
    })

    it('rejects cross-origin requests', () => {
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({ 'sec-fetch-site': 'cross-origin' as never }),
          sessionCsrfHash: sha256('x'),
        }),
      ).toThrow(/AUTH\/CSRF/)
    })

    it('allows same-origin / same-site / none', () => {
      for (const sfs of ['same-origin', 'same-site', 'none']) {
        const t = issueCsrfToken()
        expect(() =>
          verifyCsrf({
            method: 'POST',
            headers: new Headers({
              'sec-fetch-site': sfs,
              'x-csrf-token': t.token,
            }),
            sessionCsrfHash: t.hash,
          }),
        ).not.toThrow()
      }
    })
  })

  describe('verifyCsrf - allowedOrigins layer', () => {
    it('rejects when Origin not in allowedOrigins', () => {
      const t = issueCsrfToken()
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({
            origin: 'https://evil.example.com',
            'x-csrf-token': t.token,
          }),
          sessionCsrfHash: t.hash,
          cfg: { allowedOrigins: ['https://app.example.com'] },
        }),
      ).toThrow(/AUTH\/CSRF/)
    })

    it('accepts when Origin matches allowedOrigins', () => {
      const t = issueCsrfToken()
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({
            origin: 'https://app.example.com',
            'x-csrf-token': t.token,
          }),
          sessionCsrfHash: t.hash,
          cfg: { allowedOrigins: ['https://app.example.com'] },
        }),
      ).not.toThrow()
    })
  })

  describe('verifyCsrf - double-submit token', () => {
    it('rejects when X-CSRF-Token header missing', () => {
      const t = issueCsrfToken()
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers(),
          sessionCsrfHash: t.hash,
        }),
      ).toThrow(/AUTH\/CSRF/)
    })

    it('passes when sessionCsrfHash missing (unauthenticated state-change - Layer 1 is enough)', () => {
      // For signin / signup-begin there is no session yet to bind the
      // double-submit token to. Layer 1 (Sec-Fetch-Site default `none`
      // or same-origin) already defends the login-CSRF vector.
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({ 'x-csrf-token': 'whatever' }),
        }),
      ).not.toThrow()
    })

    it('rejects when header token does not hash to sessionCsrfHash', () => {
      const t = issueCsrfToken()
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({ 'x-csrf-token': 'wrong-token' }),
          sessionCsrfHash: t.hash,
        }),
      ).toThrow(/AUTH\/CSRF/)
    })

    it('accepts when header token hash matches sessionCsrfHash', () => {
      const t = issueCsrfToken()
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({ 'x-csrf-token': t.token }),
          sessionCsrfHash: t.hash,
        }),
      ).not.toThrow()
    })
  })

  describe('verifyCsrf - origin-only mode', () => {
    it('skips token validation when mode=origin-only', () => {
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({ 'sec-fetch-site': 'same-origin' }),
          cfg: { mode: 'origin-only' },
        }),
      ).not.toThrow()
    })

    it('still enforces sec-fetch-site cross-site in origin-only mode', () => {
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({ 'sec-fetch-site': 'cross-site' }),
          cfg: { mode: 'origin-only' },
        }),
      ).toThrow(/AUTH\/CSRF/)
    })

    it('origin-only mode + sec-fetch-site absent + no allowedOrigins = throw (no defense available)', () => {
      // Real browsers always attach `sec-fetch-site`; its absence means
      // a non-browser client OR a reverse-proxy stripped headers. In
      // origin-only mode without an Origin allowlist, the guard has
      // nothing to compare against - refuse rather than fail-open.
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers(), // no sec-fetch-site, no origin
          cfg: { mode: 'origin-only' },
        }),
      ).toThrow(/AUTH\/CSRF/)
    })

    it('origin-only + sec-fetch-site absent but allowedOrigins configured + matching Origin = pass', () => {
      // The Origin allowlist substitutes for sec-fetch-site.
      expect(() =>
        verifyCsrf({
          method: 'POST',
          headers: new Headers({ origin: 'https://app.example.com' }),
          cfg: { mode: 'origin-only', allowedOrigins: ['https://app.example.com'] },
        }),
      ).not.toThrow()
    })
  })

  it('config defaults expose stable names', () => {
    expect(DEFAULT_CSRF_CONFIG.cookieName).toBe('__Host-duck-csrf')
    expect(DEFAULT_CSRF_CONFIG.headerName).toBe('x-csrf-token')
    expect(DEFAULT_CSRF_CONFIG.mode).toBe('double-submit')
  })

  describe('csrfGuard convenience helper', () => {
    const fakeAuth = (resolved: { session: { csrfHash?: string } } | null) => ({
      async resolveSession() {
        return resolved as never
      },
    })

    it('passes for safe GET regardless of session/token state', async () => {
      await expect(csrfGuard(fakeAuth(null), { method: 'GET', headers: new Headers() })).resolves.toBeUndefined()
    })

    it('passes for Bearer-authenticated requests (header inspection)', async () => {
      await expect(
        csrfGuard(fakeAuth(null), {
          method: 'POST',
          headers: new Headers({ authorization: 'Bearer xyz' }),
        }),
      ).resolves.toBeUndefined()
    })

    it('passes for explicit isBearer:true (header may be absent)', async () => {
      await expect(
        csrfGuard(fakeAuth(null), { method: 'POST', headers: new Headers() }, { isBearer: true }),
      ).resolves.toBeUndefined()
    })

    it('throws on cookie-auth POST without CSRF header', async () => {
      const sessHash = sha256('plain-token')
      await expect(
        csrfGuard(fakeAuth({ session: { csrfHash: sessHash } }), {
          method: 'POST',
          headers: new Headers({ cookie: '__Host-duck-sid=x', 'sec-fetch-site': 'same-origin' }),
        }),
      ).rejects.toMatchObject({ code: 'AUTH/CSRF' })
    })

    it('passes when CSRF header matches session csrfHash', async () => {
      const token = 'plain-csrf-token-xyz'
      const sessHash = sha256(token)
      await expect(
        csrfGuard(fakeAuth({ session: { csrfHash: sessHash } }), {
          method: 'POST',
          headers: new Headers({
            cookie: '__Host-duck-sid=x',
            'sec-fetch-site': 'same-origin',
            'x-csrf-token': token,
          }),
        }),
      ).resolves.toBeUndefined()
    })
  })
})
