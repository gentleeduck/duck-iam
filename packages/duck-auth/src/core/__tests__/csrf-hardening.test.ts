import { describe, expect, it, vi } from 'vitest'
import * as crypto from '../crypto'
import { sha256 } from '../crypto'
import { csrfGuard, issueCsrfToken, verifyCsrf } from '../csrf'

/**
 * `sha256` is wrapped, not replaced: every case below still hashes for real,
 * and the spy only records that it happened. That is what lets the cap tests
 * assert the property they actually care about - that an oversize token is
 * refused *before* it reaches the hash - rather than timing the call and
 * hoping the machine is idle enough for the number to mean something.
 */
vi.mock('../crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../crypto')>()
  return { ...actual, sha256: vi.fn(actual.sha256) }
})

describe('CSRF - header-token length cap', () => {
  it('rejects oversize X-CSRF-Token (>256 chars) without hashing it', () => {
    const { token, hash: storedHash } = issueCsrfToken()
    void token
    const oversize = 'A'.repeat(257)
    vi.mocked(crypto.sha256).mockClear()

    expect(() =>
      verifyCsrf({
        method: 'POST',
        headers: new Headers({ 'x-csrf-token': oversize }),
        sessionCsrfHash: storedHash,
      }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_CSRF' }))

    // One char over the cap is the boundary the guard has to catch, so this is
    // where a regression would first show. The title has always claimed
    // "without hashing it"; now the case checks it.
    expect(crypto.sha256).not.toHaveBeenCalled()
  })

  it('accepts a 256-char token at the cap (boundary)', () => {
    // Construct a 256-char token, store its hash as the session's
    // canonical, then resubmit it - the request should succeed.
    const sized = 'A'.repeat(256)
    const storedHash = sha256(sized)
    expect(() =>
      verifyCsrf({
        method: 'POST',
        headers: new Headers({ 'x-csrf-token': sized }),
        sessionCsrfHash: storedHash,
      }),
    ).not.toThrow()
  })

  it('rejects a multi-MB X-CSRF-Token without letting sha256 touch the blob', () => {
    // The DoS this guards against is sha256 amplification: a 10 MB header that
    // reaches the hash costs real CPU per request. The defence is that the cap
    // fires first, so the assertion is that the hash was never called.
    const bigToken = 'A'.repeat(10 * 1024 * 1024)
    vi.mocked(crypto.sha256).mockClear()

    expect(() =>
      verifyCsrf({
        method: 'POST',
        headers: new Headers({ 'x-csrf-token': bigToken }),
        sessionCsrfHash: 'whatever',
      }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_CSRF' }))

    expect(crypto.sha256).not.toHaveBeenCalled()
  })

  it('does hash a token within the cap, so the guard above proves something', () => {
    // A control for the two cases above: if `sha256` were never called on any
    // path, "not called" would be vacuously true and the cap tests would pass
    // against a guard that had been deleted.
    const sized = 'A'.repeat(256)
    const storedHash = sha256(sized)
    vi.mocked(crypto.sha256).mockClear()

    verifyCsrf({
      method: 'POST',
      headers: new Headers({ 'x-csrf-token': sized }),
      sessionCsrfHash: storedHash,
    })

    expect(crypto.sha256).toHaveBeenCalledWith(sized)
  })

  it('a normal 43-char base64url token still verifies', () => {
    const { token, hash: storedHash } = issueCsrfToken()
    expect(token.length).toBeLessThanOrEqual(256)
    expect(() =>
      verifyCsrf({
        method: 'POST',
        headers: new Headers({ 'x-csrf-token': token }),
        sessionCsrfHash: storedHash,
      }),
    ).not.toThrow()
  })
})

describe('CSRF - authCsrfGuard bearer-scheme detection', () => {
  function authStub(csrfHash: string | undefined) {
    return {
      resolveSession: vi.fn(
        async (): Promise<{ session: { csrfHash?: string }; identity: unknown }> => ({
          session: csrfHash === undefined ? {} : { csrfHash },
          identity: null,
        }),
      ),
    }
  }

  it('accepts case-insensitive `Authorization: bearer xxx` lowercase (matches AuthBearerTransport behavior)', async () => {
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, {
        method: 'POST',
        headers: new Headers({ authorization: 'bearer my-token-here' }),
      }),
    ).resolves.toBeUndefined()
    // Confirm we short-circuited BEFORE resolving the session - bearer
    // requests do not need to load the session just to check CSRF.
    expect(auth.resolveSession).not.toHaveBeenCalled()
  })

  it('accepts `Authorization: BEARER xxx` uppercase', async () => {
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, {
        method: 'POST',
        headers: new Headers({ authorization: 'BEARER my-token-here' }),
      }),
    ).resolves.toBeUndefined()
    expect(auth.resolveSession).not.toHaveBeenCalled()
  })

  it('accepts `Authorization: Bearer xxx` PascalCase (the previously-only-accepted form)', async () => {
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, {
        method: 'POST',
        headers: new Headers({ authorization: 'Bearer my-token-here' }),
      }),
    ).resolves.toBeUndefined()
    expect(auth.resolveSession).not.toHaveBeenCalled()
  })

  it('refuses multi-value smuggling: `Bearer X, Bearer Y` is NOT treated as bearer', async () => {
    // AuthBearerTransport rejects commas; csrfGuard must match or both layers smuggle.
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, {
        method: 'POST',
        headers: new Headers({ authorization: 'Bearer X, Bearer Y' }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_CSRF' })
    // Bearer was refused -> guard fell through to CSRF check, which has
    // no token in the header -> AUTH_CSRF.
    expect(auth.resolveSession).toHaveBeenCalled()
  })

  it('still treats non-Bearer schemes (Basic, Digest) as cookie-auth and runs CSRF', async () => {
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, {
        method: 'POST',
        headers: new Headers({ authorization: 'Basic dXNlcjpwYXNz' }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_CSRF' })
    expect(auth.resolveSession).toHaveBeenCalled()
  })

  it('schemes that share a `Bearer`-prefix but are not Bearer (e.g. `BearerHack `) are NOT skipped', async () => {
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, {
        method: 'POST',
        headers: new Headers({ authorization: 'BearerHack abc' }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_CSRF' })
  })

  it('safe methods still bypass everything (no AUTH/header check at all)', async () => {
    const auth = authStub('some-hash')
    await expect(csrfGuard(auth, { method: 'GET', headers: new Headers() })).resolves.toBeUndefined()
    expect(auth.resolveSession).not.toHaveBeenCalled()
  })

  it('explicit isBearer: true wins over header check (caller knows best)', async () => {
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, { method: 'POST', headers: new Headers() }, { isBearer: true }),
    ).resolves.toBeUndefined()
    expect(auth.resolveSession).not.toHaveBeenCalled()
  })
})

/**
 * The bearer exemption exists because a header-borne credential is not ambient: a browser will not
 * attach it to a cross-site request on its own. That reasoning covers the double-submit token, and
 * nothing else. It was skipping the Origin / Sec-Fetch-Site gate with it.
 */
describe('CSRF - a bearer header does not disarm the cross-site gate', () => {
  function authStub() {
    return {
      resolveSession: vi.fn(
        async (): Promise<{ session: { csrfHash?: string }; identity: unknown }> => ({
          session: { csrfHash: 'some-hash' },
          identity: null,
        }),
      ),
    }
  }

  it('refuses a cross-site POST that carries an Authorization header', async () => {
    // The attack this closes: the request rides the victim's ambient session cookie, and a junk
    // `Authorization` header is added purely to take the exemption. `sec-fetch-site: cross-site` is
    // the browser saying so, and it was never read.
    await expect(
      csrfGuard(authStub(), {
        method: 'POST',
        headers: new Headers({
          authorization: 'Bearer anything-at-all',
          cookie: '__Host-duck-sid=victims-session',
          'sec-fetch-site': 'cross-site',
        }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_CSRF' })
  })

  it('refuses a cross-site POST for an explicit isBearer caller too', async () => {
    await expect(
      csrfGuard(
        authStub(),
        {
          method: 'POST',
          headers: new Headers({ cookie: '__Host-duck-sid=victims-session', 'sec-fetch-site': 'cross-site' }),
        },
        { isBearer: true },
      ),
    ).rejects.toMatchObject({ code: 'AUTH_CSRF' })
  })

  it('refuses a bearer request whose Origin is not on a configured allowlist', async () => {
    await expect(
      csrfGuard(
        authStub(),
        {
          method: 'POST',
          headers: new Headers({
            authorization: 'Bearer x',
            cookie: '__Host-duck-sid=victims-session',
            origin: 'https://evil.example',
          }),
        },
        { cfg: { allowedOrigins: ['https://app.example'] } },
      ),
    ).rejects.toMatchObject({ code: 'AUTH_CSRF' })
  })

  it('still exempts a real API client, which sends neither browser header', async () => {
    // A non-browser bearer client sends no Origin and no Sec-Fetch-Site, so layer 1 costs it nothing
    // and layer 2 is still skipped. The session is still never loaded just to check CSRF.
    const auth = authStub()
    await expect(
      csrfGuard(auth, { method: 'POST', headers: new Headers({ authorization: 'Bearer real-token' }) }),
    ).resolves.toBeUndefined()
    expect(auth.resolveSession).not.toHaveBeenCalled()
  })

  it('still exempts a genuinely cross-site bearer client that sends no cookie', async () => {
    // A browser SPA on one registrable domain calling an API on another, holding its token in memory,
    // is an ordinary architecture and is not CSRF-able: there is nothing ambient for the browser to
    // attach. Keying the exemption on the `Authorization` header alone would have covered this case by
    // accident; keying it on the absent cookie covers it on purpose.
    await expect(
      csrfGuard(authStub(), {
        method: 'POST',
        headers: new Headers({ authorization: 'Bearer real-token', 'sec-fetch-site': 'cross-site' }),
      }),
    ).resolves.toBeUndefined()
  })

  it('still exempts a same-origin browser client using a bearer token', async () => {
    await expect(
      csrfGuard(authStub(), {
        method: 'POST',
        headers: new Headers({ authorization: 'Bearer real-token', 'sec-fetch-site': 'same-origin' }),
      }),
    ).resolves.toBeUndefined()
  })

  it('exempts a bearer request from the double-submit token, which is what the exemption is for', () => {
    // No `x-csrf-token` header and a session hash present: a cookie-authed request would be refused
    // here, and a bearer one must not be.
    expect(() =>
      verifyCsrf({ headers: new Headers(), isBearer: true, method: 'POST', sessionCsrfHash: sha256('whatever') }),
    ).not.toThrow()
  })
})
