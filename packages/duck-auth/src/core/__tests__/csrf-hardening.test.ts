import { describe, expect, it, vi } from 'vitest'
import { sha256 } from '../crypto'
import { csrfGuard, issueCsrfToken, verifyCsrf } from '../csrf'

describe('CSRF - header-token length cap', () => {
  it('rejects oversize X-CSRF-Token (>256 chars) without hashing it', () => {
    const { token, hash: storedHash } = issueCsrfToken()
    void token
    const oversize = 'A'.repeat(257)
    expect(() =>
      verifyCsrf({
        method: 'POST',
        headers: new Headers({ 'x-csrf-token': oversize }),
        sessionCsrfHash: storedHash,
      }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/CSRF' }))
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

  it('rejects a multi-MB X-CSRF-Token in O(1) time (no sha256 on the blob)', () => {
    // The cap fires before sha256, so a 10 MB header is rejected almost
    // instantly. Time-bound the test to fail loudly if we ever regress
    // and let the hash function chew on the whole payload.
    const bigToken = 'A'.repeat(10 * 1024 * 1024)
    const start = performance.now()
    expect(() =>
      verifyCsrf({
        method: 'POST',
        headers: new Headers({ 'x-csrf-token': bigToken }),
        sessionCsrfHash: 'whatever',
      }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/CSRF' }))
    const elapsed = performance.now() - start
    // sha256 of 10 MB on a modern laptop is 30–60 ms; the cap should
    // be effectively instant. Anything over 25 ms means the cap regressed.
    expect(elapsed).toBeLessThan(25)
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

describe('CSRF - csrfGuard bearer-scheme detection', () => {
  function authStub(csrfHash: string | undefined) {
    return {
      resolveSession: vi.fn(
        async (): Promise<{ session: { csrfHash?: string }; identity: unknown } | null> => ({
          session: csrfHash === undefined ? {} : { csrfHash },
          identity: null,
        }),
      ),
    }
  }

  it('accepts case-insensitive `Authorization: bearer xxx` lowercase (matches BearerTransport behavior)', async () => {
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
    // BearerTransport rejects commas; csrfGuard must match or both layers smuggle.
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, {
        method: 'POST',
        headers: new Headers({ authorization: 'Bearer X, Bearer Y' }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH/CSRF' })
    // Bearer was refused -> guard fell through to CSRF check, which has
    // no token in the header -> AUTH/CSRF.
    expect(auth.resolveSession).toHaveBeenCalled()
  })

  it('still treats non-Bearer schemes (Basic, Digest) as cookie-auth and runs CSRF', async () => {
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, {
        method: 'POST',
        headers: new Headers({ authorization: 'Basic dXNlcjpwYXNz' }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH/CSRF' })
    expect(auth.resolveSession).toHaveBeenCalled()
  })

  it('schemes that share a `Bearer`-prefix but are not Bearer (e.g. `BearerHack `) are NOT skipped', async () => {
    const auth = authStub('some-hash')
    await expect(
      csrfGuard(auth, {
        method: 'POST',
        headers: new Headers({ authorization: 'BearerHack abc' }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH/CSRF' })
  })

  it('safe methods still bypass everything (no auth/header check at all)', async () => {
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
