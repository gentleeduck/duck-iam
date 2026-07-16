import { describe, expect, it } from 'vitest'
import { AuthError } from '../errors'

describe('AuthError.toJSON - SEC: sensitive meta key denylist', () => {
  it('includes the code + status fields', () => {
    const err = new AuthError('AUTH_INVALID_CREDENTIALS')
    expect(err.toJSON()).toEqual({ ok: false, error: { code: 'AUTH_INVALID_CREDENTIALS', status: 401 } })
  })

  it('passes through documented extras (retryAfter, kid, etc.)', () => {
    const err = new AuthError('AUTH_RATE_LIMITED', { retryAfter: 30 })
    expect(err.toJSON()).toEqual({ ok: false, error: { code: 'AUTH_RATE_LIMITED', status: 429, retryAfter: 30 } })
  })

  it('drops `secret` from the wire envelope', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new AuthError('AUTH_INVALID_CREDENTIALS', { secret: 'super-secret-hash' } as any)
    const wire = err.toJSON()
    expect(wire.error.secret).toBeUndefined()
    expect(wire).toEqual({ ok: false, error: { code: 'AUTH_INVALID_CREDENTIALS', status: 401 } })
  })

  it('drops `password` / `plaintext` / `privateKey`', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new AuthError('AUTH_INVALID_CREDENTIALS', {
      password: 'p@ssw0rd',
      plaintext: 'raw',
      privateKey: '-----BEGIN PRIVATE KEY-----',
    } as any)
    const wire = err.toJSON()
    expect(wire.error.password).toBeUndefined()
    expect(wire.error.plaintext).toBeUndefined()
    expect(wire.error.privateKey).toBeUndefined()
  })

  it('drops token-shaped fields (`token`, `refreshToken`, `accessToken`, `idToken`)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oauth:test',
      token: 't',
      refreshToken: 'rt',
      accessToken: 'at',
      idToken: 'it',
    } as any)
    const wire = err.toJSON()
    expect(wire.error.token).toBeUndefined()
    expect(wire.error.refreshToken).toBeUndefined()
    expect(wire.error.accessToken).toBeUndefined()
    expect(wire.error.idToken).toBeUndefined()
    // Non-sensitive providerId still passes through.
    expect(wire.error.providerId).toBe('oauth:test')
  })

  it('drops `hash` / `tokenHash` / `codeHash` / `presentedHash`', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new AuthError('AUTH_INVALID_CREDENTIALS', {
      hash: 'abc',
      tokenHash: 'def',
      codeHash: 'ghi',
      presentedHash: 'jkl',
    } as any)
    const wire = err.toJSON()
    expect(wire.error.hash).toBeUndefined()
    expect(wire.error.tokenHash).toBeUndefined()
    expect(wire.error.codeHash).toBeUndefined()
    expect(wire.error.presentedHash).toBeUndefined()
  })

  it('denylist is case-insensitive (SECRET / Password / PrivateKey all dropped)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new AuthError('AUTH_MISCONFIGURED', {
      SECRET: 'shouty',
      Password: 'mixed',
      PrivateKey: 'pemish',
    } as any)
    const wire = err.toJSON()
    expect(wire.error.SECRET).toBeUndefined()
    expect(wire.error.Password).toBeUndefined()
    expect(wire.error.PrivateKey).toBeUndefined()
  })

  it('drops `clientSecret`', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oauth:test',
      clientSecret: 'sek-12345',
    } as any)
    expect(err.toJSON().error.clientSecret).toBeUndefined()
  })

  it('scrubs sensitive keys at depth (nested objects)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oauth:test',
      user: { id: 'u1', password: 'leaked', email: 'a@x.com' },
    } as any)
    expect(err.toJSON()).toEqual({
      ok: false,
      error: {
        code: 'AUTH_PROVIDER_FAILED',
        status: 400,
        providerId: 'oauth:test',
        user: { id: 'u1', email: 'a@x.com' },
      },
    })
  })

  it('scrubs sensitive keys inside arrays', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oauth:test',
      attempts: [
        { ts: 1, password: 'x' },
        { ts: 2, password: 'y' },
      ],
    } as any)
    expect(err.toJSON().error.attempts).toEqual([{ ts: 1 }, { ts: 2 }])
  })

  it('caps recursion depth to a finite value', () => {
    let nested: Record<string, unknown> = { secret: 'leaf' }
    for (let i = 0; i < 20; i++) nested = { child: nested }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new AuthError('AUTH_MISCONFIGURED', nested as any)
    expect(() => err.toJSON()).not.toThrow()
  })
})
