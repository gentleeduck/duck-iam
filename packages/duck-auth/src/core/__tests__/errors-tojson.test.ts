import { describe, expect, it } from 'vitest'
import { AuthErrorObject } from '../errors'

describe('AuthErrorObject.toJSON - SEC: sensitive meta key denylist', () => {
  it('includes the code + status fields', () => {
    const err = new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    expect(err.toJSON()).toEqual({ code: 'AUTH/INVALID_CREDENTIALS', status: 401 })
  })

  it('passes through documented extras (retryAfter, kid, etc.)', () => {
    const err = new AuthErrorObject('AUTH/RATE_LIMITED', { retryAfter: 30 })
    expect(err.toJSON()).toEqual({ code: 'AUTH/RATE_LIMITED', status: 429, retryAfter: 30 })
  })

  it('drops `secret` from the wire envelope', () => {
    const err = new AuthErrorObject('AUTH/INVALID_CREDENTIALS', { secret: 'super-secret-hash' })
    const wire = err.toJSON()
    expect(wire.secret).toBeUndefined()
    expect(wire).toEqual({ code: 'AUTH/INVALID_CREDENTIALS', status: 401 })
  })

  it('drops `password` / `plaintext` / `privateKey`', () => {
    const err = new AuthErrorObject('AUTH/INVALID_CREDENTIALS', {
      password: 'p@ssw0rd',
      plaintext: 'raw',
      privateKey: '-----BEGIN PRIVATE KEY-----',
    })
    const wire = err.toJSON()
    expect(wire.password).toBeUndefined()
    expect(wire.plaintext).toBeUndefined()
    expect(wire.privateKey).toBeUndefined()
  })

  it('drops token-shaped fields (`token`, `refreshToken`, `accessToken`, `idToken`)', () => {
    const err = new AuthErrorObject('AUTH/PROVIDER_FAILED', {
      providerId: 'oauth:test',
      token: 't',
      refreshToken: 'rt',
      accessToken: 'at',
      idToken: 'it',
    })
    const wire = err.toJSON()
    expect(wire.token).toBeUndefined()
    expect(wire.refreshToken).toBeUndefined()
    expect(wire.accessToken).toBeUndefined()
    expect(wire.idToken).toBeUndefined()
    // Non-sensitive providerId still passes through.
    expect(wire.providerId).toBe('oauth:test')
  })

  it('drops `hash` / `tokenHash` / `codeHash` / `presentedHash`', () => {
    const err = new AuthErrorObject('AUTH/INVALID_CREDENTIALS', {
      hash: 'abc',
      tokenHash: 'def',
      codeHash: 'ghi',
      presentedHash: 'jkl',
    })
    const wire = err.toJSON()
    expect(wire.hash).toBeUndefined()
    expect(wire.tokenHash).toBeUndefined()
    expect(wire.codeHash).toBeUndefined()
    expect(wire.presentedHash).toBeUndefined()
  })

  it('denylist is case-insensitive (SECRET / Password / PrivateKey all dropped)', () => {
    // Sensitivity should not depend on the caller's casing.
    const err = new AuthErrorObject('AUTH/MISCONFIGURED', {
      SECRET: 'shouty',
      Password: 'mixed',
      PrivateKey: 'pemish',
    })
    const wire = err.toJSON()
    expect(wire.SECRET).toBeUndefined()
    expect(wire.Password).toBeUndefined()
    expect(wire.PrivateKey).toBeUndefined()
  })

  it('drops `clientSecret`', () => {
    const err = new AuthErrorObject('AUTH/PROVIDER_FAILED', {
      providerId: 'oauth:test',
      clientSecret: 'sek-12345',
    })
    expect(err.toJSON().clientSecret).toBeUndefined()
  })
})
