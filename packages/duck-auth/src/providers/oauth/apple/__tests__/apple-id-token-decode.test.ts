import { describe, expect, it } from 'vitest'
import { authDecodeIdToken } from '..'

function jwt(payload: unknown): string {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${body}.signature`
}

describe('authApple authDecodeIdToken - claim-shape validation', () => {
  it('accepts well-formed claims', () => {
    const r = authDecodeIdToken(jwt({ sub: 'authApple-user-1', email: 'a@x.com', email_verified: true }))
    expect(r).toEqual({ sub: 'authApple-user-1', email: 'a@x.com', email_verified: true })
  })

  it('accepts string-encoded email_verified (Apple quirk)', () => {
    const r = authDecodeIdToken(jwt({ sub: 'u1', email: 'a@x.com', email_verified: 'true' }))
    expect(r).toEqual({ sub: 'u1', email: 'a@x.com', email_verified: true })
  })

  it('treats email_verified=false as not-verified', () => {
    const r = authDecodeIdToken(jwt({ sub: 'u1', email: 'a@x.com', email_verified: false }))
    expect(r).toEqual({ sub: 'u1', email: 'a@x.com' })
    expect(r?.email_verified).toBeUndefined()
  })

  it('rejects non-string sub (the multi-account-collision case)', () => {
    expect(authDecodeIdToken(jwt({ sub: 42 }))).toBeNull()
    expect(authDecodeIdToken(jwt({ sub: null }))).toBeNull()
    expect(authDecodeIdToken(jwt({ sub: '' }))).toBeNull()
  })

  it('rejects missing sub', () => {
    expect(authDecodeIdToken(jwt({ email: 'a@x.com' }))).toBeNull()
  })

  it('drops non-string email (does NOT propagate array / number)', () => {
    const r = authDecodeIdToken(jwt({ sub: 'u1', email: ['a@x.com', 'b@x.com'] }))
    expect(r).toEqual({ sub: 'u1' })
  })

  it('rejects payloads with wrong dot-count (not a JWT)', () => {
    expect(authDecodeIdToken('not.a.jwt.string.with.extra')).toBeNull()
    expect(authDecodeIdToken('just-one-part')).toBeNull()
  })

  it('rejects malformed base64url payload', () => {
    expect(authDecodeIdToken('header.!!@@##.sig')).toBeNull()
  })

  it('rejects truncated JSON body', () => {
    const header = Buffer.from('{}').toString('base64url')
    const body = Buffer.from('{"sub":').toString('base64url') // truncated
    expect(authDecodeIdToken(`${header}.${body}.sig`)).toBeNull()
  })

  it('rejects array as the JWT body (JSON.parse -> array)', () => {
    expect(authDecodeIdToken(jwt(['not', 'an', 'object']))).toBeNull()
  })

  it('rejects null as the JWT body', () => {
    expect(authDecodeIdToken(jwt(null))).toBeNull()
  })
})
