/** The credential predicates are all fail-closed, which is the part worth testing. */
import { describe, expect, it } from 'vitest'
import { isCredentialExpired, isRevoked, toPublicCredential } from '../credentials'

const NOW = 1_700_000_000_000

describe('isCredentialExpired', () => {
  it('is false when no expiry is set', () => {
    expect(isCredentialExpired({ expiresAt: null }, NOW)).toBe(false)
  })

  it('is true once the expiry has passed', () => {
    expect(isCredentialExpired({ expiresAt: new Date(NOW - 1) }, NOW)).toBe(true)
  })

  it('is false while the expiry is ahead', () => {
    expect(isCredentialExpired({ expiresAt: new Date(NOW + 1) }, NOW)).toBe(false)
  })

  it('fails closed on a corrupt expiry', () => {
    expect(isCredentialExpired({ expiresAt: 'soon' as never }, NOW)).toBe(true)
    expect(isCredentialExpired({ expiresAt: new Date(Number.NaN) }, NOW)).toBe(true)
  })
})

describe('isRevoked', () => {
  it('is false for a live row', () => {
    expect(isRevoked({ revokedAt: null })).toBe(false)
  })

  it('is true once revokedAt is set', () => {
    expect(isRevoked({ revokedAt: new Date() })).toBe(true)
  })

  it('is true for a revokedAt in the future, since revocation is not scheduled', () => {
    // A future timestamp still means "this row was revoked"; treating it as live
    // would let a clock skew resurrect a killed credential.
    expect(isRevoked({ revokedAt: new Date(Date.now() + 86_400_000) })).toBe(true)
  })

  it('is false for undefined, matching the null sentinel', () => {
    expect(isRevoked({ revokedAt: undefined as never })).toBe(false)
  })
})

describe('toPublicCredential', () => {
  const row = {
    createdAt: new Date(0),
    updatedAt: new Date(0),
    createdBy: null,
    expiresAt: null,
    id: 'c1',
    identityId: 'i1',
    kind: 'totp' as const,
    lastUsedAt: null,
    metadata: { confirmed: true },
    revokedAt: null,
    // A totp seed is stored as plaintext base32, so this is the live factor.
    secret: 'JBSWY3DPEHPK3PXP',
    tenantId: null,
    updatedBy: null,
    version: 1,
  }

  it('drops the secret', () => {
    const pub = toPublicCredential(row)
    expect('secret' in pub).toBe(false)
    expect(JSON.stringify(pub)).not.toContain('JBSWY3DPEHPK3PXP')
  })

  it('keeps every other field', () => {
    const { secret: _secret, ...rest } = row
    expect(toPublicCredential(row)).toEqual(rest)
  })

  it('does not mutate the row it was given', () => {
    toPublicCredential(row)
    expect(row.secret).toBe('JBSWY3DPEHPK3PXP')
  })

  it('redacts a secret the metadata carries, which Omit cannot see', () => {
    const pub = toPublicCredential({
      ...row,
      kind: 'oauth',
      metadata: { provider: 'oauth:google', sub: 's', accessToken: 'ya29-LIVE' },
    })
    expect(pub.metadata).toEqual({ provider: 'oauth:google', sub: 's' })
    expect(JSON.stringify(pub)).not.toContain('ya29-LIVE')
  })

  it('drops a key the kind never declared, so a new secret cannot leak by being forgotten', () => {
    const pub = toPublicCredential({ ...row, metadata: { confirmed: true, futureToken: 'nope' } })
    expect(pub.metadata).toEqual({ confirmed: true })
  })

  it('keeps each kind to its own keys, so one kind cannot borrow another', () => {
    const pub = toPublicCredential({ ...row, kind: 'password', metadata: { algorithm: 'argon2id', sub: 's' } })
    expect(pub.metadata).toEqual({ algorithm: 'argon2id' })
  })

  it('leaves null metadata alone', () => {
    expect(toPublicCredential({ ...row, metadata: null }).metadata).toBeNull()
  })
})
