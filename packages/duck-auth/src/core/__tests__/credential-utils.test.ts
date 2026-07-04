import { describe, expect, it } from 'vitest'
import {
  getCredentialPurpose,
  getProfileString,
  isCredentialExpired,
  isExpiredAt,
  isProfileBooleanTrue,
  isRevoked,
  isSoftDeleted,
} from '../credential-utils'

describe('isRevoked', () => {
  it('false when revokedAt is the null/undefined live sentinel', () => {
    // `null` is the canonical "not revoked" value: upsert/create default
    // `revokedAt` to `null`, so a null here means a live credential.
    expect(isRevoked({})).toBe(false)
    expect(isRevoked({ revokedAt: undefined })).toBe(false)
    expect(isRevoked({ revokedAt: null })).toBe(false)
  })

  it('true when revokedAt is a Date (normal case)', () => {
    expect(isRevoked({ revokedAt: new Date() })).toBe(true)
  })

  it('true when revokedAt is epoch zero Date (the bug `!revokedAt` would have missed)', () => {
    expect(isRevoked({ revokedAt: new Date(0) })).toBe(true)
  })

  it('true when revokedAt is a non-null value from a buggy adapter (fail-closed)', () => {
    // @ts-expect-error: SEC test intentionally violates the typed shape
    expect(isRevoked({ revokedAt: 'compromised-marker' })).toBe(true)
    // @ts-expect-error: SEC test intentionally violates the typed shape
    expect(isRevoked({ revokedAt: { evil: 'object' } })).toBe(true)
  })
})

describe('getProfileString', () => {
  it('returns the string when present', () => {
    expect(getProfileString({ email: 'a@x.com' }, 'email')).toBe('a@x.com')
    expect(getProfileString({ phone: '+1234' }, 'phone')).toBe('+1234')
  })

  it('undefined when profile is not a plain object', () => {
    expect(getProfileString(null, 'email')).toBeUndefined()
    expect(getProfileString(undefined, 'email')).toBeUndefined()
    expect(getProfileString('a@x.com', 'email')).toBeUndefined()
    expect(getProfileString([{ email: 'a' }], 'email')).toBeUndefined()
  })

  it('undefined when key missing', () => {
    expect(getProfileString({ other: 'value' }, 'email')).toBeUndefined()
  })

  it('undefined when value is empty string', () => {
    expect(getProfileString({ email: '' }, 'email')).toBeUndefined()
  })

  it('undefined for non-string values (would have propagated unsafely into outbound channel headers)', () => {
    expect(getProfileString({ email: 42 }, 'email')).toBeUndefined()
    expect(getProfileString({ email: null }, 'email')).toBeUndefined()
    expect(getProfileString({ email: { trick: 'a@x.com' } }, 'email')).toBeUndefined()
  })
})

describe('isSoftDeleted', () => {
  it('false when deletedAt is undefined', () => {
    expect(isSoftDeleted({})).toBe(false)
    expect(isSoftDeleted({ deletedAt: undefined })).toBe(false)
  })

  it('true when deletedAt is a positive number', () => {
    expect(isSoftDeleted({ deletedAt: Date.now() })).toBe(true)
  })

  it('true when deletedAt === 0 (legitimate epoch number, previously falsy-leaked)', () => {
    expect(isSoftDeleted({ deletedAt: 0 })).toBe(true)
  })

  it('true on non-numeric deletedAt from a buggy adapter (fail-closed)', () => {
    // @ts-expect-error: SEC test intentionally violates the typed shape
    expect(isSoftDeleted({ deletedAt: 'pending-delete' })).toBe(true)
  })
})

describe('isCredentialExpired', () => {
  const now = 1_700_000_000_000

  it('false when expiresAt is the null/undefined no-expiry sentinel', () => {
    expect(isCredentialExpired({}, now)).toBe(false)
    expect(isCredentialExpired({ expiresAt: undefined }, now)).toBe(false)
    expect(isCredentialExpired({ expiresAt: null }, now)).toBe(false)
  })

  it('false when expiresAt is in the future', () => {
    expect(isCredentialExpired({ expiresAt: new Date(now + 1) }, now)).toBe(false)
  })

  it('true when expiresAt is in the past', () => {
    expect(isCredentialExpired({ expiresAt: new Date(now - 1) }, now)).toBe(true)
  })

  it('true on non-numeric expiresAt (would otherwise bypass via `NaN < N === false`)', () => {
    // @ts-expect-error: SEC test intentionally violates the typed shape
    expect(isCredentialExpired({ expiresAt: 'soon' }, now)).toBe(true)
    // @ts-expect-error: SEC test intentionally violates the typed shape
    expect(isCredentialExpired({ expiresAt: { future: true } }, now)).toBe(true)
  })

  it('true on NaN / Infinity expiresAt dates (would bypass numeric comparison)', () => {
    expect(isCredentialExpired({ expiresAt: new Date(Number.NaN) }, now)).toBe(true)
    expect(isCredentialExpired({ expiresAt: new Date(Number.POSITIVE_INFINITY) }, now)).toBe(true)
    expect(isCredentialExpired({ expiresAt: new Date(Number.NEGATIVE_INFINITY) }, now)).toBe(true)
  })

  it('uses Date.now() when no `now` supplied', () => {
    expect(isCredentialExpired({ expiresAt: new Date(Date.now() + 60_000) })).toBe(false)
    expect(isCredentialExpired({ expiresAt: new Date(Date.now() - 60_000) })).toBe(true)
  })
})

describe('isExpiredAt (low-level primitive)', () => {
  const now = 1_700_000_000_000

  it('false when timestamp is null/undefined (no expiry configured)', () => {
    expect(isExpiredAt(undefined, now)).toBe(false)
    expect(isExpiredAt(null, now)).toBe(false)
  })

  it('false when timestamp is in the future', () => {
    expect(isExpiredAt(now + 1, now)).toBe(false)
  })

  it('true when timestamp is in the past', () => {
    expect(isExpiredAt(now - 1, now)).toBe(true)
  })

  it('true for non-finite timestamps (NaN-bypass defense)', () => {
    expect(isExpiredAt(Number.NaN, now)).toBe(true)
    expect(isExpiredAt(Number.POSITIVE_INFINITY, now)).toBe(true)
  })

  it('true for non-numeric timestamps (string, object) - fail closed', () => {
    expect(isExpiredAt('soon', now)).toBe(true)
    expect(isExpiredAt({ ts: 1 }, now)).toBe(true)
  })
})

describe('getCredentialPurpose', () => {
  it('undefined when metadata is undefined', () => {
    expect(getCredentialPurpose({})).toBeUndefined()
    expect(getCredentialPurpose({ metadata: undefined })).toBeUndefined()
  })

  it('undefined when metadata.purpose is missing', () => {
    expect(getCredentialPurpose({ metadata: {} })).toBeUndefined()
    expect(getCredentialPurpose({ metadata: { other: 'value' } })).toBeUndefined()
  })

  it('returns the string when metadata.purpose is a string', () => {
    expect(getCredentialPurpose({ metadata: { purpose: 'email-verification' } })).toBe('email-verification')
  })

  it('undefined when metadata.purpose is a non-string (e.g. attacker writes an object via patchMetadata)', () => {
    expect(getCredentialPurpose({ metadata: { purpose: { evil: 'object' } } })).toBeUndefined()
    expect(getCredentialPurpose({ metadata: { purpose: 42 } })).toBeUndefined()
    expect(getCredentialPurpose({ metadata: { purpose: null } })).toBeUndefined()
  })
})

describe('isProfileBooleanTrue', () => {
  it('true ONLY when the field is strictly === true', () => {
    expect(isProfileBooleanTrue({ emailVerified: true }, 'emailVerified')).toBe(true)
  })

  it('false on missing field', () => {
    expect(isProfileBooleanTrue({}, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ other: true }, 'emailVerified')).toBe(false)
  })

  it('false on truthy-but-non-boolean values (SEC: defeats `truthy === true` confusion)', () => {
    // These would all pass a sloppy `Boolean(profile.emailVerified)`
    // gate; the strict-boolean predicate refuses them.
    expect(isProfileBooleanTrue({ emailVerified: 1 }, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ emailVerified: 'true' }, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ emailVerified: 'yes' }, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ emailVerified: 'verified' }, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ emailVerified: {} }, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ emailVerified: [] }, 'emailVerified')).toBe(false)
  })

  it('false on false / falsy values', () => {
    expect(isProfileBooleanTrue({ emailVerified: false }, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ emailVerified: 0 }, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ emailVerified: '' }, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ emailVerified: null }, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue({ emailVerified: undefined }, 'emailVerified')).toBe(false)
  })

  it('false when profile is not a plain object', () => {
    expect(isProfileBooleanTrue(null, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue(undefined, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue('true', 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue(42, 'emailVerified')).toBe(false)
    expect(isProfileBooleanTrue([{ emailVerified: true }], 'emailVerified')).toBe(false)
  })
})

describe('memory findByEmail - profile-shape robustness', () => {
  it.todo('integration test lives at src/adapters/memory/__tests__ - covered transitively')
})
