/**
 * The credential predicates had no tests, and every one of them is a security
 * decision expressed as a boolean: is this credential revoked, is it expired, is
 * this account soft-deleted, is this profile flag actually true.
 *
 * Each is documented to fail closed, which is the part worth testing. A predicate
 * that answers "not expired" for a NaN timestamp, or "verified" for the string
 * `"true"`, is wrong in the direction that admits people.
 */
import { describe, expect, it } from 'vitest'
import {
  getProfileString,
  isCredentialExpired,
  isExpiredAt,
  isFiniteNumber,
  isProfileBooleanTrue,
  isRevoked,
  isSoftDeleted,
} from '../credentials'

const NOW = 1_700_000_000_000

describe('isExpiredAt', () => {
  describe('the live sentinel', () => {
    it('treats null as no expiry configured', () => {
      expect(isExpiredAt(null, NOW)).toBe(false)
    })

    it('treats undefined as no expiry configured', () => {
      expect(isExpiredAt(undefined, NOW)).toBe(false)
    })
  })

  describe('ordinary values', () => {
    it('is false for a future timestamp', () => {
      expect(isExpiredAt(NOW + 1000, NOW)).toBe(false)
    })

    it('is true for a past timestamp', () => {
      expect(isExpiredAt(NOW - 1, NOW)).toBe(true)
    })

    it('is false at exactly now, so the boundary is inclusive of the last instant', () => {
      expect(isExpiredAt(NOW, NOW)).toBe(false)
    })

    it('handles a future Date', () => {
      expect(isExpiredAt(new Date(NOW + 1000), NOW)).toBe(false)
    })

    it('handles a past Date', () => {
      expect(isExpiredAt(new Date(NOW - 1000), NOW)).toBe(true)
    })
  })

  describe('fails closed on anything it cannot read', () => {
    // Each of these would be "not expired" under a naive `value < now`, because
    // every comparison with NaN is false. That is the bug this function exists to
    // avoid, so each case is worth its own line.
    for (const [label, value] of [
      ['NaN', Number.NaN],
      ['Infinity', Number.POSITIVE_INFINITY],
      ['negative Infinity', Number.NEGATIVE_INFINITY],
      ['a numeric string', '1700000000000'],
      ['a non-numeric string', 'never'],
      ['an empty string', ''],
      ['true', true],
      ['false', false],
      ['an array', [NOW + 1000]],
      ['an object', { time: NOW + 1000 }],
      ['a function', () => NOW + 1000],
      ['a symbol', Symbol('later')],
      ['a bigint', 10n],
    ] as const) {
      it(`treats ${label} as expired`, () => {
        expect(isExpiredAt(value, NOW)).toBe(true)
      })
    }

    it('treats an invalid Date as expired', () => {
      expect(isExpiredAt(new Date(Number.NaN), NOW)).toBe(true)
    })

    it('treats a Date built from a non-finite number as expired', () => {
      expect(isExpiredAt(new Date(Number.POSITIVE_INFINITY), NOW)).toBe(true)
    })
  })

  it('defaults `now` to the current clock', () => {
    expect(isExpiredAt(Date.now() + 60_000)).toBe(false)
    expect(isExpiredAt(Date.now() - 60_000)).toBe(true)
  })
})

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

describe('isSoftDeleted', () => {
  it('is false when deletedAt is null or absent', () => {
    expect(isSoftDeleted({ deletedAt: null })).toBe(false)
    expect(isSoftDeleted({})).toBe(false)
  })

  it('is true when deletedAt is set', () => {
    expect(isSoftDeleted({ deletedAt: new Date() })).toBe(true)
  })

  it('is true for a deletedAt in the future, which is how the grace period is stored', () => {
    // `softDelete(id, gracePeriodMs)` writes now + grace, so a future value is the
    // normal case and must still hide the row.
    expect(isSoftDeleted({ deletedAt: new Date(Date.now() + 60_000) })).toBe(true)
  })

  it('accepts a numeric timestamp as well as a Date', () => {
    expect(isSoftDeleted({ deletedAt: Date.now() })).toBe(true)
  })
})

describe('isFiniteNumber', () => {
  it('accepts ordinary numbers including zero and negatives', () => {
    for (const n of [0, -0, 1, -1, 1.5, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]) {
      expect(isFiniteNumber(n)).toBe(true)
    }
  })

  it('rejects the non-finite numbers', () => {
    for (const n of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(isFiniteNumber(n)).toBe(false)
    }
  })

  it('rejects things that merely look numeric', () => {
    for (const v of ['1', '', null, undefined, true, false, [], [1], {}, 1n, new Number(1)]) {
      expect(isFiniteNumber(v)).toBe(false)
    }
  })
})

describe('getProfileString', () => {
  it('reads a non-empty string field', () => {
    expect(getProfileString({ email: 'a@x.com' }, 'email')).toBe('a@x.com')
  })

  it('returns undefined for an empty string, which is not a usable value', () => {
    expect(getProfileString({ email: '' }, 'email')).toBeUndefined()
  })

  it('returns undefined when the field is any non-string', () => {
    for (const value of [42, true, null, undefined, [], {}, () => 'x']) {
      expect(getProfileString({ email: value }, 'email')).toBeUndefined()
    }
  })

  it('returns undefined when the profile is not a plain object', () => {
    for (const profile of [null, undefined, 'string', 42, true, ['a@x.com']]) {
      expect(getProfileString(profile, 'email')).toBeUndefined()
    }
  })

  it('returns undefined for a key that is absent', () => {
    expect(getProfileString({ email: 'a@x.com' }, 'username')).toBeUndefined()
  })

  it('does not read up the prototype chain', () => {
    // A key inherited from Object.prototype is not profile data.
    expect(getProfileString({}, 'toString')).toBeUndefined()
    expect(getProfileString({}, 'constructor')).toBeUndefined()
  })

  it('reads a key that shadows a prototype member when it is genuinely present', () => {
    expect(getProfileString({ toString: 'shadowed' }, 'toString')).toBe('shadowed')
  })
})

describe('isProfileBooleanTrue', () => {
  it('is true only for the boolean true', () => {
    expect(isProfileBooleanTrue({ emailVerified: true }, 'emailVerified')).toBe(true)
  })

  it('is false for every truthy impostor', () => {
    // `"true"`, `1` and `"yes"` all pass a loose check and all mean nothing. A
    // verified-email gate reading one of these would admit an unverified account.
    for (const value of ['true', 'TRUE', 1, -1, 'yes', [], {}, 'false', new Boolean(true)]) {
      expect(isProfileBooleanTrue({ emailVerified: value }, 'emailVerified')).toBe(false)
    }
  })

  it('is false for the falsy values', () => {
    for (const value of [false, 0, '', null, undefined, Number.NaN]) {
      expect(isProfileBooleanTrue({ emailVerified: value }, 'emailVerified')).toBe(false)
    }
  })

  it('is false when the profile is not a plain object', () => {
    for (const profile of [null, undefined, 'true', 1, true, [true]]) {
      expect(isProfileBooleanTrue(profile, 'emailVerified')).toBe(false)
    }
  })

  it('is false for an absent key', () => {
    expect(isProfileBooleanTrue({}, 'emailVerified')).toBe(false)
  })
})
