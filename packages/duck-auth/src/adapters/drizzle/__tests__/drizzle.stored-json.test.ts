/**
 * The parsers every dialect reads its JSON columns through.
 *
 * Lowest-covered file in the adapter tree at 61.5% statements and 50% branches, reached only
 * incidentally by whichever adapter suite happened to store a well-formed value. Every refusal
 * path - the ones that decide whether a malformed row is dropped, defaulted or lets `Invalid Date`
 * through - was unexercised.
 */

import { describe, expect, it } from 'vitest'
import {
  fromJsonColumn,
  isFactor,
  isProviderLink,
  parseActingAs,
  parseFactors,
  parseProviders,
  storedDate,
} from '../drizzle.stored-json'

/** What an unreadable date becomes: the epoch, never `Invalid Date`. */
const EPOCH = new Date(0)

describe('storedDate', () => {
  it('passes a usable Date straight back', () => {
    const date = new Date('2026-01-02T03:04:05.000Z')
    expect(storedDate(date)).toBe(date)
  })

  it('refuses an Invalid Date rather than passing it on', () => {
    // The whole reason this function exists: `new Date('nope')` satisfies `instanceof Date` and every
    // truthiness guard, then loses every comparison it takes part in.
    expect(storedDate(new Date('nope'))).toBeNull()
  })

  it('reads an ISO string', () => {
    expect(storedDate('2026-01-02T03:04:05.000Z')?.toISOString()).toBe('2026-01-02T03:04:05.000Z')
  })

  it('refuses a string that is not a date', () => {
    expect(storedDate('not a date')).toBeNull()
  })

  it('reads an epoch number', () => {
    expect(storedDate(0)).toEqual(EPOCH)
    expect(storedDate(1_767_322_445_000)?.getTime()).toBe(1_767_322_445_000)
  })

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['null', null],
    ['undefined', undefined],
    ['a boolean', true],
    ['an object', {}],
    ['an array', []],
  ])('refuses %s', (_label, value) => {
    expect(storedDate(value)).toBeNull()
  })
})

describe('isProviderLink', () => {
  it('accepts the pair a lookup matches on', () => {
    expect(isProviderLink({ providerId: 'github', providerSub: '1' })).toBe(true)
  })

  it.each([
    ['null', null],
    ['a string', 'github'],
    ['an object missing providerId', { providerSub: '1' }],
    ['an object missing providerSub', { providerId: 'github' }],
    ['a non-string providerId', { providerId: 1, providerSub: '1' }],
    ['a non-string providerSub', { providerId: 'github', providerSub: 1 }],
  ])('refuses %s', (_label, value) => {
    expect(isProviderLink(value)).toBe(false)
  })
})

describe('isFactor', () => {
  it('accepts a method in the union', () => {
    expect(isFactor({ method: 'passkey' })).toBe(true)
  })

  it.each([
    ['null', null],
    ['a string', 'passkey'],
    ['an object with no method', { completedAt: 0 }],
    ['a method outside the union', { method: 'carrier-pigeon' }],
  ])('refuses %s', (_label, value) => {
    expect(isFactor(value)).toBe(false)
  })
})

describe('parseProviders', () => {
  it('returns empty for anything that is not an array', () => {
    expect(parseProviders(null)).toEqual([])
    expect(parseProviders({ providerId: 'github', providerSub: '1' })).toEqual([])
  })

  it('drops a malformed entry and keeps the rest', () => {
    expect(parseProviders([{ providerId: 'github', providerSub: '1' }, { providerId: 'gitlab' }, null])).toEqual([
      { addedAt: expect.any(Date), providerId: 'github', providerSub: '1' },
    ])
  })

  it('keeps a link whose addedAt is unreadable, dated to the epoch', () => {
    // Dropping it would remove a way into the account; an epoch reads as the unknown it is.
    expect(parseProviders([{ addedAt: 'nope', providerId: 'github', providerSub: '1' }])).toEqual([
      { addedAt: EPOCH, providerId: 'github', providerSub: '1' },
    ])
  })

  it('reads only the three fields the row type has', () => {
    const [link] = parseProviders([{ providerId: 'github', providerSub: '1', stolen: 'yes' }])
    expect(link).not.toHaveProperty('stolen')
  })
})

describe('parseFactors', () => {
  it('returns empty for anything that is not an array', () => {
    expect(parseFactors(null)).toEqual([])
    expect(parseFactors('password')).toEqual([])
  })

  it('drops a method no switch handles, which would otherwise inflate eligibleAal', () => {
    expect(parseFactors([{ method: 'password' }, { method: 'carrier-pigeon' }])).toEqual([
      { completedAt: EPOCH, method: 'password' },
    ])
  })

  it('keeps a factor whose completedAt is unreadable, dated to the epoch', () => {
    expect(parseFactors([{ completedAt: {}, method: 'totp' }])).toEqual([{ completedAt: EPOCH, method: 'totp' }])
  })

  it('reads only the two fields the row type has', () => {
    const [factor] = parseFactors([{ completedAt: 0, method: 'totp', stolen: 'yes' }])
    expect(factor).not.toHaveProperty('stolen')
  })
})

describe('parseActingAs', () => {
  const window = {
    expiresAt: '2026-01-02T04:00:00.000Z',
    realIdentityId: 'admin',
    reason: 'support ticket 12',
    startedAt: '2026-01-02T03:00:00.000Z',
  }

  it('reads a complete window', () => {
    expect(parseActingAs(window)).toEqual({
      expiresAt: new Date('2026-01-02T04:00:00.000Z'),
      realIdentityId: 'admin',
      reason: 'support ticket 12',
      startedAt: new Date('2026-01-02T03:00:00.000Z'),
    })
  })

  it.each([
    ['null', null],
    ['a string', 'admin'],
    ['an unreadable startedAt', { ...window, startedAt: 'nope' }],
    ['an unreadable expiresAt', { ...window, expiresAt: undefined }],
    ['a non-string realIdentityId', { ...window, realIdentityId: 7 }],
    ['a non-string reason', { ...window, reason: null }],
  ])('drops the window whole for %s', (_label, value) => {
    // Never a fallback date: a window nobody can read the bounds of is not one anyone should be inside.
    expect(parseActingAs(value)).toBeNull()
  })
})

describe('fromJsonColumn', () => {
  it('passes an already-parsed value through, as pg and mysql2 hand it back', () => {
    const parsed = [{ providerId: 'github' }]
    expect(fromJsonColumn(parsed)).toBe(parsed)
    expect(fromJsonColumn(null)).toBeNull()
  })

  it('parses the raw TEXT sqlite hands back', () => {
    // A row must not read as `[]` on one driver and correctly on another.
    expect(fromJsonColumn('[{"providerId":"github"}]')).toEqual([{ providerId: 'github' }])
  })

  it('answers null for a string that is not JSON', () => {
    expect(fromJsonColumn('{ broken')).toBeNull()
  })
})
