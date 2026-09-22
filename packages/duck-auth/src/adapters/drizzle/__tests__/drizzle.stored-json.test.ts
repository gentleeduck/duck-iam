/** The parsers every dialect reads its JSON columns through. */

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
      { addedAt: expect.any(Date), addedBy: null, providerId: 'github', providerSub: '1' },
    ])
  })

  it('keeps a link whose addedAt is unreadable, dated to the epoch', () => {
    // Dropping it would remove a way into the account; an epoch reads as the unknown it is.
    expect(parseProviders([{ addedAt: 'nope', providerId: 'github', providerSub: '1' }])).toEqual([
      { addedAt: EPOCH, addedBy: null, providerId: 'github', providerSub: '1' },
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
    ['undefined', undefined],
  ])('reads %s as no impersonation, which is what an empty column means', (_label, value) => {
    expect(parseActingAs(value)).toBeNull()
  })

  it.each([
    ['a string', 'admin'],
    ['an unreadable startedAt', { ...window, startedAt: 'nope' }],
    ['an unreadable expiresAt', { ...window, expiresAt: undefined }],
    ['a non-string realIdentityId', { ...window, realIdentityId: 7 }],
    ['a non-string reason', { ...window, reason: null }],
  ])('refuses the session whole for %s, rather than answering no impersonation', (_label, value) => {
    // Never a fallback date, and never `null` either: `null` is the answer for a session that was never
    // an impersonation, so returning it here loads the session as an ordinary one belonging to the
    // person being impersonated - the expiry cap gone, and the audit envelope naming the real admin
    // gone with it. The redis store already refuses the whole read for this; the dialects now match.
    expect(() => parseActingAs(value)).toThrow(expect.objectContaining({ code: 'AUTH_SESSION_REVOKED' }))
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

  it('hands back the unparseable string rather than laundering it into an empty column', () => {
    // `null` here would be a lie the parsers cannot see through: a SQL NULL already arrives as `null`
    // and returns above, so answering it for unparseable TEXT makes a corrupt column indistinguishable
    // from an absent one. Left as the string, it is still *present*, and each parser applies its own
    // policy - `parseFactors` degrades, `parseActingAs` refuses.
    expect(fromJsonColumn('{ broken')).toBe('{ broken')
  })

  it('refuses an impersonation window whose TEXT will not parse, which is every sqlite read', () => {
    // sqlite hands every JSON column back as raw TEXT, so this composition is the only thing standing
    // between a corrupt `acting_as` and a session that loads as an ordinary one for the impersonated
    // person. pg and mysql reach it too whenever a column is read as text.
    expect(() => parseActingAs(fromJsonColumn('{ broken'))).toThrow(
      expect.objectContaining({ code: 'AUTH_SESSION_REVOKED' }),
    )
  })

  it('still degrades an unparseable factor list to empty, which only lowers the AAL claimed', () => {
    expect(parseFactors(fromJsonColumn('{ broken'))).toEqual([])
  })
})
