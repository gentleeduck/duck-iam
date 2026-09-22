/**
 * One address has more than one spelling. Case is folded by `lower()` in every dialect's unique
 * index; composition is folded by none of them, so two byte strings that read as one name are two
 * accounts unless the library settles the spelling before the row is written.
 */
import { describe, expect, it } from 'vitest'
import { canonicalEmail, emailSpellings, toEmailList, withNormalisedEmail } from '../identities.constants'

const NFC = 'café@x.com'
const NFD = 'café@x.com'

describe('canonicalEmail', () => {
  it('trims, lowercases and composes', () => {
    expect(canonicalEmail(`  CAFÉ@X.COM `)).toBe(NFC)
  })

  it('gives one answer for both spellings', () => {
    expect(canonicalEmail(NFD)).toBe(canonicalEmail(NFC))
  })

  it('has no answer for what is not an address', () => {
    expect(canonicalEmail('   ')).toBeNull()
    expect(canonicalEmail('')).toBeNull()
    expect(canonicalEmail(undefined)).toBeNull()
    expect(canonicalEmail(12)).toBeNull()
  })
})

describe('emailSpellings', () => {
  it('is the canonical form alone when that is how it arrived', () => {
    expect(emailSpellings(NFC)).toEqual([NFC])
  })

  it('carries the spelling as stored behind it, for a row written before addresses were normalised', () => {
    expect(emailSpellings(NFD)).toEqual([NFC, NFD])
  })

  it('has no answer for what is not an address', () => {
    expect(emailSpellings('  ')).toBeNull()
  })
})

describe('toEmailList', () => {
  it('answers every spelling of the one address it is given', () => {
    expect(toEmailList(NFC)).toEqual([NFC])
    expect(toEmailList(NFD)).toEqual([NFC, NFD])
  })

  it("answers [''] for a blank address, so the lookup matches nothing instead of no condition at all", () => {
    expect(toEmailList('  ')).toEqual([''])
  })
})

describe('withNormalisedEmail', () => {
  it('composes the address it is about to store', () => {
    expect(withNormalisedEmail({ profile: { email: NFD } }).profile.email).toBe(NFC)
  })

  it('folds case, because the index cannot be relied on to', () => {
    // RFC 5321 does leave the local part to the holder to spell, and this package has never taken that
    // reading: `toEmailList` looks up in lowercase and all three dialects index `lower(...)`. What was new
    // is that sqlite's `lower()` is ASCII-only, so leaving case to the index there meant nothing folded it
    // at all and the row became unfindable. Fold on the way in and every dialect is holding one spelling.
    expect(withNormalisedEmail({ profile: { email: 'Ada@x.com' } }).profile.email).toBe('ada@x.com')
  })

  it('hands back the same object when there is nothing to change', () => {
    const write = { profile: { email: NFC } }
    expect(withNormalisedEmail(write)).toBe(write)
  })

  it('passes through a write with no profile, or none with an address in it', () => {
    const noProfile: { emailVerified: boolean; profile?: unknown } = { emailVerified: true }
    expect(withNormalisedEmail(noProfile)).toBe(noProfile)
    const noEmail = { profile: { username: 'ada' } }
    expect(withNormalisedEmail(noEmail)).toBe(noEmail)
    const notAString = { profile: { email: 12 } }
    expect(withNormalisedEmail(notAString)).toBe(notAString)
  })
})
