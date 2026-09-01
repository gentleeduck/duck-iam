import { describe, expect, it } from 'vitest'
import { getUserinfoBooleanTrue, getUserinfoNumericIdAsString, getUserinfoString } from '../core/userinfo'

describe('getUserinfoString', () => {
  it('returns the string for a well-formed field', () => {
    expect(getUserinfoString({ sub: 'abc' }, 'sub')).toBe('abc')
  })

  it.each<[unknown]>([[null], [undefined], ['oops'], [42], [true], [[{ sub: 'abc' }]]])(
    'returns undefined when info is not a plain object: %p',
    (info) => {
      expect(getUserinfoString(info, 'sub')).toBeUndefined()
    },
  )

  it.each<[unknown]>([
    [null],
    [undefined],
    [42],
    [true],
    [['array']],
    [{ nested: 'object' }],
    [''], // empty-string fails the non-empty contract
  ])('returns undefined when the value is %p (non-string or empty)', (val) => {
    expect(getUserinfoString({ sub: val }, 'sub')).toBeUndefined()
  })

  it('does not match unrelated keys', () => {
    expect(getUserinfoString({ email: 'a@x' }, 'sub')).toBeUndefined()
  })
})

describe('getUserinfoNumericIdAsString - the GitHub bug', () => {
  it('coerces a finite numeric id to a string', () => {
    expect(getUserinfoNumericIdAsString({ id: 12345 }, 'id')).toBe('12345')
  })

  it('returns undefined when id is null (the multi-account-collapse case)', () => {
    expect(getUserinfoNumericIdAsString({ id: null }, 'id')).toBeUndefined()
  })

  it('returns undefined for non-finite numbers', () => {
    expect(getUserinfoNumericIdAsString({ id: NaN }, 'id')).toBeUndefined()
    expect(getUserinfoNumericIdAsString({ id: Infinity }, 'id')).toBeUndefined()
    expect(getUserinfoNumericIdAsString({ id: -Infinity }, 'id')).toBeUndefined()
  })

  it('returns undefined for string id (would be wrong for GitHub)', () => {
    expect(getUserinfoNumericIdAsString({ id: '12345' }, 'id')).toBeUndefined()
  })

  it('returns undefined when info is not a plain object', () => {
    expect(getUserinfoNumericIdAsString(null, 'id')).toBeUndefined()
    expect(getUserinfoNumericIdAsString([12345], 'id')).toBeUndefined()
  })
})

describe('getUserinfoBooleanTrue', () => {
  it('returns true ONLY for strict === true', () => {
    expect(getUserinfoBooleanTrue({ verified: true }, 'verified')).toBe(true)
  })

  it.each<[unknown]>([
    ['true'], // string, NOT boolean
    [1],
    ['yes'],
    [{}],
    [[true]],
  ])('returns false for truthy-but-non-boolean: %p', (val) => {
    expect(getUserinfoBooleanTrue({ verified: val }, 'verified')).toBe(false)
  })

  it.each<[unknown]>([[false], [0], [null], [undefined], ['']])('returns false for falsy values: %p', (val) => {
    expect(getUserinfoBooleanTrue({ verified: val }, 'verified')).toBe(false)
  })

  it('returns false when info is not a plain object', () => {
    expect(getUserinfoBooleanTrue(null, 'verified')).toBe(false)
    expect(getUserinfoBooleanTrue('true', 'verified')).toBe(false)
  })
})
