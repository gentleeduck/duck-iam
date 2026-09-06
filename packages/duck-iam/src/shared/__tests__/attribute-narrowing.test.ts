import { describe, expect, it } from 'vitest'
import { iamIsAttributeValue, iamNarrowAttributes } from '../attributes'

/**
 * The adapters used to conclude `v as IamPrimitives.AttributeValue` inside a
 * per-key loop having checked only that the *bag* was an object. A value the
 * type forbids therefore reached the condition operators typed as one, on all
 * six backends.
 */
describe('iamIsAttributeValue', () => {
  it.each([
    ['a string', 'x'],
    ['a number', 1],
    ['zero', 0],
    ['a boolean', false],
    ['null', null],
    ['an array of scalars', ['a', 1, true, null]],
    ['an empty array', []],
    ['a flat record of scalars', { a: 1, b: 'two' }],
    ['an empty record', {}],
  ])('accepts %s', (_label, value) => {
    expect(iamIsAttributeValue(value)).toBe(true)
  })

  it.each([
    ['a nested object', { a: { b: 1 } }],
    ['an array of objects', [{ a: 1 }]],
    ['an array of arrays', [[1]]],
    ['a record holding an array', { a: [1] }],
    ['undefined', undefined],
    ['a function', () => 1],
    ['a Date', new Date(0)],
  ])('rejects %s', (_label, value) => {
    expect(iamIsAttributeValue(value)).toBe(false)
  })
})

describe('iamNarrowAttributes', () => {
  it('returns a fresh bag for a valid one', () => {
    const source = { level: 5, tags: ['a', 'b'], tier: 'gold' }
    const out = iamNarrowAttributes(source)
    expect(out).toEqual(source)
    expect(out).not.toBe(source)
  })

  it.each([
    ['a string', '"abc"'],
    ['an array', '[1]'],
    ['null', 'null'],
    ['a number', '7'],
  ])('rejects %s as a bag', (_label, json) => {
    expect(iamNarrowAttributes(JSON.parse(json))).toBeNull()
  })

  /**
   * The whole bag, not just the offending key. Dropping one key makes that
   * attribute read as *absent*, and an absent attribute retires every deny rule
   * that tests it - the same silent-bypass shape the file adapter's
   * "Corruption != empty" throw already guards against.
   */
  it('refuses the whole bag when one value is not storable', () => {
    expect(iamNarrowAttributes({ nested: { deep: { deeper: 1 } }, tier: 'gold' })).toBeNull()
  })

  it('control: the same bag without the bad key is accepted', () => {
    expect(iamNarrowAttributes({ tier: 'gold' })).toEqual({ tier: 'gold' })
  })
})
