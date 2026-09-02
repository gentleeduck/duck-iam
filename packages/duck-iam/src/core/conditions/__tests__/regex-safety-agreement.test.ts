import { describe, expect, it } from 'vitest'
import { detectCatastrophicRegex, evalMatchesOp, getCachedRegex } from '../conditions.libs'

/**
 * Validate-time and evaluate-time must refuse exactly the same patterns. When
 * they disagree, a pattern accepted by `admin.import` returns `null` at
 * evaluation time and a deny rule built on it silently never matches.
 */
const SYNTACTICALLY_VALID = [
  '^admin$',
  'curl',
  '(https?)://example',
  '(https?)*',
  '(foo|bar)+',
  '(a+)+',
  '(a*)*',
  '(a|aa)+',
  '\\d{4}-\\d{2}',
  'a{1,2000}',
  '(\\w+)\\1+',
  '(?=(a+)+)b',
  'a*b*c*d*e*f*',
  '[a-z]+@[a-z]+',
]

describe('regex safety: one predicate, two call sites', () => {
  it.each(SYNTACTICALLY_VALID)('agrees on %s', (pattern) => {
    const safe = detectCatastrophicRegex(pattern).safe
    expect(getCachedRegex(pattern, new Map()) !== null).toBe(safe)
  })

  it('refuses the shapes the naive nested-quantifier check used to miss', () => {
    expect(detectCatastrophicRegex('(\\w+)\\1+').safe).toBe(false)
    expect(detectCatastrophicRegex('(?=(a+)+)b').safe).toBe(false)
    expect(detectCatastrophicRegex('a{1,2000}').safe).toBe(false)
  })

  it('accepts the shape the naive check used to wrongly refuse', () => {
    expect(detectCatastrophicRegex('(https?)*').safe).toBe(true)
    expect(getCachedRegex('(https?)*', new Map())).not.toBeNull()
    expect(evalMatchesOp('https', '(https?)*', new Map())).toBe(true)
  })

  it('a refused pattern never reaches new RegExp', () => {
    const cache = new Map<string, RegExp>()
    expect(getCachedRegex('(a+)+', cache)).toBeNull()
    expect(cache.size).toBe(0)
  })
})
