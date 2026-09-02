import { describe, expect, it } from 'vitest'
import { matchesScope } from '../resolve'

/**
 * One contract for scope: `undefined`/`null` and `'*'` are global, and every
 * other string, `''` included, is an ordinary scope value. `''` used to read as
 * global on the pattern side, which turned a row that looks scoped into a grant
 * across every scope.
 */
describe('matchesScope treats an empty scope as a value, not a wildcard', () => {
  it.each([
    [undefined, 'org-1'],
    [null, 'org-1'],
    ['*', 'org-1'],
    [undefined, undefined],
    ['*', undefined],
  ])('global pattern %s matches scope %s', (pattern, scope) => {
    expect(matchesScope(pattern, scope)).toBe(true)
  })

  it('an empty pattern no longer matches every scope', () => {
    expect(matchesScope('', 'org-1')).toBe(false)
    expect(matchesScope('', 'org-2')).toBe(false)
    expect(matchesScope('', undefined)).toBe(false)
  })

  it('an empty pattern still matches an empty scope exactly', () => {
    expect(matchesScope('', '')).toBe(true)
  })

  it('a scoped pattern needs an exact scope', () => {
    expect(matchesScope('org-1', 'org-1')).toBe(true)
    expect(matchesScope('org-1', 'org-2')).toBe(false)
    expect(matchesScope('org-1', undefined)).toBe(false)
    expect(matchesScope('org-1', '')).toBe(false)
  })
})
