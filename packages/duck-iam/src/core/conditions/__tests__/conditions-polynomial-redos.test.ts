import { describe, expect, it } from 'vitest'
import { detectCatastrophicRegex, MAX_REGEX_INPUT_LENGTH, ops } from '../conditions.libs'

/** Sibling quantifiers under the count cap that still backtrack polynomially; the input cap does not bound O(n^4). */
const POLYNOMIAL = ['^a+a+a+a+$', '^[a-z]+[a-z]+[a-z]+[a-z]+$', '^\\d+\\d+$', '.*.*', '^.+.+$', '^a*a*$']

/** Same quantifier count, but separated so no input is split between them; real policies use these shapes. */
const LEGITIMATE = [
  '^[a-z]+@[a-z]+\\.[a-z]+$',
  '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$',
  '^/api/.*/users/.*$',
  '^a+b+$',
  '^[a-z]+[0-9]+$',
  '^\\w+\\s*$',
  '^v\\d+\\.\\d+$',
  '^(foo|bar)-\\w+$',
  '^admin.*$',
  'curl',
]

describe('detectCatastrophicRegex: adjacent unbounded quantifiers', () => {
  it.each(POLYNOMIAL)('rejects %s', (pattern) => {
    const result = detectCatastrophicRegex(pattern)
    expect(result.safe).toBe(false)
    expect(result.reason).toMatch(/polynomial backtracking/)
  })

  it.each(LEGITIMATE)('still accepts %s', (pattern) => {
    expect(detectCatastrophicRegex(pattern)).toEqual({ safe: true })
  })

  // `\d` and `[a-z]` cannot claim the same character, so adjacency alone must not be refused.
  it('accepts adjacent quantifiers whose atoms cannot match the same character', () => {
    expect(detectCatastrophicRegex('^\\d+[a-z]+$').safe).toBe(true)
    expect(detectCatastrophicRegex('^[0-9]+[A-Z]+$').safe).toBe(true)
  })
})

describe('the `matches` operator refuses the polynomial pattern', () => {
  // Refuses without running the regex, and throws rather than answering `false` so a deny rule keeps denying.
  it('refuses a worst-case input quickly, without compiling', () => {
    const input = 'a'.repeat(MAX_REGEX_INPUT_LENGTH - 1) + '!'
    const started = Date.now()
    expect(() => ops.matches(input, '^a+a+a+a+$')).toThrow(/Indeterminate/)
    expect(Date.now() - started).toBeLessThan(1000)
  })

  // Control: the assertion above is not just "everything is rejected".
  it('still evaluates a safe pattern', () => {
    expect(ops.matches('admin-42', '^admin-\\d+$')).toBe(true)
    expect(ops.matches('user-42', '^admin-\\d+$')).toBe(false)
  })
})
