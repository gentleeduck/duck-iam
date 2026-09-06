import { describe, expect, it } from 'vitest'
import { detectCatastrophicRegex, MAX_REGEX_INPUT_LENGTH, ops } from '../conditions.libs'

/**
 * The detector used to model only *exponential* blowup - nesting, alternation -
 * plus a cap of four unbounded quantifiers. Four *sibling* quantifiers sit
 * inside that cap and still backtrack polynomially: `^a+a+a+a+$` is O(n^4), and
 * `MAX_REGEX_INPUT_LENGTH` does not bound it because 2048^4 is astronomical. A
 * 513-character input already stalled the match for eight seconds, so a policy
 * author (or anyone who can get a pattern into a policy) had a DoS of the
 * authorization path that passed validation.
 */
const POLYNOMIAL = ['^a+a+a+a+$', '^[a-z]+[a-z]+[a-z]+[a-z]+$', '^\\d+\\d+$', '.*.*', '^.+.+$', '^a*a*$']

/**
 * Patterns with the same quantifier count but a mandatory separator between
 * them. Nothing is split between the quantifiers, so there is no blowup - and
 * these are the shapes real policies use, which is why the fix targets
 * adjacency rather than simply lowering the quantifier limit.
 */
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

  // Disjoint neighbours are the case adjacency alone would over-reject: `\d`
  // and `[a-z]` cannot both claim the same character, so no input is split
  // between them however long it gets.
  it('accepts adjacent quantifiers whose atoms cannot match the same character', () => {
    expect(detectCatastrophicRegex('^\\d+[a-z]+$').safe).toBe(true)
    expect(detectCatastrophicRegex('^[0-9]+[A-Z]+$').safe).toBe(true)
  })
})

describe('the `matches` operator refuses the polynomial pattern', () => {
  // The end-to-end statement of the bug: this call is what took 8s on a
  // 513-char input. It must now return without evaluating the regex at all.
  it('returns false quickly for a worst-case input', () => {
    const input = 'a'.repeat(MAX_REGEX_INPUT_LENGTH - 1) + '!'
    const started = Date.now()
    expect(ops.matches(input, '^a+a+a+a+$')).toBe(false)
    expect(Date.now() - started).toBeLessThan(1000)
  })

  // Control: a safe pattern still matches, so the assertion above is not just
  // "everything is rejected now".
  it('still evaluates a safe pattern', () => {
    expect(ops.matches('admin-42', '^admin-\\d+$')).toBe(true)
    expect(ops.matches('user-42', '^admin-\\d+$')).toBe(false)
  })
})
