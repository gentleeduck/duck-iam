import { describe, expect, it } from 'vitest'
import { detectCatastrophicRegex } from '../conditions.libs'

/**
 * The detector refused the shapes deny guards are actually written in. Two
 * separate causes: a blanket ban on any quantifier inside a lookaround, and a
 * body scan that stripped escapes but not character classes, so a literal `*`
 * in `[a-z0-9*-]` read as a quantifier. Every pattern below runs in well under
 * a millisecond on a 2048-char adversarial input.
 */
describe('detectCatastrophicRegex accepts safe lookaround guards', () => {
  it.each([
    ['exclude a substring', '^(?!.*admin).*$'],
    ['require a substring', '^(?=.*:).+$'],
    ['require two character classes', '^(?=.*[A-Z])(?=.*\\d).{8,64}$'],
    ['negative lookahead with a class', '^(?![a-z]*root).+$'],
    ['lookbehind with a quantifier', '(?<=a+)b'],
  ])('accepts %s', (_name, pattern) => {
    const result = detectCatastrophicRegex(pattern)
    expect(result.safe).toBe(true)
  })

  it('still refuses a quantified group inside a lookahead', () => {
    const r = detectCatastrophicRegex('(?=(a+)+)')
    expect(r.safe).toBe(false)
    expect(r.reason).toBe('lookaround-with-quantified-group')
  })

  it('still refuses a quantified group inside a lookbehind', () => {
    expect(detectCatastrophicRegex('(?<=(a*)*)').safe).toBe(false)
  })

  it('still refuses a quantified group whose quantifier is `{n,}`', () => {
    expect(detectCatastrophicRegex('(?=(a+){2,})').safe).toBe(false)
  })
})

describe('detectCatastrophicRegex reads a character class as literals', () => {
  it.each([
    ['glob-shaped resource name', '^([a-z0-9*-])+$'],
    ['a literal + in a class', '^([a-z+])+$'],
    ['a literal brace range in a class', '^([a-z{2,3}])+$'],
    ['a literal pipe in a class', '^([a|b])+$'],
    ['an escaped bracket inside a class', '^([a\\]b])+$'],
  ])('accepts %s', (_name, pattern) => {
    expect(detectCatastrophicRegex(pattern).safe).toBe(true)
  })

  it('does not count a literal `*` in a class toward the unbounded limit', () => {
    // Five literal `*` in classes plus four real quantifiers is still four.
    expect(detectCatastrophicRegex('^[*]a+[*]b+[*]c+[*]d+[*]$').safe).toBe(true)
  })

  // Control: a real nested quantifier outside a class is still refused, so the
  // class strip did not turn the whole scan off.
  it('still refuses a real nested quantifier', () => {
    expect(detectCatastrophicRegex('^(a+)+$').safe).toBe(false)
  })

  it('still refuses a real nested quantifier next to a class', () => {
    expect(detectCatastrophicRegex('^([a-z]+)+$').safe).toBe(false)
  })

  // Control: a real quantifier outside the class still counts toward the cap.
  it('still counts real unbounded quantifiers past the limit', () => {
    expect(detectCatastrophicRegex('^a+b+c+d+e+$').safe).toBe(false)
  })
})

/**
 * The accepted patterns must actually be fast, or "accept" is the wrong call.
 * Each runs against the longest input the engine will ever hand a regex.
 */
describe('the newly-accepted patterns are linear on adversarial input', () => {
  const hostile = 'a'.repeat(2048)

  it.each(['^(?!.*admin).*$', '^(?=.*:).+$', '^([a-z0-9*-])+$'])('%s finishes promptly', (pattern) => {
    const re = new RegExp(pattern)
    const t0 = performance.now()
    re.test(hostile)
    expect(performance.now() - t0).toBeLessThan(100)
  })
})
