import { describe, expect, it } from 'vitest'
import { getCachedRegex } from '../../conditions/conditions.libs'
import { validatePolicy } from '../validate'

/**
 * `regex-safety-agreement.test.ts` pins `detectCatastrophicRegex` against
 * `getCachedRegex`, which is trivially true - the second calls the first. The
 * invariant that actually matters is one level up: a `matches` pattern
 * `validatePolicy` accepts must compile at evaluation time. When it does not,
 * `evalMatchesOp` gets `null` back and returns `false`, which retires a
 * `deny`-when-`matches` rule outright with nothing logged.
 */
function acceptsPattern(pattern: string): boolean {
  return validatePolicy({
    algorithm: 'first-match',
    id: 'p',
    name: 'p',
    rules: [
      {
        actions: ['read'],
        conditions: { all: [{ field: 'subject.attributes.ua', operator: 'matches', value: pattern }] },
        effect: 'deny',
        id: 'r',
        priority: 1,
        resources: ['post'],
      },
    ],
  }).valid
}

/** Safe and compilable. */
const ACCEPTED = [
  '^admin$',
  'curl',
  '(https?)://example',
  '(https?)*',
  '[a-z]+@[a-z]+',
  '\\d{4}-\\d{2}',
  '(?:ab)+',
  '[\\]]+',
  'a*b*c*',
]

/** Refused by the detector - nested/overlapping quantifiers, an oversized bound, or more unbounded quantifiers than the budget. */
const REFUSED = ['(a+)+', '(a*)*', '(a|aa)+', '(\\w+)\\1+', '(?=(a+)+)b', 'a{1,2000}', 'a*b*c*d*e*f*']

/** Syntactically invalid - a corpus the older agreement test had none of. */
const UNCOMPILABLE = ['[', '(', ')', 'a{2,1}', '\\', '[z-a]', '(?<', '*abc', 'a**']

describe('a `matches` pattern the validator accepts compiles at evaluation time', () => {
  it.each([...ACCEPTED, ...REFUSED, ...UNCOMPILABLE])('agrees on %j', (pattern) => {
    expect(acceptsPattern(pattern)).toBe(getCachedRegex(pattern, new Map()) !== null)
  })

  // Controls: without these the equivalence above would also hold if every
  // pattern were refused, or every pattern accepted.
  it('accepts the safe corpus', () => {
    expect(ACCEPTED.filter((p) => !acceptsPattern(p))).toEqual([])
  })

  it('refuses the detector corpus', () => {
    for (const pattern of REFUSED) {
      expect(acceptsPattern(pattern)).toBe(false)
    }
  })

  it('refuses the uncompilable corpus', () => {
    for (const pattern of UNCOMPILABLE) {
      expect(acceptsPattern(pattern)).toBe(false)
    }
  })

  it('names the two failures apart, so an operator can tell a typo from a ReDoS', () => {
    const codesFor = (pattern: string): string[] =>
      validatePolicy({
        algorithm: 'first-match',
        id: 'p',
        name: 'p',
        rules: [
          {
            actions: ['read'],
            conditions: { all: [{ field: 'subject.attributes.ua', operator: 'matches', value: pattern }] },
            effect: 'deny',
            id: 'r',
            priority: 1,
            resources: ['post'],
          },
        ],
      }).issues.map((i) => i.code)
    expect(codesFor('(a+)+')).toContain('ERR_REGEX_CATASTROPHIC')
    expect(codesFor('[')).toContain('ERR_REGEX_INVALID')
  })
})
