// A `matches` pattern `validatePolicy` accepts must compile at evaluation, where an uncompilable one is refused as
// Indeterminate (`IamPatternRefusedError`). This agreement keeps that path rare.
import { describe, expect, it } from 'vitest'
import { evalCondition, getCachedRegex } from '../../conditions/conditions.libs'
import type { IamRequest } from '../../types'
import { validatePolicy } from '../validate'

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

/** Refused by the detector: nested/overlapping quantifiers, an oversized bound, or too many unbounded quantifiers. */
const REFUSED = ['(a+)+', '(a*)*', '(a|aa)+', '(\\w+)\\1+', '(?=(a+)+)b', 'a{1,2000}', 'a*b*c*d*e*f*']

/** Syntactically invalid. */
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

// SECURITY: a `$`-sourced pattern is a ReDoS vector: refused at validate time, and Indeterminate (not `false`) at
// evaluation, so a deny rule seeded past the validator can't quietly stop denying.
describe('a `$`-sourced `matches` operand is refused rather than silently inert', () => {
  const req: IamRequest.IAccessRequest = {
    action: 'read',
    environment: {},
    resource: { attributes: { path: 'anything' }, type: 'post' },
    subject: { attributes: { pattern: '^anything$' }, id: 'u1', roles: [] },
  }

  const USER_SOURCED = ['$subject.attributes.pattern', '$resource.attributes.p', '$environment.p', '$']

  for (const pattern of USER_SOURCED) {
    it(`rejects ${JSON.stringify(pattern)} at validate time`, () => {
      expect(acceptsPattern(pattern)).toBe(false)
    })

    it(`${JSON.stringify(pattern)} is Indeterminate at evaluation time, not false`, () => {
      // The operand would match the field, so `false` here would mean "will not answer", not "did not match".
      expect(() =>
        evalCondition(req, { field: 'resource.attributes.path', operator: 'matches', value: pattern }),
      ).toThrow(/Indeterminate/)
    })
  }

  it('a literal pattern that does match is still true - the refusal is specific to `$`', () => {
    expect(evalCondition(req, { field: 'resource.attributes.path', operator: 'matches', value: '^anything$' })).toBe(
      true,
    )
    expect(acceptsPattern('^anything$')).toBe(true)
  })
})
