import { describe, expect, it } from 'vitest'
import { evalCondition, getCachedRegex } from '../../conditions/conditions.libs'
import type { IamRequest } from '../../types'
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

/**
 * The same invariant from the direction the corpora above cannot reach. A
 * `$`-prefixed operand is refused by `evalCondition` outright - deliberately,
 * because an attacker who controls the referenced attribute would otherwise pin
 * in a catastrophic regex - so the condition is `false` for every request that
 * will ever arrive. It is inert by construction.
 *
 * `validate.libs.ts` skips these with the comment "Non-string / $-resolved
 * values are caught elsewhere". Nothing catches them: `isUserSourcedValue`
 * appears only in `conditions.libs.ts`. So a `deny`-when-`matches` rule written
 * against a request attribute validates clean, stores clean, and never fires -
 * which is the exact outcome this file exists to prevent, arrived at by a
 * different road.
 */
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

    it(`${JSON.stringify(pattern)} is in fact inert at evaluation time`, () => {
      // Not parity for its own sake: this is why the rejection above has to
      // exist. The operand resolves to a pattern that matches the field, and
      // the condition is still false - so a deny rule carrying it never denies.
      expect(evalCondition(req, { field: 'resource.attributes.path', operator: 'matches', value: pattern })).toBe(false)
    })
  }

  it('a literal pattern that does match is still true - the refusal is specific to `$`', () => {
    expect(evalCondition(req, { field: 'resource.attributes.path', operator: 'matches', value: '^anything$' })).toBe(
      true,
    )
    expect(acceptsPattern('^anything$')).toBe(true)
  })
})
