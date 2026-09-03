import { describe, expect, it, vi } from 'vitest'
import { evaluate, evaluateFast } from '../../evaluate/evaluate'
import type { AccessControl, IamRequest } from '../../types'
import { evalConditionGroup } from '../conditions'
import { evalCondition } from '../conditions.libs'

/**
 * `evalCondition`'s first line refuses a `$`-resolved operand for `matches`,
 * because letting one through hands the regex source to whoever controls the
 * attribute it resolves from - a subject attribute is enough to pin in a
 * catastrophic pattern the validator screened. Mutation testing replaced that
 * line with `if (false)` and all 2000 tests still passed: the control that the
 * JSDoc calls the ReDoS defence had no assertion anywhere.
 */
function request(pattern: string, ua: string): IamRequest.IAccessRequest {
  return {
    action: 'read',
    environment: {},
    resource: { attributes: {}, type: 'post' },
    subject: { attributes: { pattern, ua }, id: 'u1', roles: [] },
  }
}

const USER_SOURCED: AccessControl.ICondition = {
  field: 'subject.attributes.ua',
  operator: 'matches',
  value: '$subject.attributes.pattern',
}

describe('`matches` refuses a $-resolved pattern', () => {
  it('returns false even when the resolved pattern would have matched', () => {
    expect(evalCondition(request('^curl', 'curl/8.0'), USER_SOURCED)).toBe(false)
  })

  // Control: the same field and the same effective pattern, written literally
  // by the policy author, does match. Without this the assertion above would
  // pass on any `matches` failure at all.
  it('control: the same pattern written literally does match', () => {
    expect(
      evalCondition(request('^curl', 'curl/8.0'), {
        field: 'subject.attributes.ua',
        operator: 'matches',
        value: '^curl',
      }),
    ).toBe(true)
  })

  it('refuses it inside a group, in every combinator', () => {
    const req = request('^curl', 'curl/8.0')
    expect(evalConditionGroup(req, { all: [USER_SOURCED] }, 0)).toBe(false)
    expect(evalConditionGroup(req, { any: [USER_SOURCED] }, 0)).toBe(false)
    expect(evalConditionGroup(req, { none: [USER_SOURCED] }, 0)).toBe(true)
  })

  // The refusal is a fixed `false`, so an *allow* rule built on it stops
  // granting - the safe direction - and a *deny* rule built on it stops
  // denying. The second is why the pattern must be refused at validate time
  // too, not only here.
  it('retires an allow rule that depends on it', () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'first-match',
      id: 'p',
      name: 'p',
      rules: [
        {
          actions: ['read'],
          conditions: { all: [USER_SOURCED] },
          effect: 'allow',
          id: 'r',
          priority: 1,
          resources: ['post'],
        },
      ],
    }
    expect(evaluate([policy], request('^curl', 'curl/8.0'), 'deny', 'and', vi.fn()).allowed).toBe(false)
  })

  it('both engines agree, so production cannot honour what development refuses', () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'first-match',
      id: 'p',
      name: 'p',
      rules: [
        {
          actions: ['read'],
          conditions: { all: [USER_SOURCED] },
          effect: 'allow',
          id: 'r',
          priority: 1,
          resources: ['post'],
        },
      ],
    }
    const req = request('^curl', 'curl/8.0')
    expect(evaluateFast([policy], req, 'deny', 'and', vi.fn())).toBe(
      evaluate([policy], req, 'deny', 'and', vi.fn()).allowed,
    )
  })

  // A pattern the validator would have refused, arriving through an attribute.
  // The point of the guard is that it never reaches `getCachedRegex` at all.
  it('never compiles an attacker-supplied catastrophic pattern', () => {
    expect(evalCondition(request('(a+)+$', 'a'.repeat(40)), USER_SOURCED)).toBe(false)
  })

  it.each(['$subject.attributes.pattern', '$resource.attributes.pattern', '$environment.pattern', '$nope'])(
    'refuses %s regardless of which root it names',
    (value) => {
      expect(
        evalCondition(request('^curl', 'curl/8.0'), { field: 'subject.attributes.ua', operator: 'matches', value }),
      ).toBe(false)
    },
  )

  // Only `matches` is refused: every other operator is allowed to read its
  // operand from the request, and narrowing that would break `$`-comparison.
  it('leaves $-resolved operands working for other operators', () => {
    const req: IamRequest.IAccessRequest = {
      action: 'read',
      environment: {},
      resource: { attributes: { ownerId: 'u1' }, type: 'post' },
      subject: { attributes: {}, id: 'u1', roles: [] },
    }
    expect(evalCondition(req, { field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' })).toBe(
      true,
    )
  })
})
