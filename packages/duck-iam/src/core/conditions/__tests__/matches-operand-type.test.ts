import { describe, expect, it, vi } from 'vitest'
import { evaluate } from '../../evaluate/evaluate'
import type { AccessControl, IamRequest } from '../../types'
import { evalCondition, IamOperandTypeError } from '../conditions.libs'

/**
 * `evalCondition` refuses an operand whose type the operator cannot compare
 * against, and throws so the condition reads as Indeterminate rather than as
 * "not met". `matches` was exempt from that by accident: the operator was
 * dispatched before the guard ran, so a non-string pattern fell into
 * `evalMatchesOp`, failed its own `typeof v !== 'string'` test, and answered a
 * plain `false`.
 *
 * `false` is the permissive answer for a `deny` rule. These tests pin the
 * guard's reach to every operator in `OPERAND_TYPES`, `matches` included.
 */
function request(ua: string): IamRequest.IAccessRequest {
  return {
    action: 'read',
    environment: {},
    resource: { attributes: {}, type: 'post' },
    subject: { attributes: { ua }, id: 'u1', roles: [] },
  }
}

const FIELD = 'subject.attributes.ua'

describe('`matches` is bound by the operand-type guard', () => {
  // A malformed condition is what a seeded or migrated row looks like; the
  // validator refuses all of these, and `loadPolicies` does not validate. The
  // cast manufactures exactly that deliberately-malformed shape.
  it.each([
    ['a number', 42],
    ['a boolean', true],
    ['null', null],
    ['an array', ['^curl']],
  ])('refuses %s pattern as Indeterminate, not false', (_label, value) => {
    expect(() =>
      evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value } as AccessControl.ICondition),
    ).toThrow(IamOperandTypeError)
  })

  it('refuses an absent `value` as Indeterminate, not false', () => {
    expect(() =>
      evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches' } as AccessControl.ICondition),
    ).toThrow(IamOperandTypeError)
  })

  it('names the field and the operator, so the bad row can be found', () => {
    try {
      evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value: 42 } as AccessControl.ICondition)
      expect.unreachable('a non-string pattern must not be answerable')
    } catch (err) {
      expect(err).toBeInstanceOf(IamOperandTypeError)
      expect(err).toMatchObject({ field: FIELD, operator: 'matches' })
    }
  })

  // Control: the guard did not swallow the operator. A literal string pattern
  // still compiles and still answers.
  it('control: a literal string pattern still matches, and still misses', () => {
    expect(evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value: '^curl' })).toBe(true)
    expect(evalCondition(request('wget/1.0'), { field: FIELD, operator: 'matches', value: '^curl' })).toBe(false)
  })

  // The deliberate refusals `matches` already had are unchanged: both return
  // `false` without reaching the guard or the regex cache.
  it('leaves the $-sourced-pattern refusal a plain false', () => {
    expect(
      evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value: '$subject.attributes.ua' }),
    ).toBe(false)
  })

  it('leaves an uncompilable pattern a plain false', () => {
    expect(evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value: '(a+)+$' })).toBe(false)
  })
})

describe('a seeded deny rule with a non-string pattern still denies', () => {
  const policy: AccessControl.IPolicy = {
    algorithm: 'first-match',
    id: 'p',
    name: 'p',
    rules: [
      {
        actions: ['read'],
        // The row a validator never saw: `value` should be a string.
        conditions: { all: [{ field: FIELD, operator: 'matches', value: 42 }] } as AccessControl.IConditionGroup,
        effect: 'deny',
        id: 'block-agents',
        priority: 10,
        resources: ['post'],
      },
    ],
  }

  it('is Indeterminate, so the policy votes deny rather than retiring', () => {
    const onPolicyError = vi.fn()
    // `defaultEffect: 'allow'` is the hostile setting: before the fix the rule
    // read as "condition not met" and the request was allowed outright.
    expect(evaluate([policy], request('curl/8.0'), 'allow', 'and', onPolicyError).allowed).toBe(false)
    expect(onPolicyError).toHaveBeenCalled()
  })
})
