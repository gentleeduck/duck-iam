import { describe, expect, it, vi } from 'vitest'
import { IamError, metaOf } from '../../errors'
import { evaluate } from '../../evaluate/evaluate'
import type { AccessControl, IamRequest } from '../../types'
import { evalCondition } from '../conditions.libs'

// Pins the operand-type guard to every OPERAND_TYPES operator, `matches` included:
// a wrong-typed operand throws (Indeterminate) instead of answering `false`.
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
  // The cast builds what a seeded or migrated row can hold; `loadPolicies` does not validate.
  it.each([
    ['a number', 42],
    ['a boolean', true],
    ['null', null],
    ['an array', ['^curl']],
  ])('refuses %s pattern as Indeterminate, not false', (_label, value) => {
    expect(() =>
      evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value } as AccessControl.ICondition),
    ).toThrow('IAM_CONDITION_OPERAND_TYPE')
  })

  it('refuses an absent `value` as Indeterminate, not false', () => {
    expect(() =>
      evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches' } as AccessControl.ICondition),
    ).toThrow('IAM_CONDITION_OPERAND_TYPE')
  })

  it('names the field and the operator, so the bad row can be found', () => {
    try {
      evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value: 42 } as AccessControl.ICondition)
      expect.unreachable('a non-string pattern must not be answerable')
    } catch (err) {
      expect(err).toBeInstanceOf(IamError)
      const meta = metaOf(err as IamError<'IAM_CONDITION_OPERAND_TYPE'>, 'IAM_CONDITION_OPERAND_TYPE')
      expect(meta).toMatchObject({ field: FIELD, operator: 'matches' })
    }
  })

  it('control: a literal string pattern still matches, and still misses', () => {
    expect(evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value: '^curl' })).toBe(true)
    expect(evalCondition(request('wget/1.0'), { field: FIELD, operator: 'matches', value: '^curl' })).toBe(false)
  })

  // See `matches-user-sourced-value.test.ts`.
  it('refuses a $-sourced pattern as Indeterminate', () => {
    expect(() =>
      evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value: '$subject.attributes.ua' }),
    ).toThrow('IAM_CONDITION_USER_SOURCED_PATTERN')
  })

  it('refuses an uncompilable pattern as Indeterminate', () => {
    expect(() => evalCondition(request('curl/8.0'), { field: FIELD, operator: 'matches', value: '(a+)+$' })).toThrow(
      'IAM_CONDITION_PATTERN_REFUSED',
    )
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
    // `defaultEffect: 'allow'` is the hostile setting: reading the rule as "not met" would allow outright.
    expect(evaluate([policy], request('curl/8.0'), 'allow', 'and', onPolicyError).allowed).toBe(false)
    expect(onPolicyError).toHaveBeenCalled()
  })
})
