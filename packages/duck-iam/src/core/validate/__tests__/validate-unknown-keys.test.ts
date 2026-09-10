// Unknown keys and multi-key condition groups are errors, as in `POLICY_JSON_SCHEMA`: a misspelled key is a
// restriction the engine never applies.
import { describe, expect, it } from 'vitest'
import { PolicyBuilder } from '../../builder'
import { evalConditionGroup } from '../../conditions/conditions'
import type { IamRequest } from '../../types'
import { parsePolicyRow, validatePolicy } from '../validate'

function basePolicy(): Record<string, unknown> {
  return {
    algorithm: 'first-match',
    id: 'p',
    name: 'p',
    rules: [
      {
        actions: ['read'],
        conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] },
        effect: 'allow',
        id: 'r',
        priority: 1,
        resources: ['post'],
      },
    ],
  }
}

function issuesFor(policy: unknown): { code: string; path?: string }[] {
  return validatePolicy(policy).issues.map((i) => ({ code: i.code, path: i.path }))
}

describe('unknown fields', () => {
  it.each([
    ['on the policy', { ...basePolicy(), tenant: 'acme' }, 'tenant'],
    ['a misspelled targets', { ...basePolicy(), target: { actions: ['read'] } }, 'target'],
    ['on targets', { ...basePolicy(), targets: { action: ['read'] } }, 'targets.action'],
    [
      'on a rule',
      {
        ...basePolicy(),
        rules: [
          {
            actions: ['read'],
            conditions: { all: [] },
            effect: 'allow',
            id: 'r',
            invert: true,
            priority: 1,
            resources: ['post'],
          },
        ],
      },
      'rules[0].invert',
    ],
    [
      'on a leaf condition',
      {
        ...basePolicy(),
        rules: [
          {
            actions: ['read'],
            conditions: { all: [{ field: 'subject.id', negate: true, operator: 'eq', value: 'u1' }] },
            effect: 'allow',
            id: 'r',
            priority: 1,
            resources: ['post'],
          },
        ],
      },
      'rules[0].conditions.all[0].negate',
    ],
    [
      'on a condition group',
      {
        ...basePolicy(),
        rules: [
          {
            actions: ['read'],
            conditions: { all: [], mode: 'strict' },
            effect: 'allow',
            id: 'r',
            priority: 1,
            resources: ['post'],
          },
        ],
      },
      'rules[0].conditions.mode',
    ],
  ])('are an error %s', (_label, policy, path) => {
    expect(issuesFor(policy)).toContainEqual({ code: 'UNKNOWN_FIELD', path })
    expect(validatePolicy(policy).valid).toBe(false)
  })

  it('parsePolicyRow drops a row carrying one', () => {
    expect(parsePolicyRow({ ...basePolicy(), tenant: 'acme' })).toBeNull()
  })

  // Control: the correctly spelled key is accepted, so the errors above are about spelling.
  it('control: the same policy with the key spelled correctly is valid', () => {
    expect(validatePolicy({ ...basePolicy(), targets: { actions: ['read'] } }).valid).toBe(true)
  })

  // The builders emit every optional slot; `JSON.stringify` drops the `undefined` ones before any store sees them.
  it('a key explicitly set to undefined is not an unknown field', () => {
    expect(validatePolicy({ ...basePolicy(), tenant: undefined }).valid).toBe(true)
  })

  it('PolicyBuilder output still validates', () => {
    expect(() =>
      new PolicyBuilder('p')
        .desc('d')
        .version(1)
        .rule('r', (r) => r.on('read').of('post').meta({ owner: 'team' }))
        .build(),
    ).not.toThrow()
  })
})

describe('a condition group carrying more than one key', () => {
  const twoKeys = {
    ...basePolicy(),
    rules: [
      {
        actions: ['read'],
        conditions: { all: [], any: [{ field: 'subject.id', operator: 'eq', value: 'nobody' }] },
        effect: 'allow',
        id: 'r',
        priority: 1,
        resources: ['post'],
      },
    ],
  }

  it('is an error naming both keys', () => {
    const issue = validatePolicy(twoKeys).issues.find((i) => i.code === 'INVALID_CONDITION')
    expect(issue?.message).toContain('all and any')
    expect(validatePolicy(twoKeys).valid).toBe(false)
  })

  // An error, not a warning: `any` here would deny, but the evaluator reads `all` alone and allows.
  it('because the evaluator honours only the first key it finds', () => {
    const request: IamRequest.IAccessRequest = {
      action: 'read',
      environment: {},
      resource: { attributes: {}, type: 'post' },
      subject: { attributes: {}, id: 'u1', roles: [] },
    }
    const group = JSON.parse('{"all":[],"any":[{"field":"subject.id","operator":"eq","value":"nobody"}]}')
    expect(evalConditionGroup(request, group, 0)).toBe(true)
    expect(
      evalConditionGroup(request, JSON.parse('{"any":[{"field":"subject.id","operator":"eq","value":"nobody"}]}'), 0),
    ).toBe(false)
  })

  it('still accepts each key on its own', () => {
    for (const key of ['all', 'any', 'none']) {
      const policy = {
        ...basePolicy(),
        rules: [
          {
            actions: ['read'],
            conditions: JSON.parse(`{"${key}":[]}`),
            effect: 'allow',
            id: 'r',
            priority: 1,
            resources: ['post'],
          },
        ],
      }
      expect(validatePolicy(policy).valid).toBe(true)
    }
  })
})
