import { describe, expect, it, vi } from 'vitest'
import { IamError, metaOf } from '../../errors'
import { evaluate, evaluateFast } from '../../evaluate/evaluate'
import type { AccessControl, IamRequest } from '../../types'
import { evalConditionGroup } from '../conditions'
import { evalCondition } from '../conditions.libs'

// `matches` never compiles a `$`-resolved pattern (ReDoS) and throws `IAM_CONDITION_USER_SOURCED_PATTERN`.
// Indeterminate, not `false`, so a deny rule built on it still denies.
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
  it('refuses to answer even when the resolved pattern would have matched', () => {
    expect(() => evalCondition(request('^curl', 'curl/8.0'), USER_SOURCED)).toThrow(
      'IAM_CONDITION_USER_SOURCED_PATTERN',
    )
  })

  // Without this, the refusal above would pass on any `matches` failure.
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
    // `none` negates a `false` leaf into a grant, so no verdict works here.
    for (const group of [{ all: [USER_SOURCED] }, { any: [USER_SOURCED] }, { none: [USER_SOURCED] }]) {
      expect(() => evalConditionGroup(req, group, 0)).toThrow('IAM_CONDITION_USER_SOURCED_PATTERN')
    }
  })

  // For an allow rule Indeterminate and `false` agree; the deny case below is where they differ.
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

  // The guard stops it before `getCachedRegex`.
  it('never compiles an attacker-supplied catastrophic pattern', () => {
    expect(() => evalCondition(request('(a+)+$', 'a'.repeat(40)), USER_SOURCED)).toThrow(
      'IAM_CONDITION_USER_SOURCED_PATTERN',
    )
  })

  it.each(['$subject.attributes.pattern', '$resource.attributes.pattern', '$environment.pattern', '$nope'])(
    'refuses %s regardless of which root it names',
    (value) => {
      expect(() =>
        evalCondition(request('^curl', 'curl/8.0'), { field: 'subject.attributes.ua', operator: 'matches', value }),
      ).toThrow('IAM_CONDITION_USER_SOURCED_PATTERN')
    },
  )

  it('a deny rule built on it still denies', () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p',
      name: 'p',
      rules: [
        {
          actions: ['read'],
          conditions: { all: [] },
          effect: 'allow',
          id: 'r-allow',
          priority: 1,
          resources: ['post'],
        },
        {
          actions: ['read'],
          conditions: { all: [USER_SOURCED] },
          effect: 'deny',
          id: 'r-deny',
          priority: 10,
          resources: ['post'],
        },
      ],
    }
    const req = request('^curl', 'curl/8.0')
    expect(evaluate([policy], req, 'deny', 'and', vi.fn()).allowed).toBe(false)
    // The fast engine agrees.
    expect(evaluateFast([policy], req, 'deny', 'and', vi.fn())).toBe(false)
  })

  it('reports the refusal rather than swallowing it', () => {
    const onPolicyError = vi.fn()
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p',
      name: 'p',
      rules: [
        {
          actions: ['read'],
          conditions: { all: [USER_SOURCED] },
          effect: 'deny',
          id: 'r',
          priority: 1,
          resources: ['post'],
        },
      ],
    }
    evaluate([policy], request('^curl', 'curl/8.0'), 'deny', 'and', onPolicyError)
    expect(onPolicyError).toHaveBeenCalled()
    const err = onPolicyError.mock.calls[0]?.[0] as IamError<'IAM_CONDITION_USER_SOURCED_PATTERN'>
    expect(metaOf(err, 'IAM_CONDITION_USER_SOURCED_PATTERN').field).toBe('subject.attributes.ua')
  })

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
