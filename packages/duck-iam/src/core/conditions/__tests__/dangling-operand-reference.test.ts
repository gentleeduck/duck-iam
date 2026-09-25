import { describe, expect, it } from 'vitest'
import { evaluate } from '../../evaluate/evaluate'
import type { AccessControl, IamPrimitives, IamRequest } from '../../types'
import { validatePolicy } from '../../validate'
import { evalCondition } from '../conditions.libs'

// Two shapes `validatePolicy` accepts: a `$`-reference resolving to `null` must not satisfy `eq` (`null === null`),
// and a non-scalar `not_contains` operand must not answer `true`.

const REQUEST_BASE = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
} satisfies IamRequest.IAccessRequest

/** "Allow when the subject's tenant matches the resource's" - the canonical multi-tenant guard. */
const TENANCY_POLICY: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  id: 'tenancy',
  name: 'tenancy',
  rules: [
    {
      actions: ['read'],
      conditions: {
        all: [{ field: 'subject.attributes.tenant', operator: 'eq', value: '$resource.attributes.tenant' }],
      },
      effect: 'allow',
      id: 'same-tenant',
      priority: 0,
      resources: ['post'],
    },
  ],
}

function allows(subject: IamPrimitives.Attributes, resource: IamPrimitives.Attributes): boolean {
  const request: IamRequest.IAccessRequest = {
    ...REQUEST_BASE,
    resource: { attributes: resource, type: 'post' },
    subject: { attributes: subject, id: 'u1', roles: [] },
  }
  return evaluate([TENANCY_POLICY], request, 'deny').allowed
}

describe('B-F1 a $-reference that resolves to nothing has no operand', () => {
  it('the authoring path blesses the policy, so the validator is not the guard here', () => {
    expect(validatePolicy(TENANCY_POLICY).issues).toEqual([])
  })

  it('a request carrying neither attribute is denied, not allowed', () => {
    expect(allows({}, {})).toBe(false)
  })

  it('the guard still works for the requests it was written for', () => {
    expect({
      crossTenant: allows({ tenant: 'acme' }, { tenant: 'globex' }),
      matching: allows({ tenant: 'acme' }, { tenant: 'acme' }),
      resourceOnly: allows({}, { tenant: 'acme' }),
      subjectOnly: allows({ tenant: 'acme' }, {}),
    }).toEqual({ crossTenant: false, matching: true, resourceOnly: false, subjectOnly: false })
  })

  it('a literal null operand is an explicit test and still compares', () => {
    // Only `$`-references are refused - an author writing `value: null` means it.
    expect(evalCondition(REQUEST_BASE, { field: 'subject.attributes.absent', operator: 'eq', value: null })).toBe(true)
  })

  it('refusing is a throw, so the policy is Indeterminate rather than silently false', () => {
    expect(() =>
      evalCondition(REQUEST_BASE, {
        field: 'subject.attributes.tenant',
        operator: 'eq',
        value: '$resource.attributes.tenant',
      }),
    ).toThrow('IAM_CONDITION_OPERAND_TYPE')
  })
})

describe('B-F2 not_contains takes a scalar operand', () => {
  const request: IamRequest.IAccessRequest = {
    ...REQUEST_BASE,
    subject: { attributes: { groups: ['banned'] }, id: 'u1', roles: [] },
  }

  it('an array operand no longer short-circuits true', () => {
    expect(() =>
      evalCondition(request, { field: 'subject.attributes.groups', operator: 'not_contains', value: ['banned'] }),
    ).toThrow('IAM_CONDITION_OPERAND_TYPE')
  })

  it('contains refuses the same operand, so the two cannot be bypassed in opposite directions', () => {
    expect(() =>
      evalCondition(request, { field: 'subject.attributes.groups', operator: 'contains', value: ['banned'] }),
    ).toThrow('IAM_CONDITION_OPERAND_TYPE')
  })

  it('a scalar operand still answers both ways', () => {
    expect({
      containsHit: evalCondition(request, {
        field: 'subject.attributes.groups',
        operator: 'contains',
        value: 'banned',
      }),
      containsMiss: evalCondition(request, {
        field: 'subject.attributes.groups',
        operator: 'contains',
        value: 'staff',
      }),
      notContainsHit: evalCondition(request, {
        field: 'subject.attributes.groups',
        operator: 'not_contains',
        value: 'staff',
      }),
      notContainsMiss: evalCondition(request, {
        field: 'subject.attributes.groups',
        operator: 'not_contains',
        value: 'banned',
      }),
    }).toEqual({ containsHit: true, containsMiss: false, notContainsHit: true, notContainsMiss: false })
  })

  it('an "allow unless denylisted" rule no longer admits the denylisted subject', () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'denylist',
      name: 'denylist',
      rules: [
        {
          actions: ['read'],
          // Malformed: an array operand, as a seeded row can carry.
          conditions: {
            all: [{ field: 'subject.attributes.groups', operator: 'not_contains', value: ['banned'] }],
          },
          effect: 'allow',
          id: 'not-banned',
          priority: 0,
          resources: ['post'],
        },
      ],
    }
    expect({
      allowed: evaluate([policy], request, 'deny').allowed,
      writeRefuses: validatePolicy(policy).issues.map((i) => i.code),
    }).toEqual({ allowed: false, writeRefuses: ['OPERAND_TYPE_MISMATCH'] })
  })
})
