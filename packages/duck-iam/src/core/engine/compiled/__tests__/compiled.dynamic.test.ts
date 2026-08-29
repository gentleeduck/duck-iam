import { describe, expect, it } from 'vitest'
import { evaluate } from '../../../evaluate'
import type { AccessControl, IamRequest } from '../../../types'
import { CellKind, compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'

const policies: AccessControl.IPolicy[] = [
  {
    id: 'ownership',
    name: 'Ownership',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'owner-update',
        effect: 'allow',
        priority: 0,
        actions: ['update'],
        resources: ['post'],
        conditions: { all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }] },
      },
    ],
  },
]

describe('compileTable: DYNAMIC cells', () => {
  it('a conditional rule compiles to a DYNAMIC cell, not CONST_ALLOW', () => {
    const t = compileTable([], policies, 'and')
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    expect(t.kind[idx]).toBe(CellKind.DYNAMIC)
  })

  it('groups the candidate rule under its owning policy, with the policy algorithm', () => {
    const t = compileTable([], policies, 'and')
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    const groups = t.dynamic[idx]!
    expect(groups).toHaveLength(1)
    expect(groups[0]!.policyId).toBe('ownership')
    expect(groups[0]!.algorithm).toBe('deny-overrides')
    expect(groups[0]!.rules[0]!.id).toBe('owner-update')
  })

  it('a policy with a wildcarded target is fully residual (never enters the action universe)', () => {
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['*'] } }]
    const t = compileTable([], targeted, 'and')
    expect(t.actionId.has('update')).toBe(false)
  })

  it('a policy with a literal target compiles in instead (see compiled.compile.test.ts for the dedicated coverage)', () => {
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['update'] } }]
    const t = compileTable([], targeted, 'and')
    expect(t.actionId.has('update')).toBe(true)
  })

  it('differential: DYNAMIC classification agrees with evaluate() for both a matching and non-matching request', () => {
    const t = compileTable([], policies, 'and')
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    expect(t.kind[idx]).toBe(CellKind.DYNAMIC)

    const subject: IamRequest.ISubject = { id: 'user1', roles: [], attributes: {} }

    const denyingResource: IamRequest.IResource = { type: 'post', attributes: { ownerId: 'someone-else' } }
    const denyingRequest: IamRequest.IAccessRequest = { subject, action: 'update', resource: denyingResource }
    expect(lookup(t, 0, 'update', 'post', denyingRequest, 'deny')).toBe(false)
    expect(lookup(t, 0, 'update', 'post', denyingRequest, 'deny')).toBe(
      evaluate(policies, denyingRequest, 'deny', 'and').allowed,
    )

    const allowingResource: IamRequest.IResource = { type: 'post', attributes: { ownerId: 'user1' } }
    const allowingRequest: IamRequest.IAccessRequest = { subject, action: 'update', resource: allowingResource }
    expect(lookup(t, 0, 'update', 'post', allowingRequest, 'deny')).toBe(true)
    expect(lookup(t, 0, 'update', 'post', allowingRequest, 'deny')).toBe(
      evaluate(policies, allowingRequest, 'deny', 'and').allowed,
    )
  })
})

const OPERATORS: Array<[AccessControl.Operator, unknown, unknown, boolean]> = [
  ['eq', 'a', 'a', true],
  ['neq', 'a', 'b', true],
  ['gt', 5, 3, true],
  ['gte', 3, 3, true],
  ['lt', 3, 5, true],
  ['lte', 3, 3, true],
  ['in', 'a', ['a', 'b'], true],
  ['nin', 'c', ['a', 'b'], true],
  ['contains', ['a', 'b'], 'a', true],
  ['not_contains', ['a', 'b'], 'c', true],
  ['starts_with', 'hello', 'he', true],
  ['ends_with', 'hello', 'lo', true],
  ['matches', 'hello', '^h', true],
  ['exists', 'x', undefined, true],
  ['not_exists', null, undefined, true],
  ['subset_of', ['a'], ['a', 'b'], true],
  ['superset_of', ['a', 'b'], ['a'], true],
  ['after', 2000, 1000, true],
  ['before', 1000, 2000, true],
]

describe('DYNAMIC cell evaluation: every operator, differential vs evaluate()', () => {
  for (const [operator, fieldVal, condVal, expected] of OPERATORS) {
    it(`${operator} -> ${expected}`, () => {
      const opPolicies: AccessControl.IPolicy[] = [
        {
          id: 'p',
          name: 'p',
          algorithm: 'deny-overrides',
          rules: [
            {
              id: 'r',
              effect: 'allow',
              priority: 0,
              actions: ['act'],
              resources: ['res'],
              conditions: { all: [{ field: 'resource.attributes.v', operator, value: condVal as never }] },
            },
          ],
        },
      ]
      const t = compileTable([], opPolicies, 'and')
      const request: IamRequest.IAccessRequest = {
        subject: { id: 'u1', roles: [], attributes: {} },
        action: 'act',
        resource: { type: 'res', attributes: { v: fieldVal as never } },
        environment: { now: 1 },
      }
      const got = lookup(t, 0, 'act', 'res', request, 'deny')
      expect(got).toBe(expected)
      expect(got).toBe(evaluate(opPolicies, request, 'deny', 'and').allowed)
    })
  }

  it("cross-policy 'and': both policies must allow", () => {
    const allowPolicy: AccessControl.IPolicy = {
      id: 'a',
      name: 'a',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'ra',
          effect: 'allow',
          priority: 0,
          actions: ['act'],
          resources: ['res'],
          conditions: { all: [{ field: 'resource.attributes.v', operator: 'eq', value: 1 }] },
        },
      ],
    }
    const denyPolicy: AccessControl.IPolicy = {
      id: 'b',
      name: 'b',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'rb',
          effect: 'deny',
          priority: 0,
          actions: ['act'],
          resources: ['res'],
          conditions: { all: [{ field: 'resource.attributes.v', operator: 'eq', value: 1 }] },
        },
      ],
    }
    const t = compileTable([], [allowPolicy, denyPolicy], 'and')
    const request: IamRequest.IAccessRequest = {
      subject: { id: 'u1', roles: [], attributes: {} },
      action: 'act',
      resource: { type: 'res', attributes: { v: 1 } },
      environment: { now: 1 },
    }
    expect(lookup(t, 0, 'act', 'res', request, 'deny')).toBe(false)
    expect(lookup(t, 0, 'act', 'res', request, 'deny')).toBe(
      evaluate([allowPolicy, denyPolicy], request, 'deny', 'and').allowed,
    )
  })

  it("cross-policy 'allow-overrides': one allow wins", () => {
    const allowPolicy: AccessControl.IPolicy = {
      id: 'a',
      name: 'a',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'ra',
          effect: 'allow',
          priority: 0,
          actions: ['act'],
          resources: ['res'],
          conditions: { all: [{ field: 'resource.attributes.v', operator: 'eq', value: 1 }] },
        },
      ],
    }
    const denyPolicy: AccessControl.IPolicy = {
      id: 'b',
      name: 'b',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'rb',
          effect: 'deny',
          priority: 0,
          actions: ['act'],
          resources: ['res'],
          conditions: { all: [{ field: 'resource.attributes.v', operator: 'eq', value: 1 }] },
        },
      ],
    }
    const t = compileTable([], [allowPolicy, denyPolicy], 'allow-overrides')
    const request: IamRequest.IAccessRequest = {
      subject: { id: 'u1', roles: [], attributes: {} },
      action: 'act',
      resource: { type: 'res', attributes: { v: 1 } },
      environment: { now: 1 },
    }
    expect(lookup(t, 0, 'act', 'res', request, 'deny')).toBe(true)
    expect(lookup(t, 0, 'act', 'res', request, 'deny')).toBe(
      evaluate([allowPolicy, denyPolicy], request, 'deny', 'allow-overrides').allowed,
    )
  })

  it('role-bypass fast path: matching role mask skips condition closures entirely (allow-overrides, unforced)', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'admin', name: 'Admin', permissions: [{ action: 'act', resource: 'res' }] },
    ]
    const rolePolicies: AccessControl.IPolicy[] = [
      {
        id: 'p',
        name: 'p',
        algorithm: 'deny-overrides',
        rules: [
          {
            id: 'r',
            effect: 'allow',
            priority: 0,
            actions: ['act'],
            resources: ['res'],
            conditions: { all: [{ field: 'resource.attributes.v', operator: 'eq', value: 1 }] },
          },
        ],
      },
    ]
    const t = compileTable(roles, rolePolicies, 'allow-overrides')
    const adminMask = 1 << t.roleId.get('admin')!
    expect(
      lookup(t, adminMask, 'act', 'res', {
        subject: { id: 'u', roles: ['admin'], attributes: {} },
        action: 'act',
        resource: { type: 'res', attributes: {} },
        environment: { now: 1 },
      }),
    ).toBe(true)
  })
})
