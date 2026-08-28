import { describe, expect, it } from 'vitest'
import { evaluateFast } from '../../../evaluate'
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
    const t = compileTable([], policies)
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    expect(t.kind[idx]).toBe(CellKind.DYNAMIC)
  })

  it('groups the candidate rule under its owning policy, with the policy algorithm', () => {
    const t = compileTable([], policies)
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    const groups = t.dynamic[idx]!
    expect(groups).toHaveLength(1)
    expect(groups[0]!.policyId).toBe('ownership')
    expect(groups[0]!.algorithm).toBe('deny-overrides')
    expect(groups[0]!.rules[0]!.id).toBe('owner-update')
  })

  it('a policy with targets is excluded entirely (falls through)', () => {
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['update'] } }]
    const t = compileTable([], targeted)
    expect(t.actionId.has('update')).toBe(false) // never entered the action universe
  })

  it('differential: DYNAMIC classification is not short-circuited to always-allow by evaluateFast', () => {
    const t = compileTable([], policies)
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    expect(t.kind[idx]).toBe(CellKind.DYNAMIC)

    const subject: IamRequest.ISubject = { id: 'user1', roles: [], attributes: {} }

    const denyingResource: IamRequest.IResource = { type: 'post', attributes: { ownerId: 'someone-else' } }
    const denyingRequest: IamRequest.IAccessRequest = { subject, action: 'update', resource: denyingResource }
    expect(evaluateFast(policies, denyingRequest)).toBe(false)

    const allowingResource: IamRequest.IResource = { type: 'post', attributes: { ownerId: 'user1' } }
    const allowingRequest: IamRequest.IAccessRequest = { subject, action: 'update', resource: allowingResource }
    expect(evaluateFast(policies, allowingRequest)).toBe(true)
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

describe('DYNAMIC cell evaluation: every operator, differential vs evaluateFast', () => {
  for (const [operator, fieldVal, condVal, expected] of OPERATORS) {
    it(`${operator} -> ${expected}`, () => {
      const policies: AccessControl.IPolicy[] = [
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
      const t = compileTable([], policies)
      const req: IamRequest.IAccessRequest = {
        subject: { id: 'u1', roles: [], attributes: {} },
        action: 'act',
        resource: { type: 'res', attributes: { v: fieldVal as never } },
        environment: { now: 1 },
      }
      const got = lookup(t, 0, 'act', 'res', req)
      expect(got).toBe(expected)
      expect(got).toBe(evaluateFast(policies, req))
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
    const t = compileTable([], [allowPolicy, denyPolicy])
    const req: IamRequest.IAccessRequest = {
      subject: { id: 'u1', roles: [], attributes: {} },
      action: 'act',
      resource: { type: 'res', attributes: { v: 1 } },
      environment: { now: 1 },
    }
    expect(lookup(t, 0, 'act', 'res', req, 'deny', 'and')).toBe(false)
    expect(lookup(t, 0, 'act', 'res', req, 'deny', 'and')).toBe(
      evaluateFast([allowPolicy, denyPolicy], req, 'deny', 'and'),
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
    const t = compileTable([], [allowPolicy, denyPolicy])
    const req: IamRequest.IAccessRequest = {
      subject: { id: 'u1', roles: [], attributes: {} },
      action: 'act',
      resource: { type: 'res', attributes: { v: 1 } },
      environment: { now: 1 },
    }
    expect(lookup(t, 0, 'act', 'res', req, 'deny', 'allow-overrides')).toBe(true)
    expect(lookup(t, 0, 'act', 'res', req, 'deny', 'allow-overrides')).toBe(
      evaluateFast([allowPolicy, denyPolicy], req, 'deny', 'allow-overrides'),
    )
  })

  it('role-bypass fast path: matching role mask skips condition closures entirely', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'admin', name: 'Admin', permissions: [{ action: 'act', resource: 'res' }] },
    ]
    const policies: AccessControl.IPolicy[] = [
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
    const t = compileTable(roles, policies)
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
