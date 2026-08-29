import { describe, expect, it } from 'vitest'
import { evaluate } from '../../../evaluate'
import { rolesToPolicy } from '../../../rbac'
import type { AccessControl, IamPrimitives, IamRequest } from '../../../types'
import { compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'

const roles: AccessControl.IRole[] = [
  { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
  { id: 'editor', name: 'Editor', inherits: ['viewer'], permissions: [{ action: 'update', resource: 'post' }] },
]
const policies: AccessControl.IPolicy[] = [
  {
    id: 'public',
    name: 'Public',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'pub-read',
        effect: 'allow',
        priority: 0,
        actions: ['read'],
        resources: ['comment'],
        conditions: { all: [] },
      },
    ],
  },
  {
    id: 'deny-dangerous',
    name: 'Deny Dangerous',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'deny-delete-user',
        effect: 'deny',
        priority: 0,
        actions: ['delete'],
        resources: ['user'],
        conditions: { all: [] },
      },
    ],
  },
]

function maskOf(table: ReturnType<typeof compileTable>, roleIds: string[]): number {
  let m = 0
  for (const id of roleIds) {
    const i = table.roleId.get(id)
    if (i !== undefined) m |= 1 << i
  }
  return m
}

function req(
  subjectRoles: string[],
  action: string,
  resource: string,
  attributes: IamPrimitives.Attributes = {},
): IamRequest.IAccessRequest {
  return {
    subject: { id: 'u1', roles: subjectRoles, attributes: {} },
    action,
    resource: { type: resource, attributes },
    environment: { now: 1 },
  }
}

describe('lookup: RBAC mask (fast path) + CONST_ALLOW + CONST_DENY, differential vs evaluate()', () => {
  // Single ABAC policy + roles with 'allow-overrides': not forced, matches shipped behavior.
  const table = compileTable(roles, policies, 'allow-overrides')

  it('RBAC mask: subject with the role is allowed', () => {
    const mask = maskOf(table, ['viewer'])
    const r = req(['viewer'], 'read', 'post')
    expect(lookup(table, mask, 'read', 'post', r, 'deny')).toBe(true)
    expect(lookup(table, mask, 'read', 'post', r, 'deny')).toBe(
      evaluate([rolesToPolicy(roles), ...policies], r, 'deny', 'allow-overrides').allowed,
    )
  })

  it('RBAC mask: subject without the role is denied', () => {
    const mask = maskOf(table, [])
    const r = req([], 'read', 'post')
    expect(lookup(table, mask, 'read', 'post', r, 'deny')).toBe(false)
  })

  it("inherited RBAC mask: editor inherits viewer's read", () => {
    const mask = maskOf(table, ['editor'])
    expect(lookup(table, mask, 'read', 'post', req(['editor'], 'read', 'post'), 'deny')).toBe(true)
    expect(lookup(table, mask, 'update', 'post', req(['editor'], 'update', 'post'), 'deny')).toBe(true)
  })

  it('CONST_ALLOW: allowed regardless of role', () => {
    expect(lookup(table, 0, 'read', 'comment', req([], 'read', 'comment'), 'deny')).toBe(true)
  })

  it('CONST_DENY: denied regardless of role', () => {
    expect(lookup(table, 0, 'delete', 'user', req([], 'delete', 'user'), 'deny')).toBe(false)
  })

  it('untouched cell: falls back to defaultEffect, matching evaluate()', () => {
    const r = req([], 'update', 'comment')
    const got = lookup(table, 0, 'update', 'comment', r, 'deny')
    expect(got).toBe(false)
    expect(got).toBe(evaluate(policies, r, 'deny', 'allow-overrides').allowed)
  })

  it('unknown action/resource (outside the table universe): falls back to defaultEffect', () => {
    const r = req([], 'archive', 'wiki')
    expect(lookup(table, 0, 'archive', 'wiki', r, 'deny')).toBe(false)
    expect(lookup(table, 0, 'archive', 'wiki', r, 'allow')).toBe(true)
  })
})

describe('lookup: rbacDynamic (scoped/conditioned role permissions), differential vs evaluate()', () => {
  it('scoped grant: allowed when request scope matches, denied when it differs', () => {
    const scopedRoles: AccessControl.IRole[] = [
      { id: 'org-admin', name: 'Org Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-1' }] },
    ]
    const t = compileTable(scopedRoles, [], 'and')
    const mask = maskOf(t, ['org-admin'])
    const oracle = [rolesToPolicy(scopedRoles)]

    const right = { ...req(['org-admin'], 'update', 'org'), scope: 'org-1' }
    expect(lookup(t, mask, 'update', 'org', right, 'deny')).toBe(true)
    expect(lookup(t, mask, 'update', 'org', right, 'deny')).toBe(evaluate(oracle, right, 'deny', 'and').allowed)

    const wrong = { ...req(['org-admin'], 'update', 'org'), scope: 'org-2' }
    expect(lookup(t, mask, 'update', 'org', wrong, 'deny')).toBe(false)
    expect(lookup(t, mask, 'update', 'org', wrong, 'deny')).toBe(evaluate(oracle, wrong, 'deny', 'and').allowed)
  })

  it('scoped grant: a subject without the role gets nothing, even with a matching scope', () => {
    const scopedRoles: AccessControl.IRole[] = [
      { id: 'org-admin', name: 'Org Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-1' }] },
    ]
    const t = compileTable(scopedRoles, [], 'and')
    const r = { ...req([], 'update', 'org'), scope: 'org-1' }
    expect(lookup(t, 0, 'update', 'org', r, 'deny')).toBe(false)
  })

  it('conditioned grant: allowed when the condition passes, denied when it fails', () => {
    const conditionalRoles: AccessControl.IRole[] = [
      {
        id: 'owner',
        name: 'Owner',
        permissions: [
          {
            action: 'update',
            resource: 'post',
            conditions: { all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }] },
          },
        ],
      },
    ]
    const t = compileTable(conditionalRoles, [], 'and')
    const mask = maskOf(t, ['owner'])
    const oracle = [rolesToPolicy(conditionalRoles)]

    const passing = req(['owner'], 'update', 'post', { ownerId: 'u1' })
    expect(lookup(t, mask, 'update', 'post', passing, 'deny')).toBe(true)
    expect(lookup(t, mask, 'update', 'post', passing, 'deny')).toBe(evaluate(oracle, passing, 'deny', 'and').allowed)

    const failing = req(['owner'], 'update', 'post', { ownerId: 'someone-else' })
    expect(lookup(t, mask, 'update', 'post', failing, 'deny')).toBe(false)
    expect(lookup(t, mask, 'update', 'post', failing, 'deny')).toBe(evaluate(oracle, failing, 'deny', 'and').allowed)
  })

  it('two roles at the same cell with different scopes: each grants only its own scope', () => {
    const multiRoles: AccessControl.IRole[] = [
      { id: 'org1-admin', name: 'Org1 Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-1' }] },
      { id: 'org2-admin', name: 'Org2 Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-2' }] },
    ]
    const t = compileTable(multiRoles, [], 'and')

    const mask1 = maskOf(t, ['org1-admin'])
    expect(lookup(t, mask1, 'update', 'org', { ...req(['org1-admin'], 'update', 'org'), scope: 'org-1' }, 'deny')).toBe(
      true,
    )
    expect(lookup(t, mask1, 'update', 'org', { ...req(['org1-admin'], 'update', 'org'), scope: 'org-2' }, 'deny')).toBe(
      false,
    )

    const mask2 = maskOf(t, ['org2-admin'])
    expect(lookup(t, mask2, 'update', 'org', { ...req(['org2-admin'], 'update', 'org'), scope: 'org-2' }, 'deny')).toBe(
      true,
    )
  })

  it('a plain mask hit still short-circuits before rbacDynamic is even consulted', () => {
    // Regression: a role with a simple grant at a DIFFERENT cell than its own scoped grant
    // must not have the simple grant affected by the scoped one existing at all.
    const roles: AccessControl.IRole[] = [
      {
        id: 'editor',
        name: 'Editor',
        permissions: [
          { action: 'read', resource: 'post' },
          { action: 'update', resource: 'post', scope: 'org-1' },
        ],
      },
    ]
    const t = compileTable(roles, [], 'and')
    const mask = maskOf(t, ['editor'])
    expect(lookup(t, mask, 'read', 'post', req(['editor'], 'read', 'post'), 'deny')).toBe(true)
  })
})
