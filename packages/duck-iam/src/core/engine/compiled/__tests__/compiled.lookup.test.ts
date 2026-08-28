import { describe, expect, it } from 'vitest'
import { evaluate } from '../../../evaluate'
import { rolesToPolicy } from '../../../rbac'
import type { AccessControl, IamRequest } from '../../../types'
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

function req(subjectRoles: string[], action: string, resource: string): IamRequest.IAccessRequest {
  return {
    subject: { id: 'u1', roles: subjectRoles, attributes: {} },
    action,
    resource: { type: resource, attributes: {} },
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
