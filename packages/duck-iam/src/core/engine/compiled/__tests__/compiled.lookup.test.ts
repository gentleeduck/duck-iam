import { describe, expect, it } from 'vitest'
import { evaluateFast } from '../../../evaluate'
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

describe('lookup: phase 1 (ROLE_MASK + CONST_ALLOW), differential vs evaluateFast', () => {
  const table = compileTable(roles, policies)
  // Merge RBAC policy (converted from roles) with regular policies for evaluateFast differential tests
  const rbacPolicy = rolesToPolicy(roles)
  const mergedPolicies = rbacPolicy.rules.length > 0 ? [rbacPolicy, ...policies] : policies

  it('ROLE_MASK: subject with the role is allowed', () => {
    const mask = maskOf(table, ['viewer'])
    expect(lookup(table, mask, 'read', 'post')).toBe(true)
    expect(lookup(table, mask, 'read', 'post')).toBe(
      evaluateFast(mergedPolicies, req(['viewer'], 'read', 'post'), 'deny', 'allow-overrides'),
    )
  })

  it('ROLE_MASK: subject without the role is denied', () => {
    const mask = maskOf(table, [])
    expect(lookup(table, mask, 'read', 'post')).toBe(false)
    expect(lookup(table, mask, 'read', 'post')).toBe(
      evaluateFast(mergedPolicies, req([], 'read', 'post'), 'deny', 'allow-overrides'),
    )
  })

  it("inherited ROLE_MASK: editor inherits viewer's read", () => {
    const mask = maskOf(table, ['editor'])
    expect(lookup(table, mask, 'read', 'post')).toBe(true)
    expect(lookup(table, mask, 'update', 'post')).toBe(true)
  })

  it('CONST_ALLOW: allowed regardless of role', () => {
    expect(lookup(table, 0, 'read', 'comment')).toBe(true)
    expect(lookup(table, 0, 'read', 'comment')).toBe(
      evaluateFast(mergedPolicies, req([], 'read', 'comment'), 'deny', 'allow-overrides'),
    )
  })

  it('CONST_DENY: denied regardless of role', () => {
    expect(lookup(table, 0, 'delete', 'user')).toBe(false)
    expect(lookup(table, 0, 'delete', 'user')).toBe(
      evaluateFast(mergedPolicies, req([], 'delete', 'user'), 'deny', 'allow-overrides'),
    )
  })

  it('untouched cell: signals fallthrough, does not silently deny', () => {
    // lookup() returns 'fallthrough' for untouched cells (compiled-table-only signal).
    // evaluateFast has no 'fallthrough' concept — it always returns a real verdict.
    // Callers must route lookup's 'fallthrough' to evaluateFast to get the true answer.
    expect(lookup(table, 0, 'update', 'comment')).toBe('fallthrough')
    const interpreterResult = evaluateFast(mergedPolicies, req([], 'update', 'comment'), 'deny', 'allow-overrides')
    expect(typeof interpreterResult).toBe('boolean')
    expect([true, false]).toContain(interpreterResult)
  })
})
