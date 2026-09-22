import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../../types'
import { compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'

// Each test flips under a named mutant of `compiled.lookup.ts`: skipping `rbacResidual`,
// `targetRoles.some` -> `.every`, `hasAnyGrant` -> `false`, or `hasFlatSource` -> `false`.
function maskOf(table: ReturnType<typeof compileTable>, roleIds: readonly string[]): number {
  let m = 0
  for (const id of roleIds) {
    const i = table.roleId.get(id)
    if (i !== undefined) m |= 1 << i
  }
  return m
}

function req(subjectRoles: readonly string[], action: string, resource: string): IamRequest.IAccessRequest {
  return {
    action,
    environment: {},
    resource: { attributes: {}, type: resource },
    subject: { attributes: {}, id: 'u1', roles: [...subjectRoles] },
  }
}

describe('a wildcarded role permission grants only through `rbacResidual`', () => {
  const wildcardRole: AccessControl.IRole = {
    id: 'super',
    name: 'Super',
    permissions: [{ action: '*', resource: 'post' }],
  }
  const table = compileTable([wildcardRole], [], 'and')

  // Premise: the other two RBAC sources cannot answer, so the grants below must come from `rbacResidual`.
  it('is not reachable through the grant mask or the per-cell groups', () => {
    expect(table.rbacResidual).not.toBeNull()
    const a = table.actionId.get('read')
    const r = table.resourceId.get('post')
    const idx = a !== undefined && r !== undefined ? a * table.nResources + r : undefined
    expect(idx === undefined || table.allow[idx] === 0).toBe(true)
    expect(idx === undefined || (table.rbacDynamic[idx]?.length ?? 0) === 0).toBe(true)
  })

  it('grants the action the wildcard covers', () => {
    expect(lookup(table, maskOf(table, ['super']), 'read', 'post', req(['super'], 'read', 'post'), 'deny')).toBe(true)
  })

  it('grants a second, unrelated action under the same wildcard', () => {
    expect(lookup(table, maskOf(table, ['super']), 'delete', 'post', req(['super'], 'delete', 'post'), 'deny')).toBe(
      true,
    )
  })

  it('does not grant a resource the permission does not name', () => {
    expect(lookup(table, maskOf(table, ['super']), 'read', 'comment', req(['super'], 'read', 'comment'), 'deny')).toBe(
      false,
    )
  })

  it('does not grant a subject that does not hold the role', () => {
    expect(lookup(table, 0, 'read', 'post', req([], 'read', 'post'), 'deny')).toBe(false)
  })
})

describe('a policy targeting two roles votes for a subject holding either one', () => {
  const roles: AccessControl.IRole[] = [
    { id: 'a', name: 'A', permissions: [{ action: 'read', resource: 'post' }] },
    { id: 'b', name: 'B', permissions: [{ action: 'read', resource: 'post' }] },
  ]
  // Literal actions and resources, so this compiles into a cell group carrying
  // `targetRoles` rather than staying residual.
  const twoRoleDeny: AccessControl.IPolicy = {
    algorithm: 'deny-overrides',
    id: 'p-two-roles',
    name: 'two roles',
    rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'deny', id: 'r', priority: 1, resources: ['post'] }],
    targets: { roles: ['a', 'b'] },
  }
  const table = compileTable(roles, [twoRoleDeny], 'and')

  // Under `.every` the group stops voting for a subject holding a strict
  // subset, the RBAC allow is then the only vote, and the deny disappears.
  it.each(['a', 'b'])('denies a subject holding only %s', (role) => {
    expect(lookup(table, maskOf(table, [role]), 'read', 'post', req([role], 'read', 'post'), 'deny')).toBe(false)
  })

  it('denies a subject holding both', () => {
    expect(lookup(table, maskOf(table, ['a', 'b']), 'read', 'post', req(['a', 'b'], 'read', 'post'), 'deny')).toBe(
      false,
    )
  })

  // Control: the RBAC allow is real, so the denies above come from the policy.
  it('control: the same request allows once the policy is gone', () => {
    const without = compileTable(roles, [], 'and')
    expect(lookup(without, maskOf(without, ['a']), 'read', 'post', req(['a'], 'read', 'post'), 'deny')).toBe(true)
  })

  // Control: a subject holding neither role is outside the targets, so `.some` is not "always vote".
  it('control: a subject holding neither role gets no vote from it', () => {
    const roleC: AccessControl.IRole = { id: 'c', name: 'C', permissions: [{ action: 'read', resource: 'post' }] }
    const withC = compileTable([...roles, roleC], [twoRoleDeny], 'and')
    expect(lookup(withC, maskOf(withC, ['c']), 'read', 'post', req(['c'], 'read', 'post'), 'deny')).toBe(true)
  })
})

describe('"some role grants this, just not yours" is a vote, not silence', () => {
  const roles: AccessControl.IRole[] = [
    { id: 'editor', name: 'Editor', permissions: [{ action: 'read', resource: 'post' }] },
  ]
  const abacAllow: AccessControl.IPolicy = {
    algorithm: 'deny-overrides',
    id: 'p-allow',
    name: 'allow',
    rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 1, resources: ['post'] }],
  }
  const table = compileTable(roles, [abacAllow], 'and')

  // RBAC must vote `defaultEffect` here; if it abstained, the ABAC allow would grant a roleless subject.
  it('denies a roleless subject even though an ABAC policy allows', () => {
    expect(lookup(table, 0, 'read', 'post', req([], 'read', 'post'), 'deny')).toBe(false)
  })

  it('control: the subject holding the role is allowed', () => {
    expect(lookup(table, maskOf(table, ['editor']), 'read', 'post', req(['editor'], 'read', 'post'), 'deny')).toBe(true)
  })

  // The residual abstains here (its wildcard is for `comment`); returning that without falling through drops the deny.
  it('falls through an abstaining residual to the grant check', () => {
    const withWildcard: AccessControl.IRole[] = [
      ...roles,
      { id: 'super', name: 'Super', permissions: [{ action: '*', resource: 'comment' }] },
    ]
    const t = compileTable(withWildcard, [abacAllow], 'and')
    expect(t.rbacResidual).not.toBeNull()
    expect(lookup(t, 0, 'read', 'post', req([], 'read', 'post'), 'deny')).toBe(false)
  })

  // Control: at a cell no role mentions, RBAC abstains and the ABAC vote stands alone.
  it('control: RBAC abstains at a cell no role grants', () => {
    const abacOnly: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p-comment',
      name: 'comment',
      rules: [
        { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 1, resources: ['comment'] },
      ],
    }
    const t = compileTable(roles, [abacOnly], 'and')
    expect(lookup(t, 0, 'read', 'comment', req([], 'read', 'comment'), 'deny')).toBe(true)
  })
})

describe('the ABAC flat source is consulted', () => {
  it('a flat policy is the only thing granting this request', () => {
    const abacAllow: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p',
      name: 'p',
      rules: [
        { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 1, resources: ['post'] },
      ],
    }
    const table = compileTable([], [abacAllow], 'and')
    expect(lookup(table, 0, 'read', 'post', req([], 'read', 'post'), 'deny')).toBe(true)
  })
})
