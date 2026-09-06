import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../../types'
import { compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'

/**
 * Mutation testing on `compiled.lookup.ts` scored 81% with the survivors
 * clustered on the three RBAC sources. Replacing the whole `rbacResidual`
 * consultation with `{}` changed no test outcome, even though it is the only
 * path by which a wildcarded role permission grants anything in production;
 * `targetRoles.some` could become `.every`, silently retiring a policy that
 * targets two roles for a subject holding one; and `hasAnyGrant` could become
 * `false`, turning "no role of yours grants this" into "nobody is talking about
 * this" - an abstention that removes a deny vote.
 *
 * Each test here is written so that the named mutant flips its verdict.
 */
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

  // The premise: neither of the other two RBAC sources can answer for this
  // permission. Without this the grant below would prove nothing about which
  // path produced it.
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

  // Control: the RBAC allow this policy is overriding is real, so the denies
  // above are the policy's doing and not an absent grant.
  it('control: the same request allows once the policy is gone', () => {
    const without = compileTable(roles, [], 'and')
    expect(lookup(without, maskOf(without, ['a']), 'read', 'post', req(['a'], 'read', 'post'), 'deny')).toBe(true)
  })

  // Control: a subject holding neither role is outside the policy's targets,
  // so the group correctly does not vote - `.some` is not simply "always vote".
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

  // RBAC has to cast its `defaultEffect` vote here. If `hasAnyGrant` were
  // `false` it would abstain instead, the ABAC allow would be the only vote,
  // and a subject holding no role at all would be granted.
  it('denies a roleless subject even though an ABAC policy allows', () => {
    expect(lookup(table, 0, 'read', 'post', req([], 'read', 'post'), 'deny')).toBe(false)
  })

  it('control: the subject holding the role is allowed', () => {
    expect(lookup(table, maskOf(table, ['editor']), 'read', 'post', req(['editor'], 'read', 'post'), 'deny')).toBe(true)
  })

  // The residual is consulted first and abstains here (its wildcard is for a
  // different resource). Returning that abstention as RBAC's answer - rather
  // than falling through to the grant check below it - would drop the deny and
  // leave the ABAC allow standing alone.
  it('falls through an abstaining residual to the grant check', () => {
    const withWildcard: AccessControl.IRole[] = [
      ...roles,
      { id: 'super', name: 'Super', permissions: [{ action: '*', resource: 'comment' }] },
    ]
    const t = compileTable(withWildcard, [abacAllow], 'and')
    expect(t.rbacResidual).not.toBeNull()
    expect(lookup(t, 0, 'read', 'post', req([], 'read', 'post'), 'deny')).toBe(false)
  })

  // Control: at a cell no role mentions at all, RBAC really does abstain and
  // the ABAC vote stands alone.
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
  // `hasFlatSource` could be replaced with `false` without a test noticing.
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
