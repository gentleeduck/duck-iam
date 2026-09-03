import { describe, expect, it } from 'vitest'
import { defineRole, IAM_CRUD_ACTIONS } from '../../builder/role'
import type { AccessControl } from '../../types'
import { validateRoles } from '../../validate'
import { createIam } from '../config'

/**
 * `createIam` is sold as "misspelling produces a compile-time error", but its
 * `validateRoles` discarded `input.actions` / `resources` / `scopes` entirely -
 * it was the bare export under a config-shaped name. A grant naming an
 * undeclared action or scope therefore validated clean and then denied every
 * request, because `engine.check` is constrained to the declared unions and so
 * never asks the question the grant answers. The declared `scopes` array in
 * particular constrained nothing at all.
 */
const access = createIam({
  actions: ['view', 'edit'] as const,
  resources: ['post', 'comment'] as const,
  scopes: ['org-1', 'org-2'] as const,
})

function role(permissions: AccessControl.IPermission[], scope?: string): AccessControl.IRole {
  return { id: 'r', name: 'R', permissions, scope }
}

function codes(result: { issues: readonly { code: string }[] }): string[] {
  return result.issues.map((i) => i.code)
}

describe('createIam().validateRoles checks grants against the declared vocabulary', () => {
  it('rejects an undeclared action', () => {
    const result = access.validateRoles([role([{ action: 'read', resource: 'post' }])])
    expect(result.valid).toBe(false)
    expect(codes(result)).toContain('UNREACHABLE_TARGET')
  })

  it('rejects an undeclared resource', () => {
    const result = access.validateRoles([role([{ action: 'view', resource: 'invoice' }])])
    expect(result.valid).toBe(false)
  })

  it('rejects an undeclared permission-level scope', () => {
    const result = access.validateRoles([role([{ action: 'view', resource: 'post', scope: 'org-9' }])])
    expect(result.valid).toBe(false)
  })

  it('rejects an undeclared role-level scope', () => {
    const result = access.validateRoles([role([{ action: 'view', resource: 'post' }], 'org-9')])
    expect(result.valid).toBe(false)
  })

  it('names the axis and the declared set in the message', () => {
    const result = access.validateRoles([role([{ action: 'read', resource: 'post' }])])
    const issue = result.issues.find((i) => i.code === 'UNREACHABLE_TARGET')
    expect(issue?.message).toContain('action "read"')
    expect(issue?.message).toContain('"view", "edit"')
  })

  // Controls. Without these the suite above would pass on a validator that
  // simply rejects every role.
  it('accepts a fully declared role', () => {
    expect(access.validateRoles([role([{ action: 'view', resource: 'post', scope: 'org-1' }])]).valid).toBe(true)
  })

  it("accepts '*' on every axis, which is the wildcard and not a member", () => {
    expect(access.validateRoles([role([{ action: '*', resource: '*', scope: '*' }])]).valid).toBe(true)
  })

  it('accepts an omitted scope, which is global rather than scoped to nowhere', () => {
    expect(access.validateRoles([role([{ action: 'view', resource: 'post' }])]).valid).toBe(true)
  })
})

describe('an axis the config left empty constrains nothing', () => {
  const noScopes = createIam({ actions: ['view'] as const, resources: ['post'] as const })

  it('accepts any scope when `scopes` was never declared', () => {
    expect(noScopes.validateRoles([role([{ action: 'view', resource: 'post', scope: 'anything' }])]).valid).toBe(true)
  })

  it('still rejects an undeclared action on the axes that were declared', () => {
    expect(noScopes.validateRoles([role([{ action: 'edit', resource: 'post' }])]).valid).toBe(false)
  })
})

describe('the bare `validateRoles` export is unchanged', () => {
  it('takes no vocabulary and so reports nothing about one', () => {
    expect(validateRoles([role([{ action: 'anything', resource: 'whatever', scope: 'nowhere' }])]).valid).toBe(true)
  })

  it('accepts an explicit vocabulary when one is passed', () => {
    const result = validateRoles([role([{ action: 'anything', resource: 'post' }])], { actions: ['view'] })
    expect(result.valid).toBe(false)
  })

  it('treats an empty declared list as unconstrained, not as "nothing allowed"', () => {
    expect(validateRoles([role([{ action: 'view', resource: 'post' }])], { actions: [] }).valid).toBe(true)
  })
})

/**
 * The other half of C-4: `grantRead` / `grantCRUD` cast straight past `TAction`
 * and emitted their literals whatever the config declared. The conditional
 * parameter types make that a compile error, which `@ts-expect-error` pins -
 * these lines fail the build if the gate is ever removed.
 */
describe('the CRUD convenience helpers are gated on the declared action union', () => {
  it('refuses `grantRead` when the union does not admit `read`', () => {
    // @ts-expect-error - 'read' is not in the declared actions ['view','edit']
    expect(() => access.defineRole('r').grantRead('post')).not.toThrow()
  })

  it('refuses `grantCRUD` when the union does not admit all four verbs', () => {
    // @ts-expect-error - the declared actions ['view','edit'] admit none of CRUD
    expect(() => access.defineRole('r').grantCRUD('post')).not.toThrow()
  })

  it('allows both when the config declares the verbs, and emits them', () => {
    const crud = createIam({ actions: IAM_CRUD_ACTIONS, resources: ['post'] as const })
    const built = crud.defineRole('r').grantCRUD('post').build()
    expect(built.permissions.map((p) => p.action)).toEqual([...IAM_CRUD_ACTIONS])
    expect(crud.validateRoles([built]).valid).toBe(true)
  })

  it('still works on an unparameterised builder, where every action is admitted', () => {
    expect(defineRole('r').grantRead('post').build().permissions).toEqual([{ action: 'read', resource: 'post' }])
  })
})
