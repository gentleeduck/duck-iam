import { describe, expect, it } from 'vitest'
import { createIam } from '../config'

describe('createIam()', () => {
  const config = createIam({
    actions: ['read', 'create', 'update', 'delete'] as const,
    resources: ['post', 'comment'] as const,
    scopes: ['org-1', 'org-2'] as const,
  })

  it('exposes actions, resources, and scopes', () => {
    expect(config.actions).toEqual(['read', 'create', 'update', 'delete'])
    expect(config.resources).toEqual(['post', 'comment'])
    expect(config.scopes).toEqual(['org-1', 'org-2'])
  })

  it('iamDefineRole returns a IamRoleBuilder with correct content', () => {
    const role = config.iamDefineRole('viewer').grant('read', 'post').build()
    expect(role.id).toBe('viewer')
    expect(role.permissions).toEqual([{ action: 'read', resource: 'post' }])
  })

  it('policy returns a IamPolicyBuilder', () => {
    const p = config.iamDefinePolicy('test-policy').name('Test').build()
    expect(p.id).toBe('test-policy')
    expect(p.name).toBe('Test')
  })

  it('iamDefineRule returns a IamRuleBuilder with correct actions/resources', () => {
    const rule = config.iamDefineRule('r1').on('read').of('post').build()
    expect(rule.id).toBe('r1')
    expect(rule.actions).toEqual(['read'])
    expect(rule.resources).toEqual(['post'])
  })

  it('when returns a IamWhen builder with correct condition', () => {
    const group = config.when().eq('action', 'read').buildAll()
    expect(group.all).toEqual([{ field: 'action', operator: 'eq', value: 'read' }])
  })

  it('checks() returns the exact input array unchanged', () => {
    const input = [
      { action: 'read', resource: 'post' },
      { action: 'create', resource: 'comment' },
    ] as const
    const result = config.checks(input)
    expect(result).toBe(input) // same reference
  })

  it('iamValidateRoles() validates role definitions', () => {
    const result = config.iamValidateRoles([
      { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
      { id: 'editor', name: 'Editor', inherits: ['viewer'], permissions: [] },
    ])
    expect(result.valid).toBe(true)
    expect(result.issues.filter((i) => i.type === 'error')).toHaveLength(0)
  })

  it('iamValidateRoles() detects dangling inherits', () => {
    const result = config.iamValidateRoles([{ id: 'editor', name: 'Editor', inherits: ['nonexistent'], permissions: [] }])
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'DANGLING_INHERIT')).toBe(true)
  })

  it('iamValidatePolicy() validates a valid policy', () => {
    const result = config.iamValidatePolicy({
      id: 'p1',
      name: 'Test',
      algorithm: 'deny-overrides',
      rules: [],
    })
    expect(result.valid).toBe(true)
  })

  it('iamValidatePolicy() rejects invalid input', () => {
    const result = config.iamValidatePolicy({ id: '', name: '' })
    expect(result.valid).toBe(false)
  })

  it('defaults scopes to empty array when not provided', () => {
    const noScopes = createIam({
      actions: ['read'] as const,
      resources: ['post'] as const,
    })
    expect(noScopes.scopes).toEqual([])
  })

  it('defaults roles to empty array when not provided', () => {
    const noRoles = createIam({
      actions: ['read'] as const,
      resources: ['post'] as const,
    })
    expect(noRoles.roles).toEqual([])
  })
})
