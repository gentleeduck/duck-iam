import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
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

  it('defineRole returns a RoleBuilder with correct content', () => {
    const role = config.defineRole('viewer').grant('read', 'post').build()
    expect(role.id).toBe('viewer')
    expect(role.permissions).toEqual([{ action: 'read', resource: 'post' }])
  })

  it('policy returns a PolicyBuilder', () => {
    const p = config.definePolicy('test-policy').name('Test').build()
    expect(p.id).toBe('test-policy')
    expect(p.name).toBe('Test')
  })

  it('defineRule returns a RuleBuilder with correct actions/resources', () => {
    const rule = config.defineRule('r1').on('read').of('post').build()
    expect(rule.id).toBe('r1')
    expect(rule.actions).toEqual(['read'])
    expect(rule.resources).toEqual(['post'])
  })

  it('when returns a When builder with correct condition', () => {
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

  it('validateRoles() validates role definitions', () => {
    const result = config.validateRoles([
      { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
      { id: 'editor', name: 'Editor', inherits: ['viewer'], permissions: [] },
    ])
    expect(result.valid).toBe(true)
    expect(result.issues.filter((i) => i.type === 'error')).toHaveLength(0)
  })

  it('validateRoles() detects dangling inherits', () => {
    const result = config.validateRoles([{ id: 'editor', name: 'Editor', inherits: ['nonexistent'], permissions: [] }])
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'DANGLING_INHERIT')).toBe(true)
  })

  it('validatePolicy() validates a valid policy', () => {
    const result = config.validatePolicy({
      id: 'p1',
      name: 'Test',
      algorithm: 'deny-overrides',
      rules: [],
    })
    expect(result.valid).toBe(true)
  })

  it('validatePolicy() rejects invalid input', () => {
    const result = config.validatePolicy({ id: '', name: '' })
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

describe('createIam() — uncovered surface', () => {
  const config = createIam({
    actions: ['read', 'create', 'update', 'delete'] as const,
    resources: ['post', 'comment'] as const,
    scopes: ['org-1', 'org-2'] as const,
    roles: ['viewer', 'editor'] as const,
  })

  it('exposes declared roles', () => {
    const withRoles = createIam({
      actions: ['read'] as const,
      resources: ['post'] as const,
      roles: ['viewer', 'admin'] as const,
    })
    expect(withRoles.roles).toEqual(['viewer', 'admin'])
  })

  it('createEngine returns an IamEngine wired to the given adapter', async () => {
    const adapter = new IamMemoryAdapter<
      'read' | 'create' | 'update' | 'delete',
      'post' | 'comment',
      'viewer' | 'editor',
      'org-1' | 'org-2'
    >()
    const engine = config.createEngine({ adapter, mode: 'development' })

    await engine.admin.saveRole({ id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] })
    await engine.admin.assignRole('u1', 'viewer')

    expect(await engine.can('u1', 'read', { type: 'post', attributes: {} })).toBe(true)
    expect(await engine.can('u1', 'read', { type: 'comment', attributes: {} })).toBe(false)
    expect(await engine.can('u2', 'read', { type: 'post', attributes: {} })).toBe(false)
  })

  it('definePolicy returns a builder whose rules are constrained to the config', () => {
    const p = config
      .definePolicy('p1')
      .rule('r1', (r) => r.deny().on('delete').of('post'))
      .build()
    expect(p.rules[0]!.effect).toBe('deny')
    expect(p.rules[0]!.actions).toEqual(['delete'])
  })

  it('defineRole propagates scope onto the built role', () => {
    const role = config.defineRole('editor').scope('org-1').grant('update', 'post').build()
    expect(role.scope).toBe('org-1')
  })

  it('validateRoles() reports circular inheritance as a warning, not an error', () => {
    const result = config.validateRoles([
      { id: 'viewer', name: 'Viewer', inherits: ['editor'], permissions: [] },
      { id: 'editor', name: 'Editor', inherits: ['viewer'], permissions: [] },
    ])
    const circular = result.issues.filter((i) => i.code === 'CIRCULAR_INHERIT')
    expect(circular.length).toBeGreaterThan(0)
    expect(circular.every((i) => i.type === 'warning')).toBe(true)
    expect(result.valid).toBe(true)
  })

  it('scopes/roles default to [] independently of one another', () => {
    const onlyRoles = createIam({
      actions: ['read'] as const,
      resources: ['post'] as const,
      roles: ['viewer'] as const,
    })
    expect(onlyRoles.scopes).toEqual([])
    expect(onlyRoles.roles).toEqual(['viewer'])
  })
})
