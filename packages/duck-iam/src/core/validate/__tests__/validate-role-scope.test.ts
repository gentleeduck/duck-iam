import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine/engine'
import { type IamError, metaOf } from '../../errors'
import type { AccessControl } from '../../types'
import { validateRole } from '../validate'

// `''` is a scope value, not a missing one, so a role-level `scope: ''` is a scope no request can satisfy.
describe('validateRole: role-level scope', () => {
  it('rejects an empty string', () => {
    const result = validateRole({ id: 'r', name: 'R', scope: '', permissions: [] })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.path === 'scope' && i.code === 'INVALID_TYPE')).toBe(true)
  })

  it('rejects a non-string', () => {
    expect(validateRole({ id: 'r', name: 'R', scope: 42, permissions: [] }).valid).toBe(false)
    expect(validateRole({ id: 'r', name: 'R', scope: null, permissions: [] }).valid).toBe(false)
  })

  // Controls: the two intended spellings pass, so the rejections above aren't rejecting every role.
  it('accepts an omitted scope and a non-empty one', () => {
    expect(validateRole({ id: 'r', name: 'R', permissions: [] }).valid).toBe(true)
    expect(validateRole({ id: 'r', name: 'R', scope: 'tenant-a', permissions: [] }).valid).toBe(true)
  })

  it('still rejects an empty permission-level scope', () => {
    const result = validateRole({
      id: 'r',
      name: 'R',
      permissions: [{ action: 'read', resource: 'post', scope: '' }],
    })
    expect(result.valid).toBe(false)
  })
})

describe('the validated write API refuses a role with an empty scope', () => {
  it('saveRole rejects it rather than storing unreachable data', async () => {
    const adapter = new IamMemoryAdapter({ roles: [] })
    const engine = new IamEngine({ adapter, cacheTTL: 0 })
    const role = JSON.parse('{"id":"r","name":"R","scope":"","permissions":[{"action":"read","resource":"post"}]}')
    const err = await engine.admin.saveRole(role).catch((e: unknown) => e)
    const meta = metaOf(err as IamError<'IAM_VALIDATION_FAILED'>, 'IAM_VALIDATION_FAILED')
    expect(meta.issues.some((issue) => issue.includes('scope'))).toBe(true)
    expect(await adapter.listRoles()).toHaveLength(0)
  })
})

// Only `undefined` and `'*'` are global in both engines; pins data arriving through an adapter that doesn't validate.
describe('dev and production agree on a role that carries an empty scope', () => {
  const role: AccessControl.IRole = JSON.parse(
    '{"id":"empty-scope","name":"Empty","scope":"","permissions":[{"action":"read","resource":"post"}]}',
  )

  async function can(mode: 'development' | 'production', scope?: string) {
    const adapter = new IamMemoryAdapter({ assignments: { u1: ['empty-scope'] }, roles: [role] })
    const engine = new IamEngine({ adapter, cacheTTL: 0, mode })
    return await engine.can('u1', 'read', { attributes: {}, type: 'post' }, undefined, scope)
  }

  it.each([undefined, '', 'tenant-a'])('agrees for scope %s', async (scope) => {
    const dev = await can('development', scope)
    const prod = await can('production', scope)
    expect(prod).toBe(dev)
  })

  // Control: the agreement above is not "both deny everything".
  it('control: a normally scoped role still grants in its own scope', async () => {
    const scoped: AccessControl.IRole = {
      id: 'scoped',
      name: 'Scoped',
      permissions: [{ action: 'read', resource: 'post' }],
      scope: 'tenant-a',
    }
    for (const mode of ['development', 'production'] as const) {
      const adapter = new IamMemoryAdapter({ roles: [scoped] })
      await adapter.assignRole('u1', 'scoped', 'tenant-a')
      const engine = new IamEngine({ adapter, cacheTTL: 0, mode })
      const post = { attributes: {}, type: 'post' }
      expect(await engine.can('u1', 'read', post, undefined, 'tenant-a')).toBe(true)
      expect(await engine.can('u1', 'read', post, undefined, 'tenant-b')).toBe(false)
    }
  })
})
