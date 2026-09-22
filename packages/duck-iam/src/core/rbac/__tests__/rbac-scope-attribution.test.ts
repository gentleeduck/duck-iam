// `rolesToPolicy` flattens inheritance and `compileTable` does not; they must still agree on an inherited
// permission's scope, and conditions must survive the translation.
import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { rolesToPolicy } from '../rbac'

function scopeConditionsOf(policy: AccessControl.IPolicy, description: string): unknown[] {
  const rule = policy.rules.find((r) => r.description === description)
  if (!rule) throw new Error(`no rule described "${description}", have: ${policy.rules.map((r) => r.description)}`)
  const group = rule.conditions
  if (!group || !('all' in group)) throw new Error('expected an `all` group')
  return group.all.filter((c) => 'field' in c && c.field === 'scope')
}

describe('rolesToPolicy() scope attribution', () => {
  // SECURITY: reading the scope off the inheritor would grant the parent's permission in the child's tenant.
  it('tags an inherited permission with the declaring role scope, not the inheritor', () => {
    const parent: AccessControl.IRole = {
      id: 'p',
      name: 'Parent',
      scope: 'org-1',
      permissions: [{ action: 'read', resource: 'doc' }],
    }
    const child: AccessControl.IRole = {
      id: 'c',
      name: 'Child',
      scope: 'org-2',
      inherits: ['p'],
      permissions: [{ action: 'write', resource: 'doc' }],
    }
    const policy = rolesToPolicy([parent, child])

    expect(scopeConditionsOf(policy, 'Child: read on doc (via Parent)')).toEqual([
      { field: 'scope', operator: 'eq', value: 'org-1' },
    ])
    expect(scopeConditionsOf(policy, 'Child: write on doc')).toEqual([
      { field: 'scope', operator: 'eq', value: 'org-2' },
    ])
  })

  it('a permission scope overrides the declaring role scope', () => {
    const role: AccessControl.IRole = {
      id: 'r',
      name: 'R',
      scope: 'org-1',
      permissions: [{ action: 'read', resource: 'doc', scope: 'org-9' }],
    }
    expect(scopeConditionsOf(rolesToPolicy([role]), 'R: read on doc')).toEqual([
      { field: 'scope', operator: 'eq', value: 'org-9' },
    ])
  })

  // SECURITY: only `undefined` and `'*'` are global; a truthiness test lets an adapter row's `''` grant everywhere.
  it('treats an empty-string scope as a scope, not as global', () => {
    const role: AccessControl.IRole = {
      id: 'r',
      name: 'R',
      scope: '',
      permissions: [{ action: 'read', resource: 'doc' }],
    }
    expect(scopeConditionsOf(rolesToPolicy([role]), 'R: read on doc')).toEqual([
      { field: 'scope', operator: 'eq', value: '' },
    ])
  })

  it('omits the guard only for undefined and wildcard scopes', () => {
    const undef: AccessControl.IRole = { id: 'u', name: 'U', permissions: [{ action: 'read', resource: 'doc' }] }
    const star: AccessControl.IRole = {
      id: 's',
      name: 'S',
      scope: '*',
      permissions: [{ action: 'read', resource: 'doc' }],
    }
    expect(scopeConditionsOf(rolesToPolicy([undef]), 'U: read on doc')).toEqual([])
    expect(scopeConditionsOf(rolesToPolicy([star]), 'S: read on doc')).toEqual([])
  })
})

describe('rolesToPolicy() condition passthrough', () => {
  it('keeps an `any` group instead of dropping it', () => {
    const role: AccessControl.IRole = {
      id: 'r',
      name: 'R',
      permissions: [
        {
          action: 'read',
          resource: 'doc',
          conditions: { any: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] },
        },
      ],
    }
    const rule = rolesToPolicy([role]).rules[0]
    const group = rule?.conditions
    if (!group || !('all' in group)) throw new Error('expected an `all` group')
    expect(group.all).toContainEqual({ any: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] })
  })

  // SECURITY: an unknown group key must reach the shared parser, which reads it as false, not become unconditional.
  it('passes an unrecognised group through rather than emitting an unconditional grant', () => {
    // TypeScript rejects this literal, but an adapter row or `admin.import` payload can carry it.
    const role: AccessControl.IRole = JSON.parse(
      '{"id":"r","name":"R","permissions":[{"action":"read","resource":"doc","conditions":{"nome":[]}}]}',
    )
    const rule = rolesToPolicy([role]).rules[0]
    const group = rule?.conditions
    if (!group || !('all' in group)) throw new Error('expected an `all` group')
    expect(group.all).toContainEqual({ nome: [] })
  })
})
