import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../../types'
import { CellKind, compileTable } from '../compiled.compile'

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
]

describe('compileTable', () => {
  it('compiles a role permission to ROLE_MASK', () => {
    const t = compileTable(roles, policies)
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!
    expect(t.kind[idx]).toBe(CellKind.ROLE_MASK)
    const viewerBit = 1 << t.roleId.get('viewer')!
    expect(t.allow[idx]! & viewerBit).not.toBe(0)
  })

  it("closes role inheritance: editor holds viewer's grant too", () => {
    const t = compileTable(roles, policies)
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!
    const editorBit = 1 << t.roleId.get('editor')!
    expect(t.allow[idx]! & editorBit).not.toBe(0)
  })

  it('compiles an unconditional ABAC allow rule to CONST_ALLOW', () => {
    const t = compileTable(roles, policies)
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('comment')!
    expect(t.kind[idx]).toBe(CellKind.CONST_ALLOW)
  })

  it('marks a cell no rule or permission ever touched as untouched (falls through)', () => {
    const t = compileTable(roles, policies)
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('comment')!
    expect(t.touched[idx]).toBe(0)
  })

  it('marks a role-covered cell as touched', () => {
    const t = compileTable(roles, policies)
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!
    expect(t.touched[idx]).toBe(1)
  })
})
