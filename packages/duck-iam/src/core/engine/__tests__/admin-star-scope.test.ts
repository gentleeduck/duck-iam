import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../engine'

// On an assignment `'*'` is matched literally and grants nothing, so admin refuses it in the pre-pass before any
// write. Revoking or moving a `'*'` row must stay open.
function engineWith() {
  const adapter = new IamMemoryAdapter<string, string, string, string>({
    roles: [{ id: 'reader', name: 'Reader', permissions: [{ action: 'read', resource: 'post' }] }],
  })
  return { adapter, engine: new IamEngine({ adapter, mode: 'development' }) }
}

describe('admin refuses a "*" scope on a grant', () => {
  it('rejects the single-row assign', async () => {
    const { adapter, engine } = engineWith()
    await expect(engine.admin.assignRole('u1', 'reader', '*')).rejects.toThrow('IAM_SCOPE_INVALID')
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })

  it('rejects the whole batch before writing any row', async () => {
    const { adapter, engine } = engineWith()
    await expect(
      engine.admin.assignRoles([
        { roleId: 'reader', scope: 'org-1', subjectId: 'u1' },
        { roleId: 'reader', scope: '*', subjectId: 'u2' },
      ]),
    ).rejects.toThrow('IAM_SCOPE_INVALID')
    // The good row before the bad one has not landed, so retrying the fixed batch cannot double-apply it.
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    expect(await adapter.getSubjectScopedRoles('u2')).toEqual([])
  })

  it('rejects a "*" destination on updateAssignmentScope', async () => {
    const { engine } = engineWith()
    await expect(engine.admin.updateAssignmentScope('u1', 'reader', 'org-1', '*')).rejects.toThrow('IAM_SCOPE_INVALID')
  })

  // Controls, and the directions that must stay open.
  it('accepts an ordinary scope, singly and in a batch', async () => {
    const { adapter, engine } = engineWith()
    await engine.admin.assignRole('u1', 'reader', 'org-1')
    await engine.admin.assignRoles([{ roleId: 'reader', scope: 'org-2', subjectId: 'u2' }])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'reader', scope: 'org-1' }])
    expect(await adapter.getSubjectScopedRoles('u2')).toEqual([{ role: 'reader', scope: 'org-2' }])
  })

  it('accepts an omitted scope, which is how a global grant is spelled', async () => {
    const { adapter, engine } = engineWith()
    await engine.admin.assignRole('u1', 'reader')
    expect(await adapter.getSubjectRoles('u1')).toEqual(['reader'])
  })

  it('still revokes a "*" row, singly and in a batch', async () => {
    const { engine } = engineWith()
    await expect(engine.admin.revokeRole('u1', 'reader', '*')).resolves.not.toThrow()
    await expect(engine.admin.revokeRoles([{ roleId: 'reader', scope: '*', subjectId: 'u1' }])).resolves.toMatchObject({
      applied: 1,
    })
  })

  it('still moves a "*" row off, which is the repair path', async () => {
    const { engine } = engineWith()
    await expect(engine.admin.updateAssignmentScope('u1', 'reader', '*', 'org-1')).resolves.not.toThrow()
  })
})
