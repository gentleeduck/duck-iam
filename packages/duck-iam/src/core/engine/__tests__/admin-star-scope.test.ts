import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../engine'

/**
 * `'*'` is this package's spelling of "every scope" on the scope a role or a
 * permission *declares*. On a scoped *assignment* it is matched literally, so
 * the grant is stored, the write reports success, and no request the operator
 * meant it for ever sees the role.
 *
 * The adapters refuse it, but the adapter guard runs inside `assignRoles`'
 * write loop, and that batch is documented as validating every row before
 * writing any - "a caller who fixes a malformed row and retries would otherwise
 * double-apply every row that had already landed". These cases pin the refusal
 * to the pre-pass, and pin the revoke and move directions that must stay open.
 */
function engineWith() {
  const adapter = new IamMemoryAdapter<string, string, string, string>({
    roles: [{ id: 'reader', name: 'Reader', permissions: [{ action: 'read', resource: 'post' }] }],
  })
  return { adapter, engine: new IamEngine({ adapter, mode: 'development' }) }
}

describe('admin refuses a "*" scope on a grant', () => {
  it('rejects the single-row assign', async () => {
    const { adapter, engine } = engineWith()
    await expect(engine.admin.assignRole('u1', 'reader', '*')).rejects.toThrow(/must not be "\*"/)
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })

  it('rejects the whole batch before writing any row', async () => {
    const { adapter, engine } = engineWith()
    await expect(
      engine.admin.assignRoles([
        { roleId: 'reader', scope: 'org-1', subjectId: 'u1' },
        { roleId: 'reader', scope: '*', subjectId: 'u2' },
      ]),
    ).rejects.toThrow(/must not be "\*"/)
    // The point of the pre-pass: the good row that preceded the bad one has
    // not landed, so a retry of the corrected batch cannot double-apply it.
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    expect(await adapter.getSubjectScopedRoles('u2')).toEqual([])
  })

  it('rejects a "*" destination on updateAssignmentScope', async () => {
    const { engine } = engineWith()
    await expect(engine.admin.updateAssignmentScope('u1', 'reader', 'org-1', '*')).rejects.toThrow(/must not be "\*"/)
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
