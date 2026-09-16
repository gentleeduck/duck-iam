import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { IamAdapter } from '../../types'
import { IamEngine } from '../engine'

/** Memory adapter with `withClient`; the copy shares the original's Maps, like a transaction over the same rows. */
function bindable(adapter: IamMemoryAdapter): IamMemoryAdapter {
  const copy: IamMemoryAdapter = Object.assign(Object.create(Object.getPrototypeOf(adapter)), adapter)
  return Object.assign(copy, { withClient: () => bindable(adapter) })
}

/** `assignRole` refuses unknown role ids, so the adapters below hold the roles these cases grant. */
const GRANTABLE = [
  { id: 'admin', name: 'Admin', permissions: [] },
  { id: 'editor', name: 'Editor', permissions: [] },
]

describe('IAdmin batch writes', () => {
  let engine: IamEngine

  beforeEach(() => {
    engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }) })
  })

  it('assignRoles applies every triple and reports one outcome each', async () => {
    const result = await engine.admin.assignRoles([
      { roleId: 'admin', subjectId: 'u1' },
      { roleId: 'editor', scope: 'org-1', subjectId: 'u2' },
    ])

    expect(result.outcomes).toHaveLength(2)
    expect(result.applied).toBe(2)
    expect(result.outcomes.every((o) => o.ok)).toBe(true)
    expect(await engine.getEffectiveRoles('u1')).toContain('admin')
    expect(await engine.getEffectiveRoles('u2', 'org-1')).toContain('editor')
  })

  it('revokeRoles removes every triple', async () => {
    await engine.admin.assignRoles([
      { roleId: 'admin', subjectId: 'u1' },
      { roleId: 'admin', subjectId: 'u2' },
    ])

    const result = await engine.admin.revokeRoles([
      { roleId: 'admin', subjectId: 'u1' },
      { roleId: 'admin', subjectId: 'u2' },
    ])

    expect(result.applied).toBe(2)
    expect(await engine.getEffectiveRoles('u1')).not.toContain('admin')
    expect(await engine.getEffectiveRoles('u2')).not.toContain('admin')
  })

  it('validates every row before writing any of them', async () => {
    await expect(
      engine.admin.assignRoles([
        { roleId: 'admin', subjectId: 'u1' },
        { roleId: 'admin', subjectId: '' },
      ]),
    ).rejects.toThrow()

    // The valid row must not land, or retrying the fixed batch double-applies it.
    expect(await engine.getEffectiveRoles('u1')).not.toContain('admin')
  })

  it('invalidateSubjects invalidates each distinct id once', () => {
    const spy = vi.spyOn(engine.cache, 'invalidateSubject')

    engine.admin.invalidateSubjects(['u1', 'u2', 'u1'])

    expect(spy).toHaveBeenCalledTimes(2)
  })

  it('leaves changed off when the adapter has no set-based write', async () => {
    // No `assignRoleMany` here, so the facade loops `assignRole`, which returns void: nothing to report.
    const result = await engine.admin.assignRoles([{ roleId: 'admin', subjectId: 'u1' }])
    const revoked = await engine.admin.revokeRoles([{ roleId: 'admin', subjectId: 'u1' }])

    expect(result.outcomes[0]).toEqual({ ok: true, row: { roleId: 'admin', subjectId: 'u1' }, value: {} })
    expect(revoked.outcomes[0]).toEqual({ ok: true, row: { roleId: 'admin', subjectId: 'u1' }, value: {} })
    expect(result.applied).toBe(1)
  })

  it('reports changed per row when the adapter names the rows it moved', async () => {
    const adapter = new IamMemoryAdapter({ roles: GRANTABLE })
    // Answers like a `RETURNING` clause: only the indices of triples not already granted.
    const answering = Object.assign(adapter, {
      async assignRoleMany(rows: readonly IamAdapter.IAssignRow<string, string>[]) {
        const fresh: number[] = []
        for (const [i, r] of rows.entries()) {
          if (!(await adapter.getSubjectRoles(r.subjectId)).includes(r.roleId)) fresh.push(i)
          await adapter.assignRole(r.subjectId, r.roleId, r.scope)
        }
        return fresh
      },
    })
    const e = new IamEngine({ adapter: answering })

    await e.admin.assignRoles([{ roleId: 'admin', subjectId: 'u1' }])
    const again = await e.admin.assignRoles([
      { roleId: 'admin', subjectId: 'u1' },
      { roleId: 'editor', subjectId: 'u1' },
    ])

    expect(again.applied).toBe(2)
    expect(again.outcomes.map((o) => (o.ok ? o.value.changed : null))).toEqual([false, true])
    // The row travels with its outcome, so callers never parse an id back into a triple.
    expect(again.outcomes.map((o) => o.row.roleId)).toEqual(['admin', 'editor'])
  })

  it('a batch over an empty list is a no-op', async () => {
    const spy = vi.spyOn(engine.cache, 'invalidateSubject')
    const result = await engine.admin.assignRoles([])

    expect(result).toEqual({ applied: 0, outcomes: [] })
    expect(spy).not.toHaveBeenCalled()
  })

  it('moveRoleScopes moves every row, reporting each applied', async () => {
    await engine.admin.assignRole('u1', 'admin', 'org-1')

    const result = await engine.admin.moveRoleScopes([
      { fromScope: 'org-1', roleId: 'admin', subjectId: 'u1', toScope: 'org-2' },
    ])

    expect(result.applied).toBe(1)
    expect(await engine.getEffectiveRoles('u1', 'org-2')).toContain('admin')
    expect(await engine.getEffectiveRoles('u1', 'org-1')).not.toContain('admin')
  })

  it('bound batch writes buffer their invalidations', async () => {
    const e = new IamEngine({ adapter: bindable(new IamMemoryAdapter({ roles: GRANTABLE })) })
    const spy = vi.spyOn(e.cache, 'invalidateSubject')

    const perms = e.withTransaction({})
    await perms.admin.assignRoles([
      { roleId: 'admin', subjectId: 'u1' },
      { roleId: 'admin', subjectId: 'u2' },
    ])

    expect(spy).not.toHaveBeenCalled()
    expect(perms.pending.size).toBe(2)

    await perms.pending.flush()
    expect(spy).toHaveBeenCalledWith('u1')
    expect(spy).toHaveBeenCalledWith('u2')
  })
})
