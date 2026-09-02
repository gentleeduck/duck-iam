import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { IamAdapter } from '../../types'
import { IamEngine } from '../engine'

/**
 * A memory adapter that also answers `withClient`, so the facade can bind it.
 * The copy shares the original's Maps, standing in for a transaction that reads
 * and writes the same rows.
 */
function bindable(adapter: IamMemoryAdapter): IamMemoryAdapter {
  const copy: IamMemoryAdapter = Object.assign(Object.create(Object.getPrototypeOf(adapter)), adapter)
  return Object.assign(copy, { withClient: () => bindable(adapter) })
}

describe('IAdmin batch writes', () => {
  let engine: IamEngine

  beforeEach(() => {
    engine = new IamEngine({ adapter: new IamMemoryAdapter() })
  })

  it('assignRoles applies every triple and reports one outcome each', async () => {
    const result = await engine.admin.assignRoles([
      { roleId: 'admin', subjectId: 'u1' },
      { roleId: 'editor', scope: 'org-1', subjectId: 'u2' },
    ])

    expect(result.outcomes).toHaveLength(2)
    expect(result.applied).toBe(2)
    expect(result.failed).toBe(0)
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

    // The valid row must NOT have been written - validation is a pre-pass, or a
    // caller who fixes the malformed row and retries double-applies the rest.
    expect(await engine.getEffectiveRoles('u1')).not.toContain('admin')
  })

  it('invalidateSubjects invalidates each distinct id once', () => {
    const spy = vi.spyOn(engine.cache, 'invalidateSubject')

    engine.admin.invalidateSubjects(['u1', 'u2', 'u1'])

    expect(spy).toHaveBeenCalledTimes(2)
  })

  it('leaves changed off when the adapter has no set-based write', async () => {
    // The memory adapter offers no `assignRoleMany`, so the facade loops
    // `assignRole`, which returns void. There is nothing to report, and an
    // absent `changed` says so rather than claiming every row was new.
    const result = await engine.admin.assignRoles([{ roleId: 'admin', subjectId: 'u1' }])
    const revoked = await engine.admin.revokeRoles([{ roleId: 'admin', subjectId: 'u1' }])

    expect(result.outcomes[0]).toEqual({ id: 'u1 admin ', ok: true, value: {} })
    expect(revoked.outcomes[0]).toEqual({ id: 'u1 admin ', ok: true, value: {} })
    expect(result.applied).toBe(1)
  })

  it('reports changed per row when the adapter names the rows it moved', async () => {
    const adapter = new IamMemoryAdapter()
    // A set-based write that DOES answer: it hands back only the triples that
    // were not already granted, which is what a `RETURNING` clause supplies.
    const answering = Object.assign(adapter, {
      async assignRoleMany(rows: readonly IamAdapter.IAssignRow<string, string>[]) {
        const fresh: IamAdapter.IAssignRow<string, string>[] = []
        for (const r of rows) {
          if (!(await adapter.getSubjectRoles(r.subjectId)).includes(r.roleId)) fresh.push(r)
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
  })

  it('a batch over an empty list is a no-op', async () => {
    const spy = vi.spyOn(engine.cache, 'invalidateSubject')
    const result = await engine.admin.assignRoles([])

    expect(result).toEqual({ applied: 0, failed: 0, outcomes: [] })
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
    const e = new IamEngine({ adapter: bindable(new IamMemoryAdapter()) })
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
