import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
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
