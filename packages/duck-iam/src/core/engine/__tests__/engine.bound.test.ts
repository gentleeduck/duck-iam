import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../engine'

/**
 * Memory adapter with `withClient`; the copy shares the original's Maps, like a transaction over the same rows.
 * Only cache behaviour is tested here; real isolation is covered against Postgres.
 */
function bindable(adapter: IamMemoryAdapter): IamMemoryAdapter {
  const copy: IamMemoryAdapter = Object.assign(Object.create(Object.getPrototypeOf(adapter)), adapter)
  return Object.assign(copy, { withClient: () => bindable(adapter) })
}

/** `assignRole` refuses unknown role ids, so the adapters below hold the role these cases grant. */
const GRANTABLE = [{ id: 'admin', name: 'Admin', permissions: [] }]

describe('IamEngine.withTransaction', () => {
  let engine: IamEngine

  beforeEach(() => {
    engine = new IamEngine({ adapter: bindable(new IamMemoryAdapter({ roles: GRANTABLE })) })
  })

  it('throws when the adapter cannot join a transaction', () => {
    const plain = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }) })

    expect(() => plain.withTransaction({})).toThrowError(/withClient|transaction/i)
  })

  it('a bound read sees a role assigned on the same bound facade', async () => {
    const perms = engine.withTransaction({})
    await perms.admin.assignRole('u1', 'admin')

    expect(await perms.getEffectiveRoles('u1')).toContain('admin')
  })

  it('buffers invalidation instead of applying it to the shared cache', async () => {
    const spy = vi.spyOn(engine.cache, 'invalidateSubject')
    const perms = engine.withTransaction({})
    await perms.admin.assignRole('u1', 'admin')

    expect(spy).not.toHaveBeenCalled()
    expect(perms.pending.size).toBe(1)

    await perms.pending.flush()
    expect(spy).toHaveBeenCalledWith('u1')
  })

  it('discard drops buffered invalidation, leaving the shared cache untouched', async () => {
    const spy = vi.spyOn(engine.cache, 'invalidateSubject')
    const perms = engine.withTransaction({})
    await perms.admin.assignRole('u1', 'admin')
    perms.pending.discard()
    await perms.pending.flush()

    expect(spy).not.toHaveBeenCalled()
  })

  it('the bound facade reads through its own caches, never polluting the shared ones', async () => {
    // Warm the shared cache with "u1 has no roles".
    expect(await engine.getEffectiveRoles('u1')).toEqual([])

    const perms = engine.withTransaction({})
    await perms.admin.assignRole('u1', 'admin')

    // The bound view sees the uncommitted grant; the shared engine's warm cache still says no.
    expect(await perms.getEffectiveRoles('u1')).toContain('admin')
    expect(await engine.getEffectiveRoles('u1')).toEqual([])
  })

  it('the unbound engine.admin still invalidates immediately', async () => {
    const spy = vi.spyOn(engine.cache, 'invalidateSubject')
    await engine.admin.assignRole('u1', 'admin')

    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('the bound admin validates its input exactly as the unbound one does', async () => {
    const perms = engine.withTransaction({})

    await expect(perms.admin.assignRole('', 'admin')).rejects.toThrow()
  })

  it('policy writes buffer their invalidation too', async () => {
    const spy = vi.spyOn(engine.cache, 'invalidatePolicies')
    const perms = engine.withTransaction({})
    await perms.admin.savePolicy({
      algorithm: 'deny-overrides',
      id: 'p1',
      name: 'p',
      rules: [],
    })

    expect(spy).not.toHaveBeenCalled()
    expect(perms.pending.size).toBe(1)

    await perms.pending.flush()
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('two bound facades over the same engine keep separate buffers', async () => {
    const a = engine.withTransaction({})
    const b = engine.withTransaction({})
    await a.admin.assignRole('u1', 'admin')

    expect(a.pending.size).toBe(1)
    expect(b.pending.size).toBe(0)
  })
})

describe('the bound facade exposes one write surface', () => {
  let engine: IamEngine

  beforeEach(() => {
    engine = new IamEngine({ adapter: bindable(new IamMemoryAdapter({ roles: GRANTABLE })) })
  })

  it('engine.admin is the buffered admin', () => {
    const perms = engine.withTransaction({})

    expect(perms.engine.admin).toBe(perms.admin)
  })

  it('a write through engine.admin buffers instead of touching the shared cache', async () => {
    const spy = vi.spyOn(engine.cache, 'invalidateSubject')
    const perms = engine.withTransaction({})
    await perms.engine.admin.assignRole('u1', 'admin')

    expect(spy).not.toHaveBeenCalled()
    expect(perms.pending.size).toBe(1)

    await perms.pending.flush()
    expect(spy).toHaveBeenCalledWith('u1')
  })

  it('a revoke through engine.admin stops answering on the shared engine once flushed', async () => {
    await engine.admin.assignRole('u1', 'admin')
    expect(await engine.getEffectiveRoles('u1')).toContain('admin')

    const perms = engine.withTransaction({})
    await perms.engine.admin.revokeRole('u1', 'admin')
    await perms.pending.flush()

    expect(await engine.getEffectiveRoles('u1')).toEqual([])
  })
})
