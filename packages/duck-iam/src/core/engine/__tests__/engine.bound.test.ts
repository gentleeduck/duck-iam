import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../engine'

/**
 * A memory adapter that also answers `withClient`, so the facade can bind it.
 * The copy shares the original's Maps, standing in for a transaction that reads
 * and writes the same rows - cache behaviour is what these tests are about;
 * real transactional isolation is proven against Postgres separately.
 */
function bindable(adapter: IamMemoryAdapter): IamMemoryAdapter {
  const copy: IamMemoryAdapter = Object.assign(Object.create(Object.getPrototypeOf(adapter)), adapter)
  return Object.assign(copy, { withClient: () => bindable(adapter) })
}

describe('IamEngine.withTransaction', () => {
  let engine: IamEngine

  beforeEach(() => {
    engine = new IamEngine({ adapter: bindable(new IamMemoryAdapter()) })
  })

  it('throws when the adapter cannot join a transaction', () => {
    const plain = new IamEngine({ adapter: new IamMemoryAdapter() })

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

    // The bound view sees the uncommitted grant; the shared engine serves its
    // warm, unpolluted cache and still says no.
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
