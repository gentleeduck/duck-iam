import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../engine'

// A 33rd role latches `_roleLimitExceeded`. The latch must clear when the role set changes, or the compiled table
// stays off and healthCheck reports a stale count. Verdicts stay correct either way.

const role = (i: number) => ({ id: `r${i}`, name: `r${i}`, permissions: [{ action: 'read', resource: 'post' }] })

/** 33 roles: one more than the mask can address. */
async function overLimitEngine() {
  const adapter = new IamMemoryAdapter()
  const engine = new IamEngine({ adapter, mode: 'production' })
  for (let i = 0; i < 33; i++) await engine.admin.saveRole(role(i))
  // Force the compile attempt that latches.
  await engine.can('u1', 'read', { attributes: {}, type: 'post' })
  return { adapter, engine }
}

const tableHealth = async (engine: IamEngine): Promise<unknown> => (await engine.healthCheck()).compiledTable

describe('the role-limit latch clears when the role set changes', () => {
  it('CONTROL: over the limit, the table is reported unavailable with the cause', async () => {
    const { engine } = await overLimitEngine()
    expect(await tableHealth(engine)).toEqual({
      available: false,
      limit: 32,
      reason: 'role-limit-exceeded',
      roleCount: 33,
    })
  })

  it('deleting back under the limit restores the compiled table', async () => {
    const { adapter, engine } = await overLimitEngine()
    for (let i = 0; i < 31; i++) await engine.admin.deleteRole(`r${i}`)
    expect((await adapter.listRoles()).length).toBe(2)
    await engine.can('u1', 'read', { attributes: {}, type: 'post' })
    expect(await tableHealth(engine)).toBeUndefined()
  })

  it('the health signal stops naming a role count the store no longer holds', async () => {
    const { engine } = await overLimitEngine()
    for (let i = 0; i < 31; i++) await engine.admin.deleteRole(`r${i}`)
    const health = await engine.healthCheck()
    expect(JSON.stringify(health)).not.toContain('role-limit-exceeded')
  })

  it('a full cache invalidation also clears it', async () => {
    const { engine } = await overLimitEngine()
    for (let i = 0; i < 31; i++) await engine.admin.deleteRole(`r${i}`)
    engine.cache.invalidate()
    await engine.can('u1', 'read', { attributes: {}, type: 'post' })
    expect(await tableHealth(engine)).toBeUndefined()
  })

  it('a cross-instance roles event clears it, so replicas recover too', async () => {
    const { engine } = await overLimitEngine()
    for (let i = 0; i < 31; i++) await engine.admin.deleteRole(`r${i}`)
    // What a replica receives when another instance changed the role set.
    engine.cache.invalidateRoles()
    await engine.can('u1', 'read', { attributes: {}, type: 'post' })
    expect(await tableHealth(engine)).toBeUndefined()
  })

  it('still latches again if the limit is exceeded a second time', async () => {
    const { engine } = await overLimitEngine()
    for (let i = 0; i < 31; i++) await engine.admin.deleteRole(`r${i}`)
    await engine.can('u1', 'read', { attributes: {}, type: 'post' })
    for (let i = 100; i < 131; i++) await engine.admin.saveRole(role(i))
    await engine.can('u1', 'read', { attributes: {}, type: 'post' })
    expect(await tableHealth(engine)).toEqual({
      available: false,
      limit: 32,
      reason: 'role-limit-exceeded',
      roleCount: 33,
    })
  })
})
