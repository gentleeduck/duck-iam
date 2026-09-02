import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

/**
 * A production engine with more roles than the 32-bit grant mask can address
 * cannot answer any check. That must surface at boot and on the health probe,
 * not inside the first authorization request.
 */
const rolesOf = (n: number): AccessControl.IRole[] =>
  Array.from({ length: n }, (_, i) => ({
    id: `role-${i}`,
    name: `Role ${i}`,
    permissions: [{ action: 'read', resource: 'post' }],
  }))

const engineOf = (roleCount: number, mode: 'development' | 'production') =>
  new IamEngine({
    adapter: new IamMemoryAdapter({ assignments: {}, policies: [], roles: rolesOf(roleCount) }),
    mode,
  })

describe('over-limit role count is surfaced at boot', () => {
  it('preload throws in production instead of deferring to the first check', async () => {
    await expect(engineOf(33, 'production').preload()).rejects.toThrow(/33 roles exceeds the 32-role limit/)
  })

  it('healthCheck reports not-ok rather than a green probe', async () => {
    const health = await engineOf(33, 'production').healthCheck()
    expect(health.ok).toBe(false)
    expect(health.lastError).toMatch(/32-role limit/)
  })

  it('a table that fits preloads and reports healthy', async () => {
    const engine = engineOf(32, 'production')
    await expect(engine.preload()).resolves.toBeUndefined()
    expect((await engine.healthCheck()).ok).toBe(true)
  })

  it('development mode is unaffected by the limit', async () => {
    const engine = engineOf(33, 'development')
    await expect(engine.preload()).resolves.toBeUndefined()
    expect((await engine.healthCheck()).ok).toBe(true)
  })
})
