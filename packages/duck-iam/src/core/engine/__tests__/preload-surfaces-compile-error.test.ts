import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

/**
 * An engine with more roles than the 32-bit grant mask can address still
 * answers every check - through the interpreter - so `preload()` must not
 * throw and the probe must not go red. What it must do is *say so*: an
 * operator running without the compiled table is paying for it in throughput,
 * and a green probe that mentions nothing is how that goes unnoticed for
 * months. `healthCheck().compiledTable` carries the report; `ok` stays true
 * because the engine is serving correct answers.
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

const spyWarn = () => vi.spyOn(console, 'warn').mockImplementation(() => {})

describe.each(['development', 'production'] as const)('over-limit role count (mode: %s)', (mode) => {
  it('preload resolves instead of throwing, because the interpreter can serve', async () => {
    const warn = spyWarn()
    try {
      await expect(engineOf(33, mode).preload()).resolves.toBeUndefined()
    } finally {
      warn.mockRestore()
    }
  })

  it('healthCheck stays green but reports the table as unavailable', async () => {
    const warn = spyWarn()
    try {
      const health = await engineOf(33, mode).healthCheck()
      // Green: every check is answered, and answered correctly.
      expect(health.ok).toBe(true)
      expect(health.lastError).toBeUndefined()
      // Reported: the operator can see the fast path is off, and why.
      expect(health.compiledTable).toEqual({
        available: false,
        limit: 32,
        reason: 'role-limit-exceeded',
        roleCount: 33,
      })
    } finally {
      warn.mockRestore()
    }
  })

  it('a table that fits preloads, reports healthy, and says nothing about the table', async () => {
    const warn = spyWarn()
    try {
      const engine = engineOf(32, mode)
      await expect(engine.preload()).resolves.toBeUndefined()
      const health = await engine.healthCheck()
      expect(health.ok).toBe(true)
      expect(health.compiledTable).toBeUndefined()
      expect(warn).not.toHaveBeenCalled()
    } finally {
      warn.mockRestore()
    }
  })
})
