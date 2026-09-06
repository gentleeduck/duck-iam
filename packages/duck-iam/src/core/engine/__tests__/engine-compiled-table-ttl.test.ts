import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

/**
 * `cacheTTL` is the engine's convergence window for writes made outside it - by
 * another process against the same database - and it is the only convergence
 * mechanism when no `invalidator` is configured, which is the default.
 *
 * Production mode used to opt out of it silently: the compiled table was a plain
 * field cleared only by an explicit invalidation, so a revocation made anywhere
 * else never took effect until restart, while development converged in
 * `cacheTTL` seconds against the identical adapter. The two modes are meant to
 * differ in speed, not in consistency.
 */
const granting: AccessControl.IRole = {
  id: 'reader',
  name: 'Reader',
  permissions: [{ action: 'read', resource: 'post' }],
}

/** The same role after another process removed the permission. */
const revoked: AccessControl.IRole = { id: 'reader', name: 'Reader', permissions: [] }

const post = { attributes: {}, type: 'post' }

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
})

describe.each(['production', 'development'] as const)('%s engine, out-of-band revocation', (mode) => {
  it('serves the stale grant inside cacheTTL and converges once it elapses', async () => {
    const adapter = new IamMemoryAdapter({ assignments: { u1: ['reader'] }, roles: [granting] })
    const engine = new IamEngine({ adapter, cacheTTL: 60, mode })

    expect(await engine.can('u1', 'read', post, undefined)).toBe(true)

    // Straight to the adapter: the engine is never told, exactly as a second
    // process writing the shared store would leave it.
    await adapter.saveRole(revoked)
    expect(await engine.can('u1', 'read', post, undefined)).toBe(true)

    vi.setSystemTime(Date.now() + 61_000)
    expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
  })

  // Control: an explicit invalidation still converges immediately, so the test
  // above is not passing because everything expires at once.
  it('converges immediately through the engine write API', async () => {
    const adapter = new IamMemoryAdapter({ assignments: { u1: ['reader'] }, roles: [granting] })
    const engine = new IamEngine({ adapter, cacheTTL: 60, mode })

    expect(await engine.can('u1', 'read', post, undefined)).toBe(true)
    await engine.admin.saveRole(revoked)
    expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
  })

  // A grant added out of band must appear too - the table is genuinely rebuilt
  // from the adapter, not merely dropped.
  it('picks up an out-of-band grant once cacheTTL elapses', async () => {
    const adapter = new IamMemoryAdapter({ assignments: { u1: ['reader'] }, roles: [revoked] })
    const engine = new IamEngine({ adapter, cacheTTL: 60, mode })

    expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
    await adapter.saveRole(granting)
    vi.setSystemTime(Date.now() + 61_000)
    expect(await engine.can('u1', 'read', post, undefined)).toBe(true)
  })
})
