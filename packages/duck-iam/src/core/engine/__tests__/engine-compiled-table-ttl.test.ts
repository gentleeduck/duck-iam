import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// With no `invalidator` (the default), `cacheTTL` is the only way out-of-band writes converge.
// Production and development must converge on the same schedule: they differ in speed, not consistency.
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

    // Straight to the adapter, so the engine is never told - as with a second process writing the shared store.
    await adapter.saveRole(revoked)
    expect(await engine.can('u1', 'read', post, undefined)).toBe(true)

    vi.setSystemTime(Date.now() + 61_000)
    expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
  })

  // Control: explicit invalidation converges at once, so the test above is not passing because everything expires.
  it('converges immediately through the engine write API', async () => {
    const adapter = new IamMemoryAdapter({ assignments: { u1: ['reader'] }, roles: [granting] })
    const engine = new IamEngine({ adapter, cacheTTL: 60, mode })

    expect(await engine.can('u1', 'read', post, undefined)).toBe(true)
    await engine.admin.saveRole(revoked)
    expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
  })

  // Proves the table is rebuilt from the adapter, not merely dropped.
  it('picks up an out-of-band grant once cacheTTL elapses', async () => {
    const adapter = new IamMemoryAdapter({ assignments: { u1: ['reader'] }, roles: [revoked] })
    const engine = new IamEngine({ adapter, cacheTTL: 60, mode })

    expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
    await adapter.saveRole(granting)
    vi.setSystemTime(Date.now() + 61_000)
    expect(await engine.can('u1', 'read', post, undefined)).toBe(true)
  })
})

// `invalidatePolicies` drops the table but keeps `roleCache`, so a rebuilt table must expire with its oldest input.
// Reached by `admin.savePolicy`, `admin.deletePolicy` and a peer's `{kind: 'policies'}` event.
describe.each(['production', 'development'] as const)(
  '%s engine, a policy-only invalidation does not re-age the role snapshot',
  (mode) => {
    const otherPolicy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p-unrelated',
      name: 'Unrelated',
      rules: [
        { actions: ['write'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources: ['other'] },
      ],
    }

    it('still converges within cacheTTL of the out-of-band write', async () => {
      const adapter = new IamMemoryAdapter({ assignments: { u1: ['reader'] }, roles: [granting] })
      const engine = new IamEngine({ adapter, cacheTTL: 60, mode })
      const start = Date.now()

      expect(await engine.can('u1', 'read', post, undefined)).toBe(true)

      vi.setSystemTime(start + 1_000)
      await adapter.saveRole(revoked)

      // Late in roleCache's life, an unrelated policy write drops only the policy caches and the table.
      vi.setSystemTime(start + 59_000)
      await engine.admin.savePolicy(otherPolicy)
      expect(await engine.can('u1', 'read', post, undefined)).toBe(true)

      // Past the TTL measured from when the roles were actually read.
      vi.setSystemTime(start + 61_000)
      expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
    })

    it('an out-of-band grant appears on the same schedule', async () => {
      // The other direction, so a rebuild that simply denies more often cannot pass the test above.
      const adapter = new IamMemoryAdapter({ assignments: { u1: ['reader'] }, roles: [revoked] })
      const engine = new IamEngine({ adapter, cacheTTL: 60, mode })
      const start = Date.now()

      expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
      vi.setSystemTime(start + 1_000)
      await adapter.saveRole(granting)
      vi.setSystemTime(start + 59_000)
      await engine.admin.savePolicy(otherPolicy)
      vi.setSystemTime(start + 61_000)
      expect(await engine.can('u1', 'read', post, undefined)).toBe(true)
    })

    it('a table built from genuinely fresh inputs keeps its full TTL', async () => {
      // Counterweight: with nothing separating the clocks, the cap must not shorten the normal window.
      const adapter = new IamMemoryAdapter({ assignments: { u1: ['reader'] }, roles: [granting] })
      const engine = new IamEngine({ adapter, cacheTTL: 60, mode })
      const start = Date.now()

      expect(await engine.can('u1', 'read', post, undefined)).toBe(true)
      await adapter.saveRole(revoked)

      vi.setSystemTime(start + 59_000)
      expect(await engine.can('u1', 'read', post, undefined)).toBe(true)
      vi.setSystemTime(start + 61_000)
      expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
    })
  },
)
