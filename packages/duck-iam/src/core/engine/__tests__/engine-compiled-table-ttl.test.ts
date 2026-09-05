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

/**
 * The TTL clock above only tells the truth while every cache was warmed in the
 * same tick, which is what those tests do. The clocks separate the moment
 * something drops a *derived* cache without dropping what it was derived from.
 *
 * `invalidatePolicies` is exactly that, deliberately: it clears the policy and
 * merged caches and nulls the compiled table, and leaves `roleCache` alone
 * because no role changed. The next request then recompiled the table from role
 * data read up to a full `cacheTTL` ago and stamped it `Date.now()`, handing
 * that stale snapshot a second complete TTL. At `cacheTTL: 60` an out-of-band
 * revoke written at t=1s was still answering allow at t=111s.
 *
 * The three ordinary ways to reach it are `admin.savePolicy`,
 * `admin.deletePolicy` and a peer's `{kind: 'policies'}` invalidation event -
 * none of them exotic, and none of them touching roles at all.
 *
 * A derived cache is now no fresher than its oldest input.
 */
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

      // Late in roleCache's own life, an unrelated policy write drops the
      // policy caches and the table - and nothing else.
      vi.setSystemTime(start + 59_000)
      await engine.admin.savePolicy(otherPolicy)
      expect(await engine.can('u1', 'read', post, undefined)).toBe(true)

      // Past the TTL measured from when the roles were actually read. Before
      // the fix this was still `true`, and stayed true until t=120s.
      vi.setSystemTime(start + 61_000)
      expect(await engine.can('u1', 'read', post, undefined)).toBe(false)
    })

    it('an out-of-band grant appears on the same schedule', async () => {
      // The other direction, so the test above cannot be satisfied by a rebuild
      // that simply denies more often.
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
      // The counterweight: capping the derived clock must not shorten the
      // normal case into "no caching at all". Nothing here separates the
      // clocks, so the grant has to survive the whole window.
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
