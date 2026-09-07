import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccessControl, IamAdapter } from '../../types'
import { IamEngine } from '../engine'

/**
 * A grant with an `expiresAt` is a promise about a moment, and the subject
 * cache is a snapshot taken before it. These tests are about the gap between
 * the two.
 *
 * The drizzle adapter filters `[startsAt, expiresAt)` in the query, to the
 * millisecond, and `drizzle-assignment-expiry-attributes.test.ts` pins that
 * boundary from both sides. Above it, `loadSubject` caches whatever the adapter
 * answered for the engine's whole `cacheTTL` - 60 seconds by default - with
 * nothing tying the entry's life to the grant's. Everything below is written
 * against an adapter that behaves exactly as drizzle does, so what fails here
 * fails there.
 */

/** A time-boxed grant, as the drizzle assignment row stores one. */
interface IWindowedGrant {
  readonly role: string
  readonly scope?: string
  readonly startsAt?: number
  readonly expiresAt?: number
}

/**
 * The temporal half of the drizzle adapter, and nothing else: rows carry
 * `[startsAt, expiresAt)` and every read applies the window at `Date.now()`,
 * lower bound inclusive, upper bound exclusive.
 */
class WindowedAdapter implements IamAdapter.IAdapter {
  reads = 0
  private _grants: IWindowedGrant[]
  private _roles: AccessControl.IRole[]

  constructor(roles: AccessControl.IRole[], grants: IWindowedGrant[]) {
    this._roles = roles
    this._grants = grants
  }

  private _active(): IWindowedGrant[] {
    const now = Date.now()
    return this._grants.filter(
      (g) => (g.startsAt === undefined || now >= g.startsAt) && (g.expiresAt === undefined || now < g.expiresAt),
    )
  }

  async listPolicies(): Promise<AccessControl.IPolicy[]> {
    return []
  }
  async getPolicy(): Promise<AccessControl.IPolicy | null> {
    return null
  }
  async savePolicy(): Promise<void> {}
  async deletePolicy(): Promise<void> {}
  async listRoles(): Promise<AccessControl.IRole[]> {
    return this._roles
  }
  async getRole(id: string): Promise<AccessControl.IRole | null> {
    return this._roles.find((r) => r.id === id) ?? null
  }
  async saveRole(): Promise<void> {}
  async deleteRole(): Promise<void> {}
  async getSubjectRoles(): Promise<string[]> {
    this.reads += 1
    return [
      ...new Set(
        this._active()
          .filter((g) => g.scope === undefined)
          .map((g) => g.role),
      ),
    ]
  }
  /**
   * The half of the contract that makes the rest of this file possible: the
   * store knows the bounds, the engine does not, so the store reports the next
   * one and the engine caps its cache entry there. Same rule the drizzle
   * adapter implements against `min(startsAt, expiresAt)` over the future.
   */
  async getSubjectGrantBoundary(): Promise<number | null> {
    const now = Date.now()
    const future: number[] = []
    for (const g of this._grants) {
      if (g.startsAt !== undefined && g.startsAt > now) future.push(g.startsAt)
      if (g.expiresAt !== undefined && g.expiresAt > now) future.push(g.expiresAt)
    }
    return future.length === 0 ? null : Math.min(...future)
  }

  async getSubjectScopedRoles(): Promise<{ role: string; scope: string }[]> {
    const out: { role: string; scope: string }[] = []
    for (const g of this._active()) if (g.scope !== undefined) out.push({ role: g.role, scope: g.scope })
    return out
  }
  async assignRole(): Promise<void> {}
  async revokeRole(): Promise<void> {}
  async getSubjectAttributes(): Promise<Record<string, never>> {
    return {}
  }
  async setSubjectAttributes(): Promise<void> {}
}

const ROLES: AccessControl.IRole[] = [
  { id: 'break-glass', name: 'Break glass', permissions: [{ action: 'delete', resource: 'database' }] },
  { id: 'reader', name: 'Reader', permissions: [{ action: 'read', resource: 'database' }] },
]

const DB = { attributes: {}, type: 'database' } as const

const T0 = Date.UTC(2026, 0, 15, 12, 0, 0)

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(T0)
})
afterEach(() => {
  vi.useRealTimers()
})

describe('a grant that expires stops granting, whatever the cache thinks', () => {
  it('denies the millisecond the window closes, not one cacheTTL later', async () => {
    // A 30-second break-glass grant under the default 60-second cache TTL:
    // the grant is gone from the store for the whole second half of the entry's
    // life. This is the shape an on-call escalation actually has.
    const adapter = new WindowedAdapter(ROLES, [{ expiresAt: T0 + 30_000, role: 'break-glass' }])
    const engine = new IamEngine({ adapter })

    expect(await engine.can('u1', 'delete', DB)).toBe(true)

    vi.setSystemTime(T0 + 30_000)
    expect(await engine.can('u1', 'delete', DB)).toBe(false)
  })

  it('the cached snapshot does not outlive the grant by a single millisecond', async () => {
    const adapter = new WindowedAdapter(ROLES, [{ expiresAt: T0 + 1_000, role: 'break-glass' }])
    const engine = new IamEngine({ adapter })

    expect(await engine.can('u1', 'delete', DB)).toBe(true)
    vi.setSystemTime(T0 + 999)
    expect(await engine.can('u1', 'delete', DB)).toBe(true)
    vi.setSystemTime(T0 + 1_000)
    expect(await engine.can('u1', 'delete', DB)).toBe(false)
  })

  it('a grant that has not started yet does not stay denied past its start', async () => {
    // The mirror case, and the one that costs availability rather than safety:
    // a scheduled grant cached as absent must not stay absent after it opens.
    const adapter = new WindowedAdapter(ROLES, [{ role: 'break-glass', startsAt: T0 + 10_000 }])
    const engine = new IamEngine({ adapter })

    expect(await engine.can('u1', 'delete', DB)).toBe(false)
    vi.setSystemTime(T0 + 10_000)
    expect(await engine.can('u1', 'delete', DB)).toBe(true)
  })

  it('an unbounded grant is still cached for the full TTL', async () => {
    // The cap must come from the grants, not from a blanket shortening: a store
    // with no temporal grants at all keeps exactly the caching it had.
    const adapter = new WindowedAdapter(ROLES, [{ role: 'reader' }])
    const engine = new IamEngine({ adapter })

    await engine.can('u1', 'read', DB)
    const afterFirst = adapter.reads
    vi.setSystemTime(T0 + 59_000)
    await engine.can('u1', 'read', DB)

    expect(adapter.reads).toBe(afterFirst)
  })

  it('the earliest boundary wins when a subject holds several windows', async () => {
    const adapter = new WindowedAdapter(ROLES, [
      { expiresAt: T0 + 45_000, role: 'reader' },
      { expiresAt: T0 + 5_000, role: 'break-glass' },
    ])
    const engine = new IamEngine({ adapter })

    expect(await engine.can('u1', 'delete', DB)).toBe(true)
    vi.setSystemTime(T0 + 5_000)
    expect(await engine.can('u1', 'delete', DB)).toBe(false)
    expect(await engine.can('u1', 'read', DB)).toBe(true)
    vi.setSystemTime(T0 + 45_000)
    expect(await engine.can('u1', 'read', DB)).toBe(false)
  })
})

/**
 * The boundary is a hint from the store, and a hint can be wrong.
 *
 * `getSubjectGrantBoundary` is optional and advisory: it shortens a cache
 * entry, it never lengthens one and it never decides anything. So every way a
 * store can get it wrong - a number that is not a time, a bound already behind,
 * one absurdly far ahead, or a method that simply throws - has to land on
 * "cache less", never on "grant longer" and never on "the subject is now
 * undecidable".
 */
describe('a store that reports its boundary badly', () => {
  class HintedAdapter extends WindowedAdapter {
    constructor(
      grants: IWindowedGrant[],
      private readonly _hint: () => Promise<number | null>,
    ) {
      super(ROLES, grants)
    }
    override async getSubjectGrantBoundary(): Promise<number | null> {
      return await this._hint()
    }
  }

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('%s is ignored rather than shortening or extending the entry', async (_label, hint) => {
    const adapter = new HintedAdapter([{ role: 'reader' }], async () => hint)
    const engine = new IamEngine({ adapter })

    expect(await engine.can('u1', 'read', DB)).toBe(true)
    const afterFirst = adapter.reads
    vi.setSystemTime(T0 + 59_000)
    expect(await engine.can('u1', 'read', DB)).toBe(true)
    expect(adapter.reads, 'a nonsense hint must not change the entry lifetime').toBe(afterFirst)
    vi.setSystemTime(T0 + 61_000)
    expect(await engine.can('u1', 'read', DB)).toBe(true)
    expect(adapter.reads, 'and the TTL must still expire the entry').toBeGreaterThan(afterFirst)
  })

  // `0` is not nonsense - it is the epoch, and so a bound long past. It belongs
  // with the case below, not with the values above.
  it.each([
    ['one millisecond ago', T0 - 1],
    ['the epoch', 0],
  ])('a boundary already in the past (%s) leaves nothing cached, so the next call re-reads', async (_l, hint) => {
    const adapter = new HintedAdapter([{ role: 'reader' }], async () => hint)
    const engine = new IamEngine({ adapter })

    expect(await engine.can('u1', 'read', DB)).toBe(true)
    const afterFirst = adapter.reads
    expect(await engine.can('u1', 'read', DB)).toBe(true)
    expect(adapter.reads, 'an already-passed bound must not be cached as a live entry').toBeGreaterThan(afterFirst)
  })

  it('a boundary past the TTL does not extend the entry beyond it', async () => {
    // A store claiming an hour of stability cannot buy itself an hour of
    // caching: `cacheTTL` is still the ceiling.
    const adapter = new HintedAdapter([{ role: 'reader' }], async () => T0 + 3_600_000)
    const engine = new IamEngine({ adapter })

    expect(await engine.can('u1', 'read', DB)).toBe(true)
    const afterFirst = adapter.reads
    vi.setSystemTime(T0 + 61_000)
    expect(await engine.can('u1', 'read', DB)).toBe(true)
    expect(adapter.reads).toBeGreaterThan(afterFirst)
  })

  it('a throwing boundary costs caching, not the decision', async () => {
    // The bounds are still enforced by the read itself; only the hint is gone.
    // Denying every call because an advisory method broke would turn a cache
    // optimisation into a hard dependency, so the load degrades to "do not
    // cache this subject" and the answer stays the store's.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const adapter = new HintedAdapter([{ expiresAt: T0 + 30_000, role: 'break-glass' }], async () => {
        throw new Error('boundary query blew up')
      })
      const engine = new IamEngine({ adapter })

      expect(await engine.can('u1', 'delete', DB)).toBe(true)
      const afterFirst = adapter.reads
      expect(await engine.can('u1', 'delete', DB)).toBe(true)
      expect(adapter.reads, 'an unknown boundary means no cache entry, not a longer one').toBeGreaterThan(afterFirst)

      // and the window is still the window
      vi.setSystemTime(T0 + 30_000)
      expect(await engine.can('u1', 'delete', DB)).toBe(false)
      expect(warn).toHaveBeenCalled()
    } finally {
      warn.mockRestore()
    }
  })

  it('says which subject and which method degraded, and nothing else about them', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const adapter = new HintedAdapter([{ role: 'reader' }], async () => {
        throw new Error('boundary query blew up')
      })
      await new IamEngine({ adapter }).can('u1', 'read', DB)
      const message = warn.mock.calls.map((c) => c.join(' ')).join('\n')
      expect(message).toContain('getSubjectGrantBoundary')
      expect(message).toContain('boundary query blew up')
    } finally {
      warn.mockRestore()
    }
  })
})
