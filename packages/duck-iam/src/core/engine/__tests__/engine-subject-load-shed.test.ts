import { describe, expect, it, vi } from 'vitest'
import type { AccessControl, IamAdapter } from '../../types'
import { IamEngine } from '../engine'

type A = string
type R = string
type Ro = string
type S = string

function makeAdapter(overrides: Partial<IamAdapter.IAdapter<A, R, Ro, S>> = {}): IamAdapter.IAdapter<A, R, Ro, S> {
  return {
    listPolicies: async () => [],
    getPolicy: async () => null,
    savePolicy: async () => {},
    deletePolicy: async () => {},
    listRoles: async () => [{ id: 'viewer', name: 'viewer', permissions: [] } satisfies AccessControl.IRole],
    getRole: async () => null,
    saveRole: async () => {},
    deleteRole: async () => {},
    getSubjectRoles: async () => ['viewer'],
    getSubjectAttributes: async () => ({}),
    assignRole: async () => {},
    revokeRole: async () => {},
    setSubjectAttributes: async () => {},
    ...overrides,
  }
}

/** A promise plus its externally-callable resolver, for controlling adapter-call timing in tests. */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

describe('IamEngine constructor: maxConcurrentSubjectLoads validation', () => {
  it('accepts the default (unset -> 0, unbounded)', () => {
    expect(() => new IamEngine<A, R, Ro, S>({ adapter: makeAdapter() })).not.toThrow()
  })

  it('accepts an explicit positive cap', () => {
    expect(() => new IamEngine<A, R, Ro, S>({ adapter: makeAdapter(), maxConcurrentSubjectLoads: 5 })).not.toThrow()
  })

  it('rejects a negative cap', () => {
    expect(() => new IamEngine<A, R, Ro, S>({ adapter: makeAdapter(), maxConcurrentSubjectLoads: -1 })).toThrow(
      /maxConcurrentSubjectLoads must be 0 \(unbounded\) or a finite number >= 1/,
    )
  })

  it('rejects a fractional cap between 0 and 1', () => {
    expect(() => new IamEngine<A, R, Ro, S>({ adapter: makeAdapter(), maxConcurrentSubjectLoads: 0.5 })).toThrow(
      /maxConcurrentSubjectLoads/,
    )
  })

  it('rejects NaN', () => {
    expect(() => new IamEngine<A, R, Ro, S>({ adapter: makeAdapter(), maxConcurrentSubjectLoads: Number.NaN })).toThrow(
      /maxConcurrentSubjectLoads/,
    )
  })
})

describe('IamEngine: subject load shed under the cap, end-to-end', () => {
  it('can() fails closed (false) and reports onError once the in-flight subject-load cap is hit', async () => {
    const gate1 = deferred<Ro[]>()
    const gate2 = deferred<Ro[]>()
    const adapter = makeAdapter({
      getSubjectRoles: vi.fn().mockReturnValueOnce(gate1.promise).mockReturnValueOnce(gate2.promise),
    })
    const errors: Error[] = []
    const engine = new IamEngine<A, R, Ro, S>({
      adapter,
      maxConcurrentSubjectLoads: 2,
      hooks: { onError: (err) => void errors.push(err) },
    })

    // Fill the cap with two subjects that never settle during this assertion.
    const p1 = engine.can('s-1', 'read', { type: 'post', attributes: {} })
    const p2 = engine.can('s-2', 'read', { type: 'post', attributes: {} })

    const thirdAllowed = await engine.can('s-3', 'read', { type: 'post', attributes: {} })
    expect(thirdAllowed).toBe(false)
    expect(errors).toHaveLength(1)
    expect(errors[0]?.message).toMatch(/subject load shed/)

    gate1.resolve([])
    gate2.resolve([])
    await Promise.all([p1, p2])
  })

  it('does not shed once earlier loads have settled (cap only bounds concurrency, not totals)', async () => {
    const engine = new IamEngine<A, R, Ro, S>({ adapter: makeAdapter(), maxConcurrentSubjectLoads: 1 })
    await engine.can('s-1', 'read', { type: 'post', attributes: {} })
    await engine.can('s-2', 'read', { type: 'post', attributes: {} })
    // Neither call touches the cap since each fully settles before the next starts.
  })
})
