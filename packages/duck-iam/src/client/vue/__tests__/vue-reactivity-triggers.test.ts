import { describe, expect, it } from 'vitest'
import type { IamClient } from '../../../core/types'
import { createIamVueAccess } from '../index'

// A real `ref` notifies only when the value's identity changes, so an update made in place is invisible.
// These tests model that rule instead of installing `vue`, which is an optional peer dep.

type A = 'read' | 'create'
type R = 'post'
type S = 'org-1'

interface TrackedRef<T> {
  value: T
}

function makeTrackingVue() {
  const counts = new WeakMap<object, number>()
  const vue = {
    computed<T>(getter: () => T): TrackedRef<T> {
      return { value: getter() }
    },
    defineComponent(options: Record<string, unknown>): unknown {
      return options
    },
    h(type: unknown, props?: Record<string, unknown> | null, children?: unknown): Record<string, unknown> {
      return { children, props, type }
    },
    inject<T>(): T | undefined {
      return undefined
    },
    provide(): void {},
    ref<T>(initial: T): TrackedRef<T> {
      let current = initial
      const r: TrackedRef<T> = {
        get value() {
          return current
        },
        set value(next: T) {
          if (Object.is(current, next)) return
          current = next
          counts.set(r, (counts.get(r) ?? 0) + 1)
        },
      }
      counts.set(r, 0)
      return r
    },
  }
  /** How many times a subscriber would have been woken for this ref. */
  const triggersOf = (r: object): number => {
    const n = counts.get(r)
    if (n === undefined) throw new Error('not a ref from this vue')
    return n
  }
  return { triggersOf, vue }
}

const MAP = { 'read:post': true } as unknown as IamClient.PartialPermissionMap<A, R, S>
const OTHER = { 'create:post': true } as unknown as IamClient.PartialPermissionMap<A, R, S>

describe('every vue state change the client makes is one a real ref would notify on', () => {
  it('a successful load wakes the permissions and loading refs exactly once each', async () => {
    const { triggersOf, vue } = makeTrackingVue()
    const { usePermissions } = createIamVueAccess<A, R, S>(vue)
    const state = usePermissions(() => Promise.resolve(MAP))
    await state.refetch()
    expect(state.permissions.value).toBe(MAP)
    expect(state.can('read', 'post')).toBe(true)
    expect(triggersOf(state.permissions)).toBe(1)
    expect(triggersOf(state.loading)).toBe(1)
    expect(triggersOf(state.error)).toBe(0)
  })

  it('a failed load wakes error and loading, and leaves the map cleared', async () => {
    const { triggersOf, vue } = makeTrackingVue()
    const { usePermissions } = createIamVueAccess<A, R, S>(vue)
    const state = usePermissions(() => Promise.reject(new Error('offline')))
    await state.refetch()
    expect(state.permissions.value).toEqual({})
    expect(triggersOf(state.error)).toBe(1)
    expect(triggersOf(state.loading)).toBe(1)
  })

  it('a refetch wakes the permissions ref when it clears the previous subject, not only when the new map lands', async () => {
    const { triggersOf, vue } = makeTrackingVue()
    const { usePermissions } = createIamVueAccess<A, R, S>(vue)
    let next = MAP
    const state = usePermissions(() => Promise.resolve(next))
    await state.refetch()
    expect(triggersOf(state.permissions)).toBe(1)

    next = OTHER
    const pending = state.refetch()
    // Cleared before the load resolves: a component rendering the old subject's grants is woken here.
    expect(state.permissions.value).toEqual({})
    expect(triggersOf(state.permissions)).toBe(2)
    await pending
    expect(state.permissions.value).toBe(OTHER)
    expect(triggersOf(state.permissions)).toBe(3)
  })

  it('update() on the provided state wakes the ref', () => {
    const { triggersOf, vue } = makeTrackingVue()
    const { createAccessState } = createIamVueAccess<A, R, S>(vue)
    const state = createAccessState(MAP)
    state.update(OTHER)
    // Equal, not identical: `update` stores its own frozen copy, as React's provider and `IamAccessClient` do,
    // so a later write to the caller's `OTHER` cannot grant. `client-parity.test.ts` pins that directly.
    expect(state.permissions.value).toEqual(OTHER)
    expect(state.permissions.value).not.toBe(OTHER)
    expect(triggersOf(state.permissions)).toBe(1)
  })

  it('the client never edits a map in place, so a frozen one survives a load and an update', async () => {
    const { vue } = makeTrackingVue()
    const { createAccessState, usePermissions } = createIamVueAccess<A, R, S>(vue)
    const frozen = Object.freeze({ 'read:post': true }) as unknown as IamClient.PartialPermissionMap<A, R, S>
    const loaded = usePermissions(() => Promise.resolve(frozen))
    await loaded.refetch()
    expect(loaded.can('read', 'post')).toBe(true)

    const state = createAccessState(frozen)
    state.update(Object.freeze({}) as unknown as IamClient.PartialPermissionMap<A, R, S>)
    expect(state.can('read', 'post')).toBe(false)
  })
})
