import { describe, expect, it } from 'vitest'
import type { IamClient } from '../../../core/types'
import { createIamAccessControl } from '../index'

type A = 'read' | 'delete'
type R = 'post'
type S = 'org-1'

// Pins that the React client answers from the caller's current permissions: a frozen shared loading map,
// `refetch` using the latest `fetchFn`, and a provider that shares no map with the caller in either direction.

function makeReact() {
  const states: { value: unknown }[] = []
  const effects: { cleanup?: () => void; deps?: readonly unknown[] }[] = []
  const queued: (() => void)[] = []
  const callbacks: { cb: unknown; deps?: readonly unknown[] }[] = []
  let stateIdx = 0
  let effectIdx = 0
  let callbackIdx = 0

  const depsChanged = (a?: readonly unknown[], b?: readonly unknown[]): boolean =>
    !a || !b || a.length !== b.length || a.some((v, i) => !Object.is(v, b[i]))

  const React = {
    // The context double carries a real value, because the provider assertions read back through `useContext`.
    createContext: <T>(value: T) => {
      const ctx: { Provider: unknown; current: T } = { Provider: null, current: value }
      ctx.Provider = { __ctx: ctx }
      return ctx
    },
    createElement: (type: unknown, props: { value?: unknown }) => {
      if (type !== null && typeof type === 'object' && '__ctx' in type) {
        Reflect.set(Reflect.get(type, '__ctx') as object, 'current', props.value)
      }
      return null
    },
    // Memoises on deps like React. An identity double hands the hook a fresh closure every render,
    // so a stale `fetchFn` could never occur and the refetch tests would pass vacuously.
    // biome-ignore lint/complexity/noBannedTypes: matches React's own useCallback signature
    useCallback<T extends Function>(cb: T, deps?: readonly unknown[]): T {
      const i = callbackIdx++
      const prev = callbacks[i]
      if (prev && !depsChanged(prev.deps, deps)) return prev.cb as T
      callbacks[i] = { cb, deps }
      return cb
    },
    useContext: <T>(ctx: { current: T }): T => ctx.current,
    useEffect(effect: () => void | (() => void), deps?: readonly unknown[]): void {
      const i = effectIdx++
      const prev = effects[i]
      if (prev && !depsChanged(prev.deps, deps)) return
      prev?.cleanup?.()
      const slot: { cleanup?: () => void; deps?: readonly unknown[] } = { deps }
      effects[i] = slot
      queued.push(() => {
        const cleanup = effect()
        if (typeof cleanup === 'function') slot.cleanup = cleanup
      })
    },
    useMemo: <T>(factory: () => T): T => factory(),
    useState<T>(initial: T | (() => T)): [T, (v: T) => void] {
      const i = stateIdx++
      states[i] ??= { value: typeof initial === 'function' ? (initial as () => T)() : initial }
      const slot = states[i]!
      return [slot.value as T, (v: T) => (slot.value = v)]
    },
  }

  return {
    React,
    beginRender: () => {
      stateIdx = 0
      effectIdx = 0
      callbackIdx = 0
    },
    flush: async () => {
      while (queued.length > 0) queued.shift()!()
      await new Promise((r) => setTimeout(r, 0))
    },
  }
}

const perms = (map: Record<string, boolean>) => map as unknown as IamClient.PermissionMap<A, R, S>

describe('the loading placeholder is not shared writable state', () => {
  it('CONTROL: two hooks from one factory both start with no grants', async () => {
    const a = makeReact()
    const b = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(a.React as never)
    a.beginRender()
    expect(usePermissions(async () => perms({}), []).can('delete', 'post')).toBe(false)
    b.beginRender()
    expect(usePermissions(async () => perms({}), []).can('delete', 'post')).toBe(false)
  })

  it('writing into the map a loading hook returned does not grant it elsewhere', async () => {
    const a = makeReact()
    const b = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(a.React as never)

    a.beginRender()
    const first = usePermissions(() => new Promise<IamClient.PermissionMap<A, R, S>>(() => {}), [])
    // An optimistic write into what the hook handed back; `Reflect.set` reports refusal as `false`, not a throw.
    expect(Reflect.set(first.permissions, 'delete:post', true)).toBe(false)

    b.beginRender()
    const second = usePermissions(() => new Promise<IamClient.PermissionMap<A, R, S>>(() => {}), [])
    expect(second.can('delete', 'post')).toBe(false)
    expect(first.can('delete', 'post')).toBe(false)
  })
})

describe('refetch uses the caller’s current fetchFn', () => {
  it('CONTROL: the initial load uses the fetchFn it was given', async () => {
    const { React, beginRender, flush } = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(React as never)
    beginRender()
    usePermissions(async () => perms({ 'delete:post': true }), [])
    await flush()
    beginRender()
    expect(usePermissions(async () => perms({ 'delete:post': true }), []).can('delete', 'post')).toBe(true)
  })

  it('a refetch after the fetchFn changed loads the new subject, not the first', async () => {
    const { React, beginRender, flush } = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(React as never)

    const alice = async () => perms({ 'delete:post': true })
    const bob = async () => perms({})

    // The default `deps: []`, the case the hook documents `refetch` as covering.
    beginRender()
    usePermissions(alice, [])
    await flush()
    beginRender()
    expect(usePermissions(alice, []).can('delete', 'post')).toBe(true)

    // The component re-renders with bob's fetcher and calls refetch.
    beginRender()
    const withBob = usePermissions(bob, [])
    await withBob.refetch()
    await flush()

    beginRender()
    expect(usePermissions(bob, []).can('delete', 'post')).toBe(false)
  })
})

describe('the provider does not hold the caller’s map', () => {
  it('CONTROL: the permissions passed in are the permissions answered', () => {
    const { React } = makeReact()
    const { useAccess, AccessProvider } = createIamAccessControl<A, R, S>(React as never)
    AccessProvider({ children: null, permissions: perms({ 'delete:post': true }) })
    expect(useAccess().can('delete', 'post')).toBe(true)
  })

  it('mutating the map after passing it in does not change what can() answers', () => {
    const { React } = makeReact()
    const { useAccess, AccessProvider } = createIamAccessControl<A, R, S>(React as never)
    const map = perms({})
    AccessProvider({ children: null, permissions: map })
    // No re-render happens for this, because the identity did not change.
    Reflect.set(map, 'delete:post', true)
    expect(useAccess().can('delete', 'post')).toBe(false)
  })

  it('mutating the map the context hands BACK does not change what can() answers', () => {
    const { React } = makeReact()
    const { useAccess, AccessProvider } = createIamAccessControl<A, R, S>(React as never)
    AccessProvider({ children: null, permissions: perms({}) })

    // The exposed `permissions` is the object `can()` reads, so it is frozen (stable for dependency arrays).
    const exposed = useAccess().permissions
    expect(Reflect.set(exposed, 'delete:post', true)).toBe(false)
    expect(useAccess().can('delete', 'post')).toBe(false)
    expect(useAccess().allowedActions('post')).toEqual([])
  })
})
