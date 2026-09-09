import { describe, expect, it } from 'vitest'
import type { IamClient } from '../../../core/types'
import { createIamAccessControl } from '../index'

type A = 'read' | 'delete'
type R = 'post'
type S = 'org-1'

/**
 * A deps-aware fake React. The harness in `react.test.ts` runs each effect at
 * most once, so it cannot express a refetch at all - which is why the stale
 * window below went unnoticed.
 */
function makeReact() {
  const states: { value: unknown }[] = []
  const effects: { deps?: readonly unknown[]; cleanup?: () => void }[] = []
  const queued: (() => void)[] = []
  let stateIdx = 0
  let effectIdx = 0

  const depsChanged = (a?: readonly unknown[], b?: readonly unknown[]): boolean =>
    !a || !b || a.length !== b.length || a.some((v, i) => !Object.is(v, b[i]))

  const React = {
    createContext: <T>(value: T) => ({ Provider: null, current: value }),
    // biome-ignore lint/complexity/noBannedTypes: matches React's own useCallback signature
    useCallback: <T extends Function>(cb: T): T => cb,
    useContext: <T>(ctx: { current: T }): T => ctx.current,
    useEffect(effect: () => void | (() => void), deps?: readonly unknown[]): void {
      const i = effectIdx++
      const prev = effects[i]
      if (prev && !depsChanged(prev.deps, deps)) return
      prev?.cleanup?.()
      const slot: { deps?: readonly unknown[]; cleanup?: () => void } = { deps }
      effects[i] = slot
      queued.push(() => {
        const cleanup = effect()
        if (typeof cleanup === 'function') slot.cleanup = cleanup
      })
    },
    useMemo: <T>(factory: () => T): T => factory(),
    // Honours the lazy initialiser, because `ReactLike` declares
    // `initialState: T | (() => T)` and real React runs the function once. A
    // double that stored the function itself would hand the hook a function
    // where it expects the value - a failure that says nothing about the code
    // under test.
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
    },
    flush: async () => {
      while (queued.length > 0) queued.shift()!()
      await new Promise((r) => setTimeout(r, 0))
    },
  }
}

const perms = (map: Record<string, boolean>) => map as unknown as IamClient.PermissionMap<A, R, S>

describe('usePermissions does not serve a previous subject', () => {
  it('answers false while a refetch for a new subject is in flight', async () => {
    const { React, beginRender, flush } = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(React as never)

    const alice = async () => perms({ 'delete:post': true })
    let release = (): void => {}
    const bob = () =>
      new Promise<IamClient.PermissionMap<A, R, S>>((r) => {
        release = () => r(perms({}))
      })

    beginRender()
    usePermissions(alice, ['alice'])
    await flush()
    beginRender()
    expect(usePermissions(alice, ['alice']).can('delete', 'post')).toBe(true)

    // Subject changes; bob's fetch has not resolved.
    beginRender()
    usePermissions(bob, ['bob'])
    await flush()
    beginRender()
    const inFlight = usePermissions(bob, ['bob'])
    expect(inFlight.loading).toBe(true)
    expect(inFlight.can('delete', 'post')).toBe(false)

    release()
    await flush()
  })

  it('answers false after a failed refetch, rather than keeping the old grants', async () => {
    const { React, beginRender, flush } = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(React as never)

    const alice = async () => perms({ 'delete:post': true })
    const failing = async (): Promise<IamClient.PermissionMap<A, R, S>> => {
      throw new Error('403 for bob')
    }

    beginRender()
    usePermissions(alice, ['alice'])
    await flush()
    beginRender()
    expect(usePermissions(alice, ['alice']).can('delete', 'post')).toBe(true)

    beginRender()
    usePermissions(failing, ['bob'])
    await flush()
    beginRender()
    const failed = usePermissions(failing, ['bob'])
    expect(failed.can('delete', 'post')).toBe(false)
    expect(failed.error?.message).toBe('403 for bob')
  })

  it('clears a previous error when a new fetch starts', async () => {
    const { React, beginRender, flush } = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(React as never)

    const failing = async (): Promise<IamClient.PermissionMap<A, R, S>> => {
      throw new Error('boom')
    }
    const ok = async () => perms({ 'read:post': true })

    beginRender()
    usePermissions(failing, ['a'])
    await flush()
    beginRender()
    expect(usePermissions(failing, ['a']).error).not.toBeNull()

    beginRender()
    usePermissions(ok, ['b'])
    await flush()
    beginRender()
    const recovered = usePermissions(ok, ['b'])
    expect(recovered.error).toBeNull()
    expect(recovered.can('read', 'post')).toBe(true)
  })
})

/**
 * Vue's `usePermissions` returns a `refetch` and its docblock says the two
 * frameworks are "the same shape". React's returned no such thing: the only way
 * to reload was to change `deps`, so a sign-out or an account switch that did
 * not happen to move a dependency left the previous subject's grants in place -
 * the exact case the reset above exists for, unreachable.
 */
describe('usePermissions can be refetched the way vue can', () => {
  it('refetch reloads without any deps change', async () => {
    const { React, beginRender, flush } = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(React as never)

    let served: Record<string, boolean> = { 'delete:post': true }
    const fetchFn = async () => perms(served)

    beginRender()
    usePermissions(fetchFn, ['same'])
    await flush()
    beginRender()
    const first = usePermissions(fetchFn, ['same'])
    expect(first.can('delete', 'post')).toBe(true)

    // The grant is revoked server-side. Deps are unchanged, so only `refetch`
    // can reach it.
    served = {}
    await first.refetch()
    beginRender()
    expect(usePermissions(fetchFn, ['same']).can('delete', 'post')).toBe(false)
  })

  it('a superseded slow refetch never overwrites a newer one', async () => {
    const { React, beginRender, flush } = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(React as never)

    // Two loads in flight at once, the *earlier* one resolving last. A teardown
    // flag cannot see this: no deps changed, so no effect was ever cleaned up.
    // Without the monotonic run id, alice's late answer lands on top of bob's
    // and `can()` serves the previous subject's grants indefinitely.
    const gates: ((map: Record<string, boolean>) => void)[] = []
    const fetchFn = () =>
      new Promise<IamClient.PermissionMap<A, R, S>>((resolve) => {
        gates.push((map) => resolve(perms(map)))
      })

    beginRender()
    const hook = usePermissions(fetchFn, ['subject'])
    await flush()
    // Retire the effect's own initial load so the two gates below are the only
    // ones outstanding.
    const releaseInitial = gates.shift()
    expect(releaseInitial).toBeTypeOf('function')
    releaseInitial?.({})
    await flush()

    const slowAlice = hook.refetch()
    const fastBob = hook.refetch()
    const [releaseAlice, releaseBob] = gates
    expect(releaseAlice).toBeTypeOf('function')
    expect(releaseBob).toBeTypeOf('function')

    releaseBob?.({})
    await fastBob
    releaseAlice?.({ 'delete:post': true })
    await slowAlice

    beginRender()
    const after = usePermissions(fetchFn, ['subject'])
    expect(after.can('delete', 'post')).toBe(false)
    expect(after.loading).toBe(false)
  })

  it('normalises a non-Error rejection rather than typing it as one', async () => {
    const { React, beginRender, flush } = makeReact()
    const { usePermissions } = createIamAccessControl<A, R, S>(React as never)

    // A rejected fetch chain can carry anything; `error` is declared
    // `Error | null`, so a bare string used to make that declaration false.
    const rejecting = (): Promise<IamClient.PermissionMap<A, R, S>> => Promise.reject('gateway said no')

    beginRender()
    usePermissions(rejecting, ['x'])
    await flush()
    beginRender()
    const failed = usePermissions(rejecting, ['x'])
    expect(failed.error).toBeInstanceOf(Error)
    expect(failed.error?.message).toBe('gateway said no')
  })
})
