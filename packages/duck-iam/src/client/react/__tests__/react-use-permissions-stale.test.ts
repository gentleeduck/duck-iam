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
    useState<T>(initial: T): [T, (v: T) => void] {
      const i = stateIdx++
      states[i] ??= { value: initial }
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
