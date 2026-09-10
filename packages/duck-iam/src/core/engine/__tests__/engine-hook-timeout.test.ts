import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

type Action = 'read' | 'delete'
type Res = 'post'
type Role = 'viewer'

const viewer: AccessControl.IRole<Action, Res, Role> = {
  id: 'viewer',
  name: 'Viewer',
  permissions: [{ action: 'read', resource: 'post' }],
}
const post = { attributes: {}, type: 'post' as const }
const never = () => new Promise<never>(() => undefined)

function adapter() {
  return new IamMemoryAdapter<Action, Res, Role>({ assignments: { u1: ['viewer'] }, roles: [viewer] })
}

/** A memory adapter that answers `withClient`, so the bound facade can bind it. */
function bindable(a: IamMemoryAdapter<Action, Res, Role>): IamMemoryAdapter<Action, Res, Role> {
  const copy = Object.assign(Object.create(Object.getPrototypeOf(a)), a)
  return Object.assign(copy, { withClient: () => bindable(a) })
}

function engineWith(
  hooks: IamEngineTypes.IHooks<Action, Res>,
  opts: { adapter?: IamMemoryAdapter<Action, Res, Role>; hookTimeoutMs?: number } = {},
) {
  return new IamEngine<Action, Res, Role>({
    adapter: opts.adapter ?? adapter(),
    hooks,
    hookTimeoutMs: opts.hookTimeoutMs ?? 20,
    mode: 'production',
  })
}

async function within<T>(p: Promise<T>, ms: number): Promise<T | 'pending'> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const cutoff = new Promise<'pending'>((resolve) => {
    timer = setTimeout(() => resolve('pending'), ms)
  })
  try {
    return await Promise.race([p, cutoff])
  } finally {
    clearTimeout(timer)
  }
}

let logged: string[] = []
beforeEach(() => {
  logged = []
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    logged.push(String(args[0]))
  })
})
afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('a hook whose promise never settles does not hold the call open', () => {
  it('onDeny', async () => {
    expect(await within(engineWith({ onDeny: never }).can('u1', 'delete', post), 1_000)).toBe(false)
    expect(logged.some((l) => l.includes('onDeny hook did not settle within 20ms'))).toBe(true)
  })

  it('afterEvaluate', async () => {
    expect(await within(engineWith({ afterEvaluate: never }).can('u1', 'read', post), 1_000)).toBe(true)
  })

  it('onError, with the adapter down', async () => {
    const down = adapter()
    vi.spyOn(down, 'listPolicies').mockRejectedValue(new Error('adapter down'))
    expect(await within(engineWith({ onError: never }, { adapter: down }).can('u1', 'read', post), 1_000)).toBe(false)
  })

  it('beforeEvaluate fails closed through onError', async () => {
    const errors: string[] = []
    const engine = engineWith({ beforeEvaluate: never, onError: (err) => void errors.push(err.message) })
    expect(await within(engine.can('u1', 'read', post), 1_000)).toBe(false)
    expect(errors).toEqual([expect.stringContaining('beforeEvaluate hook did not settle within 20ms')])
  })

  it('beforeEvaluate in explain() rejects', async () => {
    const engine = new IamEngine<Action, Res, Role, string, 'development'>({
      adapter: adapter(),
      hooks: { beforeEvaluate: never },
      hookTimeoutMs: 20,
      mode: 'development',
    })
    await expect(within(engine.explain('u1', 'read', post), 1_000)).rejects.toThrow(
      /beforeEvaluate hook did not settle/,
    )
  })

  it('onDeny in permissions()', async () => {
    const checks = [
      { action: 'delete', resource: 'post' },
      { action: 'read', resource: 'post' },
    ] as const
    expect(await within(engineWith({ onDeny: never }).permissions('u1', checks), 1_000)).toEqual({
      'delete:post': false,
      'read:post': true,
    })
  })

  it('onMutation, and the write still lands', async () => {
    const engine = engineWith({ onMutation: never })
    expect(await within(engine.admin.assignRole('u2', 'viewer'), 1_000)).toBeUndefined()
    expect(await engine.can('u2', 'read', post)).toBe(true)
  })

  it('onMutation draining on a transaction flush, and the invalidation still applies', async () => {
    const engine = engineWith({ onMutation: never }, { adapter: bindable(adapter()) })
    const perms = engine.withTransaction({})
    await perms.admin.assignRole('u2', 'viewer')
    const spy = vi.spyOn(engine.cache, 'invalidateSubject')

    expect(await within(perms.pending.flush(), 1_000)).toBeUndefined()
    expect(spy).toHaveBeenCalledWith('u2')
  })

  it('a rejection arriving after the window is still logged', async () => {
    const late = () => new Promise<void>((_, reject) => setTimeout(() => reject(new Error('late')), 40))
    expect(await engineWith({ onDeny: late }, { hookTimeoutMs: 10 }).can('u1', 'delete', post)).toBe(false)
    await new Promise((resolve) => setTimeout(resolve, 80))
    expect(logged.some((l) => l.includes('onDeny hook threw'))).toBe(true)
  })
})

describe('hookTimeoutMs', () => {
  it('CONTROL: a hook that settles inside the window is still awaited', async () => {
    const audited: string[] = []
    const onDeny = async () => {
      await new Promise((resolve) => setTimeout(resolve, 5))
      audited.push('denied')
    }
    await engineWith({ onDeny }, { hookTimeoutMs: 1_000 }).can('u1', 'delete', post)
    expect(audited).toEqual(['denied'])
    expect(logged).toEqual([])
  })

  it('CONTROL: 0 waits indefinitely', async () => {
    expect(await within(engineWith({ onDeny: never }, { hookTimeoutMs: 0 }).can('u1', 'delete', post), 60)).toBe(
      'pending',
    )
  })

  it('does not start a timer for a hook that returns synchronously', async () => {
    const spy = vi.spyOn(globalThis, 'setTimeout')
    const timed = () => spy.mock.calls.filter((c) => c[1] === 4_321).length
    await engineWith({ onDeny: () => undefined }, { hookTimeoutMs: 4_321 }).can('u1', 'delete', post)
    expect(timed()).toBe(0)
    await engineWith({ onDeny: async () => undefined }, { hookTimeoutMs: 4_321 }).can('u1', 'delete', post)
    expect(timed()).toBe(1)
  })

  it('defaults to 5 seconds', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    let called = false
    let done = false
    const engine = new IamEngine<Action, Res, Role>({
      adapter: adapter(),
      adapterTimeoutMs: 0,
      hooks: {
        onDeny: () => {
          called = true
          return never()
        },
      },
    })
    void engine.can('u1', 'delete', post).then(() => {
      done = true
    })
    for (let i = 0; i < 1_000 && !called; i++) await Promise.resolve()
    expect(called).toBe(true)
    await vi.advanceTimersByTimeAsync(4_999)
    expect(done).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    for (let i = 0; i < 100 && !done; i++) await Promise.resolve()
    expect(done).toBe(true)
  })

  it.each([Number.NaN, -1, Number.POSITIVE_INFINITY])('rejects %s', (hookTimeoutMs) => {
    expect(() => new IamEngine<Action, Res, Role>({ adapter: adapter(), hookTimeoutMs })).toThrow(/hookTimeoutMs/)
  })
})
