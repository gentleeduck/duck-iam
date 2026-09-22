import { afterEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

// `publish` is operator-supplied code on the revocation path, and the engine called it as a bare `void`. A
// rejection was therefore unhandled - fatal under Node's default `--unhandled-rejections=throw` - and a
// synchronous throw came back out of a write that had already landed and already cleared the local caches.

const POST = { attributes: {}, id: 'p1', type: 'post' }
const ROLES: AccessControl.IRole[] = [
  { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
]

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

function engineWith(publish: IamEngineTypes.IInvalidator['publish']) {
  const seen: string[] = []
  const engine = new IamEngine({
    adapter: new IamMemoryAdapter({ assignments: { u1: ['writer'] }, policies: [], roles: ROLES }),
    invalidator: {
      publish: (event) => {
        seen.push(event.kind)
        return publish(event)
      },
      subscribe: () => () => {},
    },
    mode: 'production',
  })
  return { engine, seen }
}

/** Counts rejections Node would otherwise treat as fatal, for the duration of one call. */
async function unhandledDuring(fn: () => Promise<unknown>): Promise<number> {
  const seen: unknown[] = []
  const onUnhandled = (reason: unknown): void => void seen.push(reason)
  process.on('unhandledRejection', onUnhandled)
  try {
    await fn()
    await sleep(20)
  } finally {
    process.off('unhandledRejection', onUnhandled)
  }
  return seen.length
}

describe('an invalidator whose publish fails', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('leaves no unhandled rejection when publish rejects', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { engine, seen } = engineWith(() => Promise.reject(new Error('fleet bus down')))
    const unhandled = await unhandledDuring(() => engine.admin.revokeRole('u1', 'writer'))
    expect(unhandled).toBe(0)
    expect(seen).toEqual(['subject'])
    expect(warn.mock.calls.map(String).join('\n')).toContain('invalidator.publish("subject") failed')
  })

  it('does not fail a write whose publish throws synchronously', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { engine } = engineWith(() => {
      throw new Error('fleet bus down')
    })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    await expect(engine.admin.revokeRole('u1', 'writer')).resolves.toBeUndefined()
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
  })

  it('still clears the local caches, which is the half that does not need the fleet', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { engine } = engineWith(() => Promise.reject(new Error('fleet bus down')))
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    await engine.admin.revokeRole('u1', 'writer')
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
  })

  it('reports the failure rather than swallowing it, naming what stays stale', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { engine } = engineWith(() => {
      throw new Error('fleet bus down')
    })
    await engine.admin.savePolicy({ algorithm: 'deny-overrides', id: 'p', name: 'P', rules: [] })
    const message = warn.mock.calls.map(String).join('\n')
    expect(message).toContain('invalidator.publish("policies") failed')
    expect(message).toContain('other instances keep their caches')
    expect(message).toContain('fleet bus down')
  })

  it('does not let a publish failure mask the write error that caused it', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const inner = new IamMemoryAdapter({ assignments: { u1: ['writer'] }, policies: [], roles: ROLES })
    const adapter = new Proxy(inner, {
      get: (target, prop, receiver) =>
        prop === 'revokeRole'
          ? () => Promise.reject(new Error('store unreachable'))
          : Reflect.get(target, prop, receiver),
    })
    const engine = new IamEngine({
      adapter,
      invalidator: {
        publish: () => {
          throw new Error('fleet bus down')
        },
        subscribe: () => () => {},
      },
      mode: 'production',
    })
    // The invalidation runs in a `finally`, so a throw there would replace the real reason the write failed.
    await expect(engine.admin.revokeRole('u1', 'writer')).rejects.toThrow('store unreachable')
  })

  it('stays quiet and publishes nothing when the invalidator works', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { engine, seen } = engineWith(() => {})
    await engine.admin.revokeRole('u1', 'writer')
    expect(seen).toEqual(['subject'])
    expect(warn).not.toHaveBeenCalled()
  })
})
