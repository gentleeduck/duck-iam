import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// `setInvalidator` assigned the invalidator before `subscribe` returned, so a throwing subscribe left an engine
// that publishes its own revocations and applies nobody else's - stale forever, with nothing reporting it.

const POST = { attributes: {}, id: 'p1', type: 'post' }
const ROLES: AccessControl.IRole[] = [
  { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
]

/** One invalidator whose every interesting behaviour is recorded in `log`. */
function spyInvalidator(name: string, log: string[], opts: { subscribeThrows?: boolean; noTeardown?: boolean } = {}) {
  let handler: ((event: unknown) => void) | null = null
  return {
    deliver(event: unknown): boolean {
      if (!handler) return false
      handler(event)
      return true
    },
    inv: {
      publish: () => void log.push(`${name}:publish`),
      subscribe: (h: (event: never) => void) => {
        if (opts.subscribeThrows) throw new Error(`${name}: bus down`)
        handler = h as unknown as (event: unknown) => void
        // Truthy and not callable, the shape that would be stored and then thrown over on every dispose.
        if (opts.noTeardown) return { not: 'a teardown' } as unknown as () => void
        return () => {
          handler = null
          log.push(`${name}:torn-down`)
        }
      },
    },
  }
}

function newEngine() {
  return new IamEngine({
    adapter: new IamMemoryAdapter({ assignments: { u1: ['writer'] }, policies: [], roles: ROLES }),
    mode: 'production',
  })
}

/** Runs `fn` with console.warn captured, returning the warnings it produced. */
function warningsFrom(fn: () => void): string[] {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
  try {
    fn()
    // Read before restoring: `mockRestore` clears the recorded calls with the implementation.
    return warn.mock.calls.map((args) => args.map(String).join(' '))
  } finally {
    warn.mockRestore()
  }
}

describe('an invalidator attached in one direction only', () => {
  it('is not attached at all when subscribe throws', async () => {
    const log: string[] = []
    const engine = newEngine()
    const a = spyInvalidator('A', log, { subscribeThrows: true })

    expect(() => engine.setInvalidator(a.inv)).toThrow('A: bus down')
    await engine.admin.revokeRole('u1', 'writer')

    expect(log).toEqual([])
  })

  it('does not keep publishing to the invalidator it just replaced, when the replacement fails to subscribe', async () => {
    const log: string[] = []
    const engine = newEngine()
    const a = spyInvalidator('A', log)
    const b = spyInvalidator('B', log, { subscribeThrows: true })

    engine.setInvalidator(a.inv)
    expect(() => engine.setInvalidator(b.inv)).toThrow('B: bus down')
    await engine.admin.revokeRole('u1', 'writer')

    // A was torn down; publishing to it afterwards would broadcast from a node that can no longer receive.
    expect(log).toEqual(['A:torn-down'])
    expect(a.deliver({ kind: 'all' })).toBe(false)
  })

  it('reports nothing about an invalidator it never attached, rather than claiming one', async () => {
    const engine = newEngine()
    const a = spyInvalidator('A', [], { subscribeThrows: true })

    expect(() => engine.setInvalidator(a.inv)).toThrow()

    expect((await engine.healthCheck()).invalidator).toBeUndefined()
  })

  it('stops publishing on dispose, not just receiving', async () => {
    const log: string[] = []
    const engine = newEngine()
    const a = spyInvalidator('A', log)

    engine.setInvalidator(a.inv)
    engine.dispose()
    await engine.admin.revokeRole('u1', 'writer')

    expect(log).toEqual(['A:torn-down'])
  })

  it('says so when subscribe hands back no way to release the subscription', async () => {
    const log: string[] = []
    const engine = newEngine()
    const a = spyInvalidator('A', log, { noTeardown: true })

    const warnings = warningsFrom(() => engine.setInvalidator(a.inv))

    expect(warnings.join('\n')).toContain('returned no teardown function')
    // Still attached - the warning is that it can never be detached, not that it failed.
    await engine.admin.revokeRole('u1', 'writer')
    expect(log).toEqual(['A:publish'])
    engine.dispose()
    expect(a.deliver({ kind: 'all' })).toBe(true)
  })

  it('says so when the teardown itself throws, and still finishes tearing down', async () => {
    const engine = newEngine()
    const a = {
      publish: () => {},
      subscribe: () => () => {
        throw new Error('unsubscribe refused')
      },
    }
    engine.setInvalidator(a)

    const warnings = warningsFrom(() => engine.dispose())

    expect(warnings.join('\n')).toContain('unsubscribe refused')
    // Cleared regardless, so a second dispose does not throw the same thing again.
    expect(warningsFrom(() => engine.dispose())).toEqual([])
  })

  it('stores no teardown at all when subscribe returned something that is not one', async () => {
    const engine = newEngine()
    const a = spyInvalidator('A', [], { noTeardown: true })
    warningsFrom(() => engine.setInvalidator(a.inv))

    // Not "a teardown that threw": nothing callable was kept, so dispose must not invent an error from it.
    expect(warningsFrom(() => engine.dispose())).toEqual([])
  })

  it('still attaches, replaces and detaches a well-behaved invalidator in both directions', async () => {
    const log: string[] = []
    const engine = newEngine()
    const a = spyInvalidator('A', log)
    const b = spyInvalidator('B', log)

    const quiet = warningsFrom(() => engine.setInvalidator(a.inv))
    expect(quiet).toEqual([])
    expect(await engine.can('u1', 'delete', POST)).toBe(true)

    engine.setInvalidator(b.inv)
    expect(a.deliver({ kind: 'all' })).toBe(false)
    expect(b.deliver({ kind: 'all' })).toBe(true)
    await engine.admin.revokeRole('u1', 'writer')

    engine.setInvalidator(null)
    await engine.admin.assignRole('u1', 'writer')

    expect(log).toEqual(['A:torn-down', 'B:publish', 'B:torn-down'])
  })
})
