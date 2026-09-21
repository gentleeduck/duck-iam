import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'
import { _resetInboundEventReports } from '../engine.invalidation'

// The inbound half of the invalidator contract. Shape-checking the event and guarding the handler both lived in
// the redis invalidator only, so any other transport delivered straight into an engine that trusted the value's
// type: an unrecognised kind was silently dropped, and a non-object threw into the transport's listener.

const POST = { attributes: {}, id: 'p1', type: 'post' }
const ROLES: AccessControl.IRole[] = [
  { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
]

function wire() {
  let deliver: (event: unknown) => void = () => {}
  const adapter = new IamMemoryAdapter({ assignments: { u1: ['writer'] }, policies: [], roles: ROLES })
  const engine = new IamEngine({
    adapter,
    invalidator: {
      publish: () => {},
      subscribe: (handler) => {
        deliver = (event: unknown) => handler(event as never)
        return () => {}
      },
    },
    mode: 'production',
  })
  return { adapter, deliver: (event: unknown) => deliver(event), engine }
}

/** Collects the warnings one delivery produces, and reports whether it threw back at the transport. */
function deliverWatched(deliver: (event: unknown) => void, event: unknown): { threw: string; warnings: string[] } {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
  const error = vi.spyOn(console, 'error').mockImplementation(() => {})
  let threw = ''
  try {
    deliver(event)
  } catch (err) {
    threw = err instanceof Error ? err.message : String(err)
  }
  const warnings = [...warn.mock.calls, ...error.mock.calls].map((args) => args.map(String).join(' '))
  warn.mockRestore()
  error.mockRestore()
  return { threw, warnings }
}

beforeEach(() => {
  _resetInboundEventReports()
})

describe('an inbound invalidation the engine cannot apply', () => {
  it('drops the caches rather than ignore it, when the kind is one it does not know', async () => {
    const { adapter, deliver, engine } = wire()
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    // Behind the engine's back, so only a real invalidation can change the answer.
    await adapter.revokeRole('u1', 'writer')
    expect(await engine.can('u1', 'delete', POST)).toBe(true)

    const { threw, warnings } = deliverWatched(deliver, { kind: 'attributes' })

    expect(threw).toBe('')
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(warnings.join('\n')).toContain('unrecognised kind "attributes"')
  })

  it('clears the compiled table too, keying off what it applied and not off the event it was sent', async () => {
    const { adapter, deliver, engine } = wire()
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    // A role definition change: only dropping the compiled table can make production notice it.
    await adapter.saveRole({ id: 'writer', name: 'W', permissions: [] })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)

    deliverWatched(deliver, { kind: 'attributes' })

    expect(await engine.can('u1', 'delete', POST)).toBe(false)
  })

  it('does not throw back into the transport when the event is not an object at all', async () => {
    for (const event of [null, undefined, 'all', 7, [{ kind: 'all' }]]) {
      _resetInboundEventReports()
      const { adapter, deliver, engine } = wire()
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      await adapter.revokeRole('u1', 'writer')

      const { threw, warnings } = deliverWatched(deliver, event)

      expect({ event, threw }).toEqual({ event, threw: '' })
      expect({ applied: await engine.can('u1', 'delete', POST), event }).toEqual({ applied: false, event })
      expect(warnings.join('\n')).toContain('not an event object')
    }
  })

  it('fails closed on a kind it knows carrying an id it cannot use', async () => {
    for (const event of [{ kind: 'subject' }, { kind: 'subject', subjectId: '' }, { kind: 'subject', subjectId: 9 }]) {
      _resetInboundEventReports()
      const { adapter, deliver, engine } = wire()
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      await adapter.revokeRole('u1', 'writer')

      deliverWatched(deliver, event)

      expect({ applied: await engine.can('u1', 'delete', POST), event }).toEqual({ applied: false, event })
    }
  })

  it('still applies a well-formed event precisely, and says nothing about it', async () => {
    const { adapter, deliver, engine } = wire()
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    await adapter.revokeRole('u1', 'writer')

    // A policy invalidation must not reach the subject cache; fail-closed is for what cannot be placed.
    const policies = deliverWatched(deliver, { kind: 'policies' })
    expect(policies.warnings).toEqual([])
    expect(await engine.can('u1', 'delete', POST)).toBe(true)

    const subject = deliverWatched(deliver, { kind: 'subject', subjectId: 'u1' })
    expect(subject.warnings).toEqual([])
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
  })

  it('fails closed when the value cannot even be inspected, instead of throwing at the transport', async () => {
    const hostile = {
      get kind(): string {
        throw new Error('getter says no')
      },
    }
    const revocable = Proxy.revocable({ kind: 'all' }, {})
    revocable.revoke()

    for (const event of [hostile, revocable.proxy]) {
      _resetInboundEventReports()
      const { adapter, deliver, engine } = wire()
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      await adapter.revokeRole('u1', 'writer')

      const { threw, warnings } = deliverWatched(deliver, event)

      expect(threw).toBe('')
      expect(await engine.can('u1', 'delete', POST)).toBe(false)
      expect(warnings.join('\n')).toContain('could not be read')
    }
  })

  it('warns once per distinct reason, and once per reason is not once overall', () => {
    const { deliver } = wire()

    const first = deliverWatched(deliver, { kind: 'attributes' })
    const repeat = deliverWatched(deliver, { kind: 'attributes' })
    const other = deliverWatched(deliver, { kind: 'tenants' })
    const nonObject = deliverWatched(deliver, null)

    expect({
      first: first.warnings.length,
      nonObject: nonObject.warnings.length,
      other: other.warnings.length,
      repeat: repeat.warnings.length,
    }).toEqual({ first: 1, nonObject: 1, other: 1, repeat: 0 })
  })
})
