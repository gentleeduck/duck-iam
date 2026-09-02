import { describe, expect, it, vi } from 'vitest'
import type { Events } from '~/core/events'
import { InMemoryEvents } from '~/core/events'
import type { Sessions } from '~/core/sessions'
import { createPending } from '../pending'

/** Minimal stand-in for a session payload; only identity is ever read here. */
function session(id: string): Sessions.Me {
  return { id, identityId: 'i1' } as unknown as Sessions.Me
}

describe('createPending', () => {
  it('buffers emits instead of publishing them', async () => {
    const target = new InMemoryEvents()
    const seen: string[] = []
    target.on('session.revoked', async () => {
      seen.push('revoked')
    })

    const { bus, pending } = createPending(target)
    await bus.emit('session.revoked', { sessionId: 's1', identityId: 'i1' })

    expect(seen).toEqual([])
    expect(pending.size).toBe(1)
  })

  it('flush publishes in emit order, then empties', async () => {
    const target = new InMemoryEvents()
    const seen: string[] = []
    target.on('session.revoked', async () => {
      seen.push('revoked')
    })
    target.on('session.created', async () => {
      seen.push('created')
    })

    const { bus, pending } = createPending(target)
    await bus.emit('session.revoked', { sessionId: 's1', identityId: 'i1' })
    await bus.emit('session.created', { session: session('s2'), identity: null })

    await pending.flush()

    expect(seen).toEqual(['revoked', 'created'])
    expect(pending.size).toBe(0)
  })

  it('flush is idempotent - a second call publishes nothing', async () => {
    const target = new InMemoryEvents()
    const handler = vi.fn(async () => {})
    target.on('session.revoked', handler)

    const { bus, pending } = createPending(target)
    await bus.emit('session.revoked', { sessionId: 's1', identityId: 'i1' })
    await pending.flush()
    await pending.flush()

    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('discard drops everything without publishing', async () => {
    const target = new InMemoryEvents()
    const handler = vi.fn(async () => {})
    target.on('session.revoked', handler)

    const { bus, pending } = createPending(target)
    await bus.emit('session.revoked', { sessionId: 's1', identityId: 'i1' })
    pending.discard()
    await pending.flush()

    expect(handler).not.toHaveBeenCalled()
    expect(pending.size).toBe(0)
  })

  it('peek exposes the buffer without draining it', async () => {
    const { bus, pending } = createPending(new InMemoryEvents())
    await bus.emit('session.revoked', { sessionId: 's1', identityId: 'i1' })

    expect(pending.peek()).toHaveLength(1)
    expect(pending.peek()[0]?.name).toBe('session.revoked')
    expect(pending.size).toBe(1)
  })

  it('flush drains every event even when the bus rejects, then reports with AggregateError', async () => {
    // InMemoryEvents catches listener errors itself, so a rejecting BUS is what
    // exercises this path: a Redis bus with a dropped connection, or an operator
    // bus that deliberately propagates. One bad publish must not strand the rest.
    const delivered: string[] = []
    const target: Events.IBus = {
      on: () => () => {},
      emit: async (event) => {
        if (event === 'session.revoked') throw new Error('publish failed')
        delivered.push(event)
      },
    }

    const { bus, pending } = createPending(target)
    await bus.emit('session.revoked', { sessionId: 's1', identityId: 'i1' })
    await bus.emit('session.created', { session: session('s2'), identity: null })

    await expect(pending.flush()).rejects.toThrow(AggregateError)
    expect(delivered).toEqual(['session.created'])
    expect(pending.size).toBe(0)
  })

  it('on() subscribes on the real bus, so listeners registered through the buffer still work', async () => {
    const target = new InMemoryEvents()
    const { bus, pending } = createPending(target)
    const handler = vi.fn(async () => {})

    bus.on('session.revoked', handler)
    await target.emit('session.revoked', { sessionId: 'direct', identityId: 'i1' })

    expect(handler).toHaveBeenCalledTimes(1)
    expect(pending.size).toBe(0)
  })
})
