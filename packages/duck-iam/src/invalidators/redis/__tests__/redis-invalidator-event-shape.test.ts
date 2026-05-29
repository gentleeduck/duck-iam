import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createRedisInvalidator, type RedisInvalidator } from '../index'

function makeBus(): {
  client: RedisInvalidator.IPubSubLike
  publish: (msg: string) => void
} {
  let handler: ((m: string) => void) | null = null
  return {
    client: {
      publish() {},
      subscribe(_channel, h) {
        handler = h
      },
      unsubscribe() {},
    },
    publish(msg) {
      handler?.(msg)
    },
  }
}

describe('Redis invalidator event-shape validation', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('drops {kind:"subject"} missing subjectId', async () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client })
    const seen: unknown[] = []
    inv.subscribe((ev) => {
      seen.push(ev)
    })
    bus.publish(JSON.stringify({ event: { kind: 'subject' }, instanceId: 'other' }))
    expect(seen).toEqual([])
  })

  it('drops {kind:"subject", subjectId: 42} (non-string)', async () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client })
    const seen: unknown[] = []
    inv.subscribe((ev) => {
      seen.push(ev)
    })
    bus.publish(JSON.stringify({ event: { kind: 'subject', subjectId: 42 }, instanceId: 'other' }))
    expect(seen).toEqual([])
  })

  it('drops {kind:"subject", subjectId: ""} (empty string)', async () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client })
    const seen: unknown[] = []
    inv.subscribe((ev) => {
      seen.push(ev)
    })
    bus.publish(JSON.stringify({ event: { kind: 'subject', subjectId: '' }, instanceId: 'other' }))
    expect(seen).toEqual([])
  })

  it('drops {kind:"roles", roleId: 42} (non-string roleId)', async () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client })
    const seen: unknown[] = []
    inv.subscribe((ev) => {
      seen.push(ev)
    })
    bus.publish(JSON.stringify({ event: { kind: 'roles', roleId: 42 }, instanceId: 'other' }))
    expect(seen).toEqual([])
  })

  it('accepts {kind:"roles"} without roleId (the field is optional)', async () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client })
    const seen: unknown[] = []
    inv.subscribe((ev) => {
      seen.push(ev)
    })
    bus.publish(JSON.stringify({ event: { kind: 'roles' }, instanceId: 'other' }))
    expect(seen).toEqual([{ kind: 'roles' }])
  })

  it('accepts well-formed {kind:"subject", subjectId:"user-1"}', async () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client })
    const seen: unknown[] = []
    inv.subscribe((ev) => {
      seen.push(ev)
    })
    bus.publish(JSON.stringify({ event: { kind: 'subject', subjectId: 'user-1' }, instanceId: 'other' }))
    expect(seen).toEqual([{ kind: 'subject', subjectId: 'user-1' }])
  })

  it('accepts well-formed {kind:"all"} and {kind:"policies"}', async () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client })
    const seen: unknown[] = []
    inv.subscribe((ev) => {
      seen.push(ev)
    })
    bus.publish(JSON.stringify({ event: { kind: 'all' }, instanceId: 'other' }))
    bus.publish(JSON.stringify({ event: { kind: 'policies' }, instanceId: 'other' }))
    expect(seen).toEqual([{ kind: 'all' }, { kind: 'policies' }])
  })

  it('drops malformed kind ({kind:"unknown"} or missing)', async () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client })
    const seen: unknown[] = []
    inv.subscribe((ev) => {
      seen.push(ev)
    })
    bus.publish(JSON.stringify({ event: { kind: 'unknown' }, instanceId: 'other' }))
    bus.publish(JSON.stringify({ event: {}, instanceId: 'other' }))
    expect(seen).toEqual([])
  })
})
