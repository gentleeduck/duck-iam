import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { IamEngineTypes } from '../../../core/engine/engine.types'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

function makeBus(): { client: IamRedisInvalidator.IPubSubLike; publish: (msg: string) => void; published: string[] } {
  let handler: ((m: string) => void) | null = null
  const published: string[] = []
  return {
    client: {
      publish(_channel, message) {
        published.push(message)
      },
      subscribe(_channel, h) {
        handler = h
      },
      unsubscribe() {},
    },
    publish(msg) {
      handler?.(msg)
    },
    published,
  }
}

// Engines can share one invalidator; a throwing handler must not stop the others clearing their caches.
describe('redis invalidator isolates a throwing handler', () => {
  let errSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    errSpy.mockRestore()
  })

  function wired() {
    const a = makeBus()
    const b = makeBus()
    const ch = `t-iso-${Math.random().toString(36).slice(2)}`
    const invA = createIamRedisInvalidator({ channel: ch, client: a.client, secret: 'k' })
    const invB = createIamRedisInvalidator({ channel: ch, client: b.client, secret: 'k' })
    return { a, b, invA, invB }
  }

  it('still delivers to a later handler when an earlier one throws', () => {
    const { a, b, invA, invB } = wired()
    const received: IamEngineTypes.IInvalidateEvent[] = []
    invB.subscribe(() => {
      throw new Error('engine A handler is broken')
    })
    invB.subscribe((e) => received.push(e))

    invA.publish({ kind: 'all' })
    b.publish(a.published[0]!)

    expect(received).toEqual([{ kind: 'all' }])
  })

  it('does not let the throw escape into the client dispatch', () => {
    const { a, b, invA, invB } = wired()
    invB.subscribe(() => {
      throw new Error('boom')
    })
    invA.publish({ kind: 'all' })
    expect(() => b.publish(a.published[0]!)).not.toThrow()
  })

  it('reports the swallowed handler error', () => {
    const { a, b, invA, invB } = wired()
    invB.subscribe(() => {
      throw new Error('boom')
    })
    invA.publish({ kind: 'all' })
    b.publish(a.published[0]!)
    const msgs = errSpy.mock.calls.map((c: unknown[]) => String(c[0] ?? ''))
    expect(
      msgs.some((m: string) => m.includes('[@gentleduck/iam:invalidator:redis]') && m.includes('handler threw')),
    ).toBe(true)
  })

  // Control: a handler registered before the thrower still runs, so the test
  // above is about isolation and not about ordering.
  it('delivers to an earlier handler too', () => {
    const { a, b, invA, invB } = wired()
    const received: IamEngineTypes.IInvalidateEvent[] = []
    invB.subscribe((e) => received.push(e))
    invB.subscribe(() => {
      throw new Error('boom')
    })
    invA.publish({ kind: 'all' })
    b.publish(a.published[0]!)
    expect(received).toEqual([{ kind: 'all' }])
  })

  // Control: with no thrower nothing is logged, so the assertion above is not
  // matching an unrelated warning.
  it('logs nothing when every handler succeeds', () => {
    const { a, b, invA, invB } = wired()
    invB.subscribe(() => {})
    invA.publish({ kind: 'all' })
    b.publish(a.published[0]!)
    expect(errSpy).not.toHaveBeenCalled()
  })
})
