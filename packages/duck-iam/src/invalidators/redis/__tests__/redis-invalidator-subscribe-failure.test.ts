import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

// A failed `client.subscribe()` is reported, is not latched as subscribed, and is retried by the next subscribe().

function bus(subscribe: IamRedisInvalidator.IPubSubLike['subscribe']): IamRedisInvalidator.IPubSubLike {
  return { publish() {}, subscribe, unsubscribe() {} }
}

/** Lets the rejection handlers attached inside `ensureSubscribed` run. */
const settle = () => new Promise((r) => setTimeout(r, 0))

const spyWarn = () => vi.spyOn(console, 'warn').mockImplementation(() => {})
let warn: ReturnType<typeof spyWarn>

beforeEach(() => {
  warn = spyWarn()
})

afterEach(() => {
  warn.mockRestore()
})

describe('a rejected client.subscribe()', () => {
  it('reaches onSubscribeError instead of becoming an unhandled rejection', async () => {
    const onSubscribeError = vi.fn()
    const inv = createIamRedisInvalidator({
      channel: 'c',
      client: bus(() => Promise.reject(new Error('NOAUTH'))),
      onSubscribeError,
      secret: 's',
    })
    inv.subscribe(() => {})
    await settle()
    expect(onSubscribeError).toHaveBeenCalledOnce()
    expect(onSubscribeError.mock.calls[0]?.[0]).toBeInstanceOf(Error)
    expect(String(onSubscribeError.mock.calls[0]?.[0])).toContain('NOAUTH')
    expect(onSubscribeError.mock.calls[0]?.[1]).toBe('c')
  })

  it('retries on the next subscribe() rather than staying latched', async () => {
    let attempts = 0
    let handler: ((m: string) => void) | null = null
    const inv = createIamRedisInvalidator({
      client: bus((_channel, h) => {
        attempts++
        if (attempts === 1) return Promise.reject(new Error('NOAUTH'))
        handler = h
        return Promise.resolve()
      }),
      onSubscribeError: () => {},
      secret: 's',
    })

    inv.subscribe(() => {})
    await settle()
    expect(attempts).toBe(1)

    const received: unknown[] = []
    inv.subscribe((e) => received.push(e))
    await settle()
    expect(attempts).toBe(2)

    // The retry actually wired the receive path up, not just re-issued a call.
    expect(handler).not.toBeNull()
    expect(received).toEqual([])
  })

  it('warns when no handler is configured, rather than failing silently', async () => {
    const inv = createIamRedisInvalidator({
      client: bus(() => Promise.reject(new Error('NOAUTH'))),
      secret: 's',
    })
    inv.subscribe(() => {})
    await settle()
    const messages = warn.mock.calls.map((c) => String(c[0]))
    expect(messages.some((m) => m.includes('subscribe to') && m.includes('NOAUTH'))).toBe(true)
  })

  it('handles a client that throws synchronously', async () => {
    const onSubscribeError = vi.fn()
    const inv = createIamRedisInvalidator({
      client: bus(() => {
        throw new Error('sync boom')
      }),
      onSubscribeError,
      secret: 's',
    })
    expect(() => inv.subscribe(() => {})).not.toThrow()
    await settle()
    expect(String(onSubscribeError.mock.calls[0]?.[0])).toContain('sync boom')
  })

  it('does not re-issue subscribe while the first attempt is still in flight', async () => {
    let attempts = 0
    let release: (() => void) | undefined
    const inv = createIamRedisInvalidator({
      client: bus(() => {
        attempts++
        return new Promise<void>((r) => {
          release = r
        })
      }),
      secret: 's',
    })
    inv.subscribe(() => {})
    inv.subscribe(() => {})
    expect(attempts).toBe(1)
    release?.()
    await settle()
    inv.subscribe(() => {})
    // Resolved, so `subscribed` is latched and no further call is made.
    expect(attempts).toBe(1)
  })

  // Control: a healthy subscribe reports nothing and is issued exactly once.
  it('control: a resolving subscribe neither warns nor calls the hook', async () => {
    const onSubscribeError = vi.fn()
    const inv = createIamRedisInvalidator({
      client: bus(() => Promise.resolve()),
      onSubscribeError,
      secret: 's',
    })
    inv.subscribe(() => {})
    await settle()
    expect(onSubscribeError).not.toHaveBeenCalled()
    expect(warn).not.toHaveBeenCalled()
  })
})
