import { afterEach, describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

/**
 * The per-request timeout timer must not outlive the request: a dangling timer
 * keeps the event loop alive and aborts an already-settled controller.
 */
describe('IamHttpAdapter per-request timeout timer', () => {
  afterEach(() => vi.useRealTimers())

  it('clears the timer once the request settles', async () => {
    vi.useFakeTimers()
    const fetch = vi.fn(async () => Response.json([]))
    const adapter = new IamHttpAdapter({ baseUrl: 'https://api.example.com', fetch, timeoutMs: 5_000 })
    await adapter.listPolicies()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('clears the timer when the request fails', async () => {
    vi.useFakeTimers()
    const fetch = vi.fn(async () => new Response('nope', { status: 400 }))
    const adapter = new IamHttpAdapter({ baseUrl: 'https://api.example.com', fetch, timeoutMs: 5_000 })
    await expect(adapter.listPolicies()).rejects.toThrow()
    expect(vi.getTimerCount()).toBe(0)
  })
})
