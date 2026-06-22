import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

type A = 'read'
type R = 'post'
type Ro = 'viewer'
type S = 'org-1'

function makeResponse(body: string, status = 400): Response {
  return {
    ok: false,
    status,
    text: async () => body,
    json: async () => JSON.parse(body),
  } as unknown as Response
}

describe('IamHttpAdapter error body cap', () => {
  it('caps a 10 MiB upstream error body at 200 chars + marker', async () => {
    const evilBody = 'X'.repeat(10 * 1024 * 1024)
    const fetch = vi.fn(async () => makeResponse(evilBody)) as unknown as typeof globalThis.fetch
    const adapter = new IamHttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com', fetch, retries: 0 })
    try {
      await adapter.listPolicies()
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      // The cap holds even though the upstream returned 10 MiB.
      expect(msg.length).toBeLessThan(500)
      expect(msg).toContain('...(truncated)')
      expect(msg).toContain('HTTP 400')
    }
  })

  it('preserves short error bodies verbatim (no false truncation)', async () => {
    const fetch = vi.fn(async () =>
      makeResponse('validation failed for field X', 400),
    ) as unknown as typeof globalThis.fetch
    const adapter = new IamHttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com', fetch, retries: 0 })
    try {
      await adapter.listPolicies()
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).toContain('validation failed for field X')
      expect(msg).not.toContain('...(truncated)')
    }
  })

  it('caps body at exactly 200 chars (boundary)', async () => {
    const body = 'A'.repeat(201)
    const fetch = vi.fn(async () => makeResponse(body, 400)) as unknown as typeof globalThis.fetch
    const adapter = new IamHttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com', fetch, retries: 0 })
    try {
      await adapter.listPolicies()
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).toContain('...(truncated)')
      // 200-char body + marker, plus the framing prefix.
      expect(msg).toContain('A'.repeat(200))
    }
  })

  it('passes through a 200-char body unchanged', async () => {
    const body = 'A'.repeat(200)
    const fetch = vi.fn(async () => makeResponse(body, 400)) as unknown as typeof globalThis.fetch
    const adapter = new IamHttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com', fetch, retries: 0 })
    try {
      await adapter.listPolicies()
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).not.toContain('...(truncated)')
    }
  })

  it('handles res.text() throwing: empty body in the error message, never crash', async () => {
    const broken = {
      ok: false,
      status: 500,
      text: async () => {
        throw new Error('body-read failed')
      },
      json: async () => ({}),
    } as unknown as Response
    const fetch = vi.fn(async () => broken) as unknown as typeof globalThis.fetch
    const adapter = new IamHttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com', fetch, retries: 0 })
    try {
      await adapter.listPolicies()
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      // Caps to empty string rather than crashing on the body read.
      expect(msg).toContain('HTTP 500')
    }
  })

  it('returns body-capped messages on the 5xx path too (transient errors)', async () => {
    const evilBody = 'Z'.repeat(5000)
    const fetch = vi.fn(async () => makeResponse(evilBody, 503)) as unknown as typeof globalThis.fetch
    const adapter = new IamHttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com', fetch, retries: 0 })
    try {
      await adapter.listPolicies()
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg.length).toBeLessThan(500)
      expect(msg).toContain('HTTP 503')
      expect(msg).toContain('...(truncated)')
    }
  })
})
