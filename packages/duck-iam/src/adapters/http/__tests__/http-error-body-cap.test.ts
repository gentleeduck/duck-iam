import { describe, expect, it, vi } from 'vitest'
import { hasIamErrorCode } from '../../../core/errors'
import { IamHttpAdapter } from '../index'

type A = 'read'
type R = 'post'
type Ro = 'viewer'
type S = 'org-1'

function responseErrorMeta(err: unknown): { status: number; body: string } {
  if (!hasIamErrorCode(err, 'IAM_HTTP_RESPONSE_ERROR')) {
    throw new Error(`expected IAM_HTTP_RESPONSE_ERROR, got ${String(err)}`)
  }
  return err.meta
}

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
      const meta = responseErrorMeta(err)
      // The cap holds even though the upstream returned 10 MiB.
      expect(meta.body.length).toBeLessThan(500)
      expect(meta.body).toContain('...(truncated)')
      expect(meta.status).toBe(400)
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
      const meta = responseErrorMeta(err)
      expect(meta.body).toContain('validation failed for field X')
      expect(meta.body).not.toContain('...(truncated)')
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
      const meta = responseErrorMeta(err)
      expect(meta.body).toContain('...(truncated)')
      expect(meta.body).toContain('A'.repeat(200))
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
      const meta = responseErrorMeta(err)
      expect(meta.body).not.toContain('...(truncated)')
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
      const meta = responseErrorMeta(err)
      // Caps to empty string rather than crashing on the body read.
      expect(meta.status).toBe(500)
      expect(meta.body).toBe('')
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
      const meta = responseErrorMeta(err)
      expect(meta.body.length).toBeLessThan(500)
      expect(meta.status).toBe(503)
      expect(meta.body).toContain('...(truncated)')
    }
  })
})
