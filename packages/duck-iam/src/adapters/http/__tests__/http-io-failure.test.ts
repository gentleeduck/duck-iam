import { describe, expect, it, vi } from 'vitest'
import { type IamHttp, IamHttpAdapter } from '../index'

type A = 'read'
type R = 'post'
type Ro = 'viewer'
type S = 'org-1'

const BASE: Pick<IamHttp.IConfig, 'allowedHosts' | 'baseUrl'> = {
  allowedHosts: ['api.example.com'],
  baseUrl: 'https://api.example.com',
}

/** Response whose body is exposed as a chunked ReadableStream reader. */
function streamResponse(chunks: Uint8Array[], status = 200): Response {
  let i = 0
  const reader = {
    async cancel() {},
    async read(): Promise<{ done: boolean; value: Uint8Array | undefined }> {
      const chunk = chunks[i++]
      return chunk === undefined ? { done: true, value: undefined } : { done: false, value: chunk }
    },
  }
  return {
    body: { getReader: () => reader },
    json: async () => {
      throw new Error('json() must not be used when a body stream exists')
    },
    ok: status >= 200 && status < 300,
    status,
    text: async () => {
      throw new Error('text() must not be used when a body stream exists')
    },
  } as unknown as Response
}

function rejectingFetch(err: unknown): { fetch: typeof globalThis.fetch; count: () => number } {
  let calls = 0
  const fetch = vi.fn(async () => {
    calls++
    throw err
  })
  return { count: () => calls, fetch: fetch as unknown as typeof globalThis.fetch }
}

describe('IamHttpAdapter I/O failure handling', () => {
  describe('malformed payload', () => {
    it('rejects when a 200 response body is not JSON (never resolves to an empty list)', async () => {
      const fetch = vi.fn(async () => ({
        json: async () => JSON.parse('not json at all'),
        ok: true,
        status: 200,
        text: async () => 'not json at all',
      })) as unknown as typeof globalThis.fetch
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, fetch, retries: 0, timeoutMs: 0 })
      await expect(adapter.listPolicies()).rejects.toThrow()
    })

    it('rejects when a streamed 200 body is not JSON', async () => {
      const chunks = [new TextEncoder().encode('{"broken":')]
      const fetch = vi.fn(async () => streamResponse(chunks)) as unknown as typeof globalThis.fetch
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, fetch, retries: 0, timeoutMs: 0 })
      await expect(adapter.listPolicies()).rejects.toThrow(SyntaxError)
    })

    it('reassembles a multi-chunk stream, including a multi-byte char split across chunks', async () => {
      const policy = {
        id: 'p-ü-1',
        name: 'ü',
        algorithm: 'deny-overrides',
        rules: [
          { id: 'r', effect: 'allow', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [] } },
        ],
      }
      const full = new TextEncoder().encode(JSON.stringify([policy]))
      // Split mid-way so the 2-byte `ü` straddles the chunk boundary.
      const cut = full.indexOf(0xc3) + 1
      const fetch = vi.fn(async () =>
        streamResponse([full.slice(0, cut), full.slice(cut)]),
      ) as unknown as typeof globalThis.fetch
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, fetch, retries: 0, timeoutMs: 0 })
      expect((await adapter.listPolicies()).map((p) => p.id)).toEqual(['p-ü-1'])
    })

    it('rejects a streamed body larger than the 4 MiB cap', async () => {
      const chunk = new Uint8Array(1024 * 1024)
      chunk.fill(0x20)
      const fetch = vi.fn(async () =>
        streamResponse([chunk, chunk, chunk, chunk, chunk]),
      ) as unknown as typeof globalThis.fetch
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, fetch, retries: 0, timeoutMs: 0 })
      await expect(adapter.listPolicies()).rejects.toThrow(/exceeds 4 MiB cap/)
    })

    it('caps a streamed error body at 200 chars', async () => {
      const chunk = new TextEncoder().encode('E'.repeat(4096))
      const fetch = vi.fn(async () => streamResponse([chunk, chunk, chunk], 400)) as unknown as typeof globalThis.fetch
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, fetch, retries: 0, timeoutMs: 0 })
      await expect(adapter.listPolicies()).rejects.toThrow(/HTTP 400/)
      await expect(adapter.listPolicies()).rejects.toThrow(/\.\.\.\(truncated\)/)
    })
  })

  describe('connection failure', () => {
    it.each(['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND'])(
      'retries %s up to the budget then surfaces the error',
      async (code) => {
        const err = Object.assign(new Error(`connect ${code}`), { code })
        const { count, fetch } = rejectingFetch(err)
        const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, backoffMs: 1, fetch, retries: 2, timeoutMs: 0 })
        await expect(adapter.getSubjectRoles('user-1')).rejects.toThrow(new RegExp(code))
        expect(count()).toBe(3)
      },
    )

    it('does not retry a non-transient rejection', async () => {
      const { count, fetch } = rejectingFetch(new Error('programmer error'))
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, backoffMs: 1, fetch, retries: 3, timeoutMs: 0 })
      await expect(adapter.listPolicies()).rejects.toThrow(/programmer error/)
      expect(count()).toBe(1)
    })

    it('a connection failure never degrades to an empty role list', async () => {
      const err = Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' })
      const { fetch } = rejectingFetch(err)
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, backoffMs: 1, fetch, retries: 0, timeoutMs: 0 })
      await expect(adapter.getSubjectRoles('user-1')).rejects.toThrow()
      await expect(adapter.getSubjectScopedRoles('user-1')).rejects.toThrow()
      await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow()
    })
  })

  describe('per-request timeout', () => {
    it('aborts a hung request and surfaces the failure', async () => {
      const fetch = vi.fn(
        (_url: string, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () => {
              const err = new Error('The operation was aborted')
              err.name = 'AbortError'
              reject(err)
            })
          }),
      ) as unknown as typeof globalThis.fetch
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, fetch, retries: 0, timeoutMs: 20 })
      await expect(adapter.listPolicies()).rejects.toThrow(/aborted/)
    })

    it('timeoutMs: 0 attaches no timeout signal', async () => {
      let sawSignal: AbortSignal | null | undefined
      const fetch = vi.fn(async (_url: string, init?: RequestInit) => {
        sawSignal = init?.signal
        return { json: async () => [], ok: true, status: 200, text: async () => '[]' } as unknown as Response
      }) as unknown as typeof globalThis.fetch
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, fetch, retries: 0, timeoutMs: 0 })
      expect(await adapter.listPolicies()).toEqual([])
      expect(sawSignal).toBeUndefined()
    })

    it('forwards a caller-supplied signal to fetch', async () => {
      let sawSignal: AbortSignal | null | undefined
      const fetch = vi.fn(async (_url: string, init?: RequestInit) => {
        sawSignal = init?.signal
        return { json: async () => [], ok: true, status: 200, text: async () => '[]' } as unknown as Response
      }) as unknown as typeof globalThis.fetch
      const adapter = new IamHttpAdapter<A, R, Ro, S>({ ...BASE, fetch, retries: 0, timeoutMs: 0 })
      const ctrl = new AbortController()
      await adapter.listPolicies({ signal: ctrl.signal })
      expect(sawSignal).toBe(ctrl.signal)
    })
  })

  describe('circuit breaker half-open', () => {
    it('rejects a concurrent caller while the half-open probe is in flight', async () => {
      let release: (() => void) | undefined
      let calls = 0
      const fetch = vi.fn(async () => {
        calls++
        if (calls === 1) throw Object.assign(new Error('down'), { code: 'ECONNREFUSED' })
        await new Promise<void>((r) => {
          release = r
        })
        return { json: async () => [], ok: true, status: 200, text: async () => '[]' } as unknown as Response
      }) as unknown as typeof globalThis.fetch
      const adapter = new IamHttpAdapter<A, R, Ro, S>({
        ...BASE,
        circuitBreakerCooldownMs: 0,
        circuitBreakerThreshold: 1,
        fetch,
        retries: 0,
        timeoutMs: 0,
      })
      await expect(adapter.listPolicies()).rejects.toThrow(/down/)
      // Cooldown 0 -> immediately half-open. First caller takes the probe slot.
      const probe = adapter.listPolicies()
      await expect(adapter.listPolicies()).rejects.toThrow(/half-open probe in flight/)
      release?.()
      expect(await probe).toEqual([])
    })
  })
})
