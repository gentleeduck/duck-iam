import { describe, expect, it, vi } from 'vitest'
import type { IamPrimitives } from '../../../core/types'
import { IamHttpAdapter } from '../index'

describe('IamHttpAdapter direct-call input shape', () => {
  it('rejects a string attrs value before any request is made', async () => {
    const fetch = vi.fn(
      async () => ({ ok: true, status: 200, text: async () => '{}', json: async () => ({}) }) as unknown as Response,
    )
    const adapter = new IamHttpAdapter({
      baseUrl: 'https://api.example.com',
      fetch: fetch as unknown as typeof globalThis.fetch,
    })
    await expect(
      adapter.setSubjectAttributes('user-1', 'admin=true' as unknown as IamPrimitives.Attributes),
    ).rejects.toThrow(/attributes for "user-1" must be a plain object \(got string\)/)
    expect(fetch).not.toHaveBeenCalled()
  })
})
