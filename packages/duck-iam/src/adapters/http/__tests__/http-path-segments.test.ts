import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

function adapterWithSpy(body = '[]') {
  const fetchSpy = vi.fn(async () => new Response(body, { headers: { 'content-type': 'application/json' } }))
  const adapter = new IamHttpAdapter({ baseUrl: 'https://api.test/access', fetch: fetchSpy, retries: 0 })
  return { adapter, fetchSpy }
}

const calledUrl = (spy: ReturnType<typeof vi.fn>): string => String(spy.mock.calls[0]?.[0])

describe('http adapter builds path segments safely', () => {
  it('percent-encodes a hostile id instead of splitting the path', async () => {
    const { adapter, fetchSpy } = adapterWithSpy('null')
    await adapter.getPolicy('a/b?c#d')
    expect(calledUrl(fetchSpy)).toBe('https://api.test/access/policies/a%2Fb%3Fc%23d')
  })

  it('refuses a dot-segment id rather than walking the remote path', async () => {
    const { adapter } = adapterWithSpy()
    await expect(adapter.getPolicy('..')).rejects.toThrow(/cannot be a path segment/)
    await expect(adapter.getRole('.')).rejects.toThrow(/cannot be a path segment/)
  })

  it('an empty id is a miss and never reaches the network', async () => {
    const { adapter, fetchSpy } = adapterWithSpy('null')
    expect(await adapter.getPolicy('')).toBeNull()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('encodes every segment of a multi-segment path', async () => {
    const { adapter, fetchSpy } = adapterWithSpy()
    await adapter.getSubjectRoles('u/1')
    expect(calledUrl(fetchSpy)).toBe('https://api.test/access/subjects/u%2F1/roles')
  })
})
