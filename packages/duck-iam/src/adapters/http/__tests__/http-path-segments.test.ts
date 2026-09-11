import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

function adapterWithSpy(body = '[]') {
  const fetchSpy = vi.fn(async () => new Response(body, { headers: { 'content-type': 'application/json' } }))
  const adapter = new IamHttpAdapter({ baseUrl: 'https://api.test/access', fetch: fetchSpy, retries: 0 })
  return { adapter, fetchSpy }
}

const calledUrl = (spy: ReturnType<typeof vi.fn>): string => String(spy.mock.calls[0]?.[0])

describe('http adapter builds path segments safely', () => {
  it('percent-encodes a hostile id that holds no separator', async () => {
    const { adapter, fetchSpy } = adapterWithSpy('null')
    await adapter.getPolicy('a?c#d')
    expect(calledUrl(fetchSpy)).toBe('https://api.test/access/policies/a%3Fc%23d')
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
})

// SECURITY: some servers decode `%2F` back into a separator before routing (e.g. Apache `AllowEncodedSlashes On`),
// so encoding `/` only moves the traversal downstream; ids with a separator are refused instead.
describe('http adapter refuses separators in an id', () => {
  const traversals = ['../../admin', 'a/../../b', 'a/b', '..\\..\\admin', 'a\\b']

  for (const id of traversals) {
    it(`refuses ${JSON.stringify(id)} without calling fetch`, async () => {
      const { adapter, fetchSpy } = adapterWithSpy()
      await expect(adapter.getPolicy(id)).rejects.toThrow(/path separator/)
      expect(fetchSpy).not.toHaveBeenCalled()
    })
  }

  it('refuses a separator in any segment, not just the first', async () => {
    const { adapter } = adapterWithSpy()
    await expect(adapter.getSubjectRoles('u/1')).rejects.toThrow(/path separator/)
  })

  it('refuses an all-dot segment longer than two', async () => {
    const { adapter } = adapterWithSpy()
    await expect(adapter.getRole('...')).rejects.toThrow(/cannot be a path segment/)
  })

  // Control: an id that already spells its separator as `%2F` holds no literal
  // one, and double-encoding it leaves a segment no single decode can split.
  it('double-encodes a pre-encoded separator rather than refusing it', async () => {
    const { adapter, fetchSpy } = adapterWithSpy('null')
    await adapter.getPolicy('..%2F..%2Fadmin')
    expect(calledUrl(fetchSpy)).toBe('https://api.test/access/policies/..%252F..%252Fadmin')
  })

  // Control: dots that are not the whole segment are ordinary id characters.
  it('still allows a dotted id', async () => {
    const { adapter, fetchSpy } = adapterWithSpy('null')
    await adapter.getPolicy('org.post.read')
    expect(calledUrl(fetchSpy)).toBe('https://api.test/access/policies/org.post.read')
  })

  // Control: the other hostile characters are still encoded, not refused.
  it('still encodes rather than refuses a space, NUL and newline', async () => {
    const { adapter, fetchSpy } = adapterWithSpy('null')
    await adapter.getPolicy(`a ${String.fromCharCode(0)}b\nc`)
    expect(calledUrl(fetchSpy)).toBe('https://api.test/access/policies/a%20%00b%0Ac')
  })
})
