import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

// Pins that a bodiless success (204, or 200 with an empty body) is not a JSON parse error,
// so writes against a spec-compliant API succeed as they do on the other adapters.
function adapterFor(res: () => Response) {
  const fetchSpy = vi.fn(async () => res())
  const adapter = new IamHttpAdapter({ baseUrl: 'https://api.test/access', fetch: fetchSpy, retries: 0 })
  return { adapter, fetchSpy }
}

const noContent = () => new Response(null, { status: 204 })
const emptyBody = () => new Response('', { status: 200, headers: { 'content-type': 'application/json' } })

describe('a bodiless success is not a parse error', () => {
  it.each([
    ['204 No Content', noContent],
    ['200 with an empty body', emptyBody],
  ])('deletePolicy accepts %s', async (_label, res) => {
    const { adapter, fetchSpy } = adapterFor(res)
    await expect(adapter.deletePolicy('p1')).resolves.toBeUndefined()
    expect(fetchSpy).toHaveBeenCalledOnce()
  })

  it.each([
    ['204 No Content', noContent],
    ['200 with an empty body', emptyBody],
  ])('the write methods accept %s', async (_label, res) => {
    const { adapter } = adapterFor(res)
    await expect(adapter.deleteRole('r1')).resolves.toBeUndefined()
    await expect(adapter.assignRole('u1', 'admin')).resolves.toBeUndefined()
    await expect(adapter.revokeRole('u1', 'admin')).resolves.toBeUndefined()
    await expect(adapter.setSubjectAttributes('u1', { a: 1 })).resolves.toBeUndefined()
    await expect(adapter.savePolicy({ algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] })).resolves.toBe(
      undefined,
    )
    await expect(adapter.saveRole({ id: 'r1', name: 'R', permissions: [] })).resolves.toBeUndefined()
  })

  // A bodiless success on a single-row read means no row, the same answer as a 404.
  it('a single-row read treats a bodiless success as a miss', async () => {
    const { adapter } = adapterFor(noContent)
    expect(await adapter.getPolicy('p1')).toBeNull()
    expect(await adapter.getRole('r1')).toBeNull()
  })

  // Controls: without these, "never parse anything" would pass.
  it('control: a real body still parses', async () => {
    const { adapter } = adapterFor(
      () =>
        new Response(JSON.stringify({ algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] }), {
          headers: { 'content-type': 'application/json' },
        }),
    )
    expect((await adapter.getPolicy('p1'))?.id).toBe('p1')
  })

  it('control: malformed JSON is still an error', async () => {
    const { adapter } = adapterFor(() => new Response('{not json', { headers: { 'content-type': 'application/json' } }))
    await expect(adapter.getPolicy('p1')).rejects.toThrow()
  })

  it('control: a non-2xx status is still an error, body or no body', async () => {
    const { adapter } = adapterFor(() => new Response(null, { status: 500 }))
    await expect(adapter.deletePolicy('p1')).rejects.toThrow(/HTTP 500/)
  })
})
