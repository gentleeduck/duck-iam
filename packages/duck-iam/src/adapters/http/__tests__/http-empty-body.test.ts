import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

/**
 * Every method routed through `_request`, which called `JSON.parse` on whatever
 * the server sent. `204 No Content` is the canonical answer to a `DELETE` and
 * an ordinary one to a `PUT` or `POST` that returns nothing, so a
 * spec-compliant API made every write throw
 * `SyntaxError: Unexpected end of JSON input` - while the same call succeeded on
 * the other five adapters. Found while pinning the delete-idempotence contract
 * across the six.
 */
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

  // A bodiless success on a single-row read is the same answer as a 404: the
  // API acknowledged the request and returned no row.
  it('a single-row read treats a bodiless success as a miss', async () => {
    const { adapter } = adapterFor(noContent)
    expect(await adapter.getPolicy('p1')).toBeNull()
    expect(await adapter.getRole('r1')).toBeNull()
  })

  // Controls. A real JSON body must still parse, and malformed JSON must still
  // be an error - without these the fix could be "never parse anything".
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
