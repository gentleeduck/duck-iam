import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

/**
 * The remote API is an untrusted boundary, and the two row kinds are handled
 * differently on purpose.
 *
 * A malformed *role* row is dropped and reported: role permissions are
 * allow-only, so losing one can only ever remove a grant, and the request
 * fails closed.
 *
 * A malformed *policy* row is reported and then throws. The row that will not
 * parse may have been the rule saying NO, and dropping it turns a corrupt byte
 * into an allow; under `policyCombine: 'and'` even an allow-only policy votes
 * deny when none of its rules match, so there is no subset of policies an
 * adapter can safely drop without knowing the combine mode it cannot see. The
 * cost is stated plainly in `iamUnreadablePolicy`: one unreadable policy row
 * denies every request until it is repaired.
 *
 * This file used to assert the drop for both kinds. The e2e differential run
 * caught what that bought: `an unreadable DENY policy was dropped and the
 * request it forbade was allowed`.
 */
function makeJsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
    json: async () => body,
  } as unknown as Response
}

function buildAdapter(handler: (path: string) => unknown, onPolicyError?: (err: Error, ctx: unknown) => void) {
  const fetch = vi.fn(async (url: string) =>
    makeJsonResponse(handler(new URL(url).pathname)),
  ) as unknown as typeof globalThis.fetch
  return new IamHttpAdapter({ baseUrl: 'https://api.example.com', fetch, retries: 0, onPolicyError })
}

const good = {
  id: 'p-good',
  name: 'good',
  algorithm: 'deny-overrides',
  rules: [{ id: 'r1', effect: 'deny', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [] } }],
}
const noPriority = {
  id: 'p-bad',
  name: 'bad',
  algorithm: 'first-match',
  rules: [{ id: 'r1', effect: 'deny', actions: ['read'], resources: ['post'], conditions: { all: [] } }],
}
const goodRole = { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] }
const badRole = { id: 'broken', name: 'Broken', permissions: 'read:post' }

describe('IamHttpAdapter refuses malformed policy rows and drops malformed role rows', () => {
  it('listPolicies: one unreadable row fails the whole read, and is reported first', async () => {
    const onPolicyError = vi.fn()
    const adapter = buildAdapter(() => [good, noPriority], onPolicyError)
    // Not `['p-good']`: returning the readable half is exactly the fail-open.
    // The caller would have got a policy set with the deny quietly missing and
    // no way to know one was ever there.
    await expect(adapter.listPolicies()).rejects.toThrow(/policy "p-bad" cannot be read and will not be skipped/)
    expect(onPolicyError).toHaveBeenCalledTimes(1)
    expect(onPolicyError.mock.calls[0]?.[1]).toEqual({ adapter: 'http', rowId: 'p-bad' })
  })

  it('getPolicy: an invalid row is reported and then rejects', async () => {
    const onPolicyError = vi.fn()
    const adapter = buildAdapter(() => noPriority, onPolicyError)
    // `null` here reads as "no such policy", which is the same shape a 404
    // takes - the caller cannot tell a missing policy from a corrupt one.
    await expect(adapter.getPolicy('p-bad')).rejects.toThrow(/cannot be read/)
    expect(onPolicyError).toHaveBeenCalledTimes(1)
  })

  // Still a drop, not a throw: this is the list envelope, not a row. Nothing
  // parsed, so nothing is being silently subtracted from a set the caller
  // believes is complete - the caller gets an empty policy set, which under
  // every combine mode denies.
  it('listPolicies: a non-array body is dropped wholesale and reported', async () => {
    const onPolicyError = vi.fn()
    const adapter = buildAdapter(() => ({ policies: [good] }), onPolicyError)
    expect(await adapter.listPolicies()).toEqual([])
    expect(onPolicyError).toHaveBeenCalledTimes(1)
  })

  it('listRoles / getRole: same treatment for roles', async () => {
    const onPolicyError = vi.fn()
    const adapter = buildAdapter((path) => (path === '/roles' ? [goodRole, badRole] : badRole), onPolicyError)
    expect((await adapter.listRoles()).map((r) => r.id)).toEqual(['viewer'])
    expect(await adapter.getRole('broken')).toBeNull()
    expect(onPolicyError).toHaveBeenCalledTimes(2)
  })

  it('falls back to console.warn when onPolicyError is not wired', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const adapter = buildAdapter(() => [noPriority])
      await expect(adapter.listPolicies()).rejects.toThrow(/cannot be read/)
      // The report still happens on the way out: refusing to serve the read is
      // not a reason to stop telling the operator which row to repair.
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })
})
