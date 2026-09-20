import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

// Pins that a bad role row from the untrusted API is dropped while a bad policy row throws, since the dropped
// policy may be the deny. See `iamUnreadablePolicy`. A role is not allow-only either, but a dropped catalogue
// row leaves any policy targeting it unresolvable, which `reportUnreachableRoleTargets` reports; a dropped
// *grant* has no such witness, so `getSubjectRoles` throws instead (`http-subject-partial-row.test.ts`).
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
    // Not `['p-good']`: returning the readable half would fail open, with the deny missing and no sign of it.
    await expect(adapter.listPolicies()).rejects.toThrow(/policy "p-bad" cannot be read and will not be skipped/)
    expect(onPolicyError).toHaveBeenCalledTimes(1)
    expect(onPolicyError.mock.calls[0]?.[1]).toEqual({ adapter: 'http', rowId: 'p-bad' })
  })

  it('getPolicy: an invalid row is reported and then rejects', async () => {
    const onPolicyError = vi.fn()
    const adapter = buildAdapter(() => noPriority, onPolicyError)
    // `null` would read as a 404, hiding a corrupt policy as a missing one.
    await expect(adapter.getPolicy('p-bad')).rejects.toThrow(/cannot be read/)
    expect(onPolicyError).toHaveBeenCalledTimes(1)
  })

  // A drop, not a throw: this is the list envelope, not a row, and the resulting empty policy set denies
  // under every combine mode.
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
      // The row is still reported before the throw, so the operator knows which one to repair.
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })
})
