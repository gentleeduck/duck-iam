import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

/**
 * The remote API is an untrusted boundary. A row that fails `parsePolicyRow`
 * / `parseRoleRow` must be dropped and reported through `onPolicyError`
 * instead of reaching the engine, matching the redis/file/prisma/drizzle contract.
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

describe('IamHttpAdapter drops malformed rows', () => {
  it('listPolicies: keeps valid rows, drops the invalid one, reports it', async () => {
    const onPolicyError = vi.fn()
    const adapter = buildAdapter(() => [good, noPriority], onPolicyError)
    const policies = await adapter.listPolicies()
    expect(policies.map((p) => p.id)).toEqual(['p-good'])
    expect(onPolicyError).toHaveBeenCalledTimes(1)
    expect(onPolicyError.mock.calls[0]?.[1]).toEqual({ adapter: 'http', rowId: 'p-bad' })
  })

  it('getPolicy: an invalid row returns null and is reported', async () => {
    const onPolicyError = vi.fn()
    const adapter = buildAdapter(() => noPriority, onPolicyError)
    expect(await adapter.getPolicy('p-bad')).toBeNull()
    expect(onPolicyError).toHaveBeenCalledTimes(1)
  })

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
      expect(await adapter.listPolicies()).toEqual([])
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })
})
