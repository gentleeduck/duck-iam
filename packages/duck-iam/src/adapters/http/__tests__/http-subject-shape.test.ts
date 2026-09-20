import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

type A = 'read'
type R = 'post'
type Ro = 'admin' | 'viewer' | 'editor'
type S = 'org-1' | 'org-2'

function makeJsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
    json: async () => body,
  } as unknown as Response
}

function buildAdapter(handler: (path: string) => unknown): IamHttpAdapter<A, R, Ro, S> {
  const fetch = vi.fn(async (url: string) => {
    const path = new URL(url).pathname
    return makeJsonResponse(handler(path))
  }) as unknown as typeof globalThis.fetch
  return new IamHttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com', fetch, retries: 0 })
}

describe('IamHttpAdapter subject-data shape validation', () => {
  describe('getSubjectAttributes', () => {
    it('rejects a string response (the corruption-as-string class)', async () => {
      const adapter = buildAdapter(() => 'admin=true')
      await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(
        /getSubjectAttributes for "user-1" returned string \(expected a JSON object of scalar values\)/,
      )
    })

    it('rejects a null response (auth API server returned `null` for missing user)', async () => {
      const adapter = buildAdapter(() => null)
      await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(
        /getSubjectAttributes for "user-1" returned null/,
      )
    })

    it('rejects an array response (server collapsed scoped+unscoped into one list)', async () => {
      const adapter = buildAdapter(() => [])
      await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(
        /getSubjectAttributes for "user-1" returned array/,
      )
    })

    it('rejects a number response', async () => {
      const adapter = buildAdapter(() => 42)
      await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(
        /getSubjectAttributes for "user-1" returned number/,
      )
    })

    it('accepts a valid object', async () => {
      const adapter = buildAdapter(() => ({ tier: 'gold', verified: true }))
      const attrs = await adapter.getSubjectAttributes('user-1')
      expect(attrs).toEqual({ tier: 'gold', verified: true })
    })

    it('accepts an empty object', async () => {
      const adapter = buildAdapter(() => ({}))
      const attrs = await adapter.getSubjectAttributes('user-1')
      expect(attrs).toEqual({})
    })
  })

  describe('getSubjectRoles', () => {
    it('rejects a string response (substring-bypass class)', async () => {
      const adapter = buildAdapter(() => 'admin-extra')
      await expect(adapter.getSubjectRoles('user-1')).rejects.toThrow(
        /getSubjectRoles for "user-1" returned string \(expected JSON array\)/,
      )
    })

    it('rejects an object response', async () => {
      const adapter = buildAdapter(() => ({ 0: 'admin' }))
      await expect(adapter.getSubjectRoles('user-1')).rejects.toThrow(/getSubjectRoles for "user-1" returned object/)
    })

    it('rejects a null response', async () => {
      const adapter = buildAdapter(() => null)
      await expect(adapter.getSubjectRoles('user-1')).rejects.toThrow(/getSubjectRoles for "user-1" returned null/)
    })

    it('accepts a valid string array', async () => {
      const adapter = buildAdapter(() => ['admin', 'viewer'])
      const roles = await adapter.getSubjectRoles('user-1')
      expect(roles).toEqual(['admin', 'viewer'])
    })

    it('accepts an empty array', async () => {
      const adapter = buildAdapter(() => [])
      const roles = await adapter.getSubjectRoles('user-1')
      expect(roles).toEqual([])
    })

    it('rejects a list with a non-string entry rather than returning the readable half', async () => {
      // Was pinned as a silent drop on the premise that roles are allow-only. They are not: a deny policy
      // targets a role, so the half that survives reads as permission. See `http-subject-partial-row.test.ts`.
      const adapter = buildAdapter(() => ['admin', 42, null, 'viewer', { id: 'editor' }, ''])
      await expect(adapter.getSubjectRoles('user-1')).rejects.toThrow(
        /getSubjectRoles for "user-1" returned number at \[1\]/,
      )
    })
  })

  describe('getSubjectScopedRoles', () => {
    it('rejects a non-array response', async () => {
      const adapter = buildAdapter(() => ({ role: 'admin', scope: 'org-1' }))
      await expect(adapter.getSubjectScopedRoles('user-1')).rejects.toThrow(
        /getSubjectScopedRoles for "user-1" returned object/,
      )
    })

    it('accepts a valid array', async () => {
      const adapter = buildAdapter(() => [
        { role: 'admin', scope: 'org-1' },
        { role: 'viewer', scope: 'org-2' },
      ])
      const sr = await adapter.getSubjectScopedRoles('user-1')
      expect(sr).toEqual([
        { role: 'admin', scope: 'org-1' },
        { role: 'viewer', scope: 'org-2' },
      ])
    })

    it('rejects entries with missing or wrong-type role', async () => {
      const adapter = buildAdapter(() => [
        { role: 'admin', scope: 'org-1' },
        { scope: 'org-2' }, // no role
        { role: 42, scope: 'org-2' }, // wrong type role
        { role: '', scope: 'org-2' }, // empty role
        { role: 'viewer', scope: 'org-2' },
      ])
      await expect(adapter.getSubjectScopedRoles('user-1')).rejects.toThrow(
        /an entry at \[1\] whose role is undefined and scope is string/,
      )
    })

    it('rejects entries with missing or wrong-type scope (unscoped form belongs in getSubjectRoles)', async () => {
      // The two endpoints are disjoint by contract, so an unscoped row here is the server mixing them up.
      const adapter = buildAdapter(() => [
        { role: 'admin', scope: 'org-1' },
        { role: 'editor' }, // no scope
        { role: 'viewer', scope: 42 }, // wrong type scope
        { role: 'viewer', scope: '' }, // empty scope
      ])
      await expect(adapter.getSubjectScopedRoles('user-1')).rejects.toThrow(
        /an entry at \[1\] whose role is string and scope is undefined/,
      )
    })

    it('rejects null / primitive / array entries', async () => {
      const adapter = buildAdapter(() => [null, 'admin', 42, [], { role: 'editor', scope: 'org-1' }])
      await expect(adapter.getSubjectScopedRoles('user-1')).rejects.toThrow(
        /getSubjectScopedRoles for "user-1" returned null at \[0\]/,
      )
    })
  })

  describe('error text safety', () => {
    it('error text names the subjectId but not the offending value', async () => {
      const adapter = buildAdapter(() => 'attacker-payload-with-credentials')
      try {
        await adapter.getSubjectAttributes('user-99')
        throw new Error('expected throw')
      } catch (err) {
        const msg = (err as Error).message
        expect(msg).toContain('user-99')
        expect(msg).toContain('string')
        expect(msg).not.toContain('attacker-payload-with-credentials')
      }
    })
  })
})
