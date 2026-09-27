import { describe, expect, it, vi } from 'vitest'
import { hasIamErrorCode } from '../../../core/errors'
import { IamHttpAdapter } from '../index'

async function toErr(p: Promise<unknown>): Promise<unknown> {
  return p.then(
    () => undefined,
    (e: unknown) => e,
  )
}

async function rejectsWithAttributesCorrupt(p: Promise<unknown>, subjectId: string): Promise<boolean> {
  const err = await toErr(p)
  return (
    hasIamErrorCode(err, 'IAM_ATTRIBUTES_CORRUPT') &&
    err.meta.subjectId === subjectId &&
    err.meta.reason === 'not-object'
  )
}

async function rejectsWithRolesInvalid(
  p: Promise<unknown>,
  expect_: { reason: 'not-array' | 'entry-invalid'; index?: number; got?: string },
): Promise<boolean> {
  const err = await toErr(p)
  if (!hasIamErrorCode(err, 'IAM_HTTP_SUBJECT_ROLES_INVALID')) return false
  const meta = err.meta
  return (
    meta.reason === expect_.reason &&
    (expect_.index === undefined || meta.index === expect_.index) &&
    (expect_.got === undefined || meta.got === expect_.got)
  )
}

async function rejectsWithScopedRolesInvalid(
  p: Promise<unknown>,
  expect_: {
    reason: 'not-array' | 'entry-not-object' | 'entry-fields-invalid'
    index?: number
    got?: string
    role?: string
    scope?: string
  },
): Promise<boolean> {
  const err = await toErr(p)
  if (!hasIamErrorCode(err, 'IAM_HTTP_SUBJECT_SCOPED_ROLES_INVALID')) return false
  const meta = err.meta
  return (
    meta.reason === expect_.reason &&
    (expect_.index === undefined || meta.index === expect_.index) &&
    (expect_.got === undefined || meta.got === expect_.got) &&
    (expect_.role === undefined || meta.role === expect_.role) &&
    (expect_.scope === undefined || meta.scope === expect_.scope)
  )
}

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
      expect(await rejectsWithAttributesCorrupt(adapter.getSubjectAttributes('user-1'), 'user-1')).toBe(true)
    })

    it('rejects a null response (auth API server returned `null` for missing user)', async () => {
      const adapter = buildAdapter(() => null)
      expect(await rejectsWithAttributesCorrupt(adapter.getSubjectAttributes('user-1'), 'user-1')).toBe(true)
    })

    it('rejects an array response (server collapsed scoped+unscoped into one list)', async () => {
      const adapter = buildAdapter(() => [])
      expect(await rejectsWithAttributesCorrupt(adapter.getSubjectAttributes('user-1'), 'user-1')).toBe(true)
    })

    it('rejects a number response', async () => {
      const adapter = buildAdapter(() => 42)
      expect(await rejectsWithAttributesCorrupt(adapter.getSubjectAttributes('user-1'), 'user-1')).toBe(true)
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
      expect(
        await rejectsWithRolesInvalid(adapter.getSubjectRoles('user-1'), { reason: 'not-array', got: 'string' }),
      ).toBe(true)
    })

    it('rejects an object response', async () => {
      const adapter = buildAdapter(() => ({ 0: 'admin' }))
      expect(
        await rejectsWithRolesInvalid(adapter.getSubjectRoles('user-1'), { reason: 'not-array', got: 'object' }),
      ).toBe(true)
    })

    it('rejects a null response', async () => {
      const adapter = buildAdapter(() => null)
      expect(
        await rejectsWithRolesInvalid(adapter.getSubjectRoles('user-1'), { reason: 'not-array', got: 'null' }),
      ).toBe(true)
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
      expect(
        await rejectsWithRolesInvalid(adapter.getSubjectRoles('user-1'), {
          reason: 'entry-invalid',
          index: 1,
          got: 'number',
        }),
      ).toBe(true)
    })
  })

  describe('getSubjectScopedRoles', () => {
    it('rejects a non-array response', async () => {
      const adapter = buildAdapter(() => ({ role: 'admin', scope: 'org-1' }))
      expect(
        await rejectsWithScopedRolesInvalid(adapter.getSubjectScopedRoles('user-1'), {
          reason: 'not-array',
          got: 'object',
        }),
      ).toBe(true)
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
      expect(
        await rejectsWithScopedRolesInvalid(adapter.getSubjectScopedRoles('user-1'), {
          reason: 'entry-fields-invalid',
          index: 1,
          role: 'undefined',
          scope: 'string',
        }),
      ).toBe(true)
    })

    it('rejects entries with missing or wrong-type scope (unscoped form belongs in getSubjectRoles)', async () => {
      // The two endpoints are disjoint by contract, so an unscoped row here is the server mixing them up.
      const adapter = buildAdapter(() => [
        { role: 'admin', scope: 'org-1' },
        { role: 'editor' }, // no scope
        { role: 'viewer', scope: 42 }, // wrong type scope
        { role: 'viewer', scope: '' }, // empty scope
      ])
      expect(
        await rejectsWithScopedRolesInvalid(adapter.getSubjectScopedRoles('user-1'), {
          reason: 'entry-fields-invalid',
          index: 1,
          role: 'string',
          scope: 'undefined',
        }),
      ).toBe(true)
    })

    it('rejects null / primitive / array entries', async () => {
      const adapter = buildAdapter(() => [null, 'admin', 42, [], { role: 'editor', scope: 'org-1' }])
      expect(
        await rejectsWithScopedRolesInvalid(adapter.getSubjectScopedRoles('user-1'), {
          reason: 'entry-not-object',
          index: 0,
          got: 'null',
        }),
      ).toBe(true)
    })
  })

  describe('error text safety', () => {
    it('error meta names the subjectId but never the offending value', async () => {
      const adapter = buildAdapter(() => 'attacker-payload-with-credentials')
      const err = await toErr(adapter.getSubjectAttributes('user-99'))
      if (!hasIamErrorCode(err, 'IAM_ATTRIBUTES_CORRUPT')) throw new Error('expected IAM_ATTRIBUTES_CORRUPT')
      expect(err.meta.subjectId).toBe('user-99')
      expect(JSON.stringify(err.meta)).not.toContain('attacker-payload-with-credentials')
    })
  })
})
