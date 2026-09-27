import { describe, expect, it, vi } from 'vitest'
import { IamEngine } from '../../../core/engine/engine'
import { hasIamErrorCode } from '../../../core/errors'
import type { AccessControl } from '../../../core/types'
import { IamHttpAdapter } from '../index'

async function rejectsWithRolesInvalid(
  p: Promise<unknown>,
  expect_: { reason: 'not-array' | 'entry-invalid'; index?: number; got?: string },
): Promise<boolean> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  )
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
  reason: 'not-array' | 'entry-not-object' | 'entry-fields-invalid',
): Promise<boolean> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  )
  return hasIamErrorCode(err, 'IAM_HTTP_SUBJECT_SCOPED_ROLES_INVALID') && err.meta.reason === reason
}

// A role is not only a grant: `policyApplies` matches `targets.roles` by equality, so a deny policy rides on the
// subject holding the role it names. Dropping one malformed entry from a grant list therefore retires that deny
// and the request is allowed - which is why a partial row fails the read here, as it does in the file store.

type A = 'delete'
type R = 'post'
type Ro = 'editor' | 'contractor'
type S = 'org-1'

const POST = { attributes: {}, id: 'p1', type: 'post' } as const

const ROLES: AccessControl.IRole<A, R, Ro, S>[] = [
  { id: 'editor', name: 'Editor', permissions: [{ action: 'delete', resource: 'post' }] },
  { id: 'contractor', name: 'Contractor', permissions: [] },
]

const GUARD: AccessControl.IPolicy<A, R, Ro> = {
  algorithm: 'deny-overrides',
  id: 'guard',
  name: 'Contractors may not delete',
  rules: [{ actions: ['delete'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 0, resources: ['post'] }],
  targets: { roles: ['contractor'] },
}

function makeJsonResponse(body: unknown): Response {
  return {
    json: async () => body,
    ok: true,
    status: 200,
    text: async () => JSON.stringify(body),
  } as unknown as Response
}

function buildAdapter(rolesRow: unknown, scopedRow: unknown = []): IamHttpAdapter<A, R, Ro, S> {
  const fetch = vi.fn(async (url: string) => {
    const path = new URL(url).pathname
    if (path === '/policies') return makeJsonResponse([GUARD])
    if (path === '/roles') return makeJsonResponse(ROLES)
    if (path === '/subjects/u1/roles') return makeJsonResponse(rolesRow)
    if (path === '/subjects/u1/scoped-roles') return makeJsonResponse(scopedRow)
    if (path === '/subjects/u1/attributes') return makeJsonResponse({})
    return makeJsonResponse(null)
  }) as unknown as typeof globalThis.fetch
  return new IamHttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com', fetch, retries: 0 })
}

function buildEngine(rolesRow: unknown) {
  return new IamEngine<A, R, Ro, S>({ adapter: buildAdapter(rolesRow), mode: 'production' })
}

describe('a partial subject grant list does not silently retire the denies it carries', () => {
  it('denies when the deny-carrying role is the entry that is malformed', async () => {
    // The scoped-role shape in the unscoped list is the exact server mistake the endpoint contract warns about.
    for (const row of [
      ['editor', { role: 'contractor', scope: 'org-1' }],
      ['editor', null],
      ['editor', 42],
      ['editor', ''],
    ]) {
      expect(await buildEngine(row).can('u1', 'delete', POST)).toBe(false)
    }
  })

  it('still allows and still denies on a well-formed list', async () => {
    // Without these the row above proves nothing: an engine that denied everything would pass it.
    expect(await buildEngine(['editor']).can('u1', 'delete', POST)).toBe(true)
    expect(await buildEngine(['editor', 'contractor']).can('u1', 'delete', POST)).toBe(false)
  })

  it('names the index and the type, never the value', async () => {
    const adapter = buildAdapter(['editor', { token: 'secret-bearer-value' }])
    expect(
      await rejectsWithRolesInvalid(adapter.getSubjectRoles('u1'), {
        reason: 'entry-invalid',
        index: 1,
        got: 'object',
      }),
    ).toBe(true)
  })

  it('rejects each malformed entry type in the unscoped list', async () => {
    for (const [entry, got] of [
      [null, 'null'],
      [42, 'number'],
      ['', 'empty string'],
      [[], 'array'],
      [{ id: 'editor' }, 'object'],
    ] as const) {
      const adapter = buildAdapter(['editor', entry])
      expect(
        await rejectsWithRolesInvalid(adapter.getSubjectRoles('u1'), { reason: 'entry-invalid', index: 1, got }),
      ).toBe(true)
    }
  })

  it('accepts a well-formed unscoped list unchanged', async () => {
    expect(await buildAdapter(['editor', 'contractor']).getSubjectRoles('u1')).toEqual(['editor', 'contractor'])
    expect(await buildAdapter([]).getSubjectRoles('u1')).toEqual([])
  })

  it('rejects a scoped entry that is not a {role, scope} object', async () => {
    for (const entry of [null, 42, 'contractor', []]) {
      const adapter = buildAdapter([], [{ role: 'editor', scope: 'org-1' }, entry])
      expect(await rejectsWithScopedRolesInvalid(adapter.getSubjectScopedRoles('u1'), 'entry-not-object')).toBe(true)
    }
  })

  it('rejects a scoped entry whose role or scope is not a non-empty string', async () => {
    for (const entry of [
      { scope: 'org-1' },
      { role: 42, scope: 'org-1' },
      { role: '', scope: 'org-1' },
      { role: 'contractor' },
      { role: 'contractor', scope: 42 },
      { role: 'contractor', scope: '' },
    ]) {
      const adapter = buildAdapter([], [{ role: 'editor', scope: 'org-1' }, entry])
      expect(await rejectsWithScopedRolesInvalid(adapter.getSubjectScopedRoles('u1'), 'entry-fields-invalid')).toBe(
        true,
      )
    }
  })

  it('accepts a well-formed scoped list unchanged', async () => {
    const rows = [{ role: 'contractor', scope: 'org-1' }]
    expect(await buildAdapter([], rows).getSubjectScopedRoles('u1')).toEqual(rows)
    expect(await buildAdapter([], []).getSubjectScopedRoles('u1')).toEqual([])
  })
})
