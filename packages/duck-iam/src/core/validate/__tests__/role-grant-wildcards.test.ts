/**
 * `validateRoles` takes the unconstrained `IRole` on purpose, so a grant read from a store can carry a prefix
 * pattern the engine honours. Matching it by equality called a working grant unreachable.
 */
import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { createIam } from '../../config'
import { IamEngine } from '../../engine'
import type { AccessControl } from '../../types'

const access = createIam({
  actions: ['read', 'post:create', 'post:edit', 'admin.reset'] as const,
  resources: ['post', 'org.team'] as const,
  roles: ['editor'] as const,
  scopes: ['org-1', 'org-1.team'] as const,
})

/** A stored row, so it is not narrowed to the declared unions - which is the case the validator exists for. */
function role(permissions: { action: string; resource: string; scope?: string }[], scope?: string) {
  return { id: 'editor', name: 'Editor', permissions, ...(scope !== undefined && { scope }) } as AccessControl.IRole
}

function codes(result: { issues: readonly { code: string; path?: string }[] }) {
  return result.issues.map((i) => `${i.code} ${i.path}`)
}

describe('a prefix grant the engine honours is not unreachable', () => {
  const wildcards = role([
    { action: 'post:*', resource: 'post' },
    { action: 'read', resource: 'org.*' },
  ])

  it('validateRoles accepts it', () => {
    const result = access.validateRoles([wildcards])
    expect({ issues: codes(result), valid: result.valid }).toEqual({ issues: [], valid: true })
  })

  it('and the engine grants exactly what it says', async () => {
    const adapter = new IamMemoryAdapter()
    await adapter.saveRole(wildcards)
    await adapter.assignRole('u1', 'editor')
    const iam = new IamEngine({ adapter, cacheTTL: 0, mode: 'development' })
    expect({
      orgTeam: await iam.can('u1', 'read', { attributes: {}, type: 'org.team' }),
      postCreate: await iam.can('u1', 'post:create', { attributes: {}, type: 'post' }),
      postEdit: await iam.can('u1', 'post:edit', { attributes: {}, type: 'post' }),
      readOnPost: await iam.can('u1', 'read', { attributes: {}, type: 'post' }),
    }).toEqual({ orgTeam: true, postCreate: true, postEdit: true, readOnPost: false })
  })

  it('CONTROL: a mistyped prefix is still reported', () => {
    const result = access.validateRoles([
      role([
        { action: 'psot:*', resource: 'post' },
        { action: 'read', resource: 'orgg.*' },
      ]),
    ])
    expect({ issues: codes(result), valid: result.valid }).toEqual({
      issues: ['UNREACHABLE_TARGET permissions[0]', 'UNREACHABLE_TARGET permissions[1]'],
      valid: false,
    })
  })
})

describe('each axis is cleared by its own matcher', () => {
  it('a dot pattern is a literal on the action axis, even with a dotted action declared', () => {
    expect(codes(access.validateRoles([role([{ action: 'post.*', resource: 'post' }])]))).toEqual([
      'UNREACHABLE_TARGET permissions[0]',
    ])
    // `admin.reset` is declared, so only `matchesAction`'s missing dot form keeps this reported.
    expect(codes(access.validateRoles([role([{ action: 'admin.*', resource: 'post' }])]))).toEqual([
      'UNREACHABLE_TARGET permissions[0]',
    ])
  })

  it('a dot pattern reaches a subtree on the resource axis', () => {
    expect(codes(access.validateRoles([role([{ action: 'read', resource: 'org.*' }])]))).toEqual([])
  })

  it('a colon pattern the declared resources do not reach is reported', () => {
    expect(codes(access.validateRoles([role([{ action: 'read', resource: 'org:*' }])]))).toEqual([
      'UNREACHABLE_TARGET permissions[0]',
    ])
  })

  it("`'*'` is still the wildcard on both axes", () => {
    expect(codes(access.validateRoles([role([{ action: '*', resource: '*' }])]))).toEqual([])
  })
})

describe('scopes keep equality matching, which is what scopeCovers uses for an exact hit', () => {
  it('an undeclared scope is reported, on the grant and on the role', () => {
    expect(
      codes(access.validateRoles([role([{ action: 'read', resource: 'post', scope: 'org-2' }], 'org-9')])),
    ).toEqual(['UNREACHABLE_TARGET permissions[0]', 'UNREACHABLE_TARGET scope'])
  })

  it("CONTROL: a declared scope, `'*'`, and an absent scope are clean", () => {
    expect(codes(access.validateRoles([role([{ action: 'read', resource: 'post', scope: 'org-1' }], '*')]))).toEqual([])
    expect(codes(access.validateRoles([role([{ action: 'read', resource: 'post' }])]))).toEqual([])
  })

  it('a prefix is not a scope wildcard, so it is still reported', () => {
    // `org-1.team` is declared, so only `matchesScope`'s exact match keeps this reported.
    expect(codes(access.validateRoles([role([{ action: 'read', resource: 'post', scope: 'org-1.*' }])]))).toEqual([
      'UNREACHABLE_TARGET permissions[0]',
    ])
  })
})
