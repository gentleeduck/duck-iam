import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// A cached subject's roles are the inheritance closure of its assignments. Creating a role that an assigned role
// inherits changes that closure, and the invalidation sweep has to reach the subjects it changes.

const engine = (adapter: IamMemoryAdapter) =>
  new IamEngine({ adapter, cacheTTL: 600, mode: 'production', scopeMode: 'hierarchical' })

const role = (id: string, permissions: AccessControl.IPermission[], inherits: string[] = [], scope?: string) =>
  ({ description: '', id, inherits, name: id, permissions, ...(scope ? { scope } : {}) }) satisfies AccessControl.IRole

const denyOnProbation: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  description: '',
  id: 'p-probation',
  name: 'p-probation',
  rules: [
    {
      actions: ['write'],
      conditions: { all: [{ field: 'action', operator: 'eq', value: 'write' }] },
      effect: 'deny',
      id: 'r1',
      priority: 100,
      resources: ['comment'],
    },
  ],
  targets: { roles: ['probation'] },
  version: 1,
}

describe('a role created after a subject was cached', () => {
  it('grants through the role that inherits it, without waiting out the TTL', async () => {
    const adapter = new IamMemoryAdapter()
    const hot = engine(adapter)
    await hot.admin.saveRole(role('manager', [], ['editor']))
    await hot.admin.assignRole('u2', 'manager', 'org-1.team-2')
    expect(await hot.can('u2', 'write', { attributes: {}, type: 'comment' }, undefined, 'org-1')).toBe(false)

    await hot.admin.saveRole(role('editor', [{ action: 'write', resource: 'comment' }], [], 'org-1'))

    expect(await hot.can('u2', 'write', { attributes: {}, type: 'comment' }, undefined, 'org-1')).toBe(true)
    expect(await engine(adapter).can('u2', 'write', { attributes: {}, type: 'comment' }, undefined, 'org-1')).toBe(true)
  })

  it('denies at once when a policy targets it, instead of staying allowed for a full TTL', async () => {
    const adapter = new IamMemoryAdapter()
    const hot = engine(adapter)
    await hot.admin.savePolicy(denyOnProbation)
    await hot.admin.saveRole(role('contractor', [{ action: 'write', resource: 'comment' }], ['probation']))
    await hot.admin.assignRole('u2', 'contractor')
    expect(await hot.can('u2', 'write', { attributes: {}, type: 'comment' })).toBe(true)

    await hot.admin.saveRole(role('probation', []))

    expect(await hot.can('u2', 'write', { attributes: {}, type: 'comment' })).toBe(false)
    expect(await engine(adapter).can('u2', 'write', { attributes: {}, type: 'comment' })).toBe(false)
  })

  it('reaches the same subjects on a peer that only sees the invalidation event', async () => {
    const adapter = new IamMemoryAdapter()
    const writer = engine(adapter)
    const peer = engine(adapter)
    await writer.admin.savePolicy(denyOnProbation)
    await writer.admin.saveRole(role('contractor', [{ action: 'write', resource: 'comment' }], ['probation']))
    await writer.admin.assignRole('u2', 'contractor')
    expect(await peer.can('u2', 'write', { attributes: {}, type: 'comment' })).toBe(true)

    await writer.admin.saveRole(role('probation', []))
    peer.cache.invalidateRoles('probation', { broadcast: false })

    expect(await peer.can('u2', 'write', { attributes: {}, type: 'comment' })).toBe(false)
  })

  it('leaves a subject holding an unrelated role cached', async () => {
    class CountingAdapter extends IamMemoryAdapter {
      roleReads = 0
      override async getSubjectRoles(id: string, opts?: Parameters<IamMemoryAdapter['getSubjectRoles']>[1]) {
        this.roleReads++
        return super.getSubjectRoles(id, opts)
      }
    }
    const adapter = new CountingAdapter()
    const hot = engine(adapter)
    await hot.admin.saveRole(role('reader', [{ action: 'read', resource: 'post' }]))
    await hot.admin.assignRole('u3', 'reader')
    expect(await hot.can('u3', 'read', { attributes: {}, type: 'post' })).toBe(true)

    await hot.admin.saveRole(role('unrelated', []))
    const before = adapter.roleReads
    expect(await hot.can('u3', 'read', { attributes: {}, type: 'post' })).toBe(true)
    expect(adapter.roleReads - before, 'u3 was evicted by a role it does not reach').toBe(0)
  })
})
