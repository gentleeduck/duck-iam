import { beforeEach, describe, expect, it } from 'vitest'
import type { AccessControl, IamAdapter } from '../../../core/types'
import { runAdapterCompliance } from '../../__compliance__/compliance'
import { IamMemoryAdapter, iamMemoryAdapter } from '../index'

// Shared adapter compliance suite - every adapter must pass.
runAdapterCompliance('IamMemoryAdapter', () => new IamMemoryAdapter())

type A = 'read' | 'write'
type R = 'post' | 'comment'
type Ro = 'viewer' | 'editor'
type S = 'org-1'

/**
 * `assignRole` refuses a role id nothing is stored under, so the assignment
 * cases below seed their roles rather than granting them out of thin air.
 */
const GRANTABLE: AccessControl.IRole<A, R, Ro, S>[] = [
  { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
  { id: 'editor', name: 'Editor', permissions: [{ action: 'write', resource: 'post' }] },
]

describe('IamMemoryAdapter', () => {
  let adapter: IamMemoryAdapter<A, R, Ro, S>

  beforeEach(() => {
    adapter = new IamMemoryAdapter<A, R, Ro, S>()
  })

  describe('IamAdapter.IPolicyStore', () => {
    const policy: AccessControl.IPolicy<A, R, Ro> = {
      id: 'p1',
      name: 'Test AccessControl.IPolicy',
      algorithm: 'deny-overrides',
      rules: [],
    }

    it('starts empty', async () => {
      expect(await adapter.listPolicies()).toEqual([])
    })

    // `version: 1` is supplied on the write path now, so a policy stored
    // without one reads back the same on all six adapters instead of `1` on
    // the two SQL backends and `undefined` on the other four. Asserting the
    // caller's object verbatim here was pinning that divergence.
    it('savePolicy + listPolicies', async () => {
      await adapter.savePolicy(policy)
      expect(await adapter.listPolicies()).toEqual([{ ...policy, version: 1 }])
    })

    it('getPolicy returns policy or null', async () => {
      expect(await adapter.getPolicy('p1')).toBeNull()
      await adapter.savePolicy(policy)
      expect(await adapter.getPolicy('p1')).toEqual({ ...policy, version: 1 })
    })

    it('deletePolicy removes policy', async () => {
      await adapter.savePolicy(policy)
      await adapter.deletePolicy('p1')
      expect(await adapter.listPolicies()).toEqual([])
    })

    it('savePolicy overwrites existing', async () => {
      await adapter.savePolicy(policy)
      const updated = { ...policy, name: 'Updated' }
      await adapter.savePolicy(updated)
      expect((await adapter.getPolicy('p1'))!.name).toBe('Updated')
    })
  })

  describe('IamAdapter.IRoleStore', () => {
    const role: AccessControl.IRole<A, R, Ro, S> = {
      id: 'viewer',
      name: 'Viewer',
      permissions: [{ action: 'read', resource: 'post' }],
    }

    it('starts empty', async () => {
      expect(await adapter.listRoles()).toEqual([])
    })

    it('saveRole + listRoles', async () => {
      await adapter.saveRole(role)
      expect(await adapter.listRoles()).toEqual([role])
    })

    it('getRole returns role or null', async () => {
      expect(await adapter.getRole('viewer')).toBeNull()
      await adapter.saveRole(role)
      expect(await adapter.getRole('viewer')).toEqual(role)
    })

    it('deleteRole removes role', async () => {
      await adapter.saveRole(role)
      await adapter.deleteRole('viewer')
      expect(await adapter.listRoles()).toEqual([])
    })
  })

  describe('IamAdapter.ISubjectStore', () => {
    beforeEach(() => {
      adapter = new IamMemoryAdapter<A, R, Ro, S>({ roles: GRANTABLE })
    })

    it('getSubjectRoles returns empty for unknown subject', async () => {
      expect(await adapter.getSubjectRoles('unknown')).toEqual([])
    })

    it('assignRole + getSubjectRoles', async () => {
      await adapter.assignRole('user-1', 'viewer')
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['viewer'])
    })

    it('assignRole deduplicates roles in getSubjectRoles', async () => {
      await adapter.assignRole('user-1', 'viewer')
      await adapter.assignRole('user-1', 'viewer')
      const roles = await adapter.getSubjectRoles('user-1')
      expect(roles).toEqual(['viewer'])
    })

    it('revokeRole removes role', async () => {
      await adapter.assignRole('user-1', 'viewer')
      await adapter.assignRole('user-1', 'editor')
      await adapter.revokeRole('user-1', 'viewer')
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
    })

    it('revokeRole is no-op for unknown subject', async () => {
      await adapter.revokeRole('unknown', 'viewer') // should not throw
    })

    it('getSubjectScopedRoles returns scoped assignments', async () => {
      await adapter.assignRole('user-1', 'editor', 'org-1')
      await adapter.assignRole('user-1', 'viewer') // no scope
      const scoped = await adapter.getSubjectScopedRoles('user-1')
      expect(scoped).toEqual([{ role: 'editor', scope: 'org-1' }])
    })

    describe('updateAssignmentScope', () => {
      // Local adapter with a second scope, kept separate from the shared `S` type above.
      type S2 = 'org-1' | 'org-2'
      let a: IamMemoryAdapter<A, R, Ro, S2>

      beforeEach(() => {
        a = new IamMemoryAdapter<A, R, Ro, S2>({
          roles: [{ id: 'editor', name: 'Editor', permissions: [{ action: 'write', resource: 'post' }] }],
        })
      })

      it('moves the assignment to the new scope in place', async () => {
        await a.assignRole('user-1', 'editor', 'org-1')
        expect(await a.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')).toBe(true)
        expect(await a.getSubjectScopedRoles('user-1')).toEqual([{ role: 'editor', scope: 'org-2' }])
      })

      it('drops the source instead of duplicating when the target scope is already granted', async () => {
        await a.assignRole('user-1', 'editor', 'org-1')
        await a.assignRole('user-1', 'editor', 'org-2')
        expect(await a.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')).toBe(true)
        expect(await a.getSubjectScopedRoles('user-1')).toEqual([{ role: 'editor', scope: 'org-2' }])
      })

      it('returns false when no assignment matches the source scope', async () => {
        expect(await a.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')).toBe(false)
      })
    })

    it('getSubjectAttributes returns empty for unknown subject', async () => {
      expect(await adapter.getSubjectAttributes('unknown')).toEqual({})
    })

    it('setSubjectAttributes merges attributes', async () => {
      await adapter.setSubjectAttributes('user-1', { a: 1, b: 'two' })
      await adapter.setSubjectAttributes('user-1', { c: true })
      expect(await adapter.getSubjectAttributes('user-1')).toEqual({ a: 1, b: 'two', c: true })
    })
  })

  describe('constructor init', () => {
    it('initializes from init object', async () => {
      const adapter = new IamMemoryAdapter<A, R, Ro, S>({
        policies: [{ id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [] }],
        roles: [{ id: 'viewer', name: 'Viewer', permissions: [] }],
        assignments: { 'user-1': ['viewer'] },
        attributes: { 'user-1': { level: 5 } },
      })

      // Seeded rows are normalised exactly as written ones are, so this is the
      // same `version: 1` the write path supplies - not a second shape.
      expect(await adapter.listPolicies()).toEqual([
        { id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [], version: 1 },
      ])
      expect(await adapter.listRoles()).toEqual([{ id: 'viewer', name: 'Viewer', permissions: [] }])
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['viewer'])
      expect(await adapter.getSubjectAttributes('user-1')).toEqual({ level: 5 })
    })
  })
})

describe('iamMemoryAdapter factory', () => {
  it('returns a working IamMemoryAdapter seeded from init', async () => {
    // `viewer` is declared here because a seeded assignment naming a role the
    // init does not define is now refused, exactly as `assignRole` refuses it.
    // This test is about the factory, and it was seeding a dangling grant only
    // incidentally - which is how the divergence stayed invisible.
    const adapter = iamMemoryAdapter({
      assignments: { 'user-1': ['viewer'] },
      roles: [{ id: 'viewer', name: 'Viewer', permissions: [] }],
    })
    expect(adapter).toBeInstanceOf(IamMemoryAdapter)
    expect(await adapter.getSubjectRoles('user-1')).toEqual(['viewer'])
  })
})
