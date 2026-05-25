import { describe, expect, it } from 'vitest'
import type { AccessControl, Adapter } from '../../core/types'

/**
 * DEBT-2: shared adapter compliance suite.
 *
 * Every shipped adapter (`MemoryAdapter`, `FileAdapter`, `RedisAdapter`,
 * `DrizzleAdapter`, `PrismaAdapter`, `HttpAdapter`) and every third-party
 * adapter must pass this matrix. The suite pins the cross-backend contract:
 * same scenarios must produce identical results regardless of storage. SEC-059
 * (file/memory returned unscoped-only; redis/drizzle/prisma returned all
 * collapsed) was a symptom of NOT having this.
 *
 * Usage in an adapter test file:
 * ```ts
 * import { runAdapterCompliance } from '../../__compliance__/compliance'
 * runAdapterCompliance('MyAdapter', () => new MyAdapter({ ... }))
 * ```
 *
 * The factory MUST return a fresh, empty adapter on each call.
 */

type AnyAdapter = Adapter.IAdapter<string, string, string, string>

const samplePolicy: AccessControl.IPolicy = {
  id: 'p-compliance',
  name: 'Compliance Test Policy',
  algorithm: 'deny-overrides',
  rules: [
    {
      id: 'r1',
      effect: 'allow',
      priority: 10,
      actions: ['read'],
      resources: ['post'],
      conditions: { all: [] },
    },
  ],
}

const sampleRole: AccessControl.IRole = {
  id: 'editor',
  name: 'Editor',
  permissions: [{ action: 'read', resource: 'post' }],
}

/**
 * Run the compliance matrix against any adapter implementation.
 *
 * @param adapterName - Human-readable name used in describe blocks.
 * @param factory - Async factory that returns a FRESH adapter per call. Must
 *   not share state across factory invocations (each test runs against a
 *   clean slate).
 */
export function runAdapterCompliance(adapterName: string, factory: () => AnyAdapter | Promise<AnyAdapter>): void {
  describe(`Adapter compliance: ${adapterName}`, () => {
    describe('IPolicyStore', () => {
      it('listPolicies returns [] on empty store', async () => {
        const a = await factory()
        expect(await a.listPolicies()).toEqual([])
      })

      it('getPolicy returns null on miss', async () => {
        const a = await factory()
        expect(await a.getPolicy('missing')).toBeNull()
      })

      it('savePolicy + getPolicy round-trips', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        const got = await a.getPolicy(samplePolicy.id)
        expect(got?.id).toBe(samplePolicy.id)
        expect(got?.name).toBe(samplePolicy.name)
        expect(got?.algorithm).toBe(samplePolicy.algorithm)
        expect(got?.rules.length).toBe(1)
      })

      it('savePolicy overwrites existing entry (upsert semantics)', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        await a.savePolicy({ ...samplePolicy, name: 'Renamed' })
        const got = await a.getPolicy(samplePolicy.id)
        expect(got?.name).toBe('Renamed')
      })

      it('deletePolicy removes the entry', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        await a.deletePolicy(samplePolicy.id)
        expect(await a.getPolicy(samplePolicy.id)).toBeNull()
      })

      it('listPolicies returns every saved policy', async () => {
        const a = await factory()
        await a.savePolicy({ ...samplePolicy, id: 'p1' })
        await a.savePolicy({ ...samplePolicy, id: 'p2' })
        const list = await a.listPolicies()
        expect(list.map((p) => p.id).sort()).toEqual(['p1', 'p2'])
      })
    })

    describe('IRoleStore', () => {
      it('listRoles returns [] on empty store', async () => {
        const a = await factory()
        expect(await a.listRoles()).toEqual([])
      })

      it('saveRole + getRole round-trips', async () => {
        const a = await factory()
        await a.saveRole(sampleRole)
        const got = await a.getRole(sampleRole.id)
        expect(got?.id).toBe(sampleRole.id)
        expect(got?.name).toBe(sampleRole.name)
        expect(got?.permissions.length).toBe(1)
      })

      it('deleteRole removes the entry', async () => {
        const a = await factory()
        await a.saveRole(sampleRole)
        await a.deleteRole(sampleRole.id)
        expect(await a.getRole(sampleRole.id)).toBeNull()
      })
    })

    describe('ISubjectStore', () => {
      it('getSubjectRoles returns [] when no assignments', async () => {
        const a = await factory()
        expect(await a.getSubjectRoles('nobody')).toEqual([])
      })

      it('assignRole + getSubjectRoles returns the role', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
      })

      it('revokeRole removes the assignment', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        await a.revokeRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual([])
      })

      it('SEC-059: getSubjectRoles returns ONLY unscoped (global) roles', async () => {
        // Every adapter must honour this contract. Returning scoped+unscoped
        // collapsed means the same subject decides differently across backends.
        const a = await factory()
        await a.assignRole('user-1', 'viewer')
        await a.assignRole('user-1', 'editor', 'org-1')
        expect((await a.getSubjectRoles('user-1')).sort()).toEqual(['viewer'])
      })

      it('SEC-059: getSubjectScopedRoles returns ONLY scoped assignments', async () => {
        const a = await factory()
        if (!a.getSubjectScopedRoles) return // optional method
        await a.assignRole('user-1', 'viewer')
        await a.assignRole('user-1', 'editor', 'org-1')
        const scoped = await a.getSubjectScopedRoles('user-1')
        expect(scoped).toEqual([{ role: 'editor', scope: 'org-1' }])
      })

      it('revokeRole with scope removes only the scoped assignment', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-1', 'editor', 'org-1')
        await a.revokeRole('user-1', 'editor', 'org-1')
        expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
        if (a.getSubjectScopedRoles) {
          expect(await a.getSubjectScopedRoles('user-1')).toEqual([])
        }
      })

      it('revokeRole without scope removes ALL matching assignments', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-1', 'editor', 'org-1')
        await a.assignRole('user-1', 'editor', 'org-2')
        await a.revokeRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual([])
        if (a.getSubjectScopedRoles) {
          expect(await a.getSubjectScopedRoles('user-1')).toEqual([])
        }
      })

      it('getSubjectAttributes returns {} when none recorded', async () => {
        const a = await factory()
        expect(await a.getSubjectAttributes('nobody')).toEqual({})
      })

      it('setSubjectAttributes merges (does not replace)', async () => {
        const a = await factory()
        await a.setSubjectAttributes('user-1', { team: 'A' })
        await a.setSubjectAttributes('user-1', { plan: 'pro' })
        expect(await a.getSubjectAttributes('user-1')).toEqual({ team: 'A', plan: 'pro' })
      })

      it('setSubjectAttributes overwrites existing key on second call', async () => {
        const a = await factory()
        await a.setSubjectAttributes('user-1', { team: 'A' })
        await a.setSubjectAttributes('user-1', { team: 'B' })
        expect((await a.getSubjectAttributes('user-1')).team).toBe('B')
      })

      it('assignments are isolated per subject', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-2', 'viewer')
        expect((await a.getSubjectRoles('user-1')).sort()).toEqual(['editor'])
        expect((await a.getSubjectRoles('user-2')).sort()).toEqual(['viewer'])
      })

      it('attributes are isolated per subject', async () => {
        const a = await factory()
        await a.setSubjectAttributes('user-1', { team: 'A' })
        await a.setSubjectAttributes('user-2', { team: 'B' })
        expect((await a.getSubjectAttributes('user-1')).team).toBe('A')
        expect((await a.getSubjectAttributes('user-2')).team).toBe('B')
      })
    })
  })
}
