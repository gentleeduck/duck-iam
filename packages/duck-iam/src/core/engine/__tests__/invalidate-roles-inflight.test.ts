import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamLRUCache } from '../../../shared/cache'
import type { AccessControl, IamAdapter, IamRequest } from '../../types'
import { IamEngine } from '../engine'
import { type IEngineCacheBag, invalidateRoles } from '../engine.invalidation'

// An in-flight load has no `subjectCache` entry, so `invalidateRoles(roleId)` must drop in-flight slots too, or a
// load started before a revoke caches the revoked role for a full TTL.

type Role = 'editor' | 'viewer'

function makeBag(): IEngineCacheBag<Role> {
  return {
    inFlight: {
      merged: { value: null },
      policies: { value: null },
      rbac: { value: null },
      roles: { value: null },
      subjects: new Map(),
    },
    mergedPolicyCache: new IamLRUCache<AccessControl.IPolicy[]>(100, 60_000),
    policyCache: new IamLRUCache<AccessControl.IPolicy[]>(100, 60_000),
    rbacPolicyCache: new IamLRUCache<AccessControl.IPolicy>(100, 60_000),
    roleCache: new IamLRUCache<AccessControl.IRole[]>(100, 60_000),
    subjectCache: new IamLRUCache<IamRequest.ISubject>(100, 60_000),
  }
}

describe('invalidateRoles drops in-flight subject loads', () => {
  it('a narrowed invalidation clears slots the subjectCache sweep cannot see', () => {
    const bag = makeBag()
    // In flight, so not in subjectCache: the sweep cannot know which roles this load returns.
    bag.inFlight.subjects.set('u-loading', Promise.resolve({ attributes: {}, id: 'u-loading', roles: [] }))
    invalidateRoles(bag, 'editor', { broadcast: false })
    expect(bag.inFlight.subjects.size).toBe(0)
  })

  it('a resolved subject holding an unrelated role is still spared', () => {
    // Narrowing still applies to entries the sweep can inspect; this must not become a wholesale clear.
    const bag = makeBag()
    bag.subjectCache.set('u-editor', { attributes: {}, id: 'u-editor', roles: ['editor'] })
    bag.subjectCache.set('u-viewer', { attributes: {}, id: 'u-viewer', roles: ['viewer'] })
    invalidateRoles(bag, 'editor', { broadcast: false })
    expect({
      editor: bag.subjectCache.get('u-editor'),
      viewer: bag.subjectCache.get('u-viewer')?.id,
    }).toEqual({ editor: undefined, viewer: 'u-viewer' })
  })

  it('end-to-end: a role revoked mid-load does not come back with a full TTL', async () => {
    /** Parks AFTER the read, so the load holds pre-revocation data while we revoke. */
    class ParkingAdapter extends IamMemoryAdapter<'read', 'post', Role, string> {
      release: () => void = () => {}
      private _gate: Promise<void> | null = null

      park(): void {
        this._gate = new Promise<void>((resolve) => {
          this.release = resolve
        })
      }

      override async getSubjectRoles(id: string, opts?: IamAdapter.IReadOptions): Promise<Role[]> {
        const roles = await super.getSubjectRoles(id, opts)
        const gate = this._gate
        if (gate) {
          this._gate = null
          await gate
        }
        return roles
      }
    }

    const adapter = new ParkingAdapter({
      assignments: { u1: ['editor'] },
      roles: [{ id: 'editor', name: 'Editor', permissions: [{ action: 'read', resource: 'post' }] }],
    })
    const engine = new IamEngine({ adapter })

    expect(await engine.check('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)
    engine.cache.invalidateSubject('u1')

    adapter.park()
    const inFlight = engine.check('u1', 'read', { attributes: {}, type: 'post' })
    // The revoke lands while that load is parked holding ['editor'].
    await adapter.revokeRole('u1', 'editor')
    engine.cache.invalidateRoles('editor')
    adapter.release()
    await inFlight

    expect(await engine.check('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })
})
