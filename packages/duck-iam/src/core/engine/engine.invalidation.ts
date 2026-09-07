/**
 * Cache + in-flight invalidation logic, extracted from the Engine class
 * so the class file stays focused on the eval pipeline. Every function
 * here takes the caches + invalidator explicitly so it can be unit-tested
 * without standing up a full Engine.
 */

import type { IamLRUCache } from '../../shared/cache'
import type { AccessControl, IamRequest } from '../types'
import type { IamEngineTypes } from './engine.types'

/**
 * Every cache one engine owns, passed explicitly rather than reached through
 * the engine instance so each function here is testable on its own.
 */
export interface IEngineCacheBag<TRole extends string = string> {
  policyCache: IamLRUCache<AccessControl.IPolicy[]>
  roleCache: IamLRUCache<AccessControl.IRole[]>
  rbacPolicyCache: IamLRUCache<AccessControl.IPolicy>
  mergedPolicyCache: IamLRUCache<AccessControl.IPolicy[]>
  subjectCache: IamLRUCache<IamRequest.ISubject>
  inFlight: IEngineInFlightBag
  invalidator?: IamEngineTypes.IInvalidator<TRole>
}

/**
 * One single-flight slot: the load in progress for a cache key, or `null` when
 * none is. A mutable box rather than a bare promise so a loader can clear its
 * own slot on settle and an invalidation can clear it from outside, both
 * through the same reference.
 */
export interface ISingleFlightSlot<T> {
  value: Promise<T> | null
}

/**
 * The single-flight slots: the in-progress load for each cache key, or `null`.
 * Clearing a cache must clear its slot too, or the load already in flight
 * settles afterwards and repopulates the cache with what was just invalidated.
 */
export interface IEngineInFlightBag {
  policies: ISingleFlightSlot<AccessControl.IPolicy[]>
  roles: ISingleFlightSlot<AccessControl.IRole[]>
  rbac: ISingleFlightSlot<AccessControl.IPolicy>
  merged: ISingleFlightSlot<AccessControl.IPolicy[]>
  subjects: Map<string, Promise<IamRequest.ISubject>>
}

/**
 * Drop everything: policies, roles, the RBAC projection, merged policies and
 * subjects, together with their in-flight slots.
 *
 * @param bag  - The caches to clear.
 * @param opts - `broadcast: false` applies the change locally without
 *               republishing it, which is how a received event is applied —
 *               otherwise two engines would bounce the same event forever.
 */
export function invalidateAll<TRole extends string>(bag: IEngineCacheBag<TRole>, opts: { broadcast?: boolean }): void {
  bag.policyCache.clear()
  bag.roleCache.clear()
  bag.rbacPolicyCache.clear()
  bag.subjectCache.clear()
  bag.inFlight.policies.value = null
  bag.inFlight.roles.value = null
  bag.inFlight.rbac.value = null
  bag.inFlight.merged.value = null
  bag.mergedPolicyCache.clear()
  bag.inFlight.subjects.clear()
  if (opts.broadcast !== false && bag.invalidator) {
    void bag.invalidator.publish({ kind: 'all' })
  }
}

/**
 * Drop one subject's resolved roles.
 *
 * A `subjectId` that is not a sane string is ignored rather than rejected: this
 * is a cache eviction, and the id may have arrived from another process over
 * the invalidator, where refusing it loudly would be worse than doing nothing.
 *
 * @param bag       - The caches to clear.
 * @param subjectId - Subject whose entry to evict.
 * @param opts      - `broadcast: false` to apply without republishing.
 */
export function invalidateSubject<TRole extends string>(
  bag: IEngineCacheBag<TRole>,
  subjectId: string,
  opts: { broadcast?: boolean },
): void {
  if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) return
  bag.subjectCache.delete(subjectId)
  bag.inFlight.subjects.delete(subjectId)
  if (opts.broadcast !== false && bag.invalidator) {
    void bag.invalidator.publish({ kind: 'subject', subjectId })
  }
}

/**
 * Drop the policy caches, and the merged view with them.
 *
 * The merged cache is a projection of policies plus the RBAC policy, so it is
 * stale the instant either input changes; clearing policies without it would
 * leave every evaluation reading the old set from the merge.
 *
 * @param bag  - The caches to clear.
 * @param opts - `broadcast: false` to apply without republishing.
 */
export function invalidatePolicies<TRole extends string>(
  bag: IEngineCacheBag<TRole>,
  opts: { broadcast?: boolean },
): void {
  bag.policyCache.clear()
  bag.inFlight.policies.value = null
  bag.inFlight.merged.value = null
  bag.mergedPolicyCache.clear()
  if (opts.broadcast !== false && bag.invalidator) {
    void bag.invalidator.publish({ kind: 'policies' })
  }
}

/**
 * Drop the role caches, the RBAC projection compiled from them, and the merged
 * view that contains it.
 *
 * `roleIdInput` narrows only what is *published*; the local caches are cleared
 * wholesale either way, because a role's edit can change any subject's
 * effective set through inheritance. An unusable id degrades to `undefined`
 * rather than throwing — see {@link invalidateSubject} for why an eviction path
 * stays quiet.
 *
 * @param bag         - The caches to clear.
 * @param roleIdInput - Role that changed, when the caller knows it.
 * @param opts        - `broadcast: false` to apply without republishing.
 */
export function invalidateRoles<TRole extends string>(
  bag: IEngineCacheBag<TRole>,
  roleIdInput: TRole | undefined,
  opts: { broadcast?: boolean },
): void {
  let roleId = roleIdInput
  if (roleId !== undefined && (typeof roleId !== 'string' || roleId.length === 0 || roleId.length > 1024)) {
    roleId = undefined
  }
  bag.roleCache.clear()
  bag.rbacPolicyCache.clear()
  bag.inFlight.roles.value = null
  bag.inFlight.rbac.value = null
  bag.inFlight.merged.value = null
  bag.mergedPolicyCache.clear()
  if (roleId === undefined) {
    bag.subjectCache.clear()
    bag.inFlight.subjects.clear()
  } else {
    for (const [subjectId, subject] of bag.subjectCache.entries()) {
      const inRoles = subject.roles.includes(roleId)
      const inScoped = subject.scopedRoles?.some((sr) => sr.role === roleId) ?? false
      if (inRoles || inScoped) {
        bag.subjectCache.delete(subjectId)
        bag.inFlight.subjects.delete(subjectId)
      }
    }
  }
  if (opts.broadcast !== false && bag.invalidator) {
    void bag.invalidator.publish({ kind: 'roles', roleId })
  }
}

/**
 * Apply an invalidation that arrived from another engine instance.
 *
 * Every branch passes `broadcast: false`. Republishing a received event would
 * make each instance echo every other instance's evictions, and the traffic
 * grows with the square of the fleet.
 *
 * @param bag   - The caches to clear.
 * @param event - The event as published by a peer.
 */
export function applyInvalidateEvent<TRole extends string>(
  bag: IEngineCacheBag<TRole>,
  event: IamEngineTypes.IInvalidateEvent<TRole>,
): void {
  switch (event.kind) {
    case 'all':
      invalidateAll(bag, { broadcast: false })
      return
    case 'policies':
      invalidatePolicies(bag, { broadcast: false })
      return
    case 'roles':
      invalidateRoles(bag, event.roleId, { broadcast: false })
      return
    case 'subject':
      invalidateSubject(bag, event.subjectId, { broadcast: false })
      return
  }
}
