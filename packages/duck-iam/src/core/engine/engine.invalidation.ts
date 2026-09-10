// Cache and in-flight invalidation, kept out of the engine class. Each function takes its caches explicitly.

import type { IamLRUCache } from '../../shared/cache'
import type { AccessControl, IamRequest } from '../types'
import type { IamEngineTypes } from './engine.types'

/** Every cache one engine owns, passed explicitly so each function here is testable on its own. */
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
 * The load in flight for one cache key, or `null`.
 * NOTE: a mutable box, not a bare promise, so the loader and an invalidation clear the same slot.
 */
export interface ISingleFlightSlot<T> {
  value: Promise<T> | null
}

/**
 * The single-flight slot for each cache.
 * WARN: clearing a cache must clear its slot too, or the in-flight load repopulates it with stale data.
 */
export interface IEngineInFlightBag {
  policies: ISingleFlightSlot<AccessControl.IPolicy[]>
  roles: ISingleFlightSlot<AccessControl.IRole[]>
  rbac: ISingleFlightSlot<AccessControl.IPolicy>
  merged: ISingleFlightSlot<AccessControl.IPolicy[]>
  subjects: Map<string, Promise<IamRequest.ISubject>>
}

/**
 * Drops every cache and its in-flight slot.
 * `broadcast: false` applies a received event without republishing it, so two engines never bounce it forever.
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
 * Drops one subject's resolved roles.
 * NOTE: an unusable `subjectId` is ignored, not thrown: it may come from a peer, and an eviction stays quiet.
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
 * Drops the policy caches and the merged view.
 * NOTE: merged is derived from policies plus RBAC; clearing policies without it would keep serving the old set.
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
 * Drops the role caches, the RBAC projection and the merged view wholesale, since inheritance can reach anyone.
 * `roleIdInput` only narrows the subject sweep; an unusable id sweeps every subject (see {@link invalidateSubject}).
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
  // SECURITY: unconditional. An in-flight load has no cache entry for the sweep below to match, and one started
  // before a revoke would cache the old roles for a full TTL.
  bag.inFlight.subjects.clear()
  if (roleId === undefined) {
    bag.subjectCache.clear()
  } else {
    for (const [subjectId, subject] of bag.subjectCache.entries()) {
      const inRoles = subject.roles.includes(roleId)
      const inScoped = subject.scopedRoles?.some((sr) => sr.role === roleId) ?? false
      if (inRoles || inScoped) bag.subjectCache.delete(subjectId)
    }
  }
  if (opts.broadcast !== false && bag.invalidator) {
    void bag.invalidator.publish({ kind: 'roles', roleId })
  }
}

/**
 * Applies an invalidation received from another engine instance.
 * NOTE: every branch passes `broadcast: false`; echoing peers' events would grow traffic with the fleet squared.
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
