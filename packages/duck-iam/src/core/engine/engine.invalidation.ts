/**
 * Cache + in-flight invalidation logic, extracted from the Engine class
 * so the class file stays focused on the eval pipeline. Every function
 * here takes the caches + invalidator explicitly so it can be unit-tested
 * without standing up a full Engine.
 */

import type { IamLRUCache } from '../../shared/cache'
import type { AccessControl, IamRequest } from '../types'
import type { IamEngineTypes } from './engine.types'

export interface IEngineCacheBag<TRole extends string = string> {
  policyCache: IamLRUCache<AccessControl.IPolicy[]>
  roleCache: IamLRUCache<AccessControl.IRole[]>
  rbacPolicyCache: IamLRUCache<AccessControl.IPolicy>
  mergedPolicyCache: IamLRUCache<AccessControl.IPolicy[]>
  subjectCache: IamLRUCache<IamRequest.ISubject>
  inFlight: IEngineInFlightBag
  invalidator?: IamEngineTypes.IInvalidator<TRole>
}

export interface IEngineInFlightBag {
  policies: { value: Promise<AccessControl.IPolicy[]> | null }
  roles: { value: Promise<AccessControl.IRole[]> | null }
  rbac: { value: Promise<AccessControl.IPolicy> | null }
  merged: { value: Promise<AccessControl.IPolicy[]> | null }
  subjects: Map<string, Promise<IamRequest.ISubject>>
}

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
