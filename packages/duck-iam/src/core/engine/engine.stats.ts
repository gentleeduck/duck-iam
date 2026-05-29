/**
 * Stats snapshot/reset, extracted from Engine. Pure plumbing over the
 * five caches.
 */

import type { LRUCache } from '../../shared/cache'
import type { AccessControl, Request } from '../types'

export interface ICachesForStats {
  policyCache: LRUCache<AccessControl.IPolicy[]>
  roleCache: LRUCache<AccessControl.IRole[]>
  rbacPolicyCache: LRUCache<AccessControl.IPolicy>
  mergedPolicyCache: LRUCache<AccessControl.IPolicy[]>
  subjectCache: LRUCache<Request.ISubject>
}

export interface IStatsSnapshot {
  policies: { hits: number; misses: number; size: number }
  roles: { hits: number; misses: number; size: number }
  rbacPolicy: { hits: number; misses: number; size: number }
  mergedPolicies: { hits: number; misses: number; size: number }
  subjects: { hits: number; misses: number; size: number }
}

export function statsSnapshot(c: ICachesForStats): IStatsSnapshot {
  return {
    policies: c.policyCache.stats,
    roles: c.roleCache.stats,
    rbacPolicy: c.rbacPolicyCache.stats,
    mergedPolicies: c.mergedPolicyCache.stats,
    subjects: c.subjectCache.stats,
  }
}

export function resetStats(c: ICachesForStats): void {
  c.policyCache.resetStats()
  c.roleCache.resetStats()
  c.rbacPolicyCache.resetStats()
  c.mergedPolicyCache.resetStats()
  c.subjectCache.resetStats()
}

export function aggregateCacheHitRate(s: IStatsSnapshot): { total: number; hits: number; rate: number } {
  const total =
    s.policies.hits +
    s.policies.misses +
    s.roles.hits +
    s.roles.misses +
    s.rbacPolicy.hits +
    s.rbacPolicy.misses +
    s.mergedPolicies.hits +
    s.mergedPolicies.misses +
    s.subjects.hits +
    s.subjects.misses
  const hits = s.policies.hits + s.roles.hits + s.rbacPolicy.hits + s.mergedPolicies.hits + s.subjects.hits
  return { total, hits, rate: total === 0 ? 0 : hits / total }
}
