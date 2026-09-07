/**
 * Stats snapshot/reset, extracted from Engine. Pure plumbing over the
 * five caches.
 */

import type { IamLRUCache } from '../../shared/cache'
import type { AccessControl, IamRequest } from '../types'

/** The five caches a stats snapshot reads. Named separately from the engine so the snapshot can be taken of any bag of caches, including in a test. */
export interface IIamCachesForStats {
  policyCache: IamLRUCache<AccessControl.IPolicy[]>
  roleCache: IamLRUCache<AccessControl.IRole[]>
  rbacPolicyCache: IamLRUCache<AccessControl.IPolicy>
  mergedPolicyCache: IamLRUCache<AccessControl.IPolicy[]>
  subjectCache: IamLRUCache<IamRequest.ISubject>
}

/** One reading of every cache's hit/miss counters and current size. */
export interface IStatsSnapshot {
  policies: { hits: number; misses: number; size: number }
  roles: { hits: number; misses: number; size: number }
  rbacPolicy: { hits: number; misses: number; size: number }
  mergedPolicies: { hits: number; misses: number; size: number }
  subjects: { hits: number; misses: number; size: number }
}

/**
 * Read every cache's counters at one instant.
 *
 * @param caches - The caches to read.
 * @returns A plain snapshot, safe to serialise; it holds no reference to the caches.
 */
export function statsSnapshot(c: IIamCachesForStats): IStatsSnapshot {
  return {
    policies: c.policyCache.stats,
    roles: c.roleCache.stats,
    rbacPolicy: c.rbacPolicyCache.stats,
    mergedPolicies: c.mergedPolicyCache.stats,
    subjects: c.subjectCache.stats,
  }
}

/**
 * Zero every cache's hit/miss counters, leaving the cached entries in place.
 *
 * Counters and contents are deliberately separate: an operator sampling a rate
 * wants the window reset, not a cold cache and the latency spike that follows.
 *
 * @param caches - The caches whose counters to reset.
 */
export function resetStats(c: IIamCachesForStats): void {
  c.policyCache.resetStats()
  c.roleCache.resetStats()
  c.rbacPolicyCache.resetStats()
  c.mergedPolicyCache.resetStats()
  c.subjectCache.resetStats()
}

/**
 * Collapse the per-cache counters into one hit rate across all five.
 *
 * @param s - A snapshot from {@link statsSnapshot}.
 * @returns The pooled `rate` (0 when nothing has been looked up yet, rather
 *          than `NaN` from dividing by zero) alongside the totals it came from.
 */
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
