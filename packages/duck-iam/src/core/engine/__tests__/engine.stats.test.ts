import { describe, expect, it } from 'vitest'
import { IamLRUCache } from '../../../shared/cache'
import type { IamAccessControl, IamRequest } from '../../types'
import { aggregateCacheHitRate, type IIamCachesForStats, resetStats, statsSnapshot } from '../engine.stats'

function makeCaches(): IIamCachesForStats {
  return {
    policyCache: new IamLRUCache<IamAccessControl.IPolicy[]>(100, 60_000),
    roleCache: new IamLRUCache<IamAccessControl.IRole[]>(100, 60_000),
    rbacPolicyCache: new IamLRUCache<IamAccessControl.IPolicy>(100, 60_000),
    mergedPolicyCache: new IamLRUCache<IamAccessControl.IPolicy[]>(100, 60_000),
    subjectCache: new IamLRUCache<IamRequest.ISubject>(100, 60_000),
  }
}

describe('statsSnapshot', () => {
  it('reads counters off every cache', () => {
    const c = makeCaches()
    c.policyCache.set('a', [])
    c.policyCache.get('a') // hit
    c.policyCache.get('z') // miss
    const s = statsSnapshot(c)
    expect(s.policies.hits).toBe(1)
    expect(s.policies.misses).toBe(1)
    expect(s.policies.size).toBe(1)
  })

  it('returns five distinct cache buckets', () => {
    const c = makeCaches()
    const s = statsSnapshot(c)
    expect(Object.keys(s).sort()).toEqual(['mergedPolicies', 'policies', 'rbacPolicy', 'roles', 'subjects'])
  })
})

describe('resetStats', () => {
  it('zeros every cache counter without dropping cached values', () => {
    const c = makeCaches()
    c.policyCache.set('a', [])
    c.policyCache.get('a')
    c.policyCache.get('z')
    resetStats(c)
    const s = statsSnapshot(c)
    expect(s.policies.hits).toBe(0)
    expect(s.policies.misses).toBe(0)
    expect(s.policies.size).toBe(1) // values preserved
  })
})

describe('aggregateCacheHitRate', () => {
  it('returns 0 when no events recorded', () => {
    const r = aggregateCacheHitRate(statsSnapshot(makeCaches()))
    expect(r.total).toBe(0)
    expect(r.hits).toBe(0)
    expect(r.rate).toBe(0)
  })

  it('sums hits across all five caches', () => {
    const c = makeCaches()
    c.policyCache.set('a', [])
    c.policyCache.get('a')
    c.roleCache.set('b', [])
    c.roleCache.get('b')
    c.policyCache.get('z')
    const r = aggregateCacheHitRate(statsSnapshot(c))
    expect(r.hits).toBe(2)
    expect(r.total).toBe(3)
    expect(r.rate).toBeCloseTo(2 / 3, 5)
  })
})
