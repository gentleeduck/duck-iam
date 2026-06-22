import { describe, expect, it, vi } from 'vitest'
import { IamLRUCache } from '../../../shared/cache'
import type { IamAccessControl, IamRequest } from '../../types'
import { disposeInvalidator, preloadEngine, runHealthCheck } from '../engine.lifecycle'
import type { IIamCachesForStats } from '../engine.stats'

function caches(): IIamCachesForStats {
  return {
    policyCache: new IamLRUCache<IamAccessControl.IPolicy[]>(100, 60_000),
    roleCache: new IamLRUCache<IamAccessControl.IRole[]>(100, 60_000),
    rbacPolicyCache: new IamLRUCache<IamAccessControl.IPolicy>(100, 60_000),
    mergedPolicyCache: new IamLRUCache<IamAccessControl.IPolicy[]>(100, 60_000),
    subjectCache: new IamLRUCache<IamRequest.ISubject>(100, 60_000),
  }
}

describe('runHealthCheck', () => {
  it('returns ok=true when the probe succeeds', async () => {
    const h = await runHealthCheck(caches(), async () => {})
    expect(h.ok).toBe(true)
    expect(h.adapter).toBe('ok')
    expect(h.lastError).toBeUndefined()
  })

  it('returns ok=false + lastError when the probe throws', async () => {
    const h = await runHealthCheck(caches(), async () => {
      throw new Error('adapter down')
    })
    expect(h.ok).toBe(false)
    expect(h.adapter).toBe('fail')
    expect(h.lastError).toBe('adapter down')
  })

  it('reports cacheHitRate from the stats snapshot', async () => {
    const c = caches()
    c.policyCache.set('a', [])
    c.policyCache.get('a')
    c.policyCache.get('z')
    const h = await runHealthCheck(c, async () => {})
    expect(h.cacheHitRate).toBeCloseTo(0.5, 5)
  })

  it('handles non-Error throws via String() coercion', async () => {
    const h = await runHealthCheck(caches(), async () => {
      // biome-ignore lint/suspicious/noExplicitAny: test fixture intentionally throws a non-Error value
      throw 'plain string' as any
    })
    expect(h.lastError).toBe('plain string')
  })
})

describe('preloadEngine', () => {
  it('runs loadAllPolicies; skips validator import when flag false', async () => {
    const loadAllPolicies = vi.fn(async () => [])
    await preloadEngine({ loadAllPolicies, loadValidator: false })
    expect(loadAllPolicies).toHaveBeenCalledTimes(1)
  })

  it('runs both when validator flag true', async () => {
    const loadAllPolicies = vi.fn(async () => [])
    await preloadEngine({ loadAllPolicies, loadValidator: true })
    expect(loadAllPolicies).toHaveBeenCalledTimes(1)
  })

  it('rejects when loadAllPolicies rejects', async () => {
    await expect(
      preloadEngine({ loadAllPolicies: async () => Promise.reject(new Error('boom')), loadValidator: false }),
    ).rejects.toThrow('boom')
  })
})

describe('disposeInvalidator', () => {
  it('calls the unsub fn and returns { unsub: null }', () => {
    const unsub = vi.fn()
    const out = disposeInvalidator(unsub)
    expect(unsub).toHaveBeenCalled()
    expect(out.unsub).toBeNull()
  })

  it('no-ops when invalidatorUnsub is null', () => {
    const out = disposeInvalidator(null)
    expect(out.unsub).toBeNull()
  })

  it('swallows unsub throws (tear-down must not throw)', () => {
    expect(() =>
      disposeInvalidator(() => {
        throw new Error('boom')
      }),
    ).not.toThrow()
  })
})
