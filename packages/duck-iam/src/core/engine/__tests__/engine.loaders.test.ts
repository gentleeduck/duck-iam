import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamLRUCache } from '../../../shared/cache'
import type { IamAccessControl, IamAdapter, IamRequest } from '../../types'
import {
  type IIamLoaderDeps,
  loadAllPolicies,
  loadPolicies,
  loadRbacPolicy,
  loadRoles,
  resolveSubject,
} from '../engine.loaders'

type A = string
type R = string
type Ro = string
type S = string

function makeAdapter(overrides: Partial<IamAdapter.IAdapter<A, R, Ro, S>> = {}): IamAdapter.IAdapter<A, R, Ro, S> {
  return {
    listPolicies: async () => [],
    getPolicy: async () => null,
    savePolicy: async () => {},
    deletePolicy: async () => {},
    listRoles: async () => [],
    getRole: async () => null,
    saveRole: async () => {},
    deleteRole: async () => {},
    getSubjectRoles: async () => [],
    getSubjectAttributes: async () => ({}),
    assignRole: async () => {},
    revokeRole: async () => {},
    setSubjectAttributes: async () => {},
    ...overrides,
  }
}

function makeDeps(overrides: Partial<IIamLoaderDeps<A, R, Ro, S>> = {}): IIamLoaderDeps<A, R, Ro, S> {
  return {
    adapter: makeAdapter(),
    policyCache: new IamLRUCache<IamAccessControl.IPolicy[]>(100, 60_000),
    roleCache: new IamLRUCache<IamAccessControl.IRole[]>(100, 60_000),
    rbacPolicyCache: new IamLRUCache<IamAccessControl.IPolicy>(100, 60_000),
    mergedPolicyCache: new IamLRUCache<IamAccessControl.IPolicy[]>(100, 60_000),
    subjectCache: new IamLRUCache<IamRequest.ISubject>(100, 60_000),
    inFlight: {
      policies: { value: null },
      roles: { value: null },
      rbac: { value: null },
      merged: { value: null },
      subjects: new Map(),
    },
    maxPolicies: 1000,
    maxRoles: 1000,
    withTimeout: (fn) => fn({ signal: new AbortController().signal }),
    ...overrides,
  }
}

describe('loadPolicies', () => {
  let deps: IIamLoaderDeps<A, R, Ro, S>
  beforeEach(() => {
    deps = makeDeps()
  })

  it('caches the policy list under "all"', async () => {
    const policies: IamAccessControl.IPolicy[] = [{ id: 'p', name: 'p', algorithm: 'deny-overrides' as const, rules: [] }]
    deps.adapter.listPolicies = vi.fn(async () => policies)
    await loadPolicies(deps)
    expect(deps.policyCache.get('all')).toEqual(policies)
    expect(deps.adapter.listPolicies).toHaveBeenCalledTimes(1)
  })

  it('returns the cached value without calling the adapter on the second call', async () => {
    const adapter = vi.fn(async () => [])
    deps.adapter.listPolicies = adapter
    await loadPolicies(deps)
    await loadPolicies(deps)
    expect(adapter).toHaveBeenCalledTimes(1)
  })

  it('single-flights concurrent callers (one adapter call, both get the same value)', async () => {
    let resolveAdapter!: (v: IamAccessControl.IPolicy[]) => void
    const adapterPromise = new Promise<IamAccessControl.IPolicy[]>((r) => {
      resolveAdapter = r
    })
    deps.adapter.listPolicies = vi.fn(() => adapterPromise)
    const p1 = loadPolicies(deps)
    const p2 = loadPolicies(deps)
    expect(deps.adapter.listPolicies).toHaveBeenCalledTimes(1)
    resolveAdapter([{ id: 'x', name: 'x', algorithm: 'deny-overrides' as const, rules: [] }])
    const [a, b] = await Promise.all([p1, p2])
    expect(a).toBe(b)
  })

  it('throws when the adapter returns more than maxPolicies', async () => {
    deps.maxPolicies = 1
    deps.adapter.listPolicies = async () => [
      { id: 'a', name: 'a', algorithm: 'deny-overrides' as const, rules: [] },
      { id: 'b', name: 'b', algorithm: 'deny-overrides' as const, rules: [] },
    ]
    await expect(loadPolicies(deps)).rejects.toThrow(/maxPolicies is 1/)
  })

  it('mid-flight cache clear is honored: produce resolves but cache stays empty', async () => {
    let resolveAdapter!: (v: IamAccessControl.IPolicy[]) => void
    const adapterPromise = new Promise<IamAccessControl.IPolicy[]>((r) => {
      resolveAdapter = r
    })
    deps.adapter.listPolicies = () => adapterPromise
    const pending = loadPolicies(deps)
    await Promise.resolve()
    // Mid-flight: clear the in-flight slot (mimics an invalidate).
    deps.inFlight.policies.value = null
    deps.policyCache.clear()
    resolveAdapter([{ id: 'p', name: 'p', algorithm: 'deny-overrides' as const, rules: [] }])
    await pending
    expect(deps.policyCache.get('all')).toBeUndefined()
  })
})

describe('loadRoles', () => {
  it('caches roles under "all"', async () => {
    const roles: IamAccessControl.IRole[] = [{ id: 'admin', name: 'admin', permissions: [] }]
    const deps = makeDeps()
    deps.adapter.listRoles = async () => roles
    await loadRoles(deps)
    expect(deps.roleCache.get('all')).toEqual(roles)
  })

  it('throws when the adapter returns more than maxRoles', async () => {
    const deps = makeDeps({ maxRoles: 1 })
    deps.adapter.listRoles = async () => [
      { id: 'a', name: 'a', permissions: [] },
      { id: 'b', name: 'b', permissions: [] },
    ]
    await expect(loadRoles(deps)).rejects.toThrow(/maxRoles is 1/)
  })
})

describe('loadRbacPolicy', () => {
  it('builds + caches a deep-frozen RBAC policy from roles', async () => {
    const deps = makeDeps()
    deps.adapter.listRoles = async () => [
      { id: 'viewer', name: 'viewer', permissions: [{ action: 'read', resource: 'post' }] },
    ]
    const policy = await loadRbacPolicy(deps)
    expect(Object.isFrozen(policy)).toBe(true)
    expect(deps.rbacPolicyCache.get('rbac')).toBe(policy)
  })

  it('returns the cached policy on the second call', async () => {
    const deps = makeDeps()
    const adapter = vi.fn(async () => [])
    deps.adapter.listRoles = adapter
    await loadRbacPolicy(deps)
    await loadRbacPolicy(deps)
    expect(adapter).toHaveBeenCalledTimes(1)
  })
})

describe('loadAllPolicies', () => {
  it('merges user policies with the synthesised RBAC policy when RBAC has rules', async () => {
    const deps = makeDeps()
    deps.adapter.listPolicies = async () => [
      { id: 'user', name: 'user', algorithm: 'deny-overrides' as const, rules: [] },
    ]
    deps.adapter.listRoles = async () => [
      { id: 'viewer', name: 'viewer', permissions: [{ action: 'read', resource: 'post' }] },
    ]
    const merged = await loadAllPolicies(deps)
    expect(merged.length).toBe(2)
    expect(merged[0]?.id).not.toBe('user') // rbac prefixed
  })

  it('omits the RBAC policy when it has no rules (avoids default-deny under AND combine)', async () => {
    const deps = makeDeps()
    deps.adapter.listPolicies = async () => [
      { id: 'user', name: 'user', algorithm: 'deny-overrides' as const, rules: [] },
    ]
    deps.adapter.listRoles = async () => []
    const merged = await loadAllPolicies(deps)
    expect(merged.length).toBe(1)
    expect(merged[0]?.id).toBe('user')
  })

  it('caches the merged result under "merged"', async () => {
    const deps = makeDeps()
    await loadAllPolicies(deps)
    expect(deps.mergedPolicyCache.get('merged')).toBeDefined()
  })
})

describe('resolveSubject', () => {
  it('builds a IamRequest.ISubject from adapter calls', async () => {
    const deps = makeDeps()
    deps.adapter.getSubjectRoles = async () => ['admin']
    deps.adapter.getSubjectAttributes = async () => ({ dept: 'eng' })
    deps.adapter.listRoles = async () => [{ id: 'admin', name: 'admin', permissions: [] }]
    const subject = await resolveSubject(deps, 's-1')
    expect(subject.id).toBe('s-1')
    expect(subject.roles).toContain('admin')
    expect(subject.attributes.dept).toBe('eng')
  })

  it('caches per-subjectId', async () => {
    const deps = makeDeps()
    const getRoles = vi.fn(async () => [])
    deps.adapter.getSubjectRoles = getRoles
    await resolveSubject(deps, 's-1')
    await resolveSubject(deps, 's-1')
    expect(getRoles).toHaveBeenCalledTimes(1)
  })

  it('different subjectIds bypass each other in the cache', async () => {
    const deps = makeDeps()
    const getRoles = vi.fn(async () => [])
    deps.adapter.getSubjectRoles = getRoles
    await resolveSubject(deps, 's-1')
    await resolveSubject(deps, 's-2')
    expect(getRoles).toHaveBeenCalledTimes(2)
  })

  it('reads scoped roles when adapter supports them', async () => {
    const deps = makeDeps()
    deps.adapter.getSubjectScopedRoles = async () => [{ scope: 'org-1', role: 'admin' }]
    const subject = await resolveSubject(deps, 's-1')
    expect(subject.scopedRoles).toEqual([{ scope: 'org-1', role: 'admin' }])
  })
})
