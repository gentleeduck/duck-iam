import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamLRUCache } from '../../../shared/cache'
import type { AccessControl, IamAdapter, IamRequest } from '../../types'
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
    policyCache: new IamLRUCache<AccessControl.IPolicy[]>(100, 60_000),
    roleCache: new IamLRUCache<AccessControl.IRole[]>(100, 60_000),
    rbacPolicyCache: new IamLRUCache<AccessControl.IPolicy>(100, 60_000),
    mergedPolicyCache: new IamLRUCache<AccessControl.IPolicy[]>(100, 60_000),
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
    maxConcurrentSubjectLoads: 0,
    withTimeout: (fn) => fn({ signal: new AbortController().signal }),
    ...overrides,
  }
}

/** A promise plus its externally-callable resolver, for controlling adapter-call timing in tests. */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

describe('loadPolicies', () => {
  let deps: IIamLoaderDeps<A, R, Ro, S>
  beforeEach(() => {
    deps = makeDeps()
  })

  it('caches the policy list under "all"', async () => {
    const policies: AccessControl.IPolicy[] = [{ id: 'p', name: 'p', algorithm: 'deny-overrides' as const, rules: [] }]
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
    let resolveAdapter!: (v: AccessControl.IPolicy[]) => void
    const adapterPromise = new Promise<AccessControl.IPolicy[]>((r) => {
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
    let resolveAdapter!: (v: AccessControl.IPolicy[]) => void
    const adapterPromise = new Promise<AccessControl.IPolicy[]>((r) => {
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
    const roles: AccessControl.IRole[] = [{ id: 'admin', name: 'admin', permissions: [] }]
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

  it('tags a role reached through cross-scope inheritance with its OWN scope, not the source assignment scope', async () => {
    const deps = makeDeps()
    deps.adapter.listRoles = async () => [
      {
        id: 'company:superadmin',
        name: 'company superadmin',
        permissions: [],
        scope: 'company',
        inherits: ['marketplace:owner'],
      },
      { id: 'marketplace:owner', name: 'marketplace owner', permissions: [], scope: 'marketplace' },
    ]
    deps.adapter.getSubjectScopedRoles = async () => [{ role: 'company:superadmin', scope: 'company' }]
    const subject = await resolveSubject(deps, 's-1')
    expect(subject.scopedRoles).toContainEqual({ role: 'company:superadmin', scope: 'company' })
    expect(subject.scopedRoles).toContainEqual({ role: 'marketplace:owner', scope: 'marketplace' })
  })

  it('falls back to the assignment row scope for an inherited role with no scope of its own', async () => {
    const deps = makeDeps()
    deps.adapter.listRoles = async () => [
      { id: 'org:admin', name: 'org admin', permissions: [], scope: 'org-1', inherits: ['legacy:base'] },
      // No `scope` field: a generic role with no declared home scope.
      { id: 'legacy:base', name: 'legacy base', permissions: [] },
    ]
    deps.adapter.getSubjectScopedRoles = async () => [{ role: 'org:admin', scope: 'org-1' }]
    const subject = await resolveSubject(deps, 's-1')
    expect(subject.scopedRoles).toContainEqual({ role: 'org:admin', scope: 'org-1' })
    expect(subject.scopedRoles).toContainEqual({ role: 'legacy:base', scope: 'org-1' })
  })
})

describe('resolveSubject: maxConcurrentSubjectLoads cap', () => {
  it('rejects a new subject load once the cap of in-flight loads is reached, without calling the adapter', async () => {
    const deps = makeDeps({ maxConcurrentSubjectLoads: 2 })
    const gate1 = deferred<string[]>()
    const gate2 = deferred<string[]>()
    const getRoles = vi.fn().mockReturnValueOnce(gate1.promise).mockReturnValueOnce(gate2.promise)
    deps.adapter.getSubjectRoles = getRoles

    // Two loads in flight, neither settled yet - fills the cap.
    const p1 = resolveSubject(deps, 's-1')
    const p2 = resolveSubject(deps, 's-2')

    await expect(resolveSubject(deps, 's-3')).rejects.toThrow(/load shed/i)
    expect(getRoles).toHaveBeenCalledTimes(2) // s-3 never reached the adapter

    gate1.resolve([])
    gate2.resolve([])
    await Promise.all([p1, p2])
  })

  it('does not count a call for an already in-flight key against the cap', async () => {
    const deps = makeDeps({ maxConcurrentSubjectLoads: 1 })
    const gate = deferred<string[]>()
    deps.adapter.getSubjectRoles = vi.fn(() => gate.promise)

    const p1 = resolveSubject(deps, 's-1')
    const p2 = resolveSubject(deps, 's-1') // same key, shares the single-flight slot

    gate.resolve(['admin'])
    const [s1, s2] = await Promise.all([p1, p2])
    expect(s1).toEqual(s2)
  })

  it('does not gate a subject already served from cache', async () => {
    const deps = makeDeps({ maxConcurrentSubjectLoads: 1 })
    await resolveSubject(deps, 's-1') // populates the cache, settles immediately
    // Cap is full only while a load is in flight; nothing is in flight here.
    await expect(resolveSubject(deps, 's-1')).resolves.toBeDefined()
  })

  it('0 (default) leaves subject loading unbounded', async () => {
    const deps = makeDeps({ maxConcurrentSubjectLoads: 0 })
    const gates = [deferred<string[]>(), deferred<string[]>(), deferred<string[]>()]
    let call = 0
    deps.adapter.getSubjectRoles = vi.fn(() => gates[call++]!.promise)

    const loads = [resolveSubject(deps, 's-1'), resolveSubject(deps, 's-2'), resolveSubject(deps, 's-3')]
    for (const g of gates) g.resolve([])
    await expect(Promise.all(loads)).resolves.toHaveLength(3)
  })
})
