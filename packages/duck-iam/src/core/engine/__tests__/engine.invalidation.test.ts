import { describe, expect, it, vi } from 'vitest'
import { IamLRUCache } from '../../../shared/cache'
import type { IamAccessControl, IamRequest } from '../../types'
import {
  applyInvalidateEvent,
  type IEngineCacheBag,
  invalidateAll,
  invalidatePolicies,
  invalidateRoles,
  invalidateSubject,
} from '../engine.invalidation'
import type { IamEngineTypes } from '../engine.types'

type Role = 'admin' | 'viewer'

function makeBag(invalidator?: IamEngineTypes.IInvalidator<Role>): IEngineCacheBag<Role> {
  return {
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
    ...(invalidator !== undefined && { invalidator }),
  }
}

describe('invalidateAll', () => {
  it('clears every cache + every in-flight slot', () => {
    const bag = makeBag()
    bag.policyCache.set('all', [])
    bag.roleCache.set('all', [])
    bag.rbacPolicyCache.set('rbac', { id: 'rbac', name: 'rbac', algorithm: 'deny-overrides' as const, rules: [] })
    bag.mergedPolicyCache.set('merged', [])
    bag.subjectCache.set('s', { id: 's', roles: [], attributes: {} })
    bag.inFlight.policies.value = Promise.resolve([])
    bag.inFlight.subjects.set('s', Promise.resolve({ id: 's', roles: [], attributes: {} }))

    invalidateAll(bag, {})

    expect(bag.policyCache.get('all')).toBeUndefined()
    expect(bag.roleCache.get('all')).toBeUndefined()
    expect(bag.rbacPolicyCache.get('rbac')).toBeUndefined()
    expect(bag.mergedPolicyCache.get('merged')).toBeUndefined()
    expect(bag.subjectCache.get('s')).toBeUndefined()
    expect(bag.inFlight.policies.value).toBeNull()
    expect(bag.inFlight.subjects.size).toBe(0)
  })

  it('publishes a broadcast unless opts.broadcast === false', () => {
    const publish = vi.fn(async () => {})
    const bag = makeBag({ publish, subscribe: () => () => {} })
    invalidateAll(bag, {})
    expect(publish).toHaveBeenCalledWith({ kind: 'all' })
    publish.mockReset()
    invalidateAll(bag, { broadcast: false })
    expect(publish).not.toHaveBeenCalled()
  })
})

describe('invalidateSubject', () => {
  it('clears only the targeted subject', () => {
    const bag = makeBag()
    bag.subjectCache.set('a', { id: 'a', roles: [], attributes: {} })
    bag.subjectCache.set('b', { id: 'b', roles: [], attributes: {} })
    invalidateSubject(bag, 'a', {})
    expect(bag.subjectCache.get('a')).toBeUndefined()
    expect(bag.subjectCache.get('b')).toBeDefined()
  })

  it('no-ops on invalid subjectId (non-string / empty / oversize)', () => {
    const bag = makeBag()
    bag.subjectCache.set('a', { id: 'a', roles: [], attributes: {} })
    invalidateSubject(bag, '', {})
    invalidateSubject(bag, 'x'.repeat(2000), {})
    expect(bag.subjectCache.get('a')).toBeDefined()
  })
})

describe('invalidatePolicies', () => {
  it('clears policyCache + mergedPolicyCache + their in-flight slots but leaves roles', () => {
    const bag = makeBag()
    bag.policyCache.set('all', [])
    bag.mergedPolicyCache.set('merged', [])
    bag.roleCache.set('all', [])
    bag.rbacPolicyCache.set('rbac', { id: 'rbac', name: 'rbac', algorithm: 'deny-overrides' as const, rules: [] })
    invalidatePolicies(bag, {})
    expect(bag.policyCache.get('all')).toBeUndefined()
    expect(bag.mergedPolicyCache.get('merged')).toBeUndefined()
    expect(bag.roleCache.get('all')).toBeDefined()
    expect(bag.rbacPolicyCache.get('rbac')).toBeDefined()
  })
})

describe('invalidateRoles', () => {
  it('without roleId: clears every subject + role cache', () => {
    const bag = makeBag()
    bag.subjectCache.set('a', { id: 'a', roles: ['admin'], attributes: {} })
    bag.subjectCache.set('b', { id: 'b', roles: ['viewer'], attributes: {} })
    invalidateRoles(bag, undefined, {})
    expect(bag.subjectCache.get('a')).toBeUndefined()
    expect(bag.subjectCache.get('b')).toBeUndefined()
  })

  it('with roleId: clears only subjects holding that role', () => {
    const bag = makeBag()
    bag.subjectCache.set('a', { id: 'a', roles: ['admin'], attributes: {} })
    bag.subjectCache.set('b', { id: 'b', roles: ['viewer'], attributes: {} })
    invalidateRoles(bag, 'admin', {})
    expect(bag.subjectCache.get('a')).toBeUndefined()
    expect(bag.subjectCache.get('b')).toBeDefined()
  })

  it('clears subjects whose scopedRoles include the role', () => {
    const bag = makeBag()
    bag.subjectCache.set('a', {
      id: 'a',
      roles: [],
      attributes: {},
      scopedRoles: [{ scope: 'org-1', role: 'admin' }],
    })
    bag.subjectCache.set('b', { id: 'b', roles: [], attributes: {} })
    invalidateRoles(bag, 'admin', {})
    expect(bag.subjectCache.get('a')).toBeUndefined()
    expect(bag.subjectCache.get('b')).toBeDefined()
  })

  it('invalid roleId (non-string / empty / oversize) falls back to clear-all', () => {
    const bag = makeBag()
    bag.subjectCache.set('a', { id: 'a', roles: ['admin'], attributes: {} })
    bag.subjectCache.set('b', { id: 'b', roles: ['viewer'], attributes: {} })
    invalidateRoles(bag, 'x'.repeat(2000) as Role, {})
    expect(bag.subjectCache.get('a')).toBeUndefined()
    expect(bag.subjectCache.get('b')).toBeUndefined()
  })
})

describe('applyInvalidateEvent', () => {
  it('dispatches by event.kind', () => {
    const bag = makeBag()
    bag.subjectCache.set('a', { id: 'a', roles: [], attributes: {} })
    applyInvalidateEvent(bag, { kind: 'subject', subjectId: 'a' })
    expect(bag.subjectCache.get('a')).toBeUndefined()
  })

  it('"all" event clears everything', () => {
    const bag = makeBag()
    bag.policyCache.set('all', [])
    applyInvalidateEvent(bag, { kind: 'all' })
    expect(bag.policyCache.get('all')).toBeUndefined()
  })

  it('does not re-broadcast when applying a remote event', () => {
    const publish = vi.fn(async () => {})
    const bag = makeBag({ publish, subscribe: () => () => {} })
    applyInvalidateEvent(bag, { kind: 'policies' })
    expect(publish).not.toHaveBeenCalled()
  })
})
