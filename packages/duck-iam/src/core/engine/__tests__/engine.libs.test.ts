import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { deepFreezePolicy, ensureEnvNow, runSingleFlight, runSingleFlightKeyed, scopeAncestors } from '../engine.libs'

function request(
  environment?: IamRequest.IAccessRequest['environment'],
): IamRequest.IAccessRequest<string, string, string> {
  return {
    action: 'read',
    environment,
    resource: { attributes: {}, type: 'post' },
    subject: { attributes: {}, id: 'user-1', roles: [] },
  }
}

describe('ensureEnvNow', () => {
  it('injects a real clock when environment is absent', () => {
    const before = Date.now()
    const out = ensureEnvNow(request())
    expect(typeof out.environment?.now).toBe('number')
    expect(out.environment?.now).toBeGreaterThanOrEqual(before)
  })

  it('injects a clock while preserving other environment keys', () => {
    const out = ensureEnvNow(request({ ip: '1.2.3.4' }))
    expect(out.environment?.ip).toBe('1.2.3.4')
    expect(typeof out.environment?.now).toBe('number')
  })

  it('returns the SAME request object when now is already set (no allocation)', () => {
    const req = request({ now: 42 })
    expect(ensureEnvNow(req)).toBe(req)
  })

  it('never overwrites an explicit now, including now: 0', () => {
    expect(ensureEnvNow(request({ now: 0 })).environment?.now).toBe(0)
  })

  it('does not mutate the input request', () => {
    const req = request()
    ensureEnvNow(req)
    expect(req.environment).toBeUndefined()
  })
})

describe('scopeAncestors', () => {
  it('returns the scope itself when there is no dot', () => {
    expect(scopeAncestors('org-1')).toEqual(['org-1'])
  })

  it('walks every ancestor prefix, most specific first', () => {
    expect(scopeAncestors('org-1.team-2.repo-3')).toEqual(['org-1.team-2.repo-3', 'org-1.team-2', 'org-1'])
  })

  it('handles an empty scope', () => {
    expect(scopeAncestors('')).toEqual([''])
  })

  it('keeps empty segments produced by a trailing or doubled dot', () => {
    expect(scopeAncestors('org-1.')).toEqual(['org-1.', 'org-1'])
    expect(scopeAncestors('a..b')).toEqual(['a..b', 'a.', 'a'])
  })
})

function policy(overrides: Partial<AccessControl.IPolicy> = {}): AccessControl.IPolicy {
  return {
    algorithm: 'deny-overrides',
    id: 'p1',
    name: 'p1',
    rules: [
      {
        actions: ['read'],
        conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'user-1' }] },
        effect: 'allow',
        id: 'r1',
        priority: 0,
        resources: ['post'],
      },
    ],
    ...overrides,
  }
}

type Branch = readonly (AccessControl.ICondition | AccessControl.IConditionGroup)[]

/** Narrows to the named branch and returns the ORIGINAL array (freeze identity matters here). */
function branch(group: AccessControl.IConditionGroup | undefined, key: 'all' | 'any' | 'none'): Branch {
  if (group === undefined || !(key in group)) {
    throw new Error(`expected a "${key}" condition group, got ${JSON.stringify(group)}`)
  }
  if (key === 'all' && 'all' in group) return group.all
  if (key === 'any' && 'any' in group) return group.any
  if (key === 'none' && 'none' in group) return group.none
  throw new Error(`unreachable: "${key}" branch missing after the guard`)
}

function nestedGroup(entry: AccessControl.ICondition | AccessControl.IConditionGroup | undefined) {
  if (entry === undefined || 'field' in entry) throw new Error('expected a nested condition group, got a leaf')
  return entry
}

describe('deepFreezePolicy', () => {
  it('freezes the policy, its rules array, and each rule', () => {
    const p = deepFreezePolicy(policy())
    expect(Object.isFrozen(p)).toBe(true)
    expect(Object.isFrozen(p.rules)).toBe(true)
    expect(Object.isFrozen(p.rules[0])).toBe(true)
  })

  it('freezes the actions and resources arrays on each rule', () => {
    const p = deepFreezePolicy(policy())
    expect(Object.isFrozen(p.rules[0]?.actions)).toBe(true)
    expect(Object.isFrozen(p.rules[0]?.resources)).toBe(true)
  })

  it('freezes the condition group and its leaves', () => {
    const p = deepFreezePolicy(policy())
    const conditions = p.rules[0]?.conditions
    const all = branch(conditions, 'all')
    expect(Object.isFrozen(conditions)).toBe(true)
    expect(Object.isFrozen(all)).toBe(true)
    expect(Object.isFrozen(all[0])).toBe(true)
  })

  it('recurses into nested condition groups under any/none', () => {
    const p = deepFreezePolicy(
      policy({
        rules: [
          {
            actions: ['read'],
            conditions: {
              any: [
                { field: 'subject.id', operator: 'eq', value: 'a' },
                { none: [{ field: 'subject.id', operator: 'eq', value: 'b' }] },
              ],
            },
            effect: 'allow',
            id: 'r1',
            priority: 0,
            resources: ['post'],
          },
        ],
      }),
    )
    const any = branch(p.rules[0]?.conditions, 'any')
    const nested = nestedGroup(any[1])
    const none = branch(nested, 'none')
    expect(Object.isFrozen(any)).toBe(true)
    expect(Object.isFrozen(nested)).toBe(true)
    expect(Object.isFrozen(none)).toBe(true)
    expect(Object.isFrozen(none[0])).toBe(true)
  })

  it('returns the same object reference it was given', () => {
    const p = policy()
    expect(deepFreezePolicy(p)).toBe(p)
  })

  it('handles a policy with no rules', () => {
    const p = deepFreezePolicy(policy({ rules: [] }))
    expect(Object.isFrozen(p)).toBe(true)
    expect(Object.isFrozen(p.rules)).toBe(true)
  })
})

describe('runSingleFlight', () => {
  function slot<T>() {
    const state: { value: Promise<T> | null } = { value: null }
    return {
      get: () => state.value,
      set: (p: Promise<T> | null) => {
        state.value = p
      },
      state,
    }
  }

  it('stores the pending promise in the slot before resolving', () => {
    const s = slot<number>()
    const p = runSingleFlight(
      s.get,
      s.set,
      async () => 1,
      () => {},
    )
    expect(s.state.value).toBe(p)
  })

  it('calls onResolve with the produced value and clears the slot', async () => {
    const s = slot<number>()
    const seen: number[] = []
    await runSingleFlight(
      s.get,
      s.set,
      async () => 7,
      (v) => seen.push(v),
    )
    expect(seen).toEqual([7])
    expect(s.state.value).toBeNull()
  })

  it('coalesces concurrent callers onto one producer call', async () => {
    const s = slot<number>()
    let calls = 0
    const produce = async () => {
      calls++
      await Promise.resolve()
      return 5
    }
    const a = runSingleFlight(s.get, s.set, produce, () => {})
    const b = s.get() ?? a
    expect(b).toBe(a)
    expect(await a).toBe(5)
    expect(calls).toBe(1)
  })

  it('does NOT call onResolve when the slot was cleared mid-flight (stale write guard)', async () => {
    const s = slot<number>()
    const seen: number[] = []
    const p = runSingleFlight(
      s.get,
      s.set,
      async () => {
        await Promise.resolve()
        return 3
      },
      (v) => seen.push(v),
    )
    s.set(null)
    await p
    expect(seen).toEqual([])
  })

  it('does not clobber a NEWER in-flight promise when the stale one settles', async () => {
    const s = slot<number>()
    const stale = runSingleFlight(
      s.get,
      s.set,
      async () => {
        await Promise.resolve()
        return 1
      },
      () => {},
    )
    const fresh = Promise.resolve(2)
    s.set(fresh)
    await stale
    expect(s.state.value).toBe(fresh)
  })

  it('propagates a producer rejection and still clears the slot', async () => {
    const s = slot<number>()
    const seen: number[] = []
    await expect(
      runSingleFlight(
        s.get,
        s.set,
        async () => {
          throw new Error('boom')
        },
        (v) => seen.push(v),
      ),
    ).rejects.toThrow('boom')
    expect(seen).toEqual([])
    expect(s.state.value).toBeNull()
  })
})

describe('runSingleFlightKeyed', () => {
  it('stores the pending promise under the key and deletes it on settle', async () => {
    const map = new Map<string, Promise<number>>()
    const p = runSingleFlightKeyed(
      map,
      'k',
      async () => 1,
      () => {},
    )
    expect(map.get('k')).toBe(p)
    await p
    expect(map.has('k')).toBe(false)
  })

  it('calls onResolve with the produced value', async () => {
    const map = new Map<string, Promise<number>>()
    const seen: number[] = []
    await runSingleFlightKeyed(
      map,
      'k',
      async () => 9,
      (v) => seen.push(v),
    )
    expect(seen).toEqual([9])
  })

  it('keeps distinct keys independent', async () => {
    const map = new Map<string, Promise<string>>()
    const a = runSingleFlightKeyed(
      map,
      'a',
      async () => 'A',
      () => {},
    )
    const b = runSingleFlightKeyed(
      map,
      'b',
      async () => 'B',
      () => {},
    )
    expect(map.size).toBe(2)
    expect(await Promise.all([a, b])).toEqual(['A', 'B'])
  })

  it('does NOT call onResolve when the key was evicted mid-flight', async () => {
    const map = new Map<string, Promise<number>>()
    const seen: number[] = []
    const p = runSingleFlightKeyed(
      map,
      'k',
      async () => {
        await Promise.resolve()
        return 4
      },
      (v) => seen.push(v),
    )
    map.delete('k')
    await p
    expect(seen).toEqual([])
  })

  it('does not delete a NEWER entry for the same key when the stale one settles', async () => {
    const map = new Map<string, Promise<number>>()
    const stale = runSingleFlightKeyed(
      map,
      'k',
      async () => {
        await Promise.resolve()
        return 1
      },
      () => {},
    )
    const fresh = Promise.resolve(2)
    map.set('k', fresh)
    await stale
    expect(map.get('k')).toBe(fresh)
  })

  it('propagates a producer rejection and still deletes the key', async () => {
    const map = new Map<string, Promise<number>>()
    await expect(
      runSingleFlightKeyed(
        map,
        'k',
        async () => {
          throw new Error('nope')
        },
        () => {},
      ),
    ).rejects.toThrow('nope')
    expect(map.has('k')).toBe(false)
  })
})
