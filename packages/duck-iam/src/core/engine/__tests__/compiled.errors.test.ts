import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamError, metaOf } from '../../errors'
import type { AccessControl } from '../../types'
import { compileTable } from '../compiled/compiled.compile'
import { IamEngine } from '../engine'

describe('compileTable throws IAM_ROLE_LIMIT_EXCEEDED past the role cap', () => {
  it('33 roles (one past IAM_MAX_COMPILED_ROLES = 32)', () => {
    const roles: AccessControl.IRole[] = Array.from({ length: 33 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: [],
    }))
    try {
      compileTable(roles, [], 'and')
      expect.unreachable()
    } catch (err) {
      expect(err).toBeInstanceOf(IamError)
      const meta = metaOf(err as IamError<'IAM_ROLE_LIMIT_EXCEEDED'>, 'IAM_ROLE_LIMIT_EXCEEDED')
      expect(meta).toEqual({ roleCount: 33, limit: 32 })
    }
  })

  it('exactly 32 roles still compiles (unchanged boundary from compiled.boundary.test.ts)', () => {
    const roles: AccessControl.IRole[] = Array.from({ length: 32 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: [],
    }))
    expect(() => compileTable(roles, [], 'and')).not.toThrow()
  })
})

describe('compileTable throws IAM_POLICY_COMPILE_FAILED for a shape it cannot walk', () => {
  it('rules missing entirely', () => {
    const policy = { id: 'p1', name: 'P1', algorithm: 'deny-overrides' } as unknown as AccessControl.IPolicy
    try {
      compileTable([], [policy], 'and')
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_POLICY_COMPILE_FAILED'>, 'IAM_POLICY_COMPILE_FAILED')
      expect(meta.policyId).toBe('p1')
      expect(meta.detail).toBe('`rules` is missing or not an array')
    }
  })

  it('a rule missing "actions"', () => {
    const policy: AccessControl.IPolicy = {
      id: 'p2',
      name: 'P2',
      algorithm: 'deny-overrides',
      rules: [{ id: 'r1', effect: 'allow', priority: 0, resources: ['doc'] } as never],
    }
    try {
      compileTable([], [policy], 'and')
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_POLICY_COMPILE_FAILED'>, 'IAM_POLICY_COMPILE_FAILED')
      expect(meta.policyId).toBe('p2')
      expect(meta.detail).toBe('rule "r1": `actions` is not an array')
    }
  })
})

describe('IamEngine: the role-limit fallback respects the compiled-table generation guard', () => {
  it('genuinely over the limit: falls back to the interpreter and healthCheck reports the degradation', async () => {
    const roles: AccessControl.IRole[] = Array.from({ length: 33 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: i === 0 ? [{ action: 'read', resource: 'doc' }] : [],
    }))
    const adapter = new IamMemoryAdapter({
      roles,
      policies: [],
      assignments: { holder: ['role-0'] },
      attributes: { holder: {} },
    })
    const engine = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    // First call falls back to the interpreter rather than throwing out of check().
    expect(await engine.can('holder', 'read', { type: 'doc', attributes: {} })).toBe(true)
    // healthCheck reports the degradation via IAM_ROLE_LIMIT_EXCEEDED's carried limit/roleCount, not a thrown error.
    const health = await engine.healthCheck()
    expect(health.compiledTable).toMatchObject({ available: false, limit: 32, reason: 'role-limit-exceeded' })
  })

  it('a stale over-limit snapshot resolving after invalidation does not latch the interpreter fallback', async () => {
    // The *current* state, 32 roles - under the limit - once the invalidation below has landed.
    const currentRoles: AccessControl.IRole[] = Array.from({ length: 32 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: i === 0 ? [{ action: 'read', resource: 'doc' }] : [],
    }))
    // A stale snapshot the store had already started answering with before role-32 (never assigned to anyone,
    // so invalidating it below cannot evict `holder`'s cached subject data) was added.
    const staleRoles: AccessControl.IRole[] = [...currentRoles, { id: 'role-32', name: 'Role 32', permissions: [] }]
    const realAdapter = new IamMemoryAdapter({
      roles: currentRoles,
      policies: [],
      assignments: { holder: ['role-0'] },
      attributes: { holder: {} },
    })

    let listRolesCalls = 0
    let armed = false
    let armedCalls = 0
    let releaseGate!: () => void
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve
    })
    let signalArmedCallStarted!: () => void
    const armedCallStarted = new Promise<void>((resolve) => {
      signalArmedCallStarted = resolve
    })
    // Passes every call through to the real adapter except the first one made once armed, which parks on the
    // gate and then hands back the stale, over-limit snapshot.
    const adapter = new Proxy(realAdapter, {
      get(target, prop, receiver) {
        if (prop !== 'listRoles') return Reflect.get(target, prop, receiver)
        return async (opts?: unknown) => {
          listRolesCalls++
          if (armed) {
            armedCalls++
            if (armedCalls === 1) {
              signalArmedCallStarted()
              await gate
              return staleRoles
            }
          }
          return (Reflect.get(target, prop, receiver) as typeof target.listRoles).call(target, opts as never)
        }
      },
    })
    const engine = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })

    // Warms the compiled table, the role cache and `holder`'s subject cache, all at generation 0.
    expect(await engine.can('holder', 'read', { type: 'doc', attributes: {} })).toBe(true)

    // Invalidates a role nothing is assigned to: clears the role cache and bumps the generation, but
    // `holder`'s cached roles don't reach role-31, so its subject-cache entry survives - the next can() call
    // resolves its subject from cache and goes straight to a compiled-table rebuild.
    engine.cache.invalidateRoles('role-31')

    armed = true
    // This rebuild's listRoles() call is the one that gets gated; it captures genAtStart before parking.
    const secondCheck = engine.can('holder', 'read', { type: 'doc', attributes: {} })
    await armedCallStarted
    // Lands while that build is still parked: bumps the generation the parked build started under.
    engine.cache.invalidateRoles()
    // Only now does the parked call resolve, with data the invalidation above already superseded.
    releaseGate()
    // The interpreter still answers the in-flight request while the stale build fails behind it.
    expect(await secondCheck).toBe(true)

    // A fresh build, current generation: the real, 32-role snapshot, under the limit, compiles cleanly.
    const health = await engine.healthCheck()
    // Guarded: the stale throw never latched. Without the generation guard this would instead be
    // `{ available: false, limit: 32, reason: 'role-limit-exceeded', roleCount: 33 }` forever after, since only
    // another role invalidation clears the latch, and a successful rebuild does not.
    expect(health.compiledTable).toBeUndefined()
  })
})

describe('IamEngine: IAM_POLICY_COMPILE_FAILED reaches onPolicyError, still typed, then fails closed', () => {
  it('carries a real IamError and the policy id to the hook, and denies rather than rejecting can()', async () => {
    // `can()` never rejects (its own doc comment: "an invalid subjectId or a failed subject load returns false,
    // never a rejection"), so a compile failure is exactly the fail-closed path onError/onPolicyError exist for.
    const policy = { id: 'bad', name: 'Bad', algorithm: 'deny-overrides' } as unknown as AccessControl.IPolicy
    const adapter = new IamMemoryAdapter({ roles: [], policies: [policy], assignments: {}, attributes: {} })
    let reportedErr: Error | undefined
    let reportedId: string | undefined
    const engine = new IamEngine({
      adapter,
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err, policyId) => ((reportedErr = err), (reportedId = policyId)) },
    })
    expect(await engine.can('anyone', 'read', { type: 'doc', attributes: {} })).toBe(false)
    expect(reportedErr).toBeInstanceOf(IamError)
    expect(metaOf(reportedErr as IamError<'IAM_POLICY_COMPILE_FAILED'>, 'IAM_POLICY_COMPILE_FAILED').policyId).toBe(
      'bad',
    )
    expect(reportedId).toBe('bad')
  })
})
