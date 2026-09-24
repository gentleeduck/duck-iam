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
  it('a build parked past the limit, invalidated mid-flight, returns null rather than latching a stale count', async () => {
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
