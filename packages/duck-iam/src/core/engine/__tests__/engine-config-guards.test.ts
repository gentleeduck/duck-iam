import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamError, metaOf } from '../../errors'
import { IamEngine } from '../engine'

// Matches the empty-adapter fixture pattern from compiled.boundary.test.ts: roles/policies live on the
// adapter, never on the engine config, so `base` only needs a working adapter plus the fields under test.
const adapter = new IamMemoryAdapter({ roles: [], policies: [], assignments: {}, attributes: {} })
const base = { adapter, defaultEffect: 'deny' as const, mode: 'production' as const }

describe('single-field config guards throw IAM_ENGINE_INVALID_CONFIG', () => {
  it.each([
    ['mode', { mode: 'prodution' as never }],
    ['scopeMode', { scopeMode: 'nested' as never }],
    ['scopeCombine', { scopeCombine: 'overide' as never }],
    ['policyCombine', { policyCombine: 'bogus' as never }],
  ])('field %s', (field, override) => {
    try {
      new IamEngine({ ...base, ...override })
      expect.unreachable()
    } catch (err) {
      expect(err).toBeInstanceOf(IamError)
      const meta = metaOf(err as IamError<'IAM_ENGINE_INVALID_CONFIG'>, 'IAM_ENGINE_INVALID_CONFIG')
      expect(meta.field).toBe(field)
    }
  })

  it.each([
    ['maxPolicies', { maxPolicies: 0 }],
    ['maxPolicies', { maxPolicies: Number.NaN }],
    ['maxRoles', { maxRoles: -1 }],
    ['adapterTimeoutMs', { adapterTimeoutMs: -5 }],
    ['hookTimeoutMs', { hookTimeoutMs: Number.POSITIVE_INFINITY }],
    ['maxConcurrentSubjectLoads', { maxConcurrentSubjectLoads: -1 }],
  ])('numeric field %s', (field, override) => {
    try {
      new IamEngine({ ...base, ...override })
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_ENGINE_INVALID_CONFIG'>, 'IAM_ENGINE_INVALID_CONFIG')
      expect(meta.field).toBe(field)
      expect(meta.got).toBe(override[field as keyof typeof override])
    }
  })
})

describe('cross-field config guards keep their own codes', () => {
  it('IAM_ENGINE_POLICY_COMBINE_INCOMPATIBLE for first-applicable in production', () => {
    try {
      new IamEngine({ ...base, mode: 'production', policyCombine: 'first-applicable' })
      expect.unreachable()
    } catch (err) {
      expect((err as IamError).code).toBe('IAM_ENGINE_POLICY_COMBINE_INCOMPATIBLE')
    }
  })

  it('first-applicable is fine in development', () => {
    expect(() => new IamEngine({ ...base, mode: 'development', policyCombine: 'first-applicable' })).not.toThrow()
  })

  it('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED for defaultEffect allow without the opt-in', () => {
    try {
      new IamEngine({ ...base, defaultEffect: 'allow' })
      expect.unreachable()
    } catch (err) {
      expect((err as IamError).code).toBe('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED')
    }
  })

  it('allowFailOpen: true confirms the intent', () => {
    expect(() => new IamEngine({ ...base, defaultEffect: 'allow', allowFailOpen: true })).not.toThrow()
  })
})
