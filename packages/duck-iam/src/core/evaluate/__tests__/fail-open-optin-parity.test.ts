import { describe, expect, it } from 'vitest'
import { hasIamErrorCode, iamEvaluate, iamEvaluateFast, iamEvaluatePolicy, iamEvaluatePolicyFast } from '../../..'
import type { AccessControl, IamRequest } from '../../types'

// SECURITY: the `allowFailOpen` gate belongs on every public evaluator entry point or none; these tests pin all
// four together so a future export cannot skip it.
const REQUEST: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
}

/** Not applicable to REQUEST, so the decision falls to `defaultEffect`. */
const POLICY: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  id: 'p1',
  name: 'P',
  rules: [
    { actions: ['write'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources: ['other'] },
  ],
}

function throws(fn: () => unknown): unknown {
  try {
    fn()
    throw new Error('expected fn to throw')
  } catch (err) {
    return err
  }
}

function isFootgun(fn: () => unknown): boolean {
  return hasIamErrorCode(throws(fn), 'IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED')
}

describe('fail-open opt-in is required by every public evaluator entry point', () => {
  it('iamEvaluate refuses defaultEffect "allow" without the opt-in', () => {
    expect(isFootgun(() => iamEvaluate([POLICY], REQUEST, 'allow'))).toBe(true)
  })

  it('iamEvaluateFast refuses defaultEffect "allow" without the opt-in', () => {
    expect(isFootgun(() => iamEvaluateFast([POLICY], REQUEST, 'allow'))).toBe(true)
  })

  it('iamEvaluatePolicy refuses defaultEffect "allow" without the opt-in', () => {
    expect(isFootgun(() => iamEvaluatePolicy(POLICY, REQUEST, 'allow'))).toBe(true)
  })

  it('iamEvaluatePolicyFast refuses defaultEffect "allow" without the opt-in', () => {
    expect(isFootgun(() => iamEvaluatePolicyFast(POLICY, REQUEST, 'allow'))).toBe(true)
  })

  it('the single-policy route cannot answer allow for a non-applicable policy without opting in', () => {
    // Ungated, this answers `{ allowed: true, applicable: false }` straight off the package root.
    expect(isFootgun(() => iamEvaluatePolicy(POLICY, REQUEST, 'allow'))).toBe(true)
  })

  it('the opt-in still works on every entry point', () => {
    expect(iamEvaluate([POLICY], REQUEST, 'allow', 'and', undefined, undefined, undefined, true).allowed).toBe(true)
    expect(iamEvaluateFast([POLICY], REQUEST, 'allow', 'and', undefined, undefined, undefined, true)).toBe(true)
    expect(iamEvaluatePolicy(POLICY, REQUEST, 'allow', undefined, undefined, true).allowed).toBe(true)
    expect(iamEvaluatePolicyFast(POLICY, REQUEST, 'allow', undefined, undefined, undefined, true)).not.toBe(false)
  })

  it('defaultEffect "deny" needs no opt-in anywhere', () => {
    expect(() => iamEvaluate([POLICY], REQUEST, 'deny')).not.toThrow()
    expect(() => iamEvaluateFast([POLICY], REQUEST, 'deny')).not.toThrow()
    expect(() => iamEvaluatePolicy(POLICY, REQUEST, 'deny')).not.toThrow()
    expect(() => iamEvaluatePolicyFast(POLICY, REQUEST, 'deny')).not.toThrow()
    expect(iamEvaluatePolicy(POLICY, REQUEST, 'deny').allowed).toBe(false)
  })

  it('omitting defaultEffect defaults to deny and is never a footgun', () => {
    expect(iamEvaluatePolicy(POLICY, REQUEST).allowed).toBe(false)
    expect(iamEvaluate([POLICY], REQUEST).allowed).toBe(false)
  })
})
