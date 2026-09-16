import { describe, expect, it, vi } from 'vitest'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import { compileTable } from '../../engine/compiled/compiled.compile'
import { lookup } from '../../engine/compiled/compiled.lookup'
import { IAM_RBAC_POLICY_ID } from '../../rbac/rbac'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast } from '../evaluate'

// Error hooks run inside the catch that casts the Indeterminate vote; a throwing hook (say, a metrics backend
// that is down) must not unwind that vote.
const OVERSIZED = 'curl'.padEnd(MAX_REGEX_INPUT_LENGTH + 1, 'x')

function request(userAgent: string): IamRequest.IAccessRequest {
  return {
    subject: { id: 'u1', roles: [], attributes: {} },
    action: 'read',
    resource: { type: 'post', attributes: {} },
    environment: { userAgent },
  }
}

const allowAll: AccessControl.IPolicy = {
  id: 'p-allow',
  name: 'allow',
  algorithm: 'first-match',
  rules: [
    { id: 'r-allow', effect: 'allow', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [] } },
  ],
}

/** `matches` throws on an input past `MAX_REGEX_INPUT_LENGTH`. */
const denyBots: AccessControl.IPolicy = {
  id: 'p-deny-bots',
  name: 'deny bots',
  algorithm: 'first-match',
  rules: [
    {
      id: 'r-deny',
      effect: 'deny',
      priority: 10,
      actions: ['*'],
      resources: ['*'],
      conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
    },
  ],
}

const boom = (): never => {
  throw new Error('hook backend unreachable')
}

describe('a throwing onPolicyError does not unwind the evaluation', () => {
  it('interpreter: still returns the Indeterminate deny', () => {
    const onPolicyError = vi.fn(boom)
    const decision = evaluate([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', onPolicyError)
    expect(decision.allowed).toBe(false)
    expect(onPolicyError).toHaveBeenCalledOnce()
  })

  it('fast path: still returns the Indeterminate deny', () => {
    const onPolicyError = vi.fn(boom)
    expect(evaluateFast([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', onPolicyError)).toBe(false)
    expect(onPolicyError).toHaveBeenCalledOnce()
  })

  // Through `lookup`, not `engine.can`, whose own catch answers `false` for any throw and would hide the escape.
  it('compiled lookup: still casts the Indeterminate deny vote', () => {
    const onPolicyError = vi.fn(boom)
    const table = compileTable([], [allowAll, denyBots], 'and')
    expect(lookup(table, 0, 'read', 'post', request(OVERSIZED), 'deny', onPolicyError)).toBe(false)
    expect(onPolicyError).toHaveBeenCalled()
  })
})

describe('a throwing onRuleError does not unwind the evaluation', () => {
  // `evaluate` passes `onPolicyError` down as the rule-level reporter, so a throwing hook must not turn an
  // abstaining RBAC rule into a rethrow.
  it('interpreter: an allow-only RBAC rule that throws still abstains', () => {
    const rbac: AccessControl.IPolicy = {
      id: IAM_RBAC_POLICY_ID,
      name: 'rbac',
      algorithm: 'first-match',
      rules: [
        {
          id: 'r-rbac-throws',
          effect: 'allow',
          priority: 1,
          actions: ['*'],
          resources: ['*'],
          conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
        },
      ],
    }
    const onPolicyError = vi.fn(boom)
    const decision = evaluate([rbac], request(OVERSIZED), 'deny', 'and', onPolicyError)
    expect(decision.allowed).toBe(false)
    expect(onPolicyError).toHaveBeenCalled()
  })
})

// A hook failure is how an operator learns evaluation is throwing, so another engine's broken hook must not silence it.
describe('the broken-hook report is latched per hook, not per process', () => {
  it('reports each throwing hook once, and reports a second hook too', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const reportsFor = (marker: string): number =>
        errorSpy.mock.calls.filter((c: unknown[]) =>
          c.some((arg) => arg instanceof Error && arg.message.includes(marker)),
        ).length

      const hookA = vi.fn(() => {
        throw new Error('backend-A-down')
      })
      const hookB = vi.fn(() => {
        throw new Error('backend-B-down')
      })

      evaluate([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', hookA)
      evaluate([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', hookA)
      // Latched: the second evaluation calls the hook again and swallows again,
      // but says so only once.
      expect(hookA.mock.calls.length).toBeGreaterThan(1)
      expect(reportsFor('backend-A-down')).toBe(1)

      // A different hook has its own budget.
      evaluate([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', hookB)
      expect(reportsFor('backend-B-down')).toBe(1)
    } finally {
      errorSpy.mockRestore()
    }
  })

  it('does not build an Error when no hook is wired', () => {
    // With no reporter `safeErrorReport` returns early; observable only as the decision staying the Indeterminate deny.
    expect(evaluate([allowAll, denyBots], request(OVERSIZED), 'deny', 'and').allowed).toBe(false)
  })
})
