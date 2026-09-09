import { describe, expect, it, vi } from 'vitest'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import { compileTable } from '../../engine/compiled/compiled.compile'
import { lookup } from '../../engine/compiled/compiled.lookup'
import { IAM_RBAC_POLICY_ID } from '../../rbac/rbac'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast } from '../evaluate'

/**
 * SEC-023. The error hooks - `onPolicyError`, `onRuleError` - are operator code
 * called from inside the catch block that implements the Indeterminate contract.
 * Called raw, a hook that throws propagates *out* of that catch, so the deny
 * vote the catch was about to cast is never cast and the whole evaluation
 * unwinds instead. The engine's own `onPolicyError` site already wraps for
 * exactly this reason (`engine.ts`, the `IamPolicyCompileError` arm); the
 * evaluator and the compiled lookup did not.
 *
 * This is reachable without a buggy hook: a hook that reports to a metrics
 * backend throws when the backend is down, and the failure mode is that a
 * padded field both defeats the deny rule AND takes the decision with it.
 */
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

  // Driven through `lookup` rather than `engine.can`: `can`'s own catch answers
  // `false` for any throw at all, so routing through it would pass with or
  // without the guard. This calls the compiled path directly, where the escaping
  // throw is observable.
  it('compiled lookup: still casts the Indeterminate deny vote', () => {
    const onPolicyError = vi.fn(boom)
    const table = compileTable([], [allowAll, denyBots], 'and')
    expect(lookup(table, 0, 'read', 'post', request(OVERSIZED), 'deny', onPolicyError)).toBe(false)
    expect(onPolicyError).toHaveBeenCalled()
  })
})

describe('a throwing onRuleError does not unwind the evaluation', () => {
  // `rulesAbstainOnThrow` is reserved for the synthesised RBAC policy when it is
  // allow-only: role permissions cannot deny, so one throwing rule abstains and
  // the scan continues. `evaluate` passes its `onPolicyError` down as the
  // rule-level reporter, so a throwing hook turned that `continue` into a
  // rethrow - and the RBAC policy is on every request that carries a role.
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

/**
 * The swallow above is rate-limited, and the latch used to be one module-level
 * boolean. Two engines in one process - two tenants - share that boolean, so
 * the first transiently broken hook anywhere permanently silenced the report
 * for every other hook for the life of the process. A hook failure is how an
 * operator learns that policy evaluation is throwing at all, so losing it to a
 * neighbour's outage loses the only signal.
 */
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

      // A different hook has its own budget. Under the old module-level latch
      // this was 0 - silenced by hookA's failure.
      evaluate([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', hookB)
      expect(reportsFor('backend-B-down')).toBe(1)
    } finally {
      errorSpy.mockRestore()
    }
  })

  it('does not build an Error when no hook is wired', () => {
    // `safeErrorReport` returns before normalising, so a throwing policy on a
    // request with no reporter costs nothing. Observable only as the decision
    // still being the Indeterminate deny.
    expect(evaluate([allowAll, denyBots], request(OVERSIZED), 'deny', 'and').allowed).toBe(false)
  })
})
