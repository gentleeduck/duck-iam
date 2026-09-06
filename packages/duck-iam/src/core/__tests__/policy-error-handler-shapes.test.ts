import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { MAX_REGEX_INPUT_LENGTH } from '../conditions/conditions.libs'
import { IamEngine } from '../engine/engine'
import { iamEvaluate } from '../evaluate/evaluate.public'
import type { AccessControl, IamRequest } from '../types'

/**
 * `onPolicyError` names three different function shapes in this package, two of
 * them reachable from the package root:
 *
 * | Where | Second argument |
 * |---|---|
 * | `iamEvaluate` / `iamEvaluateFast` | the policy **object** |
 * | `IamEngine` `hooks.onPolicyError` | the policy **id**, a string |
 * | adapter configs | `{ adapter, rowId }` |
 *
 * A handler declared with an explicit type is caught by the compiler when it is
 * wired to the wrong one. An inline arrow is not - it is contextually typed and
 * compiles against all three - so the same logging line prints a policy id in
 * one place and `[object Object]` in another. These tests state which argument
 * each caller actually passes, so the shapes cannot drift further apart
 * silently.
 */

/** A >2048-char field makes the `matches` operator throw. */
const OVERSIZED = 'curl'.padEnd(MAX_REGEX_INPUT_LENGTH + 1, 'x')

const denyBots: AccessControl.IPolicy = {
  algorithm: 'first-match',
  id: 'p-deny-bots',
  name: 'deny bots',
  rules: [
    {
      actions: ['*'],
      conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
      effect: 'deny',
      id: 'r-deny',
      priority: 10,
      resources: ['*'],
    },
  ],
}

function request(): IamRequest.IAccessRequest {
  return {
    action: 'read',
    environment: { userAgent: OVERSIZED },
    resource: { attributes: {}, type: 'post' },
    subject: { attributes: {}, id: 'u1', roles: [] },
  }
}

describe('the evaluator hands its handler the policy object', () => {
  it('passes the policy itself, not its id', () => {
    const seen: unknown[] = []
    iamEvaluate([denyBots], request(), 'deny', 'and', (_err, policy) => seen.push(policy))

    expect(seen).toHaveLength(1)
    const [policy] = seen
    expect(typeof policy).toBe('object')
    expect(policy).toMatchObject({ id: 'p-deny-bots', name: 'deny bots' })
  })

  it('passes an Error, whatever the policy threw', () => {
    const seen: unknown[] = []
    iamEvaluate([denyBots], request(), 'deny', 'and', (err) => seen.push(err))
    expect(seen[0]).toBeInstanceOf(Error)
  })
})

describe('the engine hook hands its handler the policy id', () => {
  it('passes a string, not the policy object', async () => {
    const seen: unknown[] = []
    const adapter = new IamMemoryAdapter({ policies: [denyBots] })
    const engine = new IamEngine({
      adapter,
      cacheTTL: 0,
      hooks: { onPolicyError: (_err, policyId) => seen.push(policyId) },
    })

    await engine.can('u1', 'read', { attributes: {}, type: 'post' }, { userAgent: OVERSIZED })

    expect(seen).toEqual(['p-deny-bots'])
  })

  // The concrete consequence of the two shapes sharing a name: one inline
  // arrow, two different rendered strings.
  it('renders differently from the evaluator handler under the same template', async () => {
    const lines: string[] = []
    const log = (_err: Error, p: unknown) => lines.push(`policy ${p} failed`)

    iamEvaluate([denyBots], request(), 'deny', 'and', log)
    const adapter = new IamMemoryAdapter({ policies: [denyBots] })
    const engine = new IamEngine({ adapter, cacheTTL: 0, hooks: { onPolicyError: log } })
    await engine.can('u1', 'read', { attributes: {}, type: 'post' }, { userAgent: OVERSIZED })

    expect(lines).toEqual(['policy [object Object] failed', 'policy p-deny-bots failed'])
  })
})

/**
 * The hook's own doc block used to say the offending policy is "treated as
 * NotApplicable so the rest of the policy set continues to evaluate" - the
 * pre-round-1 behaviour, and the opposite of what the evaluator does now. An
 * operator reading that would conclude a throwing deny policy is safely skipped.
 */
describe('a policy that throws stays applicable', () => {
  it('denies rather than abstaining, so a throw cannot retire a deny rule', () => {
    const decision = iamEvaluate([denyBots], request(), 'deny', 'and', () => undefined)
    expect(decision.allowed).toBe(false)
    expect(decision.reason).toContain('indeterminate')
  })

  it('reaches the same verdict through the engine', async () => {
    const adapter = new IamMemoryAdapter({ policies: [denyBots] })
    const engine = new IamEngine({ adapter, cacheTTL: 0 })
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' }, { userAgent: OVERSIZED })).toBe(false)
  })
})
