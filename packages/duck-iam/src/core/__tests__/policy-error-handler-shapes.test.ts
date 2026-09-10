import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { MAX_REGEX_INPUT_LENGTH } from '../conditions/conditions.libs'
import { IamEngine } from '../engine/engine'
import { iamEvaluate } from '../evaluate/evaluate.public'
import type { AccessControl, IamRequest } from '../types'

// `onPolicyError` has three shapes (see `AccessControl.PolicyErrorHandler`) and an inline arrow compiles against
// all of them, so these tests pin which second argument each caller actually passes.

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

  // One inline arrow, two different rendered strings.
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
