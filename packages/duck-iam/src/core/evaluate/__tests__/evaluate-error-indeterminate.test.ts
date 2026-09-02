import { describe, expect, it, vi } from 'vitest'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast } from '../evaluate'

/**
 * An evaluation error is Indeterminate, not NotApplicable. Skipping a policy
 * that throws lets an attacker disable a deny rule by padding the field it
 * matches on (a >2048-char User-Agent makes `matches` throw), after which a
 * sibling allow wins. A policy that could have denied must fail closed.
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

/** Only allow rules: a throw here must stay skippable so one rotten row cannot deny everyone. */
const allowOnlyThatThrows: AccessControl.IPolicy = {
  id: 'p-allow-throws',
  name: 'allow throws',
  algorithm: 'first-match',
  rules: [
    {
      id: 'r-allow-throws',
      effect: 'allow',
      priority: 5,
      actions: ['*'],
      resources: ['*'],
      conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
    },
  ],
}

describe("evaluate ('and') with a throwing deny policy", () => {
  it('denies rather than skipping the deny policy', () => {
    const onPolicyError = vi.fn()
    const decision = evaluate([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', onPolicyError)
    expect(decision.allowed).toBe(false)
    expect(onPolicyError).toHaveBeenCalledOnce()
  })

  it('control: a normal-length matching user agent also denies', () => {
    expect(evaluate([allowAll, denyBots], request('curl'), 'deny', 'and').allowed).toBe(false)
  })

  it('an allow-only policy that throws is still skipped', () => {
    const onPolicyError = vi.fn()
    const decision = evaluate([allowAll, allowOnlyThatThrows], request(OVERSIZED), 'deny', 'and', onPolicyError)
    expect(decision.allowed).toBe(true)
    expect(onPolicyError).toHaveBeenCalledOnce()
  })
})

describe("evaluateFast ('and') with a throwing deny policy", () => {
  it('denies rather than skipping the deny policy', () => {
    const onPolicyError = vi.fn()
    expect(evaluateFast([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', onPolicyError)).toBe(false)
    expect(onPolicyError).toHaveBeenCalledOnce()
  })

  it('an allow-only policy that throws is still skipped', () => {
    expect(evaluateFast([allowAll, allowOnlyThatThrows], request(OVERSIZED), 'deny', 'and')).toBe(true)
  })
})

/**
 * With no sibling allow, a throwing deny must not fall through to a
 * `defaultEffect: 'allow'` engine - that is the fail-open the padding buys.
 */
describe.each(['and', 'allow-overrides'] as const)('fail-open engine (%s), lone throwing deny', (combine) => {
  it('evaluate denies', () => {
    expect(evaluate([denyBots], request(OVERSIZED), 'allow', combine).allowed).toBe(false)
  })

  it('evaluateFast denies', () => {
    expect(evaluateFast([denyBots], request(OVERSIZED), 'allow', combine)).toBe(false)
  })

  it('control: an allow-only throwing policy still defaults to allow', () => {
    expect(evaluate([allowOnlyThatThrows], request(OVERSIZED), 'allow', combine).allowed).toBe(true)
  })
})
