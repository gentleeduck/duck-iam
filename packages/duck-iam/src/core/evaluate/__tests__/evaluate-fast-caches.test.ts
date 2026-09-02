import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evaluatePolicyFast } from '../evaluate'

/**
 * The ranked (first-match / highest-priority) fast path must use the caller's
 * per-engine caches like the override branches do; falling back to the
 * module-global map lets one tenant evict another's compiled regexes.
 */
const request: IamRequest.IAccessRequest = {
  subject: { id: 'u1', roles: [], attributes: { department: 'engineering' } },
  action: 'read',
  resource: { type: 'post', attributes: {} },
  environment: {},
}

function policy(algorithm: AccessControl.IPolicy['algorithm']): AccessControl.IPolicy {
  return {
    id: 'p',
    name: 'p',
    algorithm,
    rules: [
      {
        id: 'r',
        effect: 'allow',
        priority: 1,
        actions: ['read'],
        resources: ['post'],
        conditions: { all: [{ field: 'subject.attributes.department', operator: 'matches', value: '^eng' }] },
      },
    ],
  }
}

describe.each(['first-match', 'highest-priority'] as const)('evaluatePolicyFast(%s) per-engine caches', (algorithm) => {
  it('compiles the rule regex into the caches passed by the caller', () => {
    const caches = { regex: new Map<string, RegExp>(), path: new Map<string, string[] | null>() }
    expect(evaluatePolicyFast(policy(algorithm), request, 'deny', caches)).toBe(true)
    expect(caches.regex.size).toBe(1)
  })
})
