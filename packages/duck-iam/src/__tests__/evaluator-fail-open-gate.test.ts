import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../core/types'
import * as Iam from '../index'

/**
 * `IamEngine`'s constructor refuses `defaultEffect: 'allow'` without
 * `allowFailOpen: true`. The evaluator is equally public, so that guard was one
 * import away from being bypassed: `evaluate(policies, req, 'allow')` off the
 * package root returned an allow with no opt-in, no warning and no engine.
 */
const req: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
}

const FOOTGUN = /fail-open footgun/

describe('the evaluator applies the same fail-open opt-in as the engine', () => {
  it('iamEvaluate throws on defaultEffect allow without the opt-in', () => {
    expect(() => Iam.iamEvaluate([], req, 'allow')).toThrow(FOOTGUN)
  })

  it('iamEvaluateFast throws on defaultEffect allow without the opt-in', () => {
    expect(() => Iam.iamEvaluateFast([], req, 'allow')).toThrow(FOOTGUN)
  })

  it('names the package and the module in the message', () => {
    expect(() => Iam.iamEvaluate([], req, 'allow')).toThrow(/\[@gentleduck\/iam:evaluate\]/)
  })

  it('allows the fail-open evaluation once intent is confirmed', () => {
    expect(Iam.iamEvaluate([], req, 'allow', 'and', undefined, undefined, undefined, true).allowed).toBe(true)
    expect(Iam.iamEvaluateFast([], req, 'allow', 'and', undefined, undefined, undefined, true)).toBe(true)
  })

  // Controls: the default effect is the only thing gated, and the wrappers must
  // still evaluate rather than merely guard.
  it('leaves defaultEffect deny untouched', () => {
    expect(Iam.iamEvaluate([], req, 'deny').allowed).toBe(false)
    expect(Iam.iamEvaluateFast([], req, 'deny')).toBe(false)
  })

  it('still reaches a real verdict through the wrappers', () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p1',
      name: 'p1',
      rules: [
        { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources: ['post'] },
      ],
    }
    expect(Iam.iamEvaluate([policy], req, 'deny').allowed).toBe(true)
    expect(Iam.iamEvaluateFast([policy], req, 'deny')).toBe(true)
  })
})

/**
 * The unprefixed names were also the only evaluator symbols on the root
 * namespace not following the `Iam*` / `iam*` convention, and `evaluate` is very
 * easy to reach for by accident.
 */
describe('public surface: the evaluator is exported under prefixed names only', () => {
  for (const name of ['evaluate', 'evaluateFast', 'evaluatePolicy', 'evaluatePolicyFast', 'indexPolicy']) {
    it(`does not export \`${name}\``, () => {
      expect(Object.hasOwn(Iam, name)).toBe(false)
    })
  }

  it('exports the prefixed replacements', () => {
    for (const name of [
      'iamEvaluate',
      'iamEvaluateFast',
      'iamEvaluatePolicy',
      'iamEvaluatePolicyFast',
      'iamIndexPolicy',
    ]) {
      expect(Object.hasOwn(Iam, name)).toBe(true)
    }
  })
})
