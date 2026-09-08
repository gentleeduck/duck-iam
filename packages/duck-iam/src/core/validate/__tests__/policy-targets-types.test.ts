import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { validatePolicy } from '../validate'

/**
 * `validatePolicy` checks `targets.actions`, `targets.resources` and
 * `targets.roles` in one loop. Only two of the three were reachable from any
 * test: dropping `'roles'` from that array left the whole suite green, because
 * the fuzz generator that was supposed to cover it
 * (`schema-validator-agreement.test.ts`) produced 147 runtime-accepted policies
 * out of 4000 and only three with a non-empty `rules` array, and its own
 * control measured a different generator.
 *
 * A `targets.roles` that is not an array is not cosmetic: `targets` is how a
 * policy declares who it applies to, and a malformed one that validates clean
 * is a policy whose applicability nobody has checked.
 *
 * These are direct rather than generated, so the coverage does not depend on
 * what a generator happens to emit.
 */
const KEYS = ['actions', 'resources', 'roles'] as const

/** Parsed from JSON so the wrong-typed target arrives untyped, as a store row does. */
function policyWithTargets(json: string): AccessControl.IPolicy {
  return JSON.parse(`{"algorithm":"deny-overrides","id":"p1","name":"P","rules":[],"targets":${json}}`)
}

function errorPaths(policy: AccessControl.IPolicy): string[] {
  return validatePolicy(policy)
    .issues.filter((i) => i.type === 'error')
    .map((i) => i.path ?? '')
}

describe('every key of targets is type-checked, not just the first two', () => {
  const NON_ARRAYS: [string, string][] = [
    ['a string', '"admin"'],
    ['a number', '7'],
    ['an object', '{"0":"admin"}'],
    ['a boolean', 'true'],
    ['null', 'null'],
  ]

  for (const key of KEYS) {
    it.each(NON_ARRAYS)(`targets.${key} as %s is an error`, (_label, value) => {
      expect(errorPaths(policyWithTargets(`{"${key}":${value}}`))).toContain(`targets.${key}`)
    })

    it(`targets.${key} as an array is accepted`, () => {
      // Anti-vacuity: the clause above must be about the *type*, not about the
      // key existing at all.
      expect(errorPaths(policyWithTargets(`{"${key}":["x"]}`))).not.toContain(`targets.${key}`)
    })

    it(`an absent targets.${key} is not an error`, () => {
      expect(errorPaths(policyWithTargets('{}'))).not.toContain(`targets.${key}`)
    })
  }

  it('all three are reported at once rather than short-circuiting on the first', () => {
    const paths = errorPaths(policyWithTargets('{"actions":1,"resources":2,"roles":3}'))
    for (const key of KEYS) expect(paths).toContain(`targets.${key}`)
  })
})
