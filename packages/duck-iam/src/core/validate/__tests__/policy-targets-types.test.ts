// Every `targets` key, `roles` included, is type-checked by direct cases, so coverage doesn't depend on a generator.
import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { validatePolicy } from '../validate'

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
      // Anti-vacuity: the clause above is about the type, not the key existing.
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
