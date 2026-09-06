import { describe, expect, it } from 'vitest'
import { evaluate } from '../../evaluate/evaluate'
import type { AccessControl, IamRequest } from '../../types'
import { resolve } from '../resolve'

/**
 * `resolve` walked with `Reflect.get`, which reads through the prototype chain,
 * so every `Object.prototype` member resolved to a function on any object. The
 * three-name denylist covered the pollution vectors and nothing else, and
 * `exists` - which asks whether the request *carries* an attribute - answered
 * "is this name resolvable anywhere on the prototype chain" instead.
 */
const INHERITED = [
  'toString',
  'valueOf',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toLocaleString',
  '__defineGetter__',
  '__lookupGetter__',
]

const bare: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
}

describe('resolve reads own properties only', () => {
  it.each(INHERITED)('does not resolve inherited `%s`', (name) => {
    expect(resolve(bare, `subject.attributes.${name}`)).toBeNull()
  })

  it.each(INHERITED)('does not resolve inherited `%s` on a request root either', (name) => {
    expect(resolve(bare, `environment.${name}`)).toBeNull()
  })

  // Controls: real data must still resolve, including a name that shadows a
  // prototype member - the fix is about ownership, not about the name.
  it('resolves own attributes', () => {
    const req: IamRequest.IAccessRequest = {
      ...bare,
      subject: { attributes: { status: 'active', tags: ['a', 'b'], toString: 'shadowed' }, id: 'u1', roles: [] },
    }
    expect(resolve(req, 'subject.attributes.status')).toBe('active')
    expect(resolve(req, 'subject.attributes.tags')).toEqual(['a', 'b'])
    expect(resolve(req, 'subject.attributes.toString')).toBe('shadowed')
    expect(resolve(req, 'subject.id')).toBe('u1')
  })

  it('still refuses the pollution segments', () => {
    expect(resolve(bare, 'subject.attributes.__proto__')).toBeNull()
    expect(resolve(bare, 'subject.constructor')).toBeNull()
  })
})

/**
 * The consequence at policy level: with no attributes at all, an `exists`-gated
 * allow fired and a `not_exists`-gated deny did not.
 */
function policy(operator: AccessControl.Operator, effect: AccessControl.Effect): AccessControl.IPolicy {
  return {
    algorithm: 'deny-overrides',
    id: `p-${operator}`,
    name: operator,
    rules: [
      {
        actions: ['read'],
        conditions: { all: [{ field: 'subject.attributes.valueOf', operator }] },
        effect,
        id: 'r1',
        priority: 1,
        resources: ['post'],
      },
    ],
  }
}

describe('exists / not_exists on an inherited name', () => {
  it('an exists-gated allow does not fire for a subject with no attributes', () => {
    expect(evaluate([policy('exists', 'allow')], bare, 'deny', 'and').allowed).toBe(false)
  })

  it('a not_exists-gated deny does fire', () => {
    expect(evaluate([policy('not_exists', 'deny')], bare, 'deny', 'and').allowed).toBe(false)
  })

  // Control: the same allow rule still fires when the attribute is really there.
  it('the exists-gated allow fires on an own attribute of that name', () => {
    const req: IamRequest.IAccessRequest = {
      ...bare,
      subject: { attributes: { valueOf: 'present' }, id: 'u1', roles: [] },
    }
    expect(evaluate([policy('exists', 'allow')], req, 'deny', 'and').allowed).toBe(true)
  })
})
