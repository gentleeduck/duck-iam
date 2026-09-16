import { describe, expect, it } from 'vitest'
import { evaluate } from '../../evaluate/evaluate'
import type { AccessControl, IamRequest } from '../../types'
import { resolve } from '../resolve'

// `resolve` reads own properties only, so `Object.prototype` members never resolve and `exists` asks whether the
// request carries the attribute.
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

  // Controls: ownership matters, not the name, so an own attribute shadowing a prototype member still resolves.
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

/** A policy gated on `exists` / `not_exists`, to check the own-property rule at policy level. */
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
