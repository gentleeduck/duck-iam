import { describe, expect, it } from 'vitest'
import { ops } from '../../conditions/conditions.libs'
import type { IamPrimitives, IamRequest } from '../../types'
import { resolve } from '../resolve'

/**
 * `resolve()` is declared to return `IamPrimitives.AttributeValue` and every
 * `OpFn` is typed on that, but the value came straight off the request behind
 * an `as`. Adapters deserialize JSON and hand the result through, so deeply
 * nested objects, `Date`s and functions genuinely reach here. Nothing but each
 * operator's own `typeof` guard stood between a non-conforming value and a
 * wrong comparison - and a `false` from a deny rule's condition is a silent
 * grant.
 */
function requestWith(attributes: IamPrimitives.Attributes): IamRequest.IAccessRequest {
  return {
    action: 'read',
    resource: { attributes: {}, type: 'post' },
    subject: { attributes, id: 'u1', roles: ['viewer'] },
  }
}

/**
 * Attributes as they actually arrive: an adapter hands back whatever the row
 * held, and nothing between there and here narrows it.
 */
function attributesFrom(value: object): IamPrimitives.Attributes {
  const out: IamPrimitives.Attributes = {}
  for (const [k, v] of Object.entries(value)) out[k] = v
  return out
}

describe('resolve() returns only values that conform to AttributeValue', () => {
  it('resolves a doubly-nested object to null, not to the object', () => {
    const req = requestWith(attributesFrom({ nested: { deep: { deeper: 1 } } }))
    expect(resolve(req, 'subject.attributes.nested')).toBeNull()
  })

  it('resolves a Date to null', () => {
    const req = requestWith(attributesFrom({ when: new Date(0) }))
    expect(resolve(req, 'subject.attributes.when')).toBeNull()
  })

  it('resolves a function to null', () => {
    const req = requestWith(attributesFrom({ fn: () => 'pwn' }))
    expect(resolve(req, 'subject.attributes.fn')).toBeNull()
  })

  it('resolves a Map to null', () => {
    const req = requestWith(attributesFrom({ m: new Map([['a', 1]]) }))
    expect(resolve(req, 'subject.attributes.m')).toBeNull()
  })

  it('resolves a mixed array to null but a scalar array through', () => {
    const req = requestWith(attributesFrom({ mixed: [1, { a: 1 }], scalars: [1, 'a', true, null] }))
    expect(resolve(req, 'subject.attributes.mixed')).toBeNull()
    expect(resolve(req, 'subject.attributes.scalars')).toEqual([1, 'a', true, null])
  })

  it('resolves a class instance to null even when its fields are scalars', () => {
    class Attrs {
      level = 5
    }
    const req = requestWith(attributesFrom({ obj: new Attrs() }))
    expect(resolve(req, 'subject.attributes.obj')).toBeNull()
  })

  it('a null-prototype record of scalars is still an AttributeValue', () => {
    const bare = Object.create(null)
    bare.level = 5
    const req = requestWith(attributesFrom({ bare }))
    expect(resolve(req, 'subject.attributes.bare')).toEqual({ level: 5 })
  })
})

describe('resolve() still returns everything the contract allows', () => {
  const req = requestWith(attributesFrom({ flat: { a: 1, b: 'x' }, level: 5, name: 'ada', nil: null, ok: true }))

  it.each([
    ['subject.attributes.level', 5],
    ['subject.attributes.name', 'ada'],
    ['subject.attributes.ok', true],
    ['subject.attributes.nil', null],
    ['subject.id', 'u1'],
    ['action', 'read'],
  ])('resolves %s', (path, expected) => {
    expect(resolve(req, path)).toEqual(expected)
  })

  it('resolves a flat record of scalars', () => {
    expect(resolve(req, 'subject.attributes.flat')).toEqual({ a: 1, b: 'x' })
  })

  it('resolves an array of scalars', () => {
    expect(resolve(req, 'subject.roles')).toEqual(['viewer'])
  })

  it('still walks into a nested object even though the object itself is not a value', () => {
    const deep = requestWith(attributesFrom({ nested: { deep: 7 } }))
    expect(resolve(deep, 'subject.attributes.nested.deep')).toBe(7)
  })
})

/**
 * The point of the narrowing: an operator handed a non-conforming value used
 * to have to guard for itself. `null` is NotApplicable, which is what the
 * whole condition system is built to handle.
 */
describe('operators see null rather than an off-contract value', () => {
  it('contains against a function is false either way, now without the function reaching it', () => {
    const req = requestWith(attributesFrom({ fn: () => 'pwn' }))
    const resolved = resolve(req, 'subject.attributes.fn')
    expect(resolved).toBeNull()
    expect(ops.contains?.(resolved, 'pwn')).toBe(false)
  })

  it('exists is false for an off-contract value', () => {
    const req = requestWith(attributesFrom({ when: new Date(0) }))
    expect(ops.exists?.(resolve(req, 'subject.attributes.when'), true)).toBe(false)
  })

  // Control: `exists` is true for a value the contract does allow.
  it('exists is true for a conforming value', () => {
    const req = requestWith(attributesFrom({ level: 5 }))
    expect(ops.exists?.(resolve(req, 'subject.attributes.level'), true)).toBe(true)
  })
})
