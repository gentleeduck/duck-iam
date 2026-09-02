import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evalConditionGroup } from '../conditions'

const req: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: { dept: 'eng' }, id: 'u1', roles: [] },
}

const group = (g: unknown): AccessControl.IConditionGroup => g as AccessControl.IConditionGroup

describe('an unrecognised condition node does not read as "no conditions"', () => {
  it('an empty group is still unconditionally true', () => {
    expect(evalConditionGroup(req, group({}))).toBe(true)
  })

  it.each([
    ['typo in all', { al: [{ field: 'subject.attributes.dept', operator: 'eq', value: 'sales' }] }],
    ['typo in any', { anyy: [] }],
    ['unrelated key', { foo: 1 }],
  ])('%s evaluates false', (_label, node) => {
    expect(evalConditionGroup(req, group(node))).toBe(false)
  })

  it('the recognised keys still work', () => {
    const match = { field: 'subject.attributes.dept', operator: 'eq' as const, value: 'eng' }
    expect(evalConditionGroup(req, group({ all: [match] }))).toBe(true)
    expect(evalConditionGroup(req, group({ any: [match] }))).toBe(true)
    expect(evalConditionGroup(req, group({ none: [match] }))).toBe(false)
  })
})

describe('an unknown operator is indeterminate, not false', () => {
  it('throws rather than quietly failing to match', () => {
    expect(() =>
      evalConditionGroup(req, group({ all: [{ field: 'subject.id', operator: 'equals', value: 'u1' }] })),
    ).toThrow(/unknown operator "equals"/)
  })
})

describe('a malformed group key is indeterminate, not an empty list', () => {
  it.each([
    ['undefined all', { all: undefined }],
    ['string any', { any: 'nope' }],
    ['object none', { none: {} }],
  ])('%s throws', (_label, node) => {
    expect(() => evalConditionGroup(req, group(node))).toThrow(/must be an array/)
  })
})
