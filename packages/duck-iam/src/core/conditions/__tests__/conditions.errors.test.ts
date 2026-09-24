import { describe, expect, it } from 'vitest'
import { IamError, metaOf } from '../../errors'
import { evalConditionGroup, evaluateOperator } from '../conditions'
import { evalCondition, evalMatchesOp, MAX_REGEX_INPUT_LENGTH, MAX_REGEX_LENGTH } from '../conditions.libs'

const req = {
  subject: { id: 'u1', roles: [], attributes: {} },
  resource: { type: 'post', attributes: {} },
  action: 'read',
  environment: {},
}

describe('evalMatchesOp throws IamError with the real field the first time', () => {
  it('IAM_CONDITION_PATTERN_REFUSED carries the caller-supplied field, not a placeholder', () => {
    try {
      evalMatchesOp('x'.repeat(1), 'a'.repeat(MAX_REGEX_LENGTH + 1), undefined, 'subject.name')
      expect.unreachable()
    } catch (err) {
      expect(err).toBeInstanceOf(IamError)
      expect((err as IamError<'IAM_CONDITION_PATTERN_REFUSED'>).meta.field).toBe('subject.name')
    }
  })

  it('IAM_CONDITION_REGEX_INPUT_TOO_LARGE carries the real field via evalCondition, no reconstruction needed', () => {
    const longFieldReq = { ...req, resource: { type: 'a'.repeat(MAX_REGEX_INPUT_LENGTH + 1), attributes: {} } }
    try {
      evalCondition(longFieldReq, {
        field: 'resource.type',
        operator: 'matches',
        value: '^a+$',
      })
      expect.unreachable()
    } catch (err) {
      expect(err).toBeInstanceOf(IamError)
      expect((err as IamError<'IAM_CONDITION_REGEX_INPUT_TOO_LARGE'>).code).toBe('IAM_CONDITION_REGEX_INPUT_TOO_LARGE')
      expect((err as IamError<'IAM_CONDITION_REGEX_INPUT_TOO_LARGE'>).meta.field).toBe('resource.type')
    }
  })
})

describe('evalCondition throws IAM_CONDITION_USER_SOURCED_PATTERN for a $-reference matches pattern', () => {
  it('refuses rather than compiles it', () => {
    expect(() => evalCondition(req, { field: 'resource.type', operator: 'matches', value: '$subject.id' })).toThrow(
      IamError,
    )
  })
})

describe('evalCondition throws IAM_CONDITION_OPERAND_TYPE for a wrong-typed operand', () => {
  it('a missing value on a non-valueless operator', () => {
    expect(() => evalCondition(req, { field: 'resource.type', operator: 'eq' } as never)).toThrow(IamError)
  })
})

describe('evalConditionGroup throws IAM_CONDITION_GROUP_INVALID', () => {
  it('too deep', () => {
    let group: unknown = { all: [] }
    for (let i = 0; i < 12; i++) group = { all: [group] }
    expect(() => evalConditionGroup(req, group as never)).toThrow(IamError)
  })

  it('no recognised key', () => {
    expect(() => evalConditionGroup(req, { nonsense: true } as never)).toThrow(IamError)
  })
})

describe('conditions.ts throws for a group whose key is not an array, and for an unowned operator', () => {
  it('IAM_CONDITION_ITEMS_NOT_ARRAY', () => {
    expect(() => evalConditionGroup(req, { all: 'not-an-array' } as never)).toThrow(IamError)
  })

  it('IAM_CONDITION_OPERATOR_UNKNOWN from evaluateOperator, with no field (it has none to report)', () => {
    try {
      evaluateOperator('nonsense' as never, 'a', 'b')
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_CONDITION_OPERATOR_UNKNOWN'>, 'IAM_CONDITION_OPERATOR_UNKNOWN')
      expect(meta).toEqual({ operator: 'nonsense' })
    }
  })

  it('evalCondition throws the same IAM_CONDITION_OPERATOR_UNKNOWN, with the field it does have', () => {
    try {
      evalCondition(req, { field: 'resource.type', operator: 'nonsense', value: 'x' } as never)
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_CONDITION_OPERATOR_UNKNOWN'>, 'IAM_CONDITION_OPERATOR_UNKNOWN')
      expect(meta).toEqual({ operator: 'nonsense', field: 'resource.type' })
    }
  })
})
