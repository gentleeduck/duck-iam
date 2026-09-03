import { describe, expect, it } from 'vitest'
import { evalCondition } from '../../conditions/conditions.libs'
import type { IamRequest } from '../../types'
import { validatePolicy } from '../validate'
import { VALID_OPERATORS } from '../validate.libs'

/**
 * No operator throws on a wrongly-typed operand - each returns a fixed verdict
 * instead, and for the negated ones that verdict is `true`, so an "allow unless
 * denylisted" rule allows everyone. The validator is the only place that
 * failure is visible, so the whole 19-operator matrix is pinned here rather
 * than the three operators that happened to have a test.
 *
 * `EXPECTED_OPERAND` is written out rather than imported from `OPERAND_TYPES`:
 * a test that reads the table it is checking cannot catch an edit to it.
 */
type OperandKind = 'any' | 'array' | 'number' | 'string' | 'temporal' | 'none'

const EXPECTED_OPERAND: Readonly<Record<string, OperandKind>> = {
  after: 'temporal',
  before: 'temporal',
  contains: 'any',
  ends_with: 'string',
  eq: 'any',
  exists: 'none',
  gt: 'number',
  gte: 'number',
  in: 'array',
  lt: 'number',
  lte: 'number',
  matches: 'string',
  neq: 'any',
  nin: 'array',
  not_contains: 'any',
  not_exists: 'none',
  starts_with: 'string',
  subset_of: 'array',
  superset_of: 'array',
}

/** The operand samples the matrix runs; `MISSING` stands for a key that is absent. */
const MISSING = Symbol('missing')
const SAMPLES: readonly [string, unknown][] = [
  ['a string', 'x'],
  ['a number', 1],
  ['a boolean', true],
  ['null', null],
  ['an array', ['a']],
  ['an object', { a: 1 }],
  ['a $-reference', '$subject.attributes.other'],
  ['nothing', MISSING],
]

function satisfies(kind: OperandKind, value: unknown): boolean {
  // `exists` / `not_exists` read only the field, so any operand - or none - is fine.
  if (kind === 'none') return true
  // A `$`-prefixed string resolves from the request, so its type is unknowable here.
  if (typeof value === 'string' && value.startsWith('$')) return true
  if (value === MISSING) return false
  switch (kind) {
    case 'any':
      return true
    case 'array':
      return Array.isArray(value)
    case 'number':
      return typeof value === 'number'
    case 'string':
      return typeof value === 'string'
    case 'temporal':
      return typeof value === 'number' || typeof value === 'string'
  }
}

function accepts(operator: string, value: unknown): boolean {
  const condition: Record<string, unknown> = { field: 'subject.attributes.x', operator }
  if (value !== MISSING) condition.value = value
  return validatePolicy({
    algorithm: 'first-match',
    id: 'p',
    name: 'p',
    rules: [
      {
        actions: ['read'],
        conditions: { all: [condition] },
        effect: 'allow',
        id: 'r',
        priority: 1,
        resources: ['post'],
      },
    ],
  }).valid
}

const MATRIX = [...VALID_OPERATORS].flatMap((operator) =>
  SAMPLES.map(([label, value]): [string, string, unknown] => [operator, label, value]),
)

describe('operator x operand type', () => {
  it('covers every operator the evaluator supports', () => {
    expect(Object.keys(EXPECTED_OPERAND).sort()).toEqual([...VALID_OPERATORS].sort())
    expect(MATRIX).toHaveLength(19 * SAMPLES.length)
  })

  it.each(MATRIX)('%s with %s', (operator, _label, value) => {
    const kind = EXPECTED_OPERAND[operator] ?? 'any'
    expect(accepts(operator, value)).toBe(satisfies(kind, value))
  })
})

/**
 * What the matrix is protecting against, spelled out. Each of these is the
 * verdict a malformed operand produces at evaluation - all three are the
 * permissive direction, and all three are unreachable only because the
 * validator refuses the operand first.
 */
describe('the verdicts a malformed operand would produce', () => {
  const req: IamRequest.IAccessRequest = {
    action: 'read',
    environment: {},
    resource: { attributes: {}, type: 'post' },
    subject: { attributes: { groups: ['staff'], tier: 'gold' }, id: 'u1', roles: [] },
  }

  it('`nin` with a non-array operand returns true, so a denylist admits everyone', () => {
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'nin', value: 'gold' })).toBe(true)
    expect(accepts('nin', 'gold')).toBe(false)
  })

  it('`not_contains` on an absent field returns true', () => {
    expect(evalCondition(req, { field: 'subject.attributes.absent', operator: 'not_contains', value: 'staff' })).toBe(
      true,
    )
  })

  it('`eq` with a missing operand compares against null, matching an absent attribute', () => {
    expect(evalCondition(req, { field: 'subject.attributes.absent', operator: 'eq' })).toBe(true)
    expect(accepts('eq', MISSING)).toBe(false)
  })

  it('`contains` on a string-typed field returns false rather than matching a substring', () => {
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'contains', value: 'gol' })).toBe(false)
  })

  // Control: the same operators reach the right verdict on a well-formed operand.
  it('control: well-formed operands answer correctly', () => {
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'nin', value: ['gold'] })).toBe(false)
    expect(evalCondition(req, { field: 'subject.attributes.groups', operator: 'contains', value: 'staff' })).toBe(true)
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'eq', value: 'gold' })).toBe(true)
  })
})
