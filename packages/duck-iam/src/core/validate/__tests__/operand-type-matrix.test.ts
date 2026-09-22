// Pins the operand type each operator accepts; the evaluator applies the same table on read and throws.
import { describe, expect, it } from 'vitest'
import { evalCondition, IamOperandTypeError } from '../../conditions/conditions.libs'
import type { IamRequest } from '../../types'
import { validatePolicy } from '../validate'
import { VALID_OPERATORS } from '../validate.libs'

type OperandKind = 'any' | 'array' | 'number' | 'scalar' | 'string' | 'temporal' | 'none'

// NOTE: written out, not imported from `OPERAND_TYPES`: a test reading the table it checks can't catch an edit to it.
const EXPECTED_OPERAND: Readonly<Record<string, OperandKind>> = {
  after: 'temporal',
  before: 'temporal',
  // `contains`/`not_contains` ask array membership, so the operand is the scalar looked for, not anything.
  contains: 'scalar',
  ends_with: 'string',
  // `eq`/`neq` are `f === v`, so a non-scalar operand compares by reference and can never match.
  eq: 'scalar',
  exists: 'none',
  gt: 'number',
  gte: 'number',
  in: 'array',
  lt: 'number',
  lte: 'number',
  matches: 'string',
  neq: 'scalar',
  nin: 'array',
  not_contains: 'scalar',
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
  // The container being an array was never enough: membership compares elements,
  // so an array of non-scalars matched nothing by reference and retired the rule.
  ['an array of objects', [{ a: 1 }]],
  ['an array of arrays', [['a']]],
  ['an object', { a: 1 }],
  ['a $-reference', '$subject.attributes.other'],
  ['nothing', MISSING],
]

/** The model's own scalar test, kept separate from the product's. */
function isScalarSample(value: unknown): boolean {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

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
      return Array.isArray(value) && value.every(isScalarSample)
    case 'number':
      return typeof value === 'number'
    case 'scalar':
      return isScalarSample(value)
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
    // The one type-satisfying operand still refused: a `$`-sourced `matches` pattern is a ReDoS vector (see
    // `matches-pattern-agreement.test.ts`). `satisfies` models types only, so the exception lives here.
    const inertUserSourcedPattern = operator === 'matches' && typeof value === 'string' && value.startsWith('$')
    expect(accepts(operator, value)).toBe(satisfies(kind, value) && !inertUserSourcedPattern)
  })
})

// The first two are the permissive cases; both are reachable without the validator, so the evaluator throws.
describe('the verdicts a malformed operand would produce', () => {
  const req: IamRequest.IAccessRequest = {
    action: 'read',
    environment: {},
    resource: { attributes: {}, type: 'post' },
    subject: { attributes: { groups: ['staff'], tier: 'gold' }, id: 'u1', roles: [] },
  }

  it('`nin` with a non-array operand throws rather than admitting everyone', () => {
    // SECURITY: Indeterminate, not a `true` that admits every denylisted subject; the caller fails closed on it.
    expect(() => evalCondition(req, { field: 'subject.attributes.tier', operator: 'nin', value: 'gold' })).toThrow(
      IamOperandTypeError,
    )
    expect(accepts('nin', 'gold')).toBe(false)
  })

  it('`eq` with a missing operand throws rather than matching every absent attribute', () => {
    // `JSON.stringify` drops `undefined`, and a `null` operand would equal any absent attribute.
    expect(() => evalCondition(req, { field: 'subject.attributes.absent', operator: 'eq' })).toThrow(
      IamOperandTypeError,
    )
    expect(accepts('eq', MISSING)).toBe(false)
  })

  it('`not_contains` on an absent field still returns true - that is the field, not the operand', () => {
    // An empty list contains nothing, and the operand is well-formed, so this is answerable.
    expect(evalCondition(req, { field: 'subject.attributes.absent', operator: 'not_contains', value: 'staff' })).toBe(
      true,
    )
  })

  it('`contains` on a string-typed field returns false rather than matching a substring', () => {
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'contains', value: 'gol' })).toBe(false)
  })

  // Control: without this, the clauses above pass on an evaluator that throws on everything.
  it('control: well-formed operands answer correctly', () => {
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'nin', value: ['gold'] })).toBe(false)
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'nin', value: ['silver'] })).toBe(true)
    expect(evalCondition(req, { field: 'subject.attributes.groups', operator: 'contains', value: 'staff' })).toBe(true)
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'eq', value: 'gold' })).toBe(true)
  })
})
