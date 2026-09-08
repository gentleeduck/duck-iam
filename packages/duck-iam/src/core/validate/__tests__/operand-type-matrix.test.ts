import { describe, expect, it } from 'vitest'
import { evalCondition, IamOperandTypeError } from '../../conditions/conditions.libs'
import type { IamRequest } from '../../types'
import { validatePolicy } from '../validate'
import { VALID_OPERATORS } from '../validate.libs'

/**
 * A wrongly-typed operand used to make each operator return a fixed verdict,
 * and for the negated ones that verdict was `true`, so an "allow unless
 * denylisted" rule allowed everyone. The validator refused the operand, and
 * that was taken to make the verdict unreachable.
 *
 * It was not. Only `savePolicy` and `import` run the validator; `loadPolicies`
 * does not, so a policy seeded through an adapter constructor - a documented
 * API - or written straight to the store is evaluated exactly as authored.
 * Measured end to end: a seeded denylist allowed the banned subject. The
 * evaluator now applies the same matrix itself and throws, which the engine
 * absorbs as Indeterminate, and both checks read one table.
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
    // The one cell where a type-satisfying operand is still refused, and the
    // refusal is not about its type. `matches` compiles its operand, and
    // `evalCondition` will not compile one that came from the request - an
    // attacker controlling that attribute would otherwise pin in a catastrophic
    // regex. So the condition is false for every request that can ever arrive
    // and the rule never fires; the validator refuses it rather than store a
    // rule that provably does nothing. See `matches-pattern-agreement.test.ts`.
    // `satisfies` is left alone deliberately: it models operand *types*, and
    // folding a semantic refusal into it would make it wrong about types.
    const inertUserSourcedPattern = operator === 'matches' && typeof value === 'string' && value.startsWith('$')
    expect(accepts(operator, value)).toBe(satisfies(kind, value) && !inertUserSourcedPattern)
  })
})

/**
 * What the matrix is protecting against, spelled out - and what now happens
 * instead. The first two were the permissive direction; both were reachable
 * without the validator, and both now refuse to answer.
 */
describe('the verdicts a malformed operand would produce', () => {
  const req: IamRequest.IAccessRequest = {
    action: 'read',
    environment: {},
    resource: { attributes: {}, type: 'post' },
    subject: { attributes: { groups: ['staff'], tier: 'gold' }, id: 'u1', roles: [] },
  }

  it('`nin` with a non-array operand throws rather than admitting everyone', () => {
    // The old verdict was `true`: a denylist that admits every subject it was
    // written to exclude. Indeterminate is the honest answer - the operator
    // cannot compare against a non-list - and the caller fails closed on it.
    expect(() => evalCondition(req, { field: 'subject.attributes.tier', operator: 'nin', value: 'gold' })).toThrow(
      IamOperandTypeError,
    )
    expect(accepts('nin', 'gold')).toBe(false)
  })

  it('`eq` with a missing operand throws rather than matching every absent attribute', () => {
    // `JSON.stringify` drops an `undefined`, so the key simply vanishes on the
    // way to a store; `cond.value ?? null` then compared equal to any absent
    // attribute. The guard passed for exactly the subjects it excluded.
    expect(() => evalCondition(req, { field: 'subject.attributes.absent', operator: 'eq' })).toThrow(
      IamOperandTypeError,
    )
    expect(accepts('eq', MISSING)).toBe(false)
  })

  it('`not_contains` on an absent field still returns true - that is the field, not the operand', () => {
    // Unchanged, and deliberately: an empty list contains nothing. The operand
    // is well-formed here, so there is nothing unanswerable about the question.
    expect(evalCondition(req, { field: 'subject.attributes.absent', operator: 'not_contains', value: 'staff' })).toBe(
      true,
    )
  })

  it('`contains` on a string-typed field returns false rather than matching a substring', () => {
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'contains', value: 'gol' })).toBe(false)
  })

  // Control: the same operators reach the right verdict on a well-formed
  // operand. Without this the three clauses above are satisfied by an
  // evaluator that throws on everything.
  it('control: well-formed operands answer correctly', () => {
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'nin', value: ['gold'] })).toBe(false)
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'nin', value: ['silver'] })).toBe(true)
    expect(evalCondition(req, { field: 'subject.attributes.groups', operator: 'contains', value: 'staff' })).toBe(true)
    expect(evalCondition(req, { field: 'subject.attributes.tier', operator: 'eq', value: 'gold' })).toBe(true)
  })
})
