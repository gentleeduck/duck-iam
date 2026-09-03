import { describe, expect, it } from 'vitest'
import { POLICY_JSON_SCHEMA } from '../../schema'
import { validatePolicy } from '../validate'

/**
 * A condition's operand is what the operator compares against. Neither its
 * presence nor its type was checked, and no operator throws on a bad operand -
 * each returns a fixed verdict instead, so a malformed guard passes silently.
 */
function policyWithCondition(condition: unknown): unknown {
  return {
    id: 'p',
    name: 'p',
    algorithm: 'first-match',
    rules: [
      {
        id: 'r',
        effect: 'allow',
        priority: 1,
        actions: ['read'],
        resources: ['doc'],
        conditions: { all: [condition] },
      },
    ],
  }
}

function codesFor(condition: unknown): string[] {
  return validatePolicy(policyWithCondition(condition)).issues.map((i) => i.code)
}

describe('condition operand presence', () => {
  // `JSON.stringify` drops an `undefined` value, so this shape is what any
  // adapter hands back. At evaluation `cond.value ?? null` makes it `null`,
  // which equals a missing attribute - the rule fires for exactly the subjects
  // it excluded.
  it.each(['eq', 'neq', 'in', 'nin', 'contains', 'not_contains', 'matches', 'gt', 'before'])(
    'rejects "%s" with no value',
    (operator) => {
      expect(codesFor({ field: 'subject.attributes.dept', operator })).toContain('MISSING_VALUE')
    },
  )

  it('rejects an explicitly undefined value the same way', () => {
    expect(codesFor({ field: 'subject.attributes.dept', operator: 'eq', value: undefined })).toContain('MISSING_VALUE')
  })

  it.each(['exists', 'not_exists'])('accepts "%s" with no value', (operator) => {
    expect(codesFor({ field: 'subject.attributes.dept', operator })).toEqual([])
  })
})

describe('condition operand type', () => {
  // `nin` with a non-array returns `true` unconditionally, so an
  // "allow unless denylisted" rule allows everyone.
  it.each(['in', 'nin', 'subset_of', 'superset_of'])('rejects a string operand on "%s"', (operator) => {
    expect(codesFor({ field: 'subject.attributes.dept', operator, value: 'eng' })).toContain('OPERAND_TYPE_MISMATCH')
  })

  it.each(['gt', 'gte', 'lt', 'lte'])('rejects a string operand on "%s"', (operator) => {
    expect(codesFor({ field: 'subject.attributes.age', operator, value: '18' })).toContain('OPERAND_TYPE_MISMATCH')
  })

  it.each(['starts_with', 'ends_with', 'matches'])('rejects a numeric operand on "%s"', (operator) => {
    expect(codesFor({ field: 'subject.attributes.dept', operator, value: 1 })).toContain('OPERAND_TYPE_MISMATCH')
  })

  it('accepts well-typed operands', () => {
    expect(codesFor({ field: 'subject.attributes.dept', operator: 'in', value: ['eng'] })).toEqual([])
    expect(codesFor({ field: 'subject.attributes.age', operator: 'gt', value: 18 })).toEqual([])
    expect(codesFor({ field: 'subject.attributes.dept', operator: 'starts_with', value: 'en' })).toEqual([])
    expect(codesFor({ field: 'subject.attributes.at', operator: 'before', value: '2020-01-01T00:00:00Z' })).toEqual([])
  })

  // A `$`-prefixed operand resolves from the request, so its type is unknowable
  // until evaluation and must not be rejected here.
  it('exempts $-resolved operands from the type check', () => {
    expect(codesFor({ field: 'subject.attributes.dept', operator: 'in', value: '$subject.attributes.depts' })).toEqual(
      [],
    )
  })
})

describe('matches pattern compilability', () => {
  // An uncompilable pattern does not raise at evaluation; `matches` returns
  // `false`, which retires a deny-when-matches rule outright.
  it('rejects a pattern that will not compile', () => {
    expect(codesFor({ field: 'subject.attributes.ua', operator: 'matches', value: '[unclosed' })).toContain(
      'ERR_REGEX_INVALID',
    )
  })

  it('accepts a compilable pattern', () => {
    expect(codesFor({ field: 'subject.attributes.ua', operator: 'matches', value: '^curl' })).toEqual([])
  })
})

/** Walks the schema literal by runtime narrowing, so a new `allOf` branch cannot shift a positional read. */
function readPath(node: unknown, path: readonly string[]): unknown {
  let current = node
  for (const key of path) {
    if (typeof current !== 'object' || current === null) return undefined
    current = Reflect.get(current, key)
  }
  return current
}

/** The operators one `if`/`then` branch constrains, or `[]` for the presence branch. */
function branchOperators(branch: unknown): string[] {
  const list = readPath(branch, ['if', 'properties', 'operator', 'enum'])
  return Array.isArray(list) ? list.filter((v) => typeof v === 'string') : []
}

/** The single operand type a branch declares; `null` for the multi-type and length-only branches. */
function declaredKind(branch: unknown): string | null {
  const value = readPath(branch, ['then', 'properties', 'value'])
  const oneOf = readPath(value, ['oneOf'])
  const type = Array.isArray(oneOf) ? readPath(oneOf[0], ['type']) : readPath(value, ['type'])
  return typeof type === 'string' ? type : null
}

/**
 * The validator and the published schema are two statements of one rule, and a
 * drift between them is how a policy passes one and fails the other. Rather
 * than exporting the validator's table, drive the validator from the schema.
 */
describe('POLICY_JSON_SCHEMA agrees with the validator', () => {
  it('exempts exactly exists/not_exists from requiring a value', () => {
    const exempt = POLICY_JSON_SCHEMA.$defs.condition.allOf
      .map((branch) => readPath(branch, ['if', 'properties', 'operator', 'not', 'enum']))
      .find((value) => Array.isArray(value))
    expect(exempt).toEqual(['exists', 'not_exists'])
  })

  it('rejects a wrongly-typed operand for every operator the schema constrains', () => {
    const wrongOperand: Record<string, unknown> = { array: 'x', number: 'x', string: 1 }
    let checked = 0
    for (const branch of POLICY_JSON_SCHEMA.$defs.condition.allOf) {
      // `before`/`after` declare two types and the length branches declare none;
      // any scalar satisfies the first and every type the second.
      const kind = declaredKind(branch)
      if (kind === null || !(kind in wrongOperand)) continue
      for (const operator of branchOperators(branch)) {
        checked++
        expect(codesFor({ field: 'subject.attributes.x', operator, value: wrongOperand[kind] })).toContain(
          'OPERAND_TYPE_MISMATCH',
        )
      }
    }
    // Without this the loop would pass by covering nothing.
    expect(checked).toBe(11)
  })
})
