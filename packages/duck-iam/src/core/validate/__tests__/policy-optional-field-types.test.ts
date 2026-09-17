import { describe, expect, it } from 'vitest'
import { POLICY_JSON_SCHEMA } from '../../schema'
import { validatePolicy } from '../validate'

/** A minimal policy the validator accepts, so only the field under test can make it fail. */
function base(): Record<string, unknown> {
  return {
    algorithm: 'deny-overrides',
    id: 'p',
    name: 'p',
    rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 1, resources: ['post'] }],
  }
}

function withRule(patch: Record<string, unknown>): Record<string, unknown> {
  const policy = base()
  const rules = policy.rules
  if (Array.isArray(rules)) policy.rules = [{ ...rules[0], ...patch }]
  return policy
}

function errorPaths(policy: unknown): string[] {
  return validatePolicy(policy)
    .issues.filter((i) => i.type === 'error')
    .map((i) => i.path ?? '')
}

const NOT_A_STRING: readonly [string, unknown][] = [
  ['a number', 42],
  ['an object', {}],
  ['an array', ['d']],
  ['null', null],
  ['a boolean', true],
]

const NOT_AN_OBJECT: readonly [string, unknown][] = [
  ['a string', 'x'],
  ['a number', 42],
  ['an array', ['x']],
  ['null', null],
  ['a boolean', true],
]

describe('policy.description', () => {
  it.each(NOT_A_STRING)('%s is an error', (_label, value) => {
    expect(errorPaths({ ...base(), description: value })).toEqual(['description'])
  })

  it.each([
    ['a string', 'a human-readable note'],
    ['an empty string', ''],
    ['absent', undefined],
  ])('%s stays valid', (_label, value) => {
    expect(errorPaths({ ...base(), description: value })).toEqual([])
  })
})

describe('rule.description', () => {
  it.each(NOT_A_STRING)('%s is an error', (_label, value) => {
    expect(errorPaths(withRule({ description: value }))).toEqual(['rules[0].description'])
  })

  it('a string stays valid', () => {
    expect(errorPaths(withRule({ description: 'why this rule exists' }))).toEqual([])
  })
})

describe('rule.metadata', () => {
  it.each(NOT_AN_OBJECT)('%s is an error', (_label, value) => {
    expect(errorPaths(withRule({ metadata: value }))).toEqual(['rules[0].metadata'])
  })

  it.each([
    ['an empty object', {}],
    ['an object with entries', { owner: 'platform', ticket: 42 }],
    ['absent', undefined],
  ])('%s stays valid', (_label, value) => {
    expect(errorPaths(withRule({ metadata: value }))).toEqual([])
  })
})

describe('the published schema types all three', () => {
  it('names them, so the validator is not the only gate that has an opinion', () => {
    const defs = POLICY_JSON_SCHEMA.$defs
    expect({
      policyDescription: POLICY_JSON_SCHEMA.properties.description.type,
      ruleDescription: defs.rule.properties.description.type,
      ruleMetadata: defs.rule.properties.metadata.type,
      targets: POLICY_JSON_SCHEMA.properties.targets.type,
    }).toEqual({
      policyDescription: 'string',
      ruleDescription: 'string',
      ruleMetadata: 'object',
      targets: 'object',
    })
  })
})
