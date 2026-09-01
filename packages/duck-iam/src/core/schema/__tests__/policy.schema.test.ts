import { describe, expect, it } from 'vitest'
import { PolicyBuilder, RuleBuilder } from '../../builder'
import type { AccessControl } from '../../types'
import { POLICY_JSON_SCHEMA } from '../'

describe('POLICY_JSON_SCHEMA', () => {
  // Smoke checks only - full external validators (ajv, etc.) live in consumer
  // code. We verify the shape so consumers don't import a malformed schema.
  it('declares Draft 2020-12 + required top-level policy fields', () => {
    expect(POLICY_JSON_SCHEMA.$schema).toBe('https://json-schema.org/draft/2020-12/schema')
    expect(POLICY_JSON_SCHEMA.required).toEqual(['id', 'name', 'algorithm', 'rules'])
  })

  it('lists all four combining algorithms', () => {
    expect(POLICY_JSON_SCHEMA.properties.algorithm.enum).toEqual([
      'deny-overrides',
      'allow-overrides',
      'first-match',
      'highest-priority',
    ])
  })

  it('declares every operator the resolver supports', () => {
    const ops = POLICY_JSON_SCHEMA.$defs.condition.properties.operator.enum
    expect(ops).toContain('eq')
    expect(ops).toContain('subset_of')
    expect(ops).toContain('matches')
    expect(ops).toContain('before')
    expect(ops).toContain('after')
    // Closed set; new operators here must be mirrored in core/conditions.
    expect(ops.length).toBe(19)
  })

  it('every required rule field is emitted by RuleBuilder.build()', () => {
    const rule = new Map(Object.entries(new RuleBuilder('r1').on('read').of('post').build()))
    for (const key of POLICY_JSON_SCHEMA.$defs.rule.required) {
      expect(rule.get(key)).toBeDefined()
    }
  })

  it('every required policy field is emitted by PolicyBuilder.build()', () => {
    const policy = new Map(Object.entries(new PolicyBuilder('p1').build()))
    for (const key of POLICY_JSON_SCHEMA.required) {
      expect(policy.get(key)).toBeDefined()
    }
  })

  it('PolicyBuilder output introduces no key the schema forbids', () => {
    const allowed = new Set(Object.keys(POLICY_JSON_SCHEMA.properties))
    const policy = new PolicyBuilder('p1')
      .desc('d')
      .version(1)
      .target({ actions: ['read'] })
      .rule('r1', (r) => r.on('read').of('post'))
      .build()
    expect(Object.keys(policy).filter((k) => !allowed.has(k))).toEqual([])
  })

  it('RuleBuilder output introduces no key the schema forbids', () => {
    const allowed = new Set(Object.keys(POLICY_JSON_SCHEMA.$defs.rule.properties))
    const rule = new RuleBuilder('r1')
      .desc('d')
      .priority(5)
      .on('read')
      .of('post')
      .meta({ a: 1 })
      .when((w) => w.eq('action', 'read'))
      .build()
    expect(Object.keys(rule).filter((k) => !allowed.has(k))).toEqual([])
  })

  it('lists exactly the condition group keys the builders emit', () => {
    const required = POLICY_JSON_SCHEMA.$defs.conditionGroup.oneOf.flatMap((o) => o.required)
    expect(required).toEqual(['all', 'any', 'none'])
  })
})
