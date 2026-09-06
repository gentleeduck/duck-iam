import { describe, expect, it } from 'vitest'
import { MAX_CONDITION_DEPTH } from '../../conditions/conditions.libs'
import { validatePolicy } from '../../validate'
import { MAX_CONDITION_VALUE_LENGTH, MAX_FIELD_LENGTH, POLICY_LIMITS } from '../../validate/validate.libs'
import { POLICY_JSON_SCHEMA } from '../'

/**
 * The schema is published at `@gentleduck/iam/core/schema` so operators can gate
 * policies in an admin UI or in CI, which makes "schema-valid" read as "the
 * runtime will accept and honour this". It did not: the schema was stricter on
 * structure (`additionalProperties: false`, the group `oneOf`) and carried none
 * of the limits the runtime enforces, so tooling green-lit policies
 * `admin.import` refuses and refused shapes `admin.import` accepts.
 *
 * The contract pinned here is one-directional and exact: anything
 * `validatePolicy` accepts, the schema accepts. The four checks that JSON
 * Schema cannot express are enumerated below, each with a case.
 */

/** Minimal Draft 2020-12 evaluator - only the keywords `POLICY_JSON_SCHEMA` uses. */
function deref(ref: string, root: unknown): unknown {
  let node = root
  for (const segment of ref.split('/').slice(1)) {
    if (typeof node !== 'object' || node === null) return undefined
    node = Reflect.get(node, segment)
  }
  return node
}

function typeMatches(kind: unknown, value: unknown): boolean {
  switch (kind) {
    case 'object':
      return typeof value === 'object' && value !== null && !Array.isArray(value)
    case 'array':
      return Array.isArray(value)
    case 'string':
      return typeof value === 'string'
    case 'number':
      return typeof value === 'number'
    case 'boolean':
      return typeof value === 'boolean'
    case 'null':
      return value === null
    default:
      return false
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function matches(schema: unknown, value: unknown, root: unknown): boolean {
  if (typeof schema === 'boolean') return schema
  if (!isRecord(schema)) return true
  const get = (key: string): unknown => schema[key]

  const ref = get('$ref')
  if (typeof ref === 'string' && !matches(deref(ref, root), value, root)) return false

  const type = get('type')
  if (typeof type === 'string' && !typeMatches(type, value)) return false
  if (Array.isArray(type) && !type.some((kind) => typeMatches(kind, value))) return false

  const allowed = get('enum')
  if (Array.isArray(allowed) && !allowed.includes(value)) return false

  const negated = get('not')
  if (negated !== undefined && matches(negated, value, root)) return false

  const oneOf = get('oneOf')
  if (Array.isArray(oneOf) && oneOf.filter((sub) => matches(sub, value, root)).length !== 1) return false

  const allOf = get('allOf')
  if (Array.isArray(allOf) && !allOf.every((sub) => matches(sub, value, root))) return false

  const condition = get('if')
  if (condition !== undefined) {
    const branch = matches(condition, value, root) ? get('then') : get('else')
    if (branch !== undefined && !matches(branch, value, root)) return false
  }

  if (typeof value === 'string') {
    const min = get('minLength')
    const max = get('maxLength')
    const pattern = get('pattern')
    if (typeof min === 'number' && value.length < min) return false
    if (typeof max === 'number' && value.length > max) return false
    if (typeof pattern === 'string' && !new RegExp(pattern, 'u').test(value)) return false
  }

  if (Array.isArray(value)) {
    const min = get('minItems')
    const max = get('maxItems')
    const items = get('items')
    if (typeof min === 'number' && value.length < min) return false
    if (typeof max === 'number' && value.length > max) return false
    if (items !== undefined && !value.every((entry) => matches(items, entry, root))) return false
  }

  if (isRecord(value)) {
    // A key set to `undefined` is treated as absent, matching both
    // `JSON.stringify` and `checkKnownKeys`; nothing else would ever see it.
    const present = Object.entries(value).filter(([, entry]) => entry !== undefined)
    const required = get('required')
    if (Array.isArray(required) && !required.every((key) => present.some(([name]) => name === key))) return false
    const properties = get('properties')
    if (isRecord(properties)) {
      for (const [key, entry] of present) {
        const sub = properties[key]
        if (sub !== undefined && !matches(sub, entry, root)) return false
      }
      if (get('additionalProperties') === false && present.some(([key]) => !(key in properties))) return false
    } else if (get('additionalProperties') === false && present.length > 0) {
      return false
    }
  }

  return true
}

function schemaAccepts(policy: unknown): boolean {
  return matches(POLICY_JSON_SCHEMA, policy, POLICY_JSON_SCHEMA)
}

function basePolicy(): Record<string, unknown> {
  return {
    algorithm: 'first-match',
    id: 'p',
    name: 'p',
    rules: [
      {
        actions: ['read'],
        conditions: { all: [{ field: 'subject.attributes.tier', operator: 'eq', value: 'gold' }] },
        effect: 'allow',
        id: 'r',
        priority: 1,
        resources: ['post'],
      },
    ],
  }
}

/** Replaces the single rule's `conditions` group, leaving the policy otherwise valid. */
function policyWithConditions(conditions: unknown): Record<string, unknown> {
  const policy = basePolicy()
  const rules = policy.rules
  if (Array.isArray(rules) && isRecord(rules[0])) rules[0].conditions = conditions
  return policy
}

/** `{ all: [ { all: [ ... ] } ] }` nested `levels` groups deep, innermost holding one leaf. */
function nest(levels: number, key: 'all' | 'any' | 'none' = 'all'): Record<string, unknown> {
  let node: Record<string, unknown> = { [key]: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] }
  for (let i = 1; i < levels; i++) node = { [key]: [node] }
  return node
}

describe('the mini evaluator is able to fail', () => {
  it('accepts the base policy', () => {
    expect(schemaAccepts(basePolicy())).toBe(true)
  })

  it.each([
    ['a non-object', 42],
    ['a missing id', { ...basePolicy(), id: undefined }],
    ['an unknown algorithm', { ...basePolicy(), algorithm: 'random' }],
    ['a non-array rules', { ...basePolicy(), rules: {} }],
    ['an unknown operator', policyWithConditions({ all: [{ field: 'subject.id', operator: 'sorta_eq', value: 1 }] })],
  ])('rejects %s', (_label, policy) => {
    expect(schemaAccepts(policy)).toBe(false)
  })
})

/**
 * The one guarantee that holds in every case: a policy the runtime honours
 * always passes the published schema, so a schema gate never blocks a policy
 * that would have worked.
 */
describe('validatePolicy accepts nothing the schema rejects', () => {
  const CORPUS: readonly [string, unknown][] = [
    ['the base policy', basePolicy()],
    [
      'a policy with every optional field',
      { ...basePolicy(), description: 'd', targets: { actions: ['read'] }, version: 2 },
    ],
    ['an empty condition group', policyWithConditions({ all: [] })],
    ['an any group', policyWithConditions({ any: [{ field: 'action', operator: 'eq', value: 'read' }] })],
    ['a none group', policyWithConditions({ none: [{ field: 'action', operator: 'eq', value: 'read' }] })],
    ['a valueless operator', policyWithConditions({ all: [{ field: 'subject.id', operator: 'exists' }] })],
    [
      'a $-resolved operand',
      policyWithConditions({ all: [{ field: 'subject.id', operator: 'in', value: '$resource.attributes.owners' }] }),
    ],
    [
      'a temporal operand',
      policyWithConditions({ all: [{ field: 'environment.now', operator: 'before', value: '2030-01-01' }] }),
    ],
    [
      'a nested mixed group',
      policyWithConditions({ all: [{ any: [{ field: 'action', operator: 'eq', value: 'read' }] }] }),
    ],
    [
      `a group nested to exactly MAX_CONDITION_DEPTH (${MAX_CONDITION_DEPTH})`,
      policyWithConditions(nest(MAX_CONDITION_DEPTH)),
    ],
    ['a group nested to the cap with any', policyWithConditions(nest(MAX_CONDITION_DEPTH, 'any'))],
    [
      'a field at exactly MAX_FIELD_LENGTH',
      policyWithConditions({
        all: [{ field: `subject.attributes.${'a'.repeat(MAX_FIELD_LENGTH - 20)}`, operator: 'exists' }],
      }),
    ],
    [
      'a value at exactly MAX_CONDITION_VALUE_LENGTH',
      policyWithConditions({
        all: [{ field: 'subject.id', operator: 'eq', value: 'x'.repeat(MAX_CONDITION_VALUE_LENGTH) }],
      }),
    ],
    [
      'a rule with metadata and a description',
      {
        ...basePolicy(),
        rules: [
          {
            actions: ['read'],
            conditions: { all: [] },
            description: 'd',
            effect: 'allow',
            id: 'r',
            metadata: { owner: 'team' },
            priority: 1,
            resources: ['post'],
          },
        ],
      },
    ],
    [
      'a wildcard deny rule',
      {
        algorithm: 'deny-overrides',
        id: 'p',
        name: 'p',
        rules: [{ actions: ['*'], conditions: { all: [] }, effect: 'deny', id: 'r', priority: 1, resources: ['*'] }],
      },
    ],
    [
      'the maximum rule count',
      {
        ...basePolicy(),
        rules: Array.from({ length: POLICY_LIMITS.rulesPerPolicy }, (_, i) => ({
          actions: ['read'],
          conditions: { all: [] },
          effect: 'allow',
          id: `r${i}`,
          priority: 1,
          resources: ['post'],
        })),
      },
    ],
    [
      'the maximum actions per rule',
      {
        ...basePolicy(),
        rules: [
          {
            actions: Array.from({ length: POLICY_LIMITS.actionsPerRule }, (_, i) => `a${i}`),
            conditions: { all: [] },
            effect: 'allow',
            id: 'r',
            priority: 1,
            resources: ['post'],
          },
        ],
      },
    ],
  ]

  it.each(CORPUS)('%s', (_label, policy) => {
    if (!validatePolicy(policy).valid) return
    expect(schemaAccepts(policy)).toBe(true)
  })

  // Without this the block above would pass by having the runtime reject
  // everything, never reaching a schema assertion.
  it('the corpus is one the runtime actually accepts', () => {
    const rejected = CORPUS.filter(([, policy]) => !validatePolicy(policy).valid).map(([label]) => label)
    expect(rejected).toEqual([])
  })
})

/**
 * The reverse implication does not hold, and the schema's own doc block says
 * so. Each case here is a policy the schema cannot fault and the runtime
 * refuses; adding a fifth means the doc block is out of date.
 */
describe('the four checks JSON Schema cannot express', () => {
  const RUNTIME_ONLY: readonly [string, string, unknown][] = [
    [
      'ERR_REGEX_CATASTROPHIC',
      'catastrophic backtracking is a property of the pattern, not of its type',
      policyWithConditions({ all: [{ field: 'subject.attributes.ua', operator: 'matches', value: '(a+)+$' }] }),
    ],
    [
      'ERR_REGEX_INVALID',
      'whether a string compiles as a regex needs a regex engine',
      policyWithConditions({ all: [{ field: 'subject.attributes.ua', operator: 'matches', value: '[' }] }),
    ],
    [
      'LIMIT_EXCEEDED',
      'the actions x resources cartesian cap spans two sibling arrays',
      {
        ...basePolicy(),
        rules: [
          {
            actions: Array.from({ length: 40 }, (_, i) => `a${i}`),
            conditions: { all: [] },
            effect: 'allow',
            id: 'r',
            priority: 1,
            resources: Array.from({ length: 40 }, (_, i) => `res${i}`),
          },
        ],
      },
    ],
    [
      'UNREACHABLE_TARGET',
      'reachability is a relation between targets and rules',
      { ...basePolicy(), targets: { actions: ['publish'] } },
    ],
  ]

  it.each(RUNTIME_ONLY)('%s: the schema accepts it because %s', (code, _why, policy) => {
    expect(schemaAccepts(policy)).toBe(true)
    const result = validatePolicy(policy)
    expect(result.valid).toBe(false)
    expect(result.issues.map((i) => i.code)).toContain(code)
  })

  it('and there are exactly four of them', () => {
    expect(RUNTIME_ONLY).toHaveLength(4)
  })
})

/** The limits the schema now carries, pinned to the constants they mirror. */
describe('the schema declares every runtime cap it can express', () => {
  it('caps the rule count at POLICY_LIMITS.rulesPerPolicy', () => {
    expect(POLICY_JSON_SCHEMA.properties.rules.maxItems).toBe(POLICY_LIMITS.rulesPerPolicy)
  })

  it('caps actions and resources per rule', () => {
    expect(POLICY_JSON_SCHEMA.$defs.rule.properties.actions.maxItems).toBe(POLICY_LIMITS.actionsPerRule)
    expect(POLICY_JSON_SCHEMA.$defs.rule.properties.resources.maxItems).toBe(POLICY_LIMITS.resourcesPerRule)
  })

  it('caps the condition field length', () => {
    expect(POLICY_JSON_SCHEMA.$defs.condition.properties.field.maxLength).toBe(MAX_FIELD_LENGTH)
  })

  it.each([
    [
      'one rule too many',
      {
        ...basePolicy(),
        rules: Array.from({ length: POLICY_LIMITS.rulesPerPolicy + 1 }, (_, i) => ({
          actions: ['read'],
          conditions: { all: [] },
          effect: 'allow',
          id: `r${i}`,
          priority: 1,
          resources: ['post'],
        })),
      },
    ],
    [
      'one action too many',
      {
        ...basePolicy(),
        rules: [
          {
            actions: Array.from({ length: POLICY_LIMITS.actionsPerRule + 1 }, (_, i) => `a${i}`),
            conditions: { all: [] },
            effect: 'allow',
            id: 'r',
            priority: 1,
            resources: ['post'],
          },
        ],
      },
    ],
    [
      'an over-long field',
      policyWithConditions({
        all: [{ field: `subject.attributes.${'a'.repeat(MAX_FIELD_LENGTH)}`, operator: 'exists' }],
      }),
    ],
    [
      'an over-long string operand',
      policyWithConditions({
        all: [{ field: 'subject.id', operator: 'eq', value: 'x'.repeat(MAX_CONDITION_VALUE_LENGTH + 1) }],
      }),
    ],
    [
      'an over-long operand inside an array',
      policyWithConditions({
        all: [{ field: 'subject.id', operator: 'in', value: ['ok', 'x'.repeat(MAX_CONDITION_VALUE_LENGTH + 1)] }],
      }),
    ],
    [
      'a control character in an action',
      {
        ...basePolicy(),
        rules: [
          {
            actions: [`read${String.fromCharCode(0)}`],
            conditions: { all: [] },
            effect: 'allow',
            id: 'r',
            priority: 1,
            resources: ['post'],
          },
        ],
      },
    ],
    [`a group one level past MAX_CONDITION_DEPTH`, policyWithConditions(nest(MAX_CONDITION_DEPTH + 1))],
  ])('rejects %s, as the runtime does', (_label, policy) => {
    expect(schemaAccepts(policy)).toBe(false)
    expect(validatePolicy(policy).valid).toBe(false)
  })
})

/** The group chain is generated from `MAX_CONDITION_DEPTH`; a drift silently re-opens the gap. */
describe('the condition-group $defs chain', () => {
  it(`has exactly MAX_CONDITION_DEPTH (${MAX_CONDITION_DEPTH}) levels`, () => {
    const groups = Object.keys(POLICY_JSON_SCHEMA.$defs).filter((k) => k.startsWith('conditionGroup'))
    expect(groups).toHaveLength(MAX_CONDITION_DEPTH)
  })

  it('still names the entry points `conditionGroup` and `conditionList`', () => {
    expect(POLICY_JSON_SCHEMA.$defs.conditionGroup.oneOf.flatMap((branch) => branch.required)).toEqual([
      'all',
      'any',
      'none',
    ])
    expect(Object.hasOwn(POLICY_JSON_SCHEMA.$defs, 'conditionList')).toBe(true)
  })

  it('admits only leaves at the deepest level', () => {
    const deepest = Reflect.get(POLICY_JSON_SCHEMA.$defs, `conditionList${MAX_CONDITION_DEPTH - 1}`)
    expect(Reflect.get(isRecord(deepest) ? deepest : {}, 'items')).toEqual({ $ref: '#/$defs/condition' })
  })
})

/**
 * Each of these was accepted by the runtime and refused by the schema, which is
 * the direction that matters: the operator's tooling said no, the store said
 * yes, and the half of the policy the engine ignores never came up again.
 */
describe('shapes both the schema and the validator refuse', () => {
  it.each([
    [
      'a group carrying both all and any',
      policyWithConditions({ all: [], any: [{ field: 'action', operator: 'eq', value: 'read' }] }),
    ],
    ['a group carrying all three keys', policyWithConditions({ all: [], any: [], none: [] })],
    ['an unknown key on the policy', { ...basePolicy(), tenant: 'acme' }],
    ['a misspelled targets', { ...basePolicy(), target: { actions: ['publish'] } }],
    ['an unknown key on targets', { ...basePolicy(), targets: { action: ['read'] } }],
    [
      'an unknown key on a rule',
      {
        ...basePolicy(),
        rules: [
          {
            actions: ['read'],
            conditions: { all: [] },
            effect: 'allow',
            id: 'r',
            invert: true,
            priority: 1,
            resources: ['post'],
          },
        ],
      },
    ],
    [
      'an unknown key on a condition',
      policyWithConditions({ all: [{ field: 'subject.id', negate: true, operator: 'eq', value: 'u1' }] }),
    ],
    ['an unknown key on a condition group', policyWithConditions({ all: [], mode: 'strict' })],
    ['a leaf carrying a group key', policyWithConditions({ all: [{ all: [], field: 'subject.id' }] })],
  ])('%s', (_label, policy) => {
    expect(schemaAccepts(policy)).toBe(false)
    expect(validatePolicy(policy).valid).toBe(false)
  })
})

/** Deterministic LCG, fixed seed, so a counterexample is reproducible from the message alone. */
function rng(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0
    return state / 0x1_0000_0000
  }
}

describe('validatePolicy accepts nothing the schema rejects (randomised)', () => {
  it('holds over 4000 generated policies', () => {
    const next = rng(20260903)
    const pick = <T>(pool: readonly T[]): T | undefined => pool[Math.floor(next() * pool.length)]

    const IDS = ['p', '', 'x'.repeat(40), undefined, 7]
    const ALGORITHMS = ['first-match', 'deny-overrides', 'allow-overrides', 'highest-priority', 'nope', undefined]
    const EFFECTS = ['allow', 'deny', 'maybe', undefined]
    const FIELDS = ['subject.id', 'environment.now', 'action', 'nope.x', '', 'a'.repeat(300)]
    const OPERATORS = ['eq', 'in', 'nin', 'matches', 'exists', 'gt', 'before', 'contains', 'sorta_eq', undefined]
    const VALUES = [1, 'x', ['a'], true, null, '$subject.id', 'x'.repeat(1100), '(a+)+$', '[', undefined]
    const EXTRAS = [undefined, undefined, undefined, { negate: true }]
    const LISTS = [['read'], [], ['read', 'write'], [`read${String.fromCharCode(0)}`], 'read', undefined]
    const GROUP_KEYS = ['all', 'any', 'none', 'every']

    const leaf = (): unknown => ({
      field: pick(FIELDS),
      operator: pick(OPERATORS),
      value: pick(VALUES),
      ...pick(EXTRAS),
    })
    const group = (depth: number): unknown => {
      const key = pick(GROUP_KEYS) ?? 'all'
      const size = Math.floor(next() * 3)
      const items = Array.from({ length: size }, () => (depth < 3 && next() < 0.3 ? group(depth + 1) : leaf()))
      return next() < 0.05 ? { [key]: items, any: [] } : { [key]: items }
    }

    const failures: string[] = []
    for (let i = 0; i < 4000; i++) {
      const policy: unknown = JSON.parse(
        JSON.stringify({
          algorithm: pick(ALGORITHMS),
          description: next() < 0.1 ? 'd' : undefined,
          id: pick(IDS),
          name: pick(IDS),
          rules: Array.from({ length: Math.floor(next() * 3) }, (_, r) => ({
            actions: pick(LISTS),
            conditions: group(0),
            effect: pick(EFFECTS),
            id: `r${r}`,
            priority: 1,
            resources: pick(LISTS),
          })),
          targets: next() < 0.1 ? { actions: ['read'] } : undefined,
        }),
      )
      if (validatePolicy(policy).valid && !schemaAccepts(policy)) failures.push(JSON.stringify(policy))
    }
    expect(failures.slice(0, 1)).toEqual([])
  })

  // Without this the loop could pass by generating only policies the runtime
  // rejects, never testing the implication on a single accepted one.
  it('generates policies the runtime accepts', () => {
    const next = rng(20260903)
    const pick = <T>(pool: readonly T[]): T | undefined => pool[Math.floor(next() * pool.length)]
    let accepted = 0
    for (let i = 0; i < 4000; i++) {
      const policy: unknown = JSON.parse(
        JSON.stringify({
          algorithm: pick(['first-match', 'nope']),
          id: 'p',
          name: 'p',
          rules: [
            { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 1, resources: ['post'] },
          ],
        }),
      )
      if (validatePolicy(policy).valid) accepted++
    }
    expect(accepted).toBeGreaterThan(1000)
  })
})
