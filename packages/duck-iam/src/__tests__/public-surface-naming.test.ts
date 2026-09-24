import { describe, expect, it } from 'vitest'
import * as Iam from '../index'

// The root is one flat `export *` namespace, so exports carry an `Iam` / `iam` / `IAM_` prefix to avoid collisions.
// Known unprefixed names; this list may shrink but never grow.
const UNPREFIXED_BACKLOG = [
  'MAX_INHERITANCE_DEPTH',
  'PATH_CACHE_MAX',
  'POLICY_JSON_SCHEMA',
  'PolicyBuilder',
  'RoleBuilder',
  'RuleBuilder',
  'VALID_POLICY_COMBINES',
  'When',
  'asIamError',
  'clearPathCache',
  'createIam',
  'definePolicy',
  'defineRole',
  'defineRule',
  'explainEvaluation',
  'hasIamErrorCode',
  'matchesAction',
  'matchesResource',
  'matchesResourceHierarchical',
  'matchesScope',
  'metaOf',
  'resolve',
  'resolveEffectiveRoles',
  'rethrowIamError',
  'rolesToPolicy',
  'throwIamError',
  'when',
]

function unprefixedRootExports(): string[] {
  return Object.keys(Iam)
    .filter((name) => !/^(Iam|iam|IAM_)/.test(name))
    .sort()
}

describe('package root naming', () => {
  it('adds no unprefixed export beyond the known backlog', () => {
    expect(unprefixedRootExports().filter((n) => !UNPREFIXED_BACKLOG.includes(n))).toEqual([])
  })

  // Positive control: a stale backlog entry would hide a rename.
  it('every backlog entry is still exported', () => {
    expect(UNPREFIXED_BACKLOG.filter((n) => !Object.hasOwn(Iam, n))).toEqual([])
  })
})

/** Root names from `export * from './conditions'`; the barrel adds the prefix, implementation modules do not. */
const CONDITIONS_EXPORTS = [
  'IAM_MAX_BOUNDED_QUANTIFIER',
  'IAM_MAX_CONDITION_DEPTH',
  'IAM_MAX_REGEX_INPUT_LENGTH',
  'IAM_MAX_REGEX_LENGTH',
  'IAM_MAX_UNBOUNDED_QUANTIFIERS',
  'IAM_REGEX_CACHE_MAX',
  'iamClearRegexCache',
  'iamDetectCatastrophicRegex',
  'iamEvalCondition',
  'iamEvalConditionGroup',
  'iamEvaluateOperator',
  'iamGetCachedRegex',
  'iamIsCondition',
  'iamIsUserSourcedValue',
  'iamMatchesUnconditionally',
  'iamResolveConditionValue',
  'iamResolveValue',
] as const

describe('core/conditions exports', () => {
  it.each(CONDITIONS_EXPORTS)('%s is on the root under its prefixed name', (name) => {
    expect(Object.hasOwn(Iam, name)).toBe(true)
  })

  it('the regex-input limit is reachable', () => {
    expect(Iam.IAM_MAX_REGEX_INPUT_LENGTH).toBeGreaterThan(0)
  })

  // All six limits `conditions.libs` enforces, so one set of thresholds comes from one entrypoint.
  it('puts every condition limit on the root', () => {
    const limits = Object.keys(Iam).filter((n) => n.startsWith('IAM_MAX_') || n.startsWith('IAM_REGEX_'))
    expect(limits.sort()).toEqual([
      'IAM_MAX_BOUNDED_QUANTIFIER',
      'IAM_MAX_CONDITION_DEPTH',
      'IAM_MAX_REGEX_INPUT_LENGTH',
      'IAM_MAX_REGEX_LENGTH',
      'IAM_MAX_UNBOUNDED_QUANTIFIERS',
      'IAM_REGEX_CACHE_MAX',
    ])
    for (const name of limits) expect(Reflect.get(Iam, name)).toBeGreaterThan(0)
  })

  // Either name pre-flights against what the evaluator enforces.
  it('agrees with the validate chunk on the shared limits', async () => {
    const validate = await import('../core/validate')
    expect(Iam.IAM_MAX_BOUNDED_QUANTIFIER).toBe(validate.MAX_BOUNDED_QUANTIFIER)
    expect(Iam.IAM_MAX_UNBOUNDED_QUANTIFIERS).toBe(validate.MAX_UNBOUNDED_QUANTIFIERS)
  })
})
