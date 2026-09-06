import { describe, expect, it } from 'vitest'
import * as Iam from '../index'

/**
 * The house convention is an `Iam` / `iam` / `IAM_` prefix on every exported
 * symbol, and the package root is a single flat namespace assembled from
 * `export *`, so an unprefixed name there is one a consumer's own code
 * plausibly collides with. An audit of `core/conditions` found fifteen of them,
 * including a bare `ops`; those are fixed.
 *
 * The rest are listed below rather than waived: the list is allowed to shrink
 * and nothing may be added to it. A new unprefixed export fails this file.
 */
const UNPREFIXED_BACKLOG = [
  'MAX_INHERITANCE_DEPTH',
  'PATH_CACHE_MAX',
  'POLICY_JSON_SCHEMA',
  'PolicyBuilder',
  'RoleBuilder',
  'RuleBuilder',
  'VALID_POLICY_COMBINES',
  'When',
  'clearPathCache',
  'createIam',
  'definePolicy',
  'defineRole',
  'defineRule',
  'explainEvaluation',
  'matchesAction',
  'matchesResource',
  'matchesResourceHierarchical',
  'matchesScope',
  'resolve',
  'resolveEffectiveRoles',
  'rolesToPolicy',
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

  // Positive control: the backlog is a real list of real exports, not a set of
  // names that stopped existing - a stale entry would let the assertion above
  // pass while hiding a rename.
  it('every backlog entry is still exported', () => {
    expect(UNPREFIXED_BACKLOG.filter((n) => !Object.hasOwn(Iam, n))).toEqual([])
  })
})

/**
 * The `core/conditions` scope specifically. These are the names the root
 * inherited from `export * from './conditions'`; the barrel renames each one on
 * the way out, and the implementation modules keep the short name.
 */
const CONDITIONS_EXPORTS = [
  'IAM_MAX_BOUNDED_QUANTIFIER',
  'IAM_MAX_CONDITION_DEPTH',
  'IAM_MAX_REGEX_INPUT_LENGTH',
  'IAM_MAX_REGEX_LENGTH',
  'IAM_MAX_UNBOUNDED_QUANTIFIERS',
  'IAM_REGEX_CACHE_MAX',
  'IamRegexInputTooLargeError',
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

  // The error class and the limit that produces it are both reachable: a
  // consumer could previously catch the `matches` throw only by string-matching
  // the message, because neither was exported from either barrel.
  it('the regex-input error and its limit are both reachable', () => {
    expect(typeof Iam.IamRegexInputTooLargeError).toBe('function')
    expect(Iam.IAM_MAX_REGEX_INPUT_LENGTH).toBeGreaterThan(0)
  })

  /**
   * All six of the limits `conditions.libs` enforces, not the four that
   * happened to be needed first. The two quantifier limits used to be reachable
   * only through `./core/validate` - a separate opt-in chunk - and unprefixed
   * there, so assembling one set of thresholds meant two entrypoints and two
   * naming conventions.
   */
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

  // The root name and the `./core/validate` name are the same number, so a
  // consumer that reaches for either is pre-flighting against what the
  // evaluator actually enforces.
  it('agrees with the validate chunk on the shared limits', async () => {
    const validate = await import('../core/validate')
    expect(Iam.IAM_MAX_BOUNDED_QUANTIFIER).toBe(validate.MAX_BOUNDED_QUANTIFIER)
    expect(Iam.IAM_MAX_UNBOUNDED_QUANTIFIERS).toBe(validate.MAX_UNBOUNDED_QUANTIFIERS)
  })
})
