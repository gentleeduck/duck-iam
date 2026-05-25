import type { Engine } from '..'
import { MAX_CONDITION_DEPTH, MAX_REGEX_LENGTH } from '../conditions/conditions.libs'
import { ALLOWED_ROOTS } from '../resolve/resolve'
import type { Validate } from './validate.types'

/**
 * Maximum number of unbounded quantifiers (`+`, `*`, `{n,}`) allowed in a
 * single `matches` pattern. Beyond this the surface area for catastrophic
 * backtracking gets impractical to reason about, so we refuse outright.
 */
export const MAX_UNBOUNDED_QUANTIFIERS = 4

/**
 * Largest finite upper bound permitted in a `{n,m}` quantifier. The matcher
 * walks `m` iterations worst-case, so anything above ~1000 starts to look
 * like a DoS vector even though it isn't technically unbounded.
 */
export const MAX_BOUNDED_QUANTIFIER = 1_000

/**
 * Pure-JS heuristic for catastrophic-backtracking regex patterns. Cheap
 * enough to run at validate-time on every `matches` operator, and tight
 * enough to refuse the common ReDoS shapes:
 *   - nested quantifiers: `(a+)+`, `(a*)*`, `(a+)*`, `(a*)+`
 *   - alternation inside a quantifier: `(a|a)+`, `(foo|bar)*`
 *   - more than {@link MAX_UNBOUNDED_QUANTIFIERS} unbounded quantifiers in
 *     a single pattern
 *   - backreference followed by a quantifier (`(\w+)\1+`, `(?<n>\w+)\k<n>+`)
 *   - bounded quantifier with large upper bound (`a{1,1000000}`)
 *   - lookaround group containing a quantifier (`(?=(a+)+)`)
 *
 * Not a complete safe-regex linter — it deliberately errs on the side of
 * rejection. Patterns deemed unsafe should not even compile, so the runtime
 * never sees them.
 *
 * @param pattern - Raw regex source.
 * @returns `{ safe: true }` when the pattern looks benign, otherwise
 *   `{ safe: false, reason }` with a short human-readable reason.
 */
export function detectCatastrophicRegex(pattern: string): { safe: boolean; reason?: string } {
  if (typeof pattern !== 'string') return { safe: false, reason: 'pattern must be a string' }
  if (pattern.length > MAX_REGEX_LENGTH) {
    return { safe: false, reason: `pattern length ${pattern.length} exceeds MAX_REGEX_LENGTH (${MAX_REGEX_LENGTH})` }
  }

  // Backreference followed by a quantifier — run before the nested-quantifier
  // scan so the more specific reason wins for shapes like `(\w+)\1+`. Numeric
  // (`\1+`, `\3*`, `\2{1,5}`) and named (`\k<name>+`) forms can drive
  // exponential backtracking when the captured group matches a variable-length
  // pattern. Flag any backref+quantifier pair.
  if (/\\[1-9]\d*\s*[+*?{]/.test(pattern) || /\\k<[^>]+>\s*[+*?{]/.test(pattern)) {
    return { safe: false, reason: 'backref-quantifier' }
  }

  // Lookaround group whose body contains a quantifier. Run before the
  // nested-quantifier scan so `(?=(a+)+)` is reported with the more specific
  // reason. JS supports `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`. Walk
  // paren depth and inspect the body of any lookaround for `+`, `*`, or
  // `{...}`.
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]
    if (ch === '\\') {
      i++
      continue
    }
    if (ch !== '(') continue
    const tail3 = pattern.slice(i, i + 3)
    const tail4 = pattern.slice(i, i + 4)
    const isLookahead = tail3 === '(?=' || tail3 === '(?!'
    const isLookbehind = tail4 === '(?<=' || tail4 === '(?<!'
    if (!isLookahead && !isLookbehind) continue
    const bodyStart = i + (isLookahead ? 3 : 4)
    let depth = 1
    let j = bodyStart
    while (j < pattern.length && depth > 0) {
      const cj = pattern[j]
      if (cj === '\\') {
        j += 2
        continue
      }
      if (cj === '(') depth++
      else if (cj === ')') depth--
      if (depth === 0) break
      j++
    }
    if (depth !== 0) continue
    const body = pattern.slice(bodyStart, j)
    const bodyStripped = body.replace(/\\./g, '')
    if (/[+*]/.test(bodyStripped) || /\{\d+,?\d*\}/.test(bodyStripped)) {
      return { safe: false, reason: 'lookaround-with-quantifier' }
    }
    i = j
  }

  // Bounded `{n,m}` with a very large upper bound, or `{n,}` with a very
  // large lower bound. Lone repetitions like `a{5}` are fine; only the
  // comma-form is a range.
  {
    const re = /(?<!\\)\{(\d+)(?:,(\d*))?\}/g
    let m: RegExpExecArray | null
    // biome-ignore lint/suspicious/noAssignInExpressions: classic regex iteration
    while ((m = re.exec(pattern)) !== null) {
      const low = Number(m[1])
      const upperStr = m[2]
      if (upperStr === undefined) continue // `{n}` exact count — not a range.
      if (upperStr === '') {
        if (low > MAX_BOUNDED_QUANTIFIER) {
          return { safe: false, reason: 'bounded-large-quantifier' }
        }
        continue
      }
      const high = Number(upperStr)
      if (Number.isFinite(high) && high > MAX_BOUNDED_QUANTIFIER) {
        return { safe: false, reason: 'bounded-large-quantifier' }
      }
    }
  }

  // Nested quantifiers: a group whose closing `)` is immediately followed by
  // `+`, `*`, or `{n,}` AND whose body itself contains an unbounded quantifier.
  // We walk parens with a depth counter so nested groups are inspected too.
  const stack: number[] = []
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]
    if (ch === '\\') {
      i++
      continue
    }
    if (ch === '(') {
      stack.push(i)
      continue
    }
    if (ch === ')') {
      const openIdx = stack.pop()
      if (openIdx === undefined) continue
      const next = pattern[i + 1]
      const isUnboundedQuant = next === '+' || next === '*' || (next === '{' && /^\{\d+,\}?/.test(pattern.slice(i + 1)))
      if (!isUnboundedQuant) continue
      const body = pattern.slice(openIdx + 1, i)
      // Strip escapes from body before scanning so `\+` doesn't trigger.
      const bodyStripped = body.replace(/\\./g, '')
      if (/[+*]/.test(bodyStripped) || /\{\d+,\d*\}/.test(bodyStripped)) {
        return { safe: false, reason: 'nested quantifier (e.g. `(a+)+`) — catastrophic backtracking risk' }
      }
      if (bodyStripped.includes('|')) {
        return { safe: false, reason: 'alternation inside a quantified group — catastrophic backtracking risk' }
      }
    }
  }

  // Count unbounded quantifiers outside of escapes. `+`, `*`, and `{n,}`
  // each count once.
  let unbounded = 0
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]
    if (ch === '\\') {
      i++
      continue
    }
    if (ch === '+' || ch === '*') {
      unbounded++
      continue
    }
    if (ch === '{') {
      // `{n,}` or `{n,m}` — only `{n,}` (no upper bound) is unbounded.
      const close = pattern.indexOf('}', i)
      if (close === -1) continue
      const inner = pattern.slice(i + 1, close)
      if (/^\d+,\s*$/.test(inner)) unbounded++
      i = close
    }
  }
  if (unbounded > MAX_UNBOUNDED_QUANTIFIERS) {
    return {
      safe: false,
      reason: `${unbounded} unbounded quantifiers exceed limit of ${MAX_UNBOUNDED_QUANTIFIERS}`,
    }
  }

  return { safe: true }
}

/**
 * Field paths longer than this are refused. The runtime DotPath resolver
 * splits on dots, so an enormous field string would cost O(length) work
 * per evaluation with no upside.
 */
export const MAX_FIELD_LENGTH = 256
/**
 * Valid combining algorithm names.
 */
export const VALID_ALGORITHMS = new Set(['deny-overrides', 'allow-overrides', 'first-match', 'highest-priority'])

/**
 * Valid rule effect values.
 */
export const VALID_EFFECTS = new Set(['allow', 'deny'])

/**
 * Validate-time policy size caps.
 *
 * `indexPolicy()` builds an `actions x resources` cartesian per rule, so an
 * unbounded policy can stall the event loop. Limits also cap memory growth
 * in {@link Engine}'s LRU caches.
 */
export const POLICY_LIMITS = {
  rulesPerPolicy: 1_000,
  actionsPerRule: 100,
  resourcesPerRule: 100,
  /** Worst-case cartesian product per rule. */
  cartesianPerRule: 1_000,
} as const

/** Whole-path shorthands accepted alongside the dotted roots. */
const RESOLVABLE_SHORTHANDS = new Set(['action', 'scope'])

/**
 * True when `path` would resolve to a real attribute at evaluation time.
 * Shares {@link ALLOWED_ROOTS} with the resolver so the two stay in lock-step.
 *
 * @param path - Dot-path string to check.
 * @returns `true` when the path's root is a known resolvable root.
 */
export function isResolvablePath(path: string): boolean {
  if (RESOLVABLE_SHORTHANDS.has(path)) return true
  const root = path.split('.', 1)[0]
  return !!root && ALLOWED_ROOTS.has(root)
}

/**
 * Set of valid condition operator names supported by the condition evaluator.
 */
export const VALID_OPERATORS = new Set([
  'eq',
  'neq',
  'gt',
  'gte',
  'lt',
  'lte',
  'in',
  'nin',
  'contains',
  'not_contains',
  'starts_with',
  'ends_with',
  'matches',
  'exists',
  'not_exists',
  'subset_of',
  'superset_of',
])

/**
 * Validate a single condition item (leaf or group).
 *
 * A leaf condition must have a non-empty `field` string and a valid `operator`.
 * If the item does not contain a `field` key it is treated as a condition group
 * and delegated to {@link validateConditionGroup}.
 *
 * @param input  - The condition item to validate.
 * @param path   - Dot-path prefix used in reported issues.
 * @param issues - Array to push validation issues into.
 * @param depth  - Current nesting depth (defaults to `0`; bounded by `MAX_CONDITION_DEPTH`).
 */
export function validateConditionItem(input: unknown, path: string, issues: Validate.IIssue[], depth = 0): void {
  if (typeof input !== 'object' || input === null) {
    issues.push({
      type: 'error',
      code: 'INVALID_CONDITION',
      message: 'Condition must be an object',
      path,
    })
    return
  }

  const obj = input as Record<string, unknown>

  if ('field' in obj) {
    if (typeof obj.field !== 'string' || !obj.field) {
      issues.push({
        type: 'error',
        code: 'MISSING_FIELD',
        message: 'Condition must have a non-empty string "field"',
        path: `${path}.field`,
      })
    } else if (obj.field.length > MAX_FIELD_LENGTH) {
      issues.push({
        type: 'error',
        code: 'LIMIT_EXCEEDED',
        message: `Condition field is ${obj.field.length} chars; limit is ${MAX_FIELD_LENGTH}`,
        path: `${path}.field`,
      })
    } else if (!isResolvablePath(obj.field)) {
      issues.push({
        type: 'warning',
        code: 'UNRESOLVABLE_FIELD',
        message: `Condition field "${obj.field}" has no resolvable root (expected subject/resource/environment, or shorthand action/scope)`,
        path: `${path}.field`,
      })
    }
    if (!VALID_OPERATORS.has(obj.operator as string)) {
      issues.push({
        type: 'error',
        code: 'INVALID_OPERATOR',
        message: `Invalid operator "${String(obj.operator)}"`,
        path: `${path}.operator`,
      })
    }
    if (typeof obj.value === 'string' && obj.value.startsWith('$') && !isResolvablePath(obj.value.slice(1))) {
      issues.push({
        type: 'warning',
        code: 'UNRESOLVABLE_VALUE',
        message: `Condition value "${obj.value}" references an unresolvable path`,
        path: `${path}.value`,
      })
    }
    // `matches` is the only operator that compiles its value into a regex.
    // Refuse catastrophic patterns at validate-time so they never reach the
    // policy store. Non-string / $-resolved values are caught elsewhere.
    if (obj.operator === 'matches' && typeof obj.value === 'string' && !obj.value.startsWith('$')) {
      const result = detectCatastrophicRegex(obj.value)
      if (!result.safe) {
        issues.push({
          type: 'error',
          code: 'ERR_REGEX_CATASTROPHIC',
          message: `Condition "matches" pattern rejected: ${result.reason}`,
          path: `${path}.value`,
        })
      }
    }
  } else {
    validateConditionGroup(input, path, issues, depth)
  }
}

/**
 * Validate a condition group (`all`, `any`, or `none`).
 *
 * The group must be an object containing exactly one of the keys `all`, `any`,
 * or `none`, whose value must be an array of condition items.
 *
 * @param input  - The condition group to validate.
 * @param path   - Dot-path prefix used in reported issues.
 * @param issues - Array to push validation issues into.
 * @param depth  - Current nesting depth (defaults to `0`; bounded by `MAX_CONDITION_DEPTH`).
 */
export function validateConditionGroup(input: unknown, path: string, issues: Validate.IIssue[], depth = 0): void {
  if (depth > MAX_CONDITION_DEPTH) {
    issues.push({
      type: 'error',
      code: 'LIMIT_EXCEEDED',
      message: `Condition nesting exceeds MAX_CONDITION_DEPTH (${MAX_CONDITION_DEPTH})`,
      path,
    })
    return
  }
  if (typeof input !== 'object' || input === null) {
    issues.push({
      type: 'error',
      code: 'INVALID_CONDITION',
      message: 'Condition group must be an object',
      path,
    })
    return
  }

  const obj = input as Record<string, unknown>
  const groupKey = ['all', 'any', 'none'].find((k) => k in obj)

  if (!groupKey) {
    issues.push({
      type: 'error',
      code: 'INVALID_CONDITION',
      message: 'Condition group must have "all", "any", or "none" key',
      path,
    })
    return
  }

  const items = obj[groupKey]
  if (!Array.isArray(items)) {
    issues.push({
      type: 'error',
      code: 'INVALID_CONDITION',
      message: `"${groupKey}" must be an array`,
      path: `${path}.${groupKey}`,
    })
    return
  }

  for (const [i, item] of items.entries()) {
    validateConditionItem(item, `${path}.${groupKey}[${i}]`, issues, depth + 1)
  }
}

/**
 * Validate the shape of a single rule object.
 *
 * Checks that all required fields (`id`, `effect`, `priority`, `actions`,
 * `resources`) are present and have the correct types. Optionally validates
 * nested `conditions` via {@link validateConditionGroup}.
 *
 * @param input - The rule object to validate.
 * @param path - Dot-path prefix used in reported issues.
 * @param issues - Array to push validation issues into.
 */
export function validateRuleShape(input: unknown, path: string, issues: Validate.IIssue[]): void {
  if (typeof input !== 'object' || input === null) {
    issues.push({ type: 'error', code: 'INVALID_RULE', message: 'Rule must be an object', path })
    return
  }

  const rule = input as Record<string, unknown>

  if (typeof rule.id !== 'string' || !rule.id) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Rule must have a non-empty string "id"',
      path: `${path}.id`,
    })
  }

  if (!VALID_EFFECTS.has(rule.effect as string)) {
    issues.push({
      type: 'error',
      code: 'INVALID_EFFECT',
      message: `Invalid effect "${String(rule.effect)}". Must be "allow" or "deny"`,
      path: `${path}.effect`,
    })
  }

  if (typeof rule.priority !== 'number' || !Number.isFinite(rule.priority)) {
    issues.push({
      type: 'error',
      code: 'INVALID_TYPE',
      message: 'Rule "priority" must be a finite number (NaN/Infinity break highest-priority ranking)',
      path: `${path}.priority`,
    })
  }

  if (!Array.isArray(rule.actions) || rule.actions.length === 0) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Rule must have a non-empty "actions" array',
      path: `${path}.actions`,
    })
  } else {
    if (rule.actions.length > POLICY_LIMITS.actionsPerRule) {
      issues.push({
        type: 'error',
        code: 'LIMIT_EXCEEDED',
        message: `Rule has ${rule.actions.length} actions; limit is ${POLICY_LIMITS.actionsPerRule}`,
        path: `${path}.actions`,
      })
    }
    for (const [i, action] of (rule.actions as unknown[]).entries()) {
      if (typeof action !== 'string') {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: 'Action must be a string',
          path: `${path}.actions[${i}]`,
        })
      }
    }
  }

  if (!Array.isArray(rule.resources) || rule.resources.length === 0) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Rule must have a non-empty "resources" array',
      path: `${path}.resources`,
    })
  } else {
    if (rule.resources.length > POLICY_LIMITS.resourcesPerRule) {
      issues.push({
        type: 'error',
        code: 'LIMIT_EXCEEDED',
        message: `Rule has ${rule.resources.length} resources; limit is ${POLICY_LIMITS.resourcesPerRule}`,
        path: `${path}.resources`,
      })
    }
    for (const [i, resource] of (rule.resources as unknown[]).entries()) {
      if (typeof resource !== 'string') {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: 'Resource must be a string',
          path: `${path}.resources[${i}]`,
        })
      }
    }
  }

  // Broad-allow warning: `effect: 'allow'` + `actions: ['*']` + `resources: ['*']`
  // + zero conditions grants every operation to every subject the policy applies to.
  // Intent is ambiguous from the policy alone (super-admin vs. mistake) - surface
  // for review so the operator confirms once.
  if (rule.effect === 'allow' && Array.isArray(rule.actions) && Array.isArray(rule.resources)) {
    const allActions = rule.actions.length === 1 && rule.actions[0] === '*'
    const allResources = rule.resources.length === 1 && rule.resources[0] === '*'
    const cond = rule.conditions as { all?: unknown[]; any?: unknown[]; none?: unknown[] } | undefined
    const hasConditions =
      !!cond && ((cond.all?.length ?? 0) > 0 || (cond.any?.length ?? 0) > 0 || (cond.none?.length ?? 0) > 0)
    if (allActions && allResources && !hasConditions) {
      issues.push({
        type: 'warning',
        code: 'BROAD_ALLOW',
        message:
          'Rule allows every action on every resource with no conditions. This is the broadest possible grant - confirm it is intentional.',
        path,
      })
    }
  }

  // Indexer cost is actions x resources per rule. Bound the cartesian even when
  // each list passes its own cap, so a 99x99 rule doesn't slip through.
  if (Array.isArray(rule.actions) && Array.isArray(rule.resources)) {
    const cartesian = rule.actions.length * rule.resources.length
    if (cartesian > POLICY_LIMITS.cartesianPerRule) {
      issues.push({
        type: 'error',
        code: 'LIMIT_EXCEEDED',
        message: `Rule actionxresource cartesian is ${cartesian}; limit is ${POLICY_LIMITS.cartesianPerRule}`,
        path,
      })
    }
  }

  if (rule.conditions !== undefined) {
    validateConditionGroup(rule.conditions, `${path}.conditions`, issues)
  }
}
