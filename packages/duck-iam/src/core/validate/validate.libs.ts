import type { IamEngine } from '..'
import { detectCatastrophicRegex, MAX_CONDITION_DEPTH } from '../conditions/conditions.libs'

// The regex-safety heuristic lives next to `getCachedRegex` so validate-time and
// evaluate-time agree on exactly which patterns are refusable. Re-exported here
// because it was part of this module's public surface.
export {
  detectCatastrophicRegex,
  MAX_BOUNDED_QUANTIFIER,
  MAX_UNBOUNDED_QUANTIFIERS,
} from '../conditions/conditions.libs'

import { ALLOWED_ROOTS } from '../resolve/resolve'
import type { IamValidate } from './validate.types'

function isPlainObjectLike(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/**
 * Field paths longer than this are refused. The runtime DotPath resolver
 * splits on dots, so an enormous field string would cost O(length) work
 * per evaluation with no upside.
 */
export const MAX_FIELD_LENGTH = 256

/** Max allowed length for a string `value` on a condition. */
export const MAX_CONDITION_VALUE_LENGTH = 1024
/** Valid combining algorithm names. */
export const VALID_ALGORITHMS: ReadonlySet<string> = new Set([
  'deny-overrides',
  'allow-overrides',
  'first-match',
  'highest-priority',
])

/**
 * Control characters have no meaning in an action or resource name and are
 * invisible in every UI that would show one, so a name carrying one reads as a
 * different name than it is. Rejected at validation rather than normalized:
 * silently rewriting a name would change which rules a policy matches.
 */
function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code < 0x20 || code === 0x7f) return true
  }
  return false
}

/** Valid rule effect values. */
export const VALID_EFFECTS: ReadonlySet<string> = new Set(['allow', 'deny'])

/**
 * Validate-time policy size caps.
 *
 * `indexPolicy()` builds an `actions x resources` cartesian per rule, so an
 * unbounded policy can stall the event loop. Limits also cap memory growth
 * in {@link IamEngine}'s LRU caches.
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

/** Set of valid condition operator names supported by the condition evaluator. */
export const VALID_OPERATORS: ReadonlySet<string> = new Set([
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
  'before',
  'after',
])

function isCompilableRegex(pattern: string): boolean {
  try {
    new RegExp(pattern)
    return true
  } catch {
    return false
  }
}

/** Operators that read only the field; an operand on them is meaningless. */
const VALUELESS_OPERATORS: ReadonlySet<string> = new Set(['exists', 'not_exists'])

/**
 * The operand type each listed operator compares against. A wrongly-typed
 * operand does not raise at evaluation - it makes the operator return a fixed
 * verdict, and for the negated ones (`nin`, `not_contains`) that verdict is
 * `true`, so an "allow unless denylisted" rule allows everyone. Operators not
 * listed here accept any scalar.
 */
const OPERAND_TYPES: ReadonlyMap<string, 'array' | 'number' | 'string' | 'temporal'> = new Map([
  ['in', 'array'],
  ['nin', 'array'],
  ['subset_of', 'array'],
  ['superset_of', 'array'],
  ['gt', 'number'],
  ['gte', 'number'],
  ['lt', 'number'],
  ['lte', 'number'],
  ['starts_with', 'string'],
  ['ends_with', 'string'],
  ['matches', 'string'],
  ['before', 'temporal'],
  ['after', 'temporal'],
])

function operandHasType(kind: 'array' | 'number' | 'string' | 'temporal', value: unknown): boolean {
  switch (kind) {
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

/**
 * `POLICY_JSON_SCHEMA` sets `additionalProperties: false` on the policy, the
 * rule, the target and the condition, so tooling built on the published schema
 * already refuses an unknown key. Accepting one here left the runtime the more
 * permissive of the two, and an unknown key is rarely inert: a misspelled
 * `targets` / `conditions` / `value` is a restriction the author wrote and the
 * engine silently never applies.
 *
 * A key explicitly set to `undefined` is ignored - `JSON.stringify` drops it,
 * so it reaches neither a store nor an external validator.
 */
export function checkKnownKeys(
  obj: object,
  allowed: ReadonlySet<string>,
  path: string,
  issues: IamValidate.IIssue[],
): void {
  for (const [key, value] of Object.entries(obj)) {
    if (value === undefined || allowed.has(key)) continue
    issues.push({
      type: 'error',
      code: 'UNKNOWN_FIELD',
      message: `Unknown field "${key}"; the policy schema forbids additional properties here`,
      path: path ? `${path}.${key}` : key,
    })
  }
}

/** Keys `POLICY_JSON_SCHEMA` declares on a policy. */
export const POLICY_KEYS: ReadonlySet<string> = new Set([
  'id',
  'name',
  'description',
  'version',
  'algorithm',
  'rules',
  'targets',
])

/** Keys `POLICY_JSON_SCHEMA` declares on `policy.targets`. */
export const TARGET_KEYS: ReadonlySet<string> = new Set(['actions', 'resources', 'roles'])

/** Keys `POLICY_JSON_SCHEMA` declares on a rule. */
const RULE_KEYS: ReadonlySet<string> = new Set([
  'id',
  'effect',
  'description',
  'priority',
  'actions',
  'resources',
  'conditions',
  'metadata',
])

/** Keys `POLICY_JSON_SCHEMA` declares on a leaf condition. */
const CONDITION_KEYS: ReadonlySet<string> = new Set(['field', 'operator', 'value'])

/**
 * Validate one condition item (leaf or group); groups delegate to {@link validateConditionGroup}.
 *
 * @param input  - The condition item to validate.
 * @param path   - Dot-path prefix used in reported issues.
 * @param issues - Array to push validation issues into.
 * @param depth  - Current nesting depth (defaults to `0`; bounded by `MAX_CONDITION_DEPTH`).
 */
export function validateConditionItem(input: unknown, path: string, issues: IamValidate.IIssue[], depth = 0): void {
  if (!isPlainObjectLike(input)) {
    issues.push({
      type: 'error',
      code: 'INVALID_CONDITION',
      message: 'Condition must be an object',
      path,
    })
    return
  }

  const obj = input

  if ('field' in obj) {
    checkKnownKeys(obj, CONDITION_KEYS, path, issues)
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
    const operator = typeof obj.operator === 'string' && VALID_OPERATORS.has(obj.operator) ? obj.operator : null
    if (operator === null) {
      issues.push({
        type: 'error',
        code: 'INVALID_OPERATOR',
        message: `Invalid operator "${String(obj.operator)}"`,
        path: `${path}.operator`,
      })
    } else if (!VALUELESS_OPERATORS.has(operator)) {
      // `JSON.stringify` drops an `undefined` value, so a policy authored with
      // one reaches the engine through any adapter with the key simply absent.
      // There `cond.value ?? null` makes it `null`, which compares equal to a
      // missing attribute - the guard passes for exactly the subjects it was
      // written to exclude. Missing and explicitly-`undefined` are one case.
      if (!('value' in obj) || obj.value === undefined) {
        issues.push({
          type: 'error',
          code: 'MISSING_VALUE',
          message: `Operator "${operator}" requires a "value"`,
          path: `${path}.value`,
        })
      } else if (!(typeof obj.value === 'string' && obj.value.startsWith('$'))) {
        // A `$`-prefixed value resolves from the request at evaluation time, so
        // its type is unknowable here.
        const expected = OPERAND_TYPES.get(operator)
        if (expected !== undefined && !operandHasType(expected, obj.value)) {
          issues.push({
            type: 'error',
            code: 'OPERAND_TYPE_MISMATCH',
            message: `Operator "${operator}" expects ${expected === 'temporal' ? 'a number or ISO-8601 string' : `a ${expected}`} value`,
            path: `${path}.value`,
          })
        }
      }
    }
    if (typeof obj.value === 'string' && obj.value.length > MAX_CONDITION_VALUE_LENGTH) {
      issues.push({
        type: 'error',
        code: 'LIMIT_EXCEEDED',
        message: `Condition value is ${obj.value.length} chars; limit is ${MAX_CONDITION_VALUE_LENGTH}`,
        path: `${path}.value`,
      })
    } else if (Array.isArray(obj.value)) {
      for (const [i, entry] of obj.value.entries()) {
        if (typeof entry === 'string' && entry.length > MAX_CONDITION_VALUE_LENGTH) {
          issues.push({
            type: 'error',
            code: 'LIMIT_EXCEEDED',
            message: `Condition value[${i}] is ${entry.length} chars; limit is ${MAX_CONDITION_VALUE_LENGTH}`,
            path: `${path}.value[${i}]`,
          })
          break
        }
      }
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
      } else if (!isCompilableRegex(obj.value)) {
        // A pattern that will not compile does not raise at evaluation - the
        // operator returns `false`, which retires a `deny`-when-`matches` rule
        // outright. Compiling it here is the only place the failure is visible.
        issues.push({
          type: 'error',
          code: 'ERR_REGEX_INVALID',
          message: 'Condition "matches" pattern is not a valid regular expression',
          path: `${path}.value`,
        })
      }
    }
  } else {
    validateConditionGroup(input, path, issues, depth)
  }
}

/**
 * Validate a condition group `{ all | any | none: ConditionItem[] }`; depth-bounded.
 *
 * @param input  - The condition group to validate.
 * @param path   - Dot-path prefix used in reported issues.
 * @param issues - Array to push validation issues into.
 * @param depth  - Current nesting depth (defaults to `0`; bounded by `MAX_CONDITION_DEPTH`).
 */
export function validateConditionGroup(input: unknown, path: string, issues: IamValidate.IIssue[], depth = 0): void {
  // `evalConditionGroup` refuses a group at `depth >= MAX_CONDITION_DEPTH` and
  // fails closed. Using `>` here would accept exactly one level deeper than the
  // evaluator will ever match, so a deny rule at that depth would validate and
  // then silently stop denying. Keep the two comparisons identical.
  if (depth >= MAX_CONDITION_DEPTH) {
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

  const present = (['all', 'any', 'none'] as const).filter((k) => k in input)

  if (present.length === 0) {
    issues.push({
      type: 'error',
      code: 'INVALID_CONDITION',
      message: 'Condition group must have "all", "any", or "none" key',
      path,
    })
    return
  }

  // `evalConditionGroup` reads one key and ignores the rest, so `{ all, any }`
  // silently drops whichever it does not reach - the schema's `oneOf` refuses
  // the shape and the runtime honoured half of it.
  if (present.length > 1) {
    issues.push({
      type: 'error',
      code: 'INVALID_CONDITION',
      message: `Condition group has ${present.join(' and ')}; exactly one of "all", "any" or "none" is evaluated`,
      path,
    })
    return
  }

  const groupKey = present[0]
  if (groupKey === undefined) return
  if (isPlainObjectLike(input)) checkKnownKeys(input, new Set([groupKey]), path, issues)

  const items = Reflect.get(input, groupKey)
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
 * Validate a Rule's shape (id, effect, priority, actions, resources, optional conditions).
 *
 * @param input  - The rule object to validate.
 * @param path   - Dot-path prefix used in reported issues.
 * @param issues - Array to push validation issues into.
 */
export function validateRuleShape(input: unknown, path: string, issues: IamValidate.IIssue[]): void {
  if (!isPlainObjectLike(input)) {
    issues.push({ type: 'error', code: 'INVALID_RULE', message: 'Rule must be an object', path })
    return
  }

  const rule = input
  checkKnownKeys(rule, RULE_KEYS, path, issues)

  if (typeof rule.id !== 'string' || !rule.id) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Rule must have a non-empty string "id"',
      path: `${path}.id`,
    })
  }

  if (typeof rule.effect !== 'string' || !VALID_EFFECTS.has(rule.effect)) {
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
    for (const [i, action] of rule.actions.entries()) {
      if (typeof action !== 'string') {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: 'Action must be a string',
          path: `${path}.actions[${i}]`,
        })
      } else if (hasControlChar(action)) {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: 'Action must not contain control characters',
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
    for (const [i, resource] of rule.resources.entries()) {
      if (typeof resource !== 'string') {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: 'Resource must be a string',
          path: `${path}.resources[${i}]`,
        })
      } else if (hasControlChar(resource)) {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: 'Resource must not contain control characters',
          path: `${path}.resources[${i}]`,
        })
      }
    }
  }

  // Required by IRule and the JSON schema; evaluate narrows defensively too, but
  // a row that omits it must fail here so it never reaches the engine. Present
  // non-object values fall through to validateConditionGroup below.
  if (rule.conditions === undefined) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Rule must have a "conditions" object (use `{ all: [] }` for an unconditional rule)',
      path: `${path}.conditions`,
    })
  }

  // Warn on unconditional allow * * (super-admin vs. mistake ambiguity).
  if (rule.effect === 'allow' && Array.isArray(rule.actions) && Array.isArray(rule.resources)) {
    const allActions = rule.actions.length === 1 && rule.actions[0] === '*'
    const allResources = rule.resources.length === 1 && rule.resources[0] === '*'
    const conditionArrLen = (cond: unknown, key: string): number => {
      if (cond === null || typeof cond !== 'object') return 0
      const arr = Reflect.get(cond, key)
      return Array.isArray(arr) ? arr.length : 0
    }
    const cond = rule.conditions
    const hasConditions =
      conditionArrLen(cond, 'all') > 0 || conditionArrLen(cond, 'any') > 0 || conditionArrLen(cond, 'none') > 0
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
