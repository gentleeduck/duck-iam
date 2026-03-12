import { resolve } from './resolve'
import type { AccessRequest, AttributeValue, Condition, ConditionGroup, Operator, Scalar } from './types'

// --- Operator implementations ---

/** Function signature for a single operator implementation. */
type OpFn = (field: AttributeValue, value: AttributeValue) => boolean

/** Max allowed regex pattern length to mitigate ReDoS */
const MAX_REGEX_LENGTH = 512

/** LRU cache for compiled regex patterns to avoid recompilation on every evaluation */
const REGEX_CACHE_MAX = 256
const regexCache = new Map<string, RegExp>()

function getCachedRegex(pattern: string): RegExp | null {
  const cached = regexCache.get(pattern)
  if (cached) return cached
  try {
    const re = new RegExp(pattern)
    if (regexCache.size >= REGEX_CACHE_MAX) {
      // Evict oldest entry
      const first = regexCache.keys().next().value
      if (first !== undefined) regexCache.delete(first)
    }
    regexCache.set(pattern, re)
    return re
  } catch {
    return null
  }
}

const ops: Record<Operator, OpFn> = {
  eq: (f, v) => f === v,
  neq: (f, v) => f !== v,

  gt: (f, v) => typeof f === 'number' && typeof v === 'number' && f > v,
  gte: (f, v) => typeof f === 'number' && typeof v === 'number' && f >= v,
  lt: (f, v) => typeof f === 'number' && typeof v === 'number' && f < v,
  lte: (f, v) => typeof f === 'number' && typeof v === 'number' && f <= v,

  in: (f, v) => {
    if (!Array.isArray(v)) return false
    if (Array.isArray(f)) return f.some((i) => v.includes(i))
    return v.includes(f as Scalar)
  },
  nin: (f, v) => {
    if (!Array.isArray(v)) return true
    if (Array.isArray(f)) return !f.some((i) => v.includes(i))
    return !v.includes(f as Scalar)
  },

  contains: (f, v) => {
    if (Array.isArray(f)) return f.includes(v as Scalar)
    if (typeof f === 'string' && typeof v === 'string') return f.includes(v)
    return false
  },
  not_contains: (f, v) => {
    if (Array.isArray(f)) return !f.includes(v as Scalar)
    if (typeof f === 'string' && typeof v === 'string') return !f.includes(v)
    return true
  },

  starts_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.startsWith(v),
  ends_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.endsWith(v),

  matches: (f, v) => {
    if (typeof f !== 'string' || typeof v !== 'string') return false
    if (v.length > MAX_REGEX_LENGTH) return false
    const re = getCachedRegex(v)
    return re ? re.test(f) : false
  },

  exists: (f) => f !== null && f !== undefined,
  not_exists: (f) => f === null || f === undefined,

  subset_of: (f, v) => {
    if (!Array.isArray(f) || !Array.isArray(v)) return false
    return f.every((i) => v.includes(i))
  },
  superset_of: (f, v) => {
    if (!Array.isArray(f) || !Array.isArray(v)) return false
    return v.every((i) => f.includes(i))
  },
}

// --- Condition evaluation ---

/** Maximum nesting depth for condition groups to prevent stack overflow */
const MAX_CONDITION_DEPTH = 10

function isCondition(item: Condition | ConditionGroup): item is Condition {
  return 'field' in item
}

/**
 * Resolve a condition value, handling `$`-prefixed variable references.
 * e.g. `$subject.id` resolves to the request's subject.id at eval time.
 */
function resolveValue(req: AccessRequest, value: AttributeValue): AttributeValue {
  if (typeof value === 'string' && value.startsWith('$')) {
    return resolve(req, value.slice(1))
  }
  return value
}

function evalCondition(req: AccessRequest, cond: Condition): boolean {
  const fieldVal = resolve(req, cond.field)
  const condVal = resolveValue(req, cond.value ?? null)
  return ops[cond.operator](fieldVal, condVal)
}

function evalItem(req: AccessRequest, item: Condition | ConditionGroup, depth: number): boolean {
  return isCondition(item) ? evalCondition(req, item) : evalConditionGroup(req, item, depth)
}

/** Evaluate a single operator. Exposed for explain/trace functionality. */
export function evaluateOperator(op: Operator, fieldValue: AttributeValue, condValue: AttributeValue): boolean {
  return ops[op](fieldValue, condValue)
}

/** Resolve $-variable references in condition values against a request. */
export function resolveConditionValue(req: AccessRequest, value: AttributeValue): AttributeValue {
  return resolveValue(req, value)
}

/**
 * Evaluates a condition group tree against an access request.
 *
 * Handles `all` (AND), `any` (OR), and `none` (NOT/NOR) groups recursively.
 * Fails closed (returns `false`) when nesting exceeds `MAX_CONDITION_DEPTH`.
 *
 * @param req   - The access request providing field values
 * @param group - The condition group to evaluate
 * @param depth - Current recursion depth (internal, do not set)
 * @returns Whether the condition group is satisfied
 */
export function evalConditionGroup(req: AccessRequest, group: ConditionGroup, depth = 0): boolean {
  if (depth >= MAX_CONDITION_DEPTH) {
    return false // Deny when nesting is too deep -- fail closed
  }

  if ('all' in group) {
    return group.all.every((item) => evalItem(req, item, depth + 1))
  }

  if ('any' in group) {
    return group.any.some((item) => evalItem(req, item, depth + 1))
  }

  if ('none' in group) {
    return group.none.every((item) => !evalItem(req, item, depth + 1))
  }

  return false
}
