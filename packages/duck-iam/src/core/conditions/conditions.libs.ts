import { iamResolve } from '../resolve'
import type { IamAccessControl, IamPrimitives, IamRequest } from '../types'

/**
 * Max allowed regex pattern length to mitigate ReDoS. Catastrophic
 * backtracking patterns are tiny (e.g. `(a+)+$`), so a tight bound here is
 * appropriate - larger patterns only give attackers more rope.
 */
export const IAM_MAX_REGEX_LENGTH = 128

/**
 * Hard cap on the candidate input string handed to `RegExp.test()`.
 *
 * Even if a catastrophic pattern slips past static detection, capping the
 * input length bounds worst-case backtracking work. Strings longer than this
 * cause the `matches` operator to throw {@link IamRegexInputTooLargeError}, which
 * the evaluator catches and treats as a policy error (NotApplicable). Returning
 * `false` instead would flip `deny`-when-`matches` rules to allow on
 * adversarially-long input.
 */
export const IAM_MAX_REGEX_INPUT_LENGTH = 2048

/**
 * Thrown by the `matches` operator when the candidate string exceeds
 * {@link IAM_MAX_REGEX_INPUT_LENGTH}.
 *
 * Carried as a tagged error so the evaluator's `safeEval` can route it through
 * `onPolicyError` and mark the entire policy as NotApplicable. Critically, we
 * do NOT silently return `false`: a `false` result from a `matches` operator
 * inside a `deny` rule would flip the rule's effect to "condition not met ->
 * allow". By throwing, the whole policy drops out of the decision instead of
 * silently becoming permissive.
 */
export class IamRegexInputTooLargeError extends Error {
  readonly name = 'IamRegexInputTooLargeError'
  readonly tag = 'duck-iam/regex-input-too-large'
  readonly field: string
  readonly length: number
  constructor(field: string, length: number) {
    super(
      `[@gentleduck/iam:conditions] matches input on field "${field}" is ${length} bytes (> IAM_MAX_REGEX_INPUT_LENGTH=${IAM_MAX_REGEX_INPUT_LENGTH}); policy dropped as NotApplicable.`,
    )
    this.field = field
    this.length = length
  }
}

/**
 * LRU cache capacity for compiled regex patterns. Shared by both the
 * process-wide default cache and per-instance caches an engine may pass in.
 */
export const IAM_REGEX_CACHE_MAX = 256

/**
 * Default process-wide LRU cache for compiled regex patterns. Used when a
 * caller does not pass a per-instance cache. Multi-tenant deployments should
 * prefer per-Engine caches to prevent cross-tenant eviction.
 */
export const iamRegexCache = new Map<string, RegExp>()

/**
 * Retrieve a cached compiled regex, or compile and cache it.
 * Returns `null` if the pattern is invalid.
 *
 * On a cache hit the entry is re-inserted so iteration order becomes recency
 * order; eviction then drops the *least recently used* pattern instead of
 * the oldest-inserted one. Without this, a hot pattern compiled early gets
 * evicted as soon as IAM_REGEX_CACHE_MAX cold patterns roll through.
 *
 * @param pattern - Regex source string.
 * @param cache - Optional per-instance Map. Falls back to the module-global
 *   `iamRegexCache` when omitted. Engine instances pass their own cache to
 *   prevent cross-tenant eviction.
 * @returns The compiled `RegExp`, or `null` when the pattern fails to compile.
 */
/**
 * Drop every entry in the process-wide regex cache. Intended for multi-tenant
 * operators who flush periodically to bound any single tenant's eviction
 * influence. Per-instance caches passed via the optional `cache` argument to
 * {@link iamGetCachedRegex} are NOT affected.
 */
export function iamClearRegexCache(): void {
  iamRegexCache.clear()
}

// Patterns containing nested quantifiers — `(a+)+`, `(a*)*`, `(a|aa)+` — are
// the textbook ReDoS shape that turns into super-linear backtracking. The cheap
// detection here rejects the obvious forms before they reach `new RegExp`.
// It is not a complete catastrophic-backtracking analyser; the length cap in
// `matches` keeps the residual risk bounded.
const NESTED_QUANTIFIER_RE = /\([^)]*[*+?][^)]*\)[*+?{]/

export function iamGetCachedRegex(pattern: string, cache: Map<string, RegExp> = iamRegexCache): RegExp | null {
  if (NESTED_QUANTIFIER_RE.test(pattern)) return null
  const cached = cache.get(pattern)
  if (cached) {
    cache.delete(pattern)
    cache.set(pattern, cached)
    return cached
  }
  try {
    const re = new RegExp(pattern)
    if (cache.size >= IAM_REGEX_CACHE_MAX) {
      const first = cache.keys().next().value
      if (first !== undefined) cache.delete(first)
    }
    cache.set(pattern, re)
    return re
  } catch {
    return null
  }
}

function isScalar(v: IamPrimitives.AttributeValue | undefined): v is IamPrimitives.Scalar {
  return v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
}

/** Record mapping every supported operator to its implementation function. */
export const iamOps: Record<IamAccessControl.Operator, IamAccessControl.OpFn> = {
  eq: (f, v) => f === v,
  neq: (f, v) => f !== v,

  gt: (f, v) => typeof f === 'number' && typeof v === 'number' && f > v,
  gte: (f, v) => typeof f === 'number' && typeof v === 'number' && f >= v,
  lt: (f, v) => typeof f === 'number' && typeof v === 'number' && f < v,
  lte: (f, v) => typeof f === 'number' && typeof v === 'number' && f <= v,

  in: (f, v) => {
    if (!Array.isArray(v)) return false
    if (Array.isArray(f)) return f.some((i) => isScalar(i) && v.includes(i))
    return isScalar(f) && v.includes(f)
  },
  nin: (f, v) => {
    if (!Array.isArray(v)) return true
    if (Array.isArray(f)) return !f.some((i) => isScalar(i) && v.includes(i))
    return !isScalar(f) || !v.includes(f)
  },

  contains: (f, v) => {
    if (Array.isArray(f)) return isScalar(v) && f.includes(v)
    if (typeof f === 'string' && typeof v === 'string') return f.includes(v)
    return false
  },
  not_contains: (f, v) => {
    if (Array.isArray(f)) return !isScalar(v) || !f.includes(v)
    if (typeof f === 'string' && typeof v === 'string') return !f.includes(v)
    return true
  },

  starts_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.startsWith(v),
  ends_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.endsWith(v),

  matches: (f, v) => {
    if (typeof f !== 'string' || typeof v !== 'string') return false
    if (v.length > IAM_MAX_REGEX_LENGTH) return false
    // Throw on oversize input so `deny`-when-`matches` rules do not flip
    // to allow on adversarial inputs; iamEvalCondition() routes it through
    // onPolicyError.
    if (f.length > IAM_MAX_REGEX_INPUT_LENGTH) {
      throw new IamRegexInputTooLargeError('<unknown>', f.length)
    }
    const re = iamGetCachedRegex(v)
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

/** Maximum nesting depth for condition groups to prevent stack overflow. */
export const IAM_MAX_CONDITION_DEPTH = 10

/**
 * Type guard that distinguishes a flat {@link IamAccessControl.ICondition} from a nested {@link IamAccessControl.IConditionGroup}.
 *
 * @param item - Either a leaf condition or a group node.
 * @returns `true` when `item` is a leaf `ICondition`.
 */
export function iamIsCondition(
  item: IamAccessControl.ICondition | IamAccessControl.IConditionGroup,
): item is IamAccessControl.ICondition {
  return 'field' in item
}

/**
 * Resolve a condition value, handling `$`-prefixed variable references.
 * e.g. `$subject.id` resolves to the request's subject.id at eval time.
 *
 * @param req   - The access request providing resolution roots.
 * @param value - Raw condition value (possibly `$`-prefixed reference).
 * @returns The resolved value, or `value` unchanged when no `$` prefix is present.
 */
export function iamResolveValue(
  req: IamRequest.IAccessRequest,
  value: IamPrimitives.AttributeValue,
  caches?: { path?: Map<string, string[] | null> },
): IamPrimitives.AttributeValue {
  if (typeof value === 'string' && value.startsWith('$')) {
    return iamResolve(req, value.slice(1), caches)
  }
  return value
}

/**
 * The `matches` operator compiles the value into a regex. Allowing a
 * `$`-prefixed value to resolve from request attributes would let any
 * attacker who controls a subject/resource/env attribute pin in a
 * catastrophic regex (ReDoS). We refuse `$`-resolved patterns for
 * `matches` regardless of where the attribute came from.
 *
 * @param value - Candidate operand value to inspect.
 * @returns `true` when the value is a `$`-prefixed string reference.
 */
export function iamIsUserSourcedValue(value: IamPrimitives.AttributeValue): boolean {
  return typeof value === 'string' && value.startsWith('$')
}

/**
 * IamEvaluate a single flat condition against an access request.
 *
 * @param req  - The access request providing field values.
 * @param cond - The condition to test.
 * @returns `true` when the operator predicate holds against the resolved field.
 */
export function iamEvalCondition(
  req: IamRequest.IAccessRequest,
  cond: IamAccessControl.ICondition,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (cond.operator === 'matches' && iamIsUserSourcedValue(cond.value ?? null)) return false
  const fieldVal = iamResolve(req, cond.field, caches)
  const condVal = iamResolveValue(req, cond.value ?? null, caches)
  try {
    // Per-Engine regex cache when supplied, module-global fallback.
    if (cond.operator === 'matches') return iamEvalMatchesOp(fieldVal, condVal, caches?.regex)
    return iamOps[cond.operator](fieldVal, condVal)
  } catch (err) {
    if (err instanceof IamRegexInputTooLargeError && err.field === '<unknown>') {
      throw new IamRegexInputTooLargeError(cond.field, err.length)
    }
    throw err
  }
}

/**
 * Per-instance-cache-aware `matches` operator. The module-global `iamOps.matches`
 * uses the process-wide regex cache; this variant accepts an optional cache
 * override so multi-tenant Engine instances can isolate compile pools.
 */
export function iamEvalMatchesOp(
  f: IamPrimitives.AttributeValue,
  v: IamPrimitives.AttributeValue,
  cache?: Map<string, RegExp>,
): boolean {
  if (typeof f !== 'string' || typeof v !== 'string') return false
  if (v.length > IAM_MAX_REGEX_LENGTH) return false
  if (f.length > IAM_MAX_REGEX_INPUT_LENGTH) {
    throw new IamRegexInputTooLargeError('<unknown>', f.length)
  }
  const re = iamGetCachedRegex(v, cache ?? iamRegexCache)
  return re ? re.test(f) : false
}
