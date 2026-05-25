import { resolve } from '../resolve'
import type { AccessControl, Primitives, Request } from '../types'

/**
 * @deprecated Use {@link AccessControl.OpFn}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type OpFn = AccessControl.OpFn

/**
 * Max allowed regex pattern length to mitigate ReDoS.
 *
 * Tightened from 512 -> 128 as part of P1 hardening: catastrophic
 * backtracking patterns are tiny (e.g. `(a+)+$`), so 512 chars only
 * gave attackers more rope. See `audit/audit-issue-P1-redos-matches-operator.md`.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export const MAX_REGEX_LENGTH = 128

/**
 * Hard cap on the candidate input string handed to `RegExp.test()`.
 *
 * Even if a catastrophic pattern slips past static detection, capping the
 * input length bounds worst-case backtracking work. Strings longer than this
 * cause the `matches` operator to throw {@link RegexInputTooLargeError}, which
 * the evaluator catches and treats as a policy error (NotApplicable). Returning
 * `false` instead would flip `deny`-when-`matches` rules to allow on
 * adversarially-long input.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export const MAX_REGEX_INPUT_LENGTH = 2048

/**
 * Thrown by the `matches` operator when the candidate string exceeds
 * {@link MAX_REGEX_INPUT_LENGTH}.
 *
 * Carried as a tagged error so the evaluator's `safeEval` can route it through
 * `onPolicyError` and mark the entire policy as NotApplicable. Critically, we
 * do NOT silently return `false`: a `false` result from a `matches` operator
 * inside a `deny` rule would flip the rule's effect to "condition not met →
 * allow". By throwing, the whole policy drops out of the decision instead of
 * silently becoming permissive.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export class RegexInputTooLargeError extends Error {
  readonly name = 'RegexInputTooLargeError'
  readonly tag = 'duck-iam/regex-input-too-large'
  readonly field: string
  readonly length: number
  constructor(field: string, length: number) {
    super(
      `duck-iam: matches input on field "${field}" is ${length} bytes (> MAX_REGEX_INPUT_LENGTH=${MAX_REGEX_INPUT_LENGTH}); policy dropped as NotApplicable.`,
    )
    this.field = field
    this.length = length
  }
}

/**
 * LRU cache capacity for compiled regex patterns. Shared by both the
 * process-wide default cache and per-instance caches an engine may pass in.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export const REGEX_CACHE_MAX = 256

/**
 * Default process-wide LRU cache for compiled regex patterns. Used when a
 * caller does not pass a per-instance cache. SEC-050: prefer per-Engine
 * caches in multi-tenant deployments to prevent cross-tenant eviction.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export const regexCache = new Map<string, RegExp>()

/**
 * Retrieve a cached compiled regex, or compile and cache it.
 * Returns `null` if the pattern is invalid.
 *
 * On a cache hit the entry is re-inserted so iteration order becomes recency
 * order; eviction then drops the *least recently used* pattern instead of
 * the oldest-inserted one. Without this, a hot pattern compiled early gets
 * evicted as soon as REGEX_CACHE_MAX cold patterns roll through.
 *
 * @param pattern - Regex source string.
 * @param cache - Optional per-instance Map (SEC-050). Falls back to the
 *   module-global `regexCache` when omitted. Engine instances pass their
 *   own cache to prevent cross-tenant eviction.
 * @returns The compiled `RegExp`, or `null` when the pattern fails to compile.
 * @author wildduck2 <https://github.com/wildduck2>
 */
/**
 * SEC-050: drop every entry in the process-wide regex cache. Intended for
 * multi-tenant operators who want to flush periodically to bound any single
 * tenant's eviction influence. Per-instance caches passed via the optional
 * `cache` argument to {@link getCachedRegex} are NOT affected.
 */
export function clearRegexCache(): void {
  regexCache.clear()
}

export function getCachedRegex(pattern: string, cache: Map<string, RegExp> = regexCache): RegExp | null {
  const cached = cache.get(pattern)
  if (cached) {
    cache.delete(pattern)
    cache.set(pattern, cached)
    return cached
  }
  try {
    const re = new RegExp(pattern)
    if (cache.size >= REGEX_CACHE_MAX) {
      const first = cache.keys().next().value
      if (first !== undefined) cache.delete(first)
    }
    cache.set(pattern, re)
    return re
  } catch {
    return null
  }
}

/**
 * Record mapping every supported operator to its implementation function.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export const ops: Record<AccessControl.Operator, AccessControl.OpFn> = {
  eq: (f, v) => f === v,
  neq: (f, v) => f !== v,

  gt: (f, v) => typeof f === 'number' && typeof v === 'number' && f > v,
  gte: (f, v) => typeof f === 'number' && typeof v === 'number' && f >= v,
  lt: (f, v) => typeof f === 'number' && typeof v === 'number' && f < v,
  lte: (f, v) => typeof f === 'number' && typeof v === 'number' && f <= v,

  in: (f, v) => {
    if (!Array.isArray(v)) return false
    if (Array.isArray(f)) return f.some((i) => v.includes(i))
    return v.includes(f as Primitives.Scalar)
  },
  nin: (f, v) => {
    if (!Array.isArray(v)) return true
    if (Array.isArray(f)) return !f.some((i) => v.includes(i))
    return !v.includes(f as Primitives.Scalar)
  },

  contains: (f, v) => {
    if (Array.isArray(f)) return f.includes(v as Primitives.Scalar)
    if (typeof f === 'string' && typeof v === 'string') return f.includes(v)
    return false
  },
  not_contains: (f, v) => {
    if (Array.isArray(f)) return !f.includes(v as Primitives.Scalar)
    if (typeof f === 'string' && typeof v === 'string') return !f.includes(v)
    return true
  },

  starts_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.startsWith(v),
  ends_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.endsWith(v),

  matches: (f, v) => {
    if (typeof f !== 'string' || typeof v !== 'string') return false
    if (v.length > MAX_REGEX_LENGTH) return false
    // Bound worst-case backtracking work even if a pathological pattern
    // somehow landed in the store. Inputs longer than MAX_REGEX_INPUT_LENGTH
    // throw RegexInputTooLargeError instead of returning false, because a
    // silent false would flip `deny`-when-`matches` rules to allow on
    // adversarial input. The thrown error is caught by the evaluator's
    // policy-error path and the whole policy is dropped as NotApplicable.
    // Field name is unknown at this layer; evalCondition() handles the throw.
    if (f.length > MAX_REGEX_INPUT_LENGTH) {
      throw new RegexInputTooLargeError('<unknown>', f.length)
    }
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

/**
 * Maximum nesting depth for condition groups to prevent stack overflow.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export const MAX_CONDITION_DEPTH = 10

/**
 * Type guard that distinguishes a flat {@link AccessControl.ICondition} from a nested {@link AccessControl.IConditionGroup}.
 *
 * @param item - Either a leaf condition or a group node.
 * @returns `true` when `item` is a leaf `ICondition`.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function isCondition(
  item: AccessControl.ICondition | AccessControl.IConditionGroup,
): item is AccessControl.ICondition {
  return 'field' in item
}

/**
 * Resolve a condition value, handling `$`-prefixed variable references.
 * e.g. `$subject.id` resolves to the request's subject.id at eval time.
 *
 * @param req   - The access request providing resolution roots.
 * @param value - Raw condition value (possibly `$`-prefixed reference).
 * @returns The resolved value, or `value` unchanged when no `$` prefix is present.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function resolveValue(
  req: Request.IAccessRequest,
  value: Primitives.AttributeValue,
  caches?: { path?: Map<string, string[] | null> },
): Primitives.AttributeValue {
  if (typeof value === 'string' && value.startsWith('$')) {
    return resolve(req, value.slice(1), caches)
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
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function isUserSourcedValue(value: Primitives.AttributeValue): boolean {
  return typeof value === 'string' && value.startsWith('$')
}

/**
 * Evaluate a single flat condition against an access request.
 *
 * @param req  - The access request providing field values.
 * @param cond - The condition to test.
 * @returns `true` when the operator predicate holds against the resolved field.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function evalCondition(
  req: Request.IAccessRequest,
  cond: AccessControl.ICondition,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (cond.operator === 'matches' && isUserSourcedValue(cond.value ?? null)) return false
  const fieldVal = resolve(req, cond.field, caches)
  const condVal = resolveValue(req, cond.value ?? null, caches)
  try {
    // DEBT-6: per-Engine regex cache when supplied, module-global fallback.
    if (cond.operator === 'matches') return evalMatchesOp(fieldVal, condVal, caches?.regex)
    return ops[cond.operator](fieldVal, condVal)
  } catch (err) {
    if (err instanceof RegexInputTooLargeError && err.field === '<unknown>') {
      throw new RegexInputTooLargeError(cond.field, err.length)
    }
    throw err
  }
}

/**
 * DEBT-6: per-instance-cache-aware `matches` operator. Module-global `ops.matches`
 * uses the process-wide regex cache; this variant accepts an optional cache
 * override so multi-tenant Engine instances can isolate compile pools.
 */
export function evalMatchesOp(
  f: Primitives.AttributeValue,
  v: Primitives.AttributeValue,
  cache?: Map<string, RegExp>,
): boolean {
  if (typeof f !== 'string' || typeof v !== 'string') return false
  if (v.length > MAX_REGEX_LENGTH) return false
  if (f.length > MAX_REGEX_INPUT_LENGTH) {
    throw new RegexInputTooLargeError('<unknown>', f.length)
  }
  const re = getCachedRegex(v, cache ?? regexCache)
  return re ? re.test(f) : false
}
