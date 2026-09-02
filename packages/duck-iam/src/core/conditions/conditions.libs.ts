import { resolve } from '../resolve'
import type { AccessControl, IamPrimitives, IamRequest } from '../types'

/**
 * Max allowed regex pattern length to mitigate ReDoS. Catastrophic
 * backtracking patterns are tiny (e.g. `(a+)+$`), so a tight bound here is
 * appropriate - larger patterns only give attackers more rope.
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
 */
export const MAX_REGEX_INPUT_LENGTH = 2048

/**
 * Thrown by the `matches` operator when the candidate string exceeds
 * {@link MAX_REGEX_INPUT_LENGTH}.
 *
 * Carried as a tagged error so the evaluator's `safeEval` can route it through
 * `onPolicyError` and mark the entire policy as NotApplicable. Critically, we
 * do NOT silently return `false`: a `false` result from a `matches` operator
 * inside a `deny` rule would flip the rule's effect to "condition not met ->
 * allow". By throwing, the whole policy drops out of the decision instead of
 * silently becoming permissive.
 */
export class RegexInputTooLargeError extends Error {
  readonly name = 'RegexInputTooLargeError'
  readonly tag = 'duck-iam/regex-input-too-large'
  readonly field: string
  readonly length: number
  constructor(field: string, length: number) {
    super(
      `[@gentleduck/iam:conditions] matches input on field "${field}" is ${length} bytes (> MAX_REGEX_INPUT_LENGTH=${MAX_REGEX_INPUT_LENGTH}); policy dropped as NotApplicable.`,
    )
    this.field = field
    this.length = length
  }
}

/**
 * LRU cache capacity for compiled regex patterns. Shared by both the
 * process-wide default cache and per-instance caches an engine may pass in.
 */
export const REGEX_CACHE_MAX = 256

/**
 * Default process-wide LRU cache for compiled regex patterns. Used when a
 * caller does not pass a per-instance cache. Multi-tenant deployments should
 * prefer per-Engine caches to prevent cross-tenant eviction.
 */
export const regexCache = new Map<string, RegExp>()

/**
 * Drop every entry in the process-wide regex cache. Intended for multi-tenant
 * operators who flush periodically to bound any single tenant's eviction
 * influence. Per-instance caches passed via the optional `cache` argument to
 * {@link getCachedRegex} are NOT affected.
 */
export function clearRegexCache(): void {
  regexCache.clear()
}

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
 * Cheap heuristic for catastrophic-backtracking regex (nested quantifiers, large bounds, backref-quantifier, etc).
 *
 * @param pattern - Raw regex source.
 * @returns `{ safe: true }` when the pattern looks benign, otherwise `{ safe: false, reason }`.
 */
export function detectCatastrophicRegex(pattern: string): { safe: boolean; reason?: string } {
  if (typeof pattern !== 'string') return { safe: false, reason: 'pattern must be a string' }
  if (pattern.length > MAX_REGEX_LENGTH) {
    return {
      safe: false,
      reason: `pattern length ${pattern.length} exceeds MAX_REGEX_LENGTH (${MAX_REGEX_LENGTH})`,
    }
  }

  // Backreference followed by a quantifier - run before the nested-quantifier
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
      if (upperStr === undefined) continue // `{n}` exact count - not a range.
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
        return { safe: false, reason: 'nested quantifier (e.g. `(a+)+`) - catastrophic backtracking risk' }
      }
      if (bodyStripped.includes('|')) {
        return { safe: false, reason: 'alternation inside a quantified group - catastrophic backtracking risk' }
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
      // `{n,}` or `{n,m}` - only `{n,}` (no upper bound) is unbounded.
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
 * Retrieve a cached compiled regex, or compile and cache it.
 * Returns `null` if the pattern fails to compile, or if
 * {@link detectCatastrophicRegex} rejects it as a ReDoS-shaped pattern. This is
 * the same predicate the validator runs, so a pattern accepted at import time
 * can never be refused at evaluation time (or the reverse).
 *
 * On a cache hit the entry is re-inserted so iteration order becomes recency
 * order; eviction then drops the *least recently used* pattern instead of
 * the oldest-inserted one. Without this, a hot pattern compiled early gets
 * evicted as soon as REGEX_CACHE_MAX cold patterns roll through.
 *
 * @param pattern - Regex source string.
 * @param cache - Optional per-instance Map. Falls back to the module-global
 *   `regexCache` when omitted. Engine instances pass their own cache to
 *   prevent cross-tenant eviction.
 * @returns The compiled `RegExp`, or `null` when the pattern is invalid or rejected.
 */
export function getCachedRegex(pattern: string, cache: Map<string, RegExp> = regexCache): RegExp | null {
  // Cache lookup first: an entry only exists because it already passed the
  // detector, so re-running the walker on every hit would be pure cost.
  const cached = cache.get(pattern)
  if (cached) {
    cache.delete(pattern)
    cache.set(pattern, cached)
    return cached
  }
  if (!detectCatastrophicRegex(pattern).safe) return null
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

function isScalar(v: IamPrimitives.AttributeValue | undefined): v is IamPrimitives.Scalar {
  return v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
}

/**
 * Coerce a value to epoch milliseconds for the temporal operators
 * (`before` / `after`). Numbers pass through as-is (already epoch ms).
 * `Date.parse`-able strings (ISO-8601 etc.) convert. Anything else -> `NaN`,
 * which makes the comparison fail closed rather than silently allow.
 */
function toEpoch(v: IamPrimitives.AttributeValue): number {
  if (typeof v === 'number') return v
  if (typeof v === 'string') return Date.parse(v)
  return NaN
}

/** Record mapping every supported operator to its implementation function. */
export const ops: Record<AccessControl.Operator, AccessControl.OpFn> = {
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
    if (v.length > MAX_REGEX_LENGTH) return false
    // Throw on oversize input so `deny`-when-`matches` rules do not flip
    // to allow on adversarial inputs; evalCondition() routes it through
    // onPolicyError.
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

  // Temporal operators. Both operands are coerced to epoch ms via `toEpoch`
  // (number passthrough, ISO-8601 string parse). Non-temporal operands yield
  // `NaN`, so the comparison fails closed. Pair with the engine-injected
  // `$environment.now` for "is X still in the future / already in the past".
  after: (f, v) => {
    const a = toEpoch(f)
    const b = toEpoch(v)
    return Number.isFinite(a) && Number.isFinite(b) && a > b
  },
  before: (f, v) => {
    const a = toEpoch(f)
    const b = toEpoch(v)
    return Number.isFinite(a) && Number.isFinite(b) && a < b
  },
}

/** Maximum nesting depth for condition groups to prevent stack overflow. */
export const MAX_CONDITION_DEPTH = 10

/**
 * Type guard that distinguishes a flat {@link AccessControl.ICondition} from a nested {@link AccessControl.IConditionGroup}.
 *
 * @param item - Either a leaf condition or a group node.
 * @returns `true` when `item` is a leaf `ICondition`.
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
 */
export function resolveValue(
  req: IamRequest.IAccessRequest,
  value: IamPrimitives.AttributeValue,
  caches?: { path?: Map<string, string[] | null> },
): IamPrimitives.AttributeValue {
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
 */
export function isUserSourcedValue(value: IamPrimitives.AttributeValue): boolean {
  return typeof value === 'string' && value.startsWith('$')
}

/**
 * Evaluate a single flat condition against an access request.
 *
 * @param req  - The access request providing field values.
 * @param cond - The condition to test.
 * @returns `true` when the operator predicate holds against the resolved field.
 */
export function evalCondition(
  req: IamRequest.IAccessRequest,
  cond: AccessControl.ICondition,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (cond.operator === 'matches' && isUserSourcedValue(cond.value ?? null)) return false
  const fieldVal = resolve(req, cond.field, caches)
  const condVal = resolveValue(req, cond.value ?? null, caches)
  try {
    // Per-Engine regex cache when supplied, module-global fallback.
    if (cond.operator === 'matches') return evalMatchesOp(fieldVal, condVal, caches?.regex)
    const op = ops[cond.operator]
    // An operator we cannot evaluate is indeterminate, not false: returning
    // false here would quietly retire a deny rule. Throwing routes it through
    // onPolicyError and the caller's fail-closed handling.
    if (typeof op !== 'function') {
      throw new Error(
        `[@gentleduck/iam:conditions] unknown operator "${String(cond.operator)}" on field "${cond.field}"`,
      )
    }
    return op(fieldVal, condVal)
  } catch (err) {
    if (err instanceof RegexInputTooLargeError && err.field === '<unknown>') {
      throw new RegexInputTooLargeError(cond.field, err.length)
    }
    throw err
  }
}

/**
 * Per-instance-cache-aware `matches` operator. The module-global `ops.matches`
 * uses the process-wide regex cache; this variant accepts an optional cache
 * override so multi-tenant Engine instances can isolate compile pools.
 */
export function evalMatchesOp(
  f: IamPrimitives.AttributeValue,
  v: IamPrimitives.AttributeValue,
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
