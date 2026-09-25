import { throwIamError } from '../errors'
import { resolve } from '../resolve'
import type { AccessControl, IamPrimitives, IamRequest } from '../types'

/**
 * Max `matches` pattern length.
 * SECURITY: ReDoS patterns are tiny (`(a+)+$`), so a tight bound costs nothing and limits attacker rope.
 */
export const MAX_REGEX_LENGTH = 128

/**
 * Max `matches` input length in UTF-16 code units, the unit backtracking work scales with.
 * SECURITY: bounds backtracking a missed pattern can cause; longer input throws `IAM_CONDITION_REGEX_INPUT_TOO_LARGE`.
 */
export const MAX_REGEX_INPUT_LENGTH = 2048

/** Operators that read only the field; an operand on them is meaningless. */
export const VALUELESS_OPERATORS: ReadonlySet<string> = new Set(['exists', 'not_exists'])

/**
 * Operand type each listed operator compares against; unlisted operators accept any scalar.
 * NOTE: `validate.libs` imports this table, so write-time and read-time checks cannot drift.
 */
export const OPERAND_TYPES: ReadonlyMap<string, 'array' | 'number' | 'scalar' | 'string' | 'temporal'> = new Map([
  // SECURITY: `eq`/`neq` are `===`/`!==`, so an object operand would make `eq` always false and `neq` always true.
  ['eq', 'scalar'],
  ['neq', 'scalar'],
  ['in', 'array'],
  ['nin', 'array'],
  // SECURITY: the operand is the scalar looked for; without these entries `not_contains` answers `true`
  // for any non-scalar operand.
  ['contains', 'scalar'],
  ['not_contains', 'scalar'],
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

/** Scalar check over `unknown`, for use before anything is narrowed. */
function isScalarUnknown(value: unknown): boolean {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

/** Whether `value` has the operand type `kind`. */
export function operandHasType(kind: 'array' | 'number' | 'scalar' | 'string' | 'temporal', value: unknown): boolean {
  switch (kind) {
    case 'array':
      // SECURITY: elements too, since `includes` never matches an object element and the rule would retire.
      return Array.isArray(value) && value.every(isScalarUnknown)
    case 'number':
      return typeof value === 'number'
    case 'scalar':
      // Matches `isScalar`, which the membership operators use on their operand.
      return isScalarUnknown(value)
    case 'string':
      return typeof value === 'string'
    case 'temporal':
      return typeof value === 'number' || typeof value === 'string'
  }
}

/** LRU capacity of every compiled-regex cache, process-wide or per-Engine. */
export const REGEX_CACHE_MAX = 256

/**
 * Process-wide LRU of compiled patterns, used when no per-instance cache is passed.
 * NOTE: multi-tenant deployments should pass per-Engine caches so tenants cannot evict each other.
 */
export const regexCache = new Map<string, RegExp>()

/** Clears the process-wide regex cache; per-instance caches passed to {@link getCachedRegex} are untouched. */
export function clearRegexCache(): void {
  regexCache.clear()
}

/** Max unbounded quantifiers (`+`, `*`, `{n,}`) in one `matches` pattern before it is refused. */
export const MAX_UNBOUNDED_QUANTIFIERS = 4

/**
 * Longest allowed run of unbounded quantifiers competing for the same characters.
 * A run of length k backtracks O(n^k), so the run sets the cost, not the total count.
 */
export const MAX_OVERLAPPING_UNBOUNDED_CHAIN = 2

/** Largest bound allowed in `{n,m}` (upper) or `{n,}` (lower); the matcher can walk that many iterations. */
export const MAX_BOUNDED_QUANTIFIER = 1_000

/** Index of the `]` closing the character class opened at `start`, or -1. */
function findClassEnd(pattern: string, start: number): number {
  for (let i = start + 1; i < pattern.length; i++) {
    if (pattern[i] === '\\') {
      i++
      continue
    }
    if (pattern[i] === ']') return i
  }
  return -1
}

/** Strips escapes and class bodies so a literal `*` in `[a-z0-9*-]` is not read as a quantifier. */
function stripLiterals(fragment: string): string {
  return fragment.replace(/\\./g, '').replace(/\[[^\]]*\]/g, 'C')
}

/** Whether a fragment contains a group immediately followed by `+`, `*` or `{n,}`. */
function hasQuantifiedGroup(stripped: string): boolean {
  return /\)[+*]/.test(stripped) || /\)\{\d+,\}/.test(stripped)
}

/**
 * Static ReDoS screen for a policy-supplied `matches` pattern, run before it is ever compiled.
 * SECURITY: errs toward refusing; a refused pattern fails closed, a missed one stalls the process.
 * @returns `{ safe: true }`, or `{ safe: false, reason }` naming the most specific shape found.
 */
export function detectCatastrophicRegex(pattern: string): { safe: boolean; reason?: string } {
  if (typeof pattern !== 'string') return { safe: false, reason: 'pattern must be a string' }
  if (pattern.length > MAX_REGEX_LENGTH) {
    return {
      safe: false,
      reason: `pattern length ${pattern.length} exceeds MAX_REGEX_LENGTH (${MAX_REGEX_LENGTH})`,
    }
  }

  // Backreference plus quantifier (`\1+`, `\k<name>*`). Before the nested scan so `(\w+)\1+` gets this reason.
  if (/\\[1-9]\d*\s*[+*?{]/.test(pattern) || /\\k<[^>]+>\s*[+*?{]/.test(pattern)) {
    return { safe: false, reason: 'backref-quantifier' }
  }

  // Lookaround bodies. Before the nested scan so `(?=(a+)+)` gets the more specific reason.
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
    // NOTE: only a quantified group in the body is refused; `^(?!.*admin)` is linear and a common deny guard.
    if (hasQuantifiedGroup(stripLiterals(pattern.slice(bodyStart, j)))) {
      return { safe: false, reason: 'lookaround-with-quantified-group' }
    }
    i = j
  }

  // `{n,m}` with a large upper bound, or `{n,}` with a large lower bound. Exact `{n}` is fine.
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

  // Nested quantifiers: a group followed by `+`, `*` or `{n,` whose body has its own quantifier or alternation.
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
      const bodyStripped = stripLiterals(pattern.slice(openIdx + 1, i))
      if (/[+*]/.test(bodyStripped) || /\{\d+,\d*\}/.test(bodyStripped)) {
        return { safe: false, reason: 'nested quantifier (e.g. `(a+)+`) - catastrophic backtracking risk' }
      }
      if (bodyStripped.includes('|')) {
        return { safe: false, reason: 'alternation inside a quantified group - catastrophic backtracking risk' }
      }
    }
  }

  // Count unbounded quantifiers outside escapes and character classes.
  let unbounded = 0
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]
    if (ch === '\\') {
      i++
      continue
    }
    if (ch === '[') {
      // A `*` or `+` inside a character class is a literal, not a quantifier.
      const close = findClassEnd(pattern, i)
      if (close !== -1) {
        i = close
        continue
      }
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

  const adjacent = findAdjacentUnboundedOverlap(pattern)
  if (adjacent !== null) {
    return {
      safe: false,
      reason: `adjacent unbounded quantifiers over overlapping characters (${adjacent}) - polynomial backtracking risk`,
    }
  }

  const chain = findOverlappingUnboundedChain(pattern)
  if (chain !== null) {
    return {
      safe: false,
      reason: `${MAX_OVERLAPPING_UNBOUNDED_CHAIN + 1}+ unbounded quantifiers competing for the same characters (${chain}) - polynomial backtracking risk`,
    }
  }

  return { safe: true }
}

/**
 * Probe characters for atom overlap: atoms are compiled and tested, so the regex engine decides what a class matches.
 * Callers add the pattern's own literals so a class like `[q-s]` is still covered.
 */
const OVERLAP_PROBE_CHARS = 'aZ0 _-./@:%\t'.split('')

/** Compile one atom for probing. Returns `null` if it will not compile alone. */
function atomMatcher(source: string): RegExp | null {
  try {
    return new RegExp(`^(?:${source})$`)
  } catch {
    return null
  }
}

/**
 * Whether two atoms can match the same character.
 * SECURITY: an atom that will not compile alone (a group, a backreference) counts as overlapping.
 */
function atomsOverlap(a: string, b: string, extraProbes: readonly string[]): boolean {
  if (a === b) return true
  const ra = atomMatcher(a)
  const rb = atomMatcher(b)
  if (ra === null || rb === null) return true
  for (const c of [...OVERLAP_PROBE_CHARS, ...extraProbes]) {
    if (ra.test(c) && rb.test(c)) return true
  }
  return false
}

/**
 * Finds neighbouring unbounded quantifiers whose atoms overlap (`a+a+`, `.*.*`); the input cap does not bound these.
 * Separated runs are {@link findOverlappingUnboundedChain}'s job.
 * @returns The offending pair as `` `x` then `y` ``, or `null`.
 */
function findAdjacentUnboundedOverlap(pattern: string): string | null {
  const atoms = scanQuantifiedAtoms(pattern)
  const literals = pattern.replace(/[^A-Za-z0-9]/g, '').split('')
  let prev: QuantifiedAtom | undefined
  for (const cur of atoms) {
    const pair = prev
    prev = cur
    if (pair === undefined || !pair.unbounded || !cur.unbounded || !cur.adjacent) continue
    if (atomsOverlap(pair.source, cur.source, literals)) return `\`${pair.source}\` then \`${cur.source}\``
  }
  return null
}

/**
 * Whether one character is matched by every atom in `sources`.
 * SECURITY: an atom that will not compile alone counts as matching.
 */
function overlapsAll(sources: readonly string[], extraProbes: readonly string[]): boolean {
  const matchers = sources.map(atomMatcher)
  if (matchers.some((m) => m === null)) return true
  for (const c of [...OVERLAP_PROBE_CHARS, ...extraProbes]) {
    if (matchers.every((m) => m?.test(c) === true)) return true
  }
  return false
}

/**
 * Finds more than {@link MAX_OVERLAPPING_UNBOUNDED_CHAIN} unbounded quantifiers competing for the same characters.
 * A separator links two atoms only if optional or matched with both: `.*\/.*\/.*` links, `[a-z]+@[a-z]+` does not.
 * @returns The offending run as `` `x` then `y` then `z` ``, or `null`.
 */
function findOverlappingUnboundedChain(pattern: string): string | null {
  const atoms = scanQuantifiedAtoms(pattern)
  const literals = pattern.replace(/[^A-Za-z0-9]/g, '').split('')
  let chain: QuantifiedAtom[] = []
  let separators: QuantifiedAtom[] = []
  for (const atom of atoms) {
    if (!atom.unbounded) {
      separators.push(atom)
      continue
    }
    const prev = chain.at(-1)
    const linked =
      prev !== undefined &&
      atomsOverlap(prev.source, atom.source, literals) &&
      separators.every((sep) => sep.optional || overlapsAll([sep.source, prev.source, atom.source], literals))
    chain = linked ? [...chain, atom] : [atom]
    separators = []
    if (chain.length > MAX_OVERLAPPING_UNBOUNDED_CHAIN) {
      return chain.map((a) => `\`${a.source}\``).join(' then ')
    }
  }
  return null
}

interface QuantifiedAtom {
  /** The atom's regex source, without its quantifier. */
  readonly source: string
  /** Carries a `+`, `*` or `{n,}` quantifier. */
  readonly unbounded: boolean
  /** Immediately follows the previous atom, with nothing in between. */
  readonly adjacent: boolean
  /** Can match zero characters (`?`, `*`, `{0,...}`), so it separates nothing. */
  readonly optional: boolean
}

/** Splits a pattern into quantified atoms. Groups are opaque (the nested scan covers `(a+)+`), keeping this linear. */
function scanQuantifiedAtoms(pattern: string): QuantifiedAtom[] {
  const atoms: QuantifiedAtom[] = []
  let i = 0
  let prevEnd = -1
  while (i < pattern.length) {
    const start = i
    const ch = pattern[i]
    if (ch === '\\') {
      i += 2
    } else if (ch === '[') {
      i++
      while (i < pattern.length && pattern[i] !== ']') i += pattern[i] === '\\' ? 2 : 1
      i++
    } else if (ch === '(') {
      let depth = 1
      i++
      while (i < pattern.length && depth > 0) {
        if (pattern[i] === '\\') i++
        else if (pattern[i] === '(') depth++
        else if (pattern[i] === ')') depth--
        i++
      }
    } else {
      i++
    }
    const source = pattern.slice(start, i)

    let unbounded = false
    let optional = false
    const q = pattern[i]
    if (q === '+' || q === '*') {
      unbounded = true
      optional = q === '*'
      i++
    } else if (q === '{') {
      const close = pattern.indexOf('}', i)
      if (close !== -1) {
        const inner = pattern.slice(i + 1, close)
        if (/^\d+,\s*$/.test(inner)) unbounded = true
        if (/^0\s*(,|$)/.test(inner)) optional = true
        i = close + 1
      }
    } else if (q === '?') {
      optional = true
      i++
    }
    // A lazy `?` marker does not remove the backtracking.
    if (pattern[i] === '?' && unbounded) i++

    // Anchors and boundaries are not atoms an input character is split across.
    if (source !== '^' && source !== '$' && source !== '\\b' && source !== '\\B') {
      atoms.push({ adjacent: start === prevEnd, optional, source, unbounded })
      prevEnd = i
    }
  }
  return atoms
}

/**
 * Compiled regex for `pattern`, or `null` when it is invalid or refused by {@link detectCatastrophicRegex}.
 * PERF: a hit is re-inserted, so Map order is recency order and eviction is LRU.
 * @param pattern - Regex source.
 * @param cache - Per-Engine cache that isolates tenants; defaults to the process-wide `regexCache`.
 */
export function getCachedRegex(pattern: string, cache: Map<string, RegExp> = regexCache): RegExp | null {
  // PERF: only detector-approved patterns are cached, so a hit skips the detector.
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
 * Epoch ms for `before`/`after`: numbers pass through, strings go through `Date.parse`, anything else is `NaN`.
 * SECURITY: `NaN` makes the comparison fail closed.
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

  // SECURITY: array membership only, never substring. A present non-array field satisfies neither operator;
  // an absent field is an empty list, so `not_contains` holds.
  contains: (f, v) => Array.isArray(f) && isScalar(v) && f.includes(v),
  not_contains: (f, v) => {
    if (f === null || f === undefined) return true
    if (!Array.isArray(f)) return false
    return !isScalar(v) || !f.includes(v)
  },

  starts_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.startsWith(v),
  ends_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.endsWith(v),

  // NOTE: delegates so the cached and module-global `matches` paths cannot drift apart.
  matches: (f, v) => evalMatchesOp(f, v),

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

  // Both operands go through `toEpoch`; a non-temporal one is `NaN` and fails closed.
  // Pair with `$environment.now` for "still in the future" / "already past".
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

/** Whether `item` is a leaf {@link AccessControl.ICondition} rather than an {@link AccessControl.IConditionGroup}. */
export function isCondition(
  item: AccessControl.ICondition | AccessControl.IConditionGroup,
): item is AccessControl.ICondition {
  return 'field' in item
}

/** Resolves a `$`-prefixed reference (e.g. `$subject.id`) against the request; other values pass through unchanged. */
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
 * Whether `value` is a `$`-reference resolved from the request.
 * SECURITY: `matches` refuses these, since a request-controlled pattern is a ReDoS primitive.
 */
export function isUserSourcedValue(value: IamPrimitives.AttributeValue): boolean {
  return typeof value === 'string' && value.startsWith('$')
}

/**
 * Evaluates one flat condition against the request.
 * SECURITY: throws instead of returning `false` when the condition cannot be answered (Indeterminate).
 */
export function evalCondition(
  req: IamRequest.IAccessRequest,
  cond: AccessControl.ICondition,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  // SECURITY: a `$`-reference pattern is never compiled (ReDoS). Throw rather than return `false`,
  // which would retire a deny rule, or grant inside a `none`.
  if (cond.operator === 'matches' && isUserSourcedValue(cond.value ?? null)) {
    throwIamError('IAM_CONDITION_USER_SOURCED_PATTERN', { field: cond.field, value: String(cond.value) })
  }
  const fieldVal = resolve(req, cond.field, caches)
  const condVal = resolveValue(req, cond.value ?? null, caches)
  // SECURITY: own properties only, as `resolve` does per path segment. `ops` is an object literal, so
  // `constructor` and `toString` are inherited functions that answered truthy and fired the rule.
  const op = Object.hasOwn(ops, cond.operator) ? ops[cond.operator] : undefined
  // SECURITY: an unknown operator is Indeterminate; `false` would retire a deny rule.
  if (typeof op !== 'function') {
    throwIamError('IAM_CONDITION_OPERATOR_UNKNOWN', { operator: String(cond.operator), field: cond.field })
  }
  // SECURITY: wrong-typed operands are Indeterminate, checked before every operator (`matches` included):
  // seeded or migrated rows skip the validator, and a `$`-reference only has a type once resolved.
  if (!VALUELESS_OPERATORS.has(cond.operator)) {
    if (cond.value === undefined) {
      throwIamError('IAM_CONDITION_OPERAND_TYPE', {
        field: cond.field,
        operator: cond.operator,
        detail: 'requires a "value" and the key is absent',
      })
    }
    // SECURITY: a `$`-reference that resolved to `null` would let `eq` compare `null === null` and allow.
    // A literal `value: null` is an explicit null test and still works.
    if (isUserSourcedValue(cond.value) && condVal === null) {
      throwIamError('IAM_CONDITION_OPERAND_TYPE', {
        field: cond.field,
        operator: cond.operator,
        detail: `operand reference ${JSON.stringify(cond.value)} resolved to nothing`,
      })
    }
    const expected = OPERAND_TYPES.get(cond.operator)
    if (expected !== undefined && !operandHasType(expected, condVal)) {
      const wanted = expected === 'temporal' ? 'a number or ISO-8601 string' : `a ${expected}`
      throwIamError('IAM_CONDITION_OPERAND_TYPE', {
        field: cond.field,
        operator: cond.operator,
        detail: `expects ${wanted} operand, got ${typeof condVal}`,
      })
    }
  }
  if (cond.operator === 'matches') return evalMatchesOp(fieldVal, condVal, caches?.regex, cond.field)
  return op(fieldVal, condVal)
}

/** The `matches` operator with an optional per-Engine regex cache; `ops.matches` uses the process-wide one. */
export function evalMatchesOp(
  f: IamPrimitives.AttributeValue,
  v: IamPrimitives.AttributeValue,
  cache?: Map<string, RegExp>,
  field = '<unknown>',
): boolean {
  if (typeof f !== 'string' || typeof v !== 'string') return false
  if (v.length > MAX_REGEX_LENGTH) {
    throwIamError('IAM_CONDITION_PATTERN_REFUSED', {
      field,
      reason: 'too-long',
      detail: `is ${v.length} characters (> ${MAX_REGEX_LENGTH})`,
    })
  }
  if (f.length > MAX_REGEX_INPUT_LENGTH) {
    throwIamError('IAM_CONDITION_REGEX_INPUT_TOO_LARGE', { field, length: f.length })
  }
  const re = getCachedRegex(v, cache ?? regexCache)
  // SECURITY: a refused pattern is Indeterminate, like an oversized input; `false` would retire deny rules.
  if (!re) {
    throwIamError('IAM_CONDITION_PATTERN_REFUSED', {
      field,
      reason: 'uncompilable',
      detail: 'was refused by the catastrophic-backtracking detector or is not a valid regular expression',
    })
  }
  return re.test(f)
}
