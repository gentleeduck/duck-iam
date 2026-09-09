/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { evalConditionGroup, matchesUnconditionally } from '../conditions/conditions'
import { MAX_CONDITION_DEPTH, ops } from '../conditions/conditions.libs'
import { matchesAction, matchesResource, matchesResourceHierarchical } from '../resolve'
import type { AccessControl, IamRequest } from '../types'
import type { Evaluate } from './evaluate.types'
/**
 * Action+resource shape only, no conditions. Distinguishes "this rule has
 * nothing to do with the request" (false) from "shape matches, condition
 * decides" (true) - the top-level combine needs that distinction to tell a
 * genuinely silent policy apart from one that considered this request and
 * said no.
 */
export function ruleTargetsMatch(rule: AccessControl.IRule, req: IamRequest.IAccessRequest): boolean {
  const actionMatch = rule.actions.some((a) => matchesAction(a, req.action))
  if (!actionMatch) return false

  // Hoist the dot check - compute once before the .some() loop
  const resourceHasDot = req.resource.type.includes('.')

  return rule.resources.some((r) => {
    // Use dot-based matching if either pattern or resource type contains a dot
    if (resourceHasDot || r.includes('.')) {
      return matchesResourceHierarchical(r, req.resource.type)
    }
    return matchesResource(r, req.resource.type)
  })
}

/** `ruleTargetsMatch` plus its conditions - `true` only if the rule shape-matches AND all conditions evaluate to true. */
export function ruleApplies(
  rule: AccessControl.IRule,
  req: IamRequest.IAccessRequest,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (!ruleTargetsMatch(rule, req)) return false
  return evalConditionGroup(req, rule.conditions, 0, caches)
}

/**
 * `targets.actions`/`targets.resources` only, no roles. Unlike the role dimension, these two
 * don't depend on who's asking - only on the (action, resource) pair - so `compileTable` can
 * call this at compile time with two literal strings (no `req` yet) to decide which cells a
 * target-restricted policy's rules belong in. `policyApplies` below is this plus the
 * (request-only) role check.
 */
export function policyTargetsActionResource(policy: AccessControl.IPolicy, action: string, resource: string): boolean {
  const targets = policy.targets
  if (!targets) return true
  if (targets.actions?.length && !targets.actions.some((a) => matchesAction(a, action))) return false
  if (targets.resources?.length && !targets.resources.some((r) => matchesResource(r, resource))) return false
  return true
}

/**
 * Checks whether a policy's target constraints match the given access request.
 *
 * If the policy has no targets defined, it applies to all requests.
 * Otherwise, each target dimension (actions, resources, roles) is checked
 * independently - all specified dimensions must match.
 *
 * @param policy - The policy whose targets to check
 * @param req    - The incoming access request
 * @returns `true` if the policy should be evaluated for this request
 */
export function policyApplies(policy: AccessControl.IPolicy, req: IamRequest.IAccessRequest): boolean {
  if (!policyTargetsActionResource(policy, req.action, req.resource.type)) return false

  const roles = policy.targets?.roles
  if (roles?.length) {
    const subjectRoles = Array.isArray(req.subject.roles) ? req.subject.roles : []
    if (!roles.some((role) => subjectRoles.includes(role))) {
      return false
    }
  }

  return true
}

/**
 * The cross-policy combine strategies both engines implement. `evaluate` and
 * `evaluateFast` branch on `'and'` and `'allow-overrides'` and treat everything
 * else as `first-applicable`, which is the most permissive of the three - so an
 * unrecognised value must be rejected at construction rather than silently
 * dropping deny-overrides semantics. TypeScript already refuses one; a
 * config-driven or plain-JS caller does not.
 */
export const VALID_POLICY_COMBINES: readonly AccessControl.PolicyCombine[] = [
  'and',
  'allow-overrides',
  'first-applicable',
]

/**
 * Highest priority wins; the strict `>` keeps ties on the earliest match, which
 * is source order. `first-match` and `highest-priority` differ only in the
 * `reason` they report, so they rank through this one function rather than two
 * copies that could drift.
 */
function topByPriority<T extends { rule: { readonly priority: number } }>(matched: readonly T[]): T | undefined {
  let best = matched[0]
  if (best === undefined) return undefined
  for (let i = 1; i < matched.length; i++) {
    const cur = matched[i]
    if (cur !== undefined && rulePriority(cur.rule) > rulePriority(best.rule)) best = cur
  }
  return best
}

/**
 * Combining-algorithm implementations. Each picks one matched rule's effect:
 *
 * - `deny-overrides`   - any deny wins; otherwise first allow wins.
 * - `allow-overrides`  - any allow wins; otherwise first deny wins.
 * - `first-match`      - highest-priority match wins; ties resolved by source order.
 * - `highest-priority` - identical to `first-match`: same ranking, same source-order tie-break.
 *
 * Source order is `policy.rules` order, which for a stored policy is the
 * adapter's row order. Two equal-priority rules of opposing effect make the
 * verdict depend on it; both engines agree on the answer for any given order,
 * but the order itself is the adapter's to guarantee.
 */
export const combiners: Record<AccessControl.CombiningAlgorithm, Evaluate.Combiner> = {
  'deny-overrides': (matched, defaultEffect) => {
    const deny = matched.find((m) => m.effect === 'deny')
    if (deny) {
      return {
        rule: deny.rule,
        effect: 'deny',
        reason: `Denied by rule "${deny.rule.id}"`,
      }
    }
    const allow = matched.find((m) => m.effect === 'allow')
    if (allow) {
      return {
        rule: allow.rule,
        effect: 'allow',
        reason: `Allowed by rule "${allow.rule.id}"`,
      }
    }
    return { effect: defaultEffect, reason: `No matching rules. Defaulted to ${defaultEffect}` }
  },

  'allow-overrides': (matched, defaultEffect) => {
    const allow = matched.find((m) => m.effect === 'allow')
    if (allow) {
      return {
        rule: allow.rule,
        effect: 'allow',
        reason: `Allowed by rule "${allow.rule.id}"`,
      }
    }
    const deny = matched.find((m) => m.effect === 'deny')
    if (deny) {
      return {
        rule: deny.rule,
        effect: 'deny',
        reason: `Denied by rule "${deny.rule.id}"`,
      }
    }
    return { effect: defaultEffect, reason: `No matching rules. Defaulted to ${defaultEffect}` }
  },

  'first-match': (matched, defaultEffect) => {
    const first = topByPriority(matched)
    if (!first) return { effect: defaultEffect, reason: `No matching rules. Defaulted to ${defaultEffect}` }
    return {
      rule: first.rule,
      effect: first.effect,
      reason: `First match: rule "${first.rule.id}" (${first.effect})`,
    }
  },

  'highest-priority': (matched, defaultEffect) => {
    const top = topByPriority(matched)
    if (!top) return { effect: defaultEffect, reason: `No matching rules. Defaulted to ${defaultEffect}` }
    return {
      rule: top.rule,
      effect: top.effect,
      reason: `Highest priority: rule "${top.rule.id}" (p=${top.rule.priority})`,
    }
  },
}

/**
 * True when a pattern matches more than its own literal value (`'*'`, `'foo:*'`,
 * `'foo.*'`). Such patterns can't be served by the literal-keyed `byActionResource`
 * map - they go into whichever wildcard bucket still has a literal side to key on
 * (`byActionWildcardResource` / `byResourceWildcardAction`), or `wildcardBoth` if
 * neither side is literal.
 */
function isExpansivePattern(p: string): boolean {
  return p.includes('*')
}

/**
 * Keyed on the `rules` array, not the policy: `readonly rules` is a
 * compile-time annotation only, and keying on the policy meant that replacing
 * its rules array served the stale index for the object's whole lifetime -
 * production kept granting what the interpreter, which walks `policy.rules`
 * live, had already stopped granting. `length` and `algorithm` are recorded
 * with it so an append and an algorithm change also invalidate.
 *
 * WeakMap so indexes are GC'd when the rules array is no longer referenced.
 */
const indexCache = new WeakMap<
  readonly AccessControl.IRule[],
  { algorithm: AccessControl.CombiningAlgorithm; index: Evaluate.IPolicyRuleIndex; length: number }
>()

/** Push `entry` onto `map.get(key)`, creating the bucket on first use. */
function addToBucket(map: Map<string, Evaluate.IIndexedRule[]>, key: string, entry: Evaluate.IIndexedRule): void {
  let bucket = map.get(key)
  if (!bucket) {
    bucket = []
    map.set(key, bucket)
  }
  bucket.push(entry)
}

/**
 * Push `entry` into the two-level action -> resource bucket map.
 *
 * Two levels rather than one keyed `` `${a}\0${r}` ``: literal buckets are
 * trusted as exact-key hits and skip `candidateShapeMatches` entirely, so a
 * non-injective key was enough to make a rule fire for a request it has
 * nothing to do with. An embedded NUL in either component collided - a rule on
 * action `read\0post` / resource `x` answered a request for action `read` /
 * resource `post\0x` - in production only. A nested map has no delimiter.
 */
function addToPairBucket(
  map: Map<string, Map<string, Evaluate.IIndexedRule[]>>,
  action: string,
  resource: string,
  entry: Evaluate.IIndexedRule,
): void {
  let byResource = map.get(action)
  if (!byResource) {
    byResource = new Map()
    map.set(action, byResource)
  }
  addToBucket(byResource, resource, entry)
}

/**
 * True when the policy carries at least one deny rule, i.e. failing to evaluate
 * it could hide a deny. Used to fail closed on an evaluation error. A row that
 * reached us without a `rules` array cannot hide anything, so it stays skippable.
 */
export function policyHasDenyRule(policy: AccessControl.IPolicy): boolean {
  return Array.isArray(policy.rules) && policy.rules.some((r) => r.effect === 'deny')
}

/**
 * Priority used for ranking. `NaN`/missing (a row that bypassed validation)
 * ranks as 0 instead of silently losing every `>` comparison and vanishing.
 */
export function rulePriority(rule: { readonly priority: number }): number {
  return Number.isFinite(rule.priority) ? rule.priority : 0
}

/**
 * True when the rule's conditions have to be handed to `evalConditionGroup`
 * rather than being read as an unconditional match. Anything the evaluator
 * would not answer `true` to for every request belongs here - a group that can
 * never match (`{ any: [] }`, an unrecognised key set) as much as one that
 * depends on the request, and an absent or non-object group, on which the
 * evaluator throws. Skipping any of those turns a rule the interpreter refuses
 * into one the fast paths honour.
 */
function needsConditionEval(c: AccessControl.IConditionGroup | undefined): boolean {
  return !matchesUnconditionally(c)
}

/**
 * Whether any condition under `item` can throw at evaluation. Conservative: an
 * unreadable shape, or nesting past the evaluator's own depth bound, counts as
 * throwing so the policy falls back to the interpreter rather than being
 * decided by a fast path that might never reach the offending rule.
 */
function conditionMayThrow(item: unknown, depth = 0): boolean {
  if (depth > MAX_CONDITION_DEPTH) return true
  if (item === null || typeof item !== 'object') return false
  if (Array.isArray(item)) return item.some((child) => conditionMayThrow(child, depth + 1))
  if ('operator' in item) {
    const { operator } = item
    return operator === 'matches' || typeof operator !== 'string' || !Object.hasOwn(ops, operator)
  }
  for (const key of ['all', 'any', 'none']) {
    if (key in item && conditionMayThrow(Reflect.get(item, key), depth + 1)) return true
  }
  return false
}

/**
 * Build (or retrieve from cache) a rule index for a policy.
 *
 * @param policy - The policy whose rules should be indexed.
 * @returns The cached or freshly built {@link Evaluate.IPolicyRuleIndex}.
 */
export function indexPolicy(policy: AccessControl.IPolicy): Evaluate.IPolicyRuleIndex {
  const rules = policy.rules
  const cached = indexCache.get(rules)
  if (cached && cached.length === rules.length && cached.algorithm === policy.algorithm) return cached.index

  const byActionResource = new Map<string, Map<string, Evaluate.IIndexedRule[]>>()
  const byActionWildcardResource = new Map<string, Evaluate.IIndexedRule[]>()
  const byResourceWildcardAction = new Map<string, Evaluate.IIndexedRule[]>()
  const wildcardBoth: Evaluate.IIndexedRule[] = []

  let mayThrow = false
  for (const [order, rule] of policy.rules.entries()) {
    if (!mayThrow && conditionMayThrow(rule.conditions)) mayThrow = true
    const actions = new Set<string>(rule.actions)
    const resources = new Set<string>(rule.resources)
    let hasWildcardAction = false
    for (const a of actions) {
      if (isExpansivePattern(a)) {
        hasWildcardAction = true
        break
      }
    }
    let hasWildcardResource = false
    for (const r of resources) {
      if (isExpansivePattern(r)) {
        hasWildcardResource = true
        break
      }
    }
    const c = rule.conditions
    const hasConditions = needsConditionEval(c)
    const entry: Evaluate.IIndexedRule = {
      rule,
      actions,
      resources,
      hasConditions,
      order,
    }

    if (hasWildcardAction && hasWildcardResource) {
      // Neither side is literal - nothing to key on, stays a linear scan.
      wildcardBoth.push(entry)
    } else if (hasWildcardResource) {
      // Action is guaranteed all-literal (hasWildcardAction is false) - key on every
      // literal action so a request only finds this entry via its own exact action.
      for (const a of actions) addToBucket(byActionWildcardResource, a, entry)
    } else if (hasWildcardAction) {
      // Mirror of the above: resource is guaranteed all-literal here.
      for (const r of resources) addToBucket(byResourceWildcardAction, r, entry)
    } else {
      for (const a of actions) {
        for (const r of resources) addToPairBucket(byActionResource, a, r, entry)
      }
    }
  }

  // Pre-compute results for unconditional exact-match rules (CASL-like O(1)).
  // Only when no wildcard rules exist (they could override the result).
  const precomputed = new Map<string, Map<string, boolean>>()
  const algo = policy.algorithm
  const hasNoWildcards =
    wildcardBoth.length === 0 && byActionWildcardResource.size === 0 && byResourceWildcardAction.size === 0

  // `highest-priority` ranks identically to `first-match` - only the reported
  // `reason` differs - so excluding it here left an identical policy O(1) under
  // one algorithm name and O(rules) under the other.
  const precomputable =
    algo === 'deny-overrides' || algo === 'allow-overrides' || algo === 'first-match' || algo === 'highest-priority'

  if (hasNoWildcards && precomputable) {
    for (const rule of policy.rules) {
      const c = rule.conditions
      if (needsConditionEval(c)) continue
      if (rule.actions.some(isExpansivePattern) || rule.resources.some(isExpansivePattern)) continue

      for (const a of rule.actions) {
        for (const r of rule.resources) {
          const entries = byActionResource.get(a)?.get(r)
          if (!entries) continue

          // Only precompute when every entry in this bucket is unconditional -
          // otherwise the result depends on the request and can't be cached.
          let allUnconditional = true
          for (const e of entries) {
            const ec = e.rule.conditions
            if (needsConditionEval(ec)) {
              allUnconditional = false
              break
            }
          }
          if (!allUnconditional) continue

          // Simulate combining algorithm
          let result: boolean | undefined
          if (algo === 'deny-overrides') {
            let hasAllow = false
            for (const e of entries) {
              if (e.rule.effect === 'deny') {
                result = false
                break
              }
              if (e.rule.effect === 'allow') hasAllow = true
            }
            if (result === undefined && hasAllow) result = true
          } else if (algo === 'allow-overrides') {
            let hasDeny = false
            for (const e of entries) {
              if (e.rule.effect === 'allow') {
                result = true
                break
              }
              if (e.rule.effect === 'deny') hasDeny = true
            }
            if (result === undefined && hasDeny) result = false
          } else {
            // Entries are appended in `policy.rules` order, so `topByPriority`
            // breaks ties the same way the interpreter's linear scan does.
            const best = topByPriority(entries)
            if (best) result = best.rule.effect === 'allow'
          }

          if (result !== undefined) {
            let actionMap = precomputed.get(a)
            if (!actionMap) {
              actionMap = new Map()
              precomputed.set(a, actionMap)
            }
            actionMap.set(r, result)
          }
        }
      }
    }
  }

  const idx: Evaluate.IPolicyRuleIndex = {
    byActionResource,
    byActionWildcardResource,
    byResourceWildcardAction,
    wildcardBoth,
    precomputed,
    mayThrow,
  }
  indexCache.set(rules, { algorithm: policy.algorithm, index: idx, length: rules.length })
  return idx
}

/**
 * Hooks already reported as throwing.
 *
 * A broken hook is a wiring fault the operator fixes once; the report is
 * reachable per policy per request on an attacker-controlled path (a padded
 * field makes `matches` throw), so repeating it would hand that attacker a log
 * flood. Same reasoning as the file adapter's `rootDir` warn latch.
 *
 * Keyed on the hook, not one module-level boolean. A single latch meant one
 * engine's transiently broken `onPolicyError` permanently silenced a different
 * engine's - a different tenant's - hook failure for the life of the process,
 * and a hook failure is how an operator learns that policy evaluation is
 * throwing at all. A `WeakSet` because the key is the operator's own function
 * and this must not be the reference that keeps their engine alive.
 */
const _ERROR_HOOK_THREW = new WeakSet<object>()

/**
 * Run an error-reporting hook so that a throw inside it cannot escape.
 *
 * Every caller is *already inside* the catch block that implements the
 * Indeterminate contract: a policy that threw votes deny if it carries any deny
 * rule, otherwise it casts `defaultEffect`. Called raw, a hook that throws
 * propagates out of that catch, so the vote is never cast and the evaluation
 * unwinds instead - the padded field that defeated the deny rule takes the
 * whole decision with it. Reporting an error must not be able to change the
 * decision being reported.
 *
 * Synchronous by design: these sites are on the evaluation path, so the async
 * `safeHookCall` would only leave a floating promise. Prefer `safeHookCall` for
 * the engine's own lifecycle hooks, which are already awaited.
 *
 * Takes the hook and its arguments rather than a `() => hook?.(...)` thunk. The
 * thunk form gave the latch nothing stable to key on - every call built a fresh
 * closure - and it made each of the six call sites repeat the same
 * `err instanceof Error ? err : new Error(String(err))`. Normalising here keeps
 * that in one place and, because the `if (!hook) return` comes first, stops
 * allocating an `Error` on every throwing policy of every request when no hook
 * is wired at all - which is the default.
 *
 * @param hook   - The operator's reporter, or `undefined` when none is wired.
 * @param err    - Whatever was thrown; normalised to an `Error` for the hook.
 * @param policy - The policy the throw came from.
 */
export function safeErrorReport(
  hook: ((err: Error, policy: AccessControl.IPolicy) => void) | undefined,
  err: unknown,
  policy: AccessControl.IPolicy,
): void {
  if (!hook) return
  try {
    hook(err instanceof Error ? err : new Error(String(err)), policy)
  } catch (hookErr) {
    if (_ERROR_HOOK_THREW.has(hook)) return
    _ERROR_HOOK_THREW.add(hook)
    try {
      console.error(
        '[@gentleduck/iam:evaluate] an error-reporting hook threw - swallowed to preserve the decision. ' +
          'This is reported once per hook; the hook is still broken.',
        hookErr,
      )
    } catch {
      /* last-resort: give up logging; the decision matters more than diagnostics */
    }
  }
}
