/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { evalConditionGroup, matchesUnconditionally } from '../conditions/conditions'
import {
  MAX_CONDITION_DEPTH,
  OPERAND_TYPES,
  operandHasType,
  ops,
  VALUELESS_OPERATORS,
} from '../conditions/conditions.libs'
import { matchesAction, matchesResource } from '../resolve'
import type { AccessControl, IamRequest } from '../types'
import type { Evaluate } from './evaluate.types'
/**
 * Action+resource shape only, no conditions: separates "nothing to do with this request" from "shape matches,
 * condition decides", which the cross-policy combine needs to spot a genuinely silent policy.
 */
export function ruleTargetsMatch(rule: AccessControl.IRule, req: IamRequest.IAccessRequest): boolean {
  const actionMatch = rule.actions.some((a) => matchesAction(a, req.action))
  if (!actionMatch) return false

  // The separator comes from the pattern, as `policy.targets` does: `a:*` is a colon prefix, `a.*` a dot subtree.
  return rule.resources.some((r) => matchesResource(r, req.resource.type))
}

/** `ruleTargetsMatch` plus conditions: `true` only when the shape matches AND every condition holds. */
export function ruleApplies(
  rule: AccessControl.IRule,
  req: IamRequest.IAccessRequest,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (!ruleTargetsMatch(rule, req)) return false
  return evalConditionGroup(req, rule.conditions, 0, caches)
}

/**
 * `targets.actions` / `targets.resources` only. Both depend on the (action, resource) pair rather than on who is
 * asking, so `compileTable` can call this with two literals; {@link policyApplies} adds the role check.
 */
export function policyTargetsActionResource(policy: AccessControl.IPolicy, action: string, resource: string): boolean {
  const targets = policy.targets
  if (!targets) return true
  if (targets.actions?.length && !targets.actions.some((a) => matchesAction(a, action))) return false
  if (targets.resources?.length && !targets.resources.some((r) => matchesResource(r, resource))) return false
  return true
}

/**
 * Whether a policy's targets match the request, so it should be evaluated at all.
 * A policy with no targets applies to every request; otherwise every specified dimension must match.
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
 * The cross-policy combine strategies both engines implement.
 * SECURITY: refuse anything else at construction - `evaluate` falls through to `first-applicable` and
 * `evaluateFast` to `'and'`, and TypeScript cannot stop a config-driven or plain-JS caller.
 */
export const VALID_POLICY_COMBINES: readonly AccessControl.PolicyCombine[] = [
  'and',
  'allow-overrides',
  'first-applicable',
]

/**
 * Highest priority wins; the strict `>` keeps a tie on the earliest match, which is source order.
 * `first-match` and `highest-priority` differ only in their `reason`, so they rank through this one function.
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
 * NOTE: source order is `policy.rules` order, which for a stored policy is the adapter's row order, and two
 * equal-priority rules of opposing effect make the verdict depend on it.
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
 * Whether a pattern matches more than its own literal value (`'*'`, `'foo:*'`, `'foo.*'`).
 * Such a pattern cannot use the literal-keyed `byActionResource` map and goes to a wildcard bucket instead.
 */
function isExpansivePattern(p: string): boolean {
  return p.includes('*')
}

/**
 * Cached rule indexes, keyed on the `rules` array so a replaced array cannot serve a stale index, and weak so an
 * index dies with its rules. `length` and `algorithm` are stored alongside, so an append invalidates too.
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
 * Pushes `entry` into the two-level action -> resource bucket map.
 * SECURITY: nested maps, not a joined `` `${a}\0${r}` `` key - literal buckets skip the shape check, so a
 * non-injective key lets a rule fire for an unrelated request.
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
 * Whether the policy carries a deny rule, so failing to evaluate it could hide a deny; used to fail closed.
 * A row with no `rules` array can hide nothing and stays skippable.
 */
export function policyHasDenyRule(policy: AccessControl.IPolicy): boolean {
  return Array.isArray(policy.rules) && policy.rules.some((r) => r.effect === 'deny')
}

/** Priority for ranking; `NaN` or missing (an unvalidated row) ranks as 0 rather than losing every comparison. */
export function rulePriority(rule: { readonly priority: number }): number {
  return Number.isFinite(rule.priority) ? rule.priority : 0
}

/**
 * Whether the conditions must go through `evalConditionGroup` rather than read as an unconditional match.
 * SECURITY: a group that can never match, and an absent or non-object one, belong here too; skipping either
 * would make the fast path honour a rule the interpreter refuses.
 */
function needsConditionEval(c: AccessControl.IConditionGroup | undefined): boolean {
  return !matchesUnconditionally(c)
}

/**
 * Whether any condition under `item` can throw at evaluation, so the policy is handed to the interpreter.
 * SECURITY: covers every throw site in `evalCondition` / `assertItems` - unknown operator, `matches`, absent
 * `value`, operand-type mismatch, `$`-reference, non-array group body, depth, unknown keys - and errs toward `true`.
 */
function conditionMayThrow(item: unknown, depth = 0): boolean {
  // `>=`, matching `evalConditionGroup`: under-approximating would answer a group the interpreter throws on,
  // over-approximating only costs a delegation.
  if (depth >= MAX_CONDITION_DEPTH) return true
  if (item === null || typeof item !== 'object') return false
  if (Array.isArray(item)) return item.some((child) => conditionMayThrow(child, depth + 1))
  if ('operator' in item) {
    const { operator } = item
    if (typeof operator !== 'string' || !Object.hasOwn(ops, operator)) return true
    // `matches` can throw on an oversized input or a refused pattern whatever its operand looks like.
    if (operator === 'matches') return true
    if (VALUELESS_OPERATORS.has(operator)) return false
    const value = Reflect.get(item, 'value')
    if (value === undefined) return true
    const expected = OPERAND_TYPES.get(operator)
    if (expected === undefined) return false
    if (typeof value === 'string' && value.startsWith('$')) return true
    return !operandHasType(expected, value)
  }
  for (const key of ['all', 'any', 'none']) {
    if (!(key in item)) continue
    const body = Reflect.get(item, key)
    if (!Array.isArray(body)) return true
    return conditionMayThrow(body, depth + 1)
  }
  // No recognised key: `{}` is unconditionally true, anything else is Indeterminate and must be handed over.
  return Object.keys(item).length !== 0
}

/** Builds, or retrieves from cache, the {@link Evaluate.IPolicyRuleIndex} for a policy. */
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
      // Action is all-literal here, so key on every literal action; a request finds this entry by its exact action.
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

  // PERF: pre-compute unconditional exact-match rules, but only when no wildcard rule could override the result.
  const precomputed = new Map<string, Map<string, boolean>>()
  const algo = policy.algorithm
  const hasNoWildcards =
    wildcardBoth.length === 0 && byActionWildcardResource.size === 0 && byResourceWildcardAction.size === 0

  // `highest-priority` ranks identically to `first-match`, so it precomputes too.
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

          // Only when every entry in the bucket is unconditional; otherwise the result depends on the request.
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
            // Entries are appended in `policy.rules` order, so ties break as the interpreter's linear scan does.
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
 * Hooks already reported as throwing, latched per hook so one engine cannot silence another's.
 * SECURITY: the report is reachable per policy per request on an attacker-controlled path, so repeating it is a
 * log flood; a WeakSet, since the key is the operator's own function and must not keep their engine alive.
 */
const _ERROR_HOOK_THREW = new WeakSet<object>()

/**
 * Runs an error-reporting hook so a throw inside it cannot escape; the hook itself keys the warn-once latch.
 * SECURITY: callers sit inside the Indeterminate catch, so a throwing hook would unwind the vote it reports.
 * @param hook - The operator's reporter, or `undefined` when none is wired.
 * @param err - Whatever was thrown; normalised to an `Error` for the hook.
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
