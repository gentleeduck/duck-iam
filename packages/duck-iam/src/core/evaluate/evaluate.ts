/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */

import { evalConditionGroup } from '../conditions'
import { matchesAction, matchesResource, matchesResourceHierarchical } from '../resolve'
import type { AccessControl, Request } from '../types'
import { combiners, indexPolicy, policyApplies, ruleApplies } from './evaluate.libs'
import type { Evaluate } from './evaluate.types'

// Literal resource patterns match only the exact resource type; recursive
// grants require the explicit `:*` / `.*` suffix and are handled by
// `wildcardAny`.

/**
 * Inline candidate matching - checks resource + conditions without allocating.
 * Action is already narrowed by the index lookup.
 */
function matchCandidate(
  entry: Evaluate.IIndexedRule,
  action: string,
  resType: string,
  resHasDot: boolean,
  req: Request.IAccessRequest,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  // Action - already narrowed by index, but handle prefix patterns
  if (!entry.hasWildcardAction && !entry.actions.has(action)) {
    let ok = false
    for (const a of entry.rule.actions) {
      if (matchesAction(a, action)) {
        ok = true
        break
      }
    }
    if (!ok) return false
  }

  // Resource
  if (!entry.hasWildcardResource) {
    let ok = false
    for (const r of entry.rule.resources) {
      if (resHasDot || r.includes('.')) {
        if (matchesResourceHierarchical(r, resType)) {
          ok = true
          break
        }
      } else {
        if (matchesResource(r, resType)) {
          ok = true
          break
        }
      }
    }
    if (!ok) return false
  }

  if (!entry.hasConditions) return true
  return evalConditionGroup(req, entry.rule.conditions, 0, caches)
}

/**
 * Evaluates a single policy against an access request.
 *
 * Pure function with no side effects. Checks policy targets first, then
 * evaluates matching rules using the policy's combining algorithm.
 *
 * @param policy        - The policy to evaluate
 * @param request       - The access request to evaluate against
 * @param defaultEffect - Effect to use when no rules match (defaults to `'deny'`)
 * @returns An {@link AccessControl.IDecision} with the evaluation result
 */
export function evaluatePolicy(
  policy: AccessControl.IPolicy,
  request: Request.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): AccessControl.IDecision {
  const start = performance.now()

  if (!policyApplies(policy, request)) {
    // NotApplicable: policy is neutral - the cross-policy combine must skip it,
    // not fold it as the default effect.
    return {
      allowed: defaultEffect === 'allow',
      effect: defaultEffect,
      policy: policy.id,
      reason: `Policy "${policy.id}" targets do not match. Not applicable.`,
      duration: performance.now() - start,
      timestamp: Date.now(),
      applicable: false,
    }
  }

  const matched: Array<{ rule: AccessControl.IRule; effect: AccessControl.Effect }> = []

  for (const rule of policy.rules) {
    if (ruleApplies(rule, request, caches)) {
      matched.push({ rule, effect: rule.effect })
    }
  }

  const combiner = combiners[policy.algorithm]
  const result = combiner(matched, defaultEffect)

  return {
    allowed: result.effect === 'allow',
    effect: result.effect,
    rule: result.rule,
    policy: policy.id,
    reason: result.reason,
    duration: performance.now() - start,
    timestamp: Date.now(),
  }
}

/**
 * Combine decisions across multiple policies according to `combine`.
 *
 * - `'and'` (default): every policy must allow. First deny short-circuits.
 * - `'allow-overrides'`: any allowing policy wins, regardless of denies elsewhere.
 * - `'first-applicable'`: first policy whose targets+rules fired a non-default
 *   decision wins. Useful when policies are ordered by specificity.
 *
 * @param policies      All policies to evaluate.
 * @param request       The access request.
 * @param defaultEffect Effect when no rule fires within a policy.
 * @param combine       Cross-policy combine strategy (defaults to `'and'`).
 * @param onPolicyError Invoked when a single policy throws; the offending policy
 *   is treated as NotApplicable so the rest still evaluate.
 * @returns The merged {@link AccessControl.IDecision} across all policies.
 * @example
 * ```ts
 * const decision = evaluate(policies, request, 'deny', 'and')
 * if (!decision.allowed) console.warn(decision.reason)
 * ```
 */
export function evaluate(
  policies: AccessControl.IPolicy[],
  request: Request.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  combine: AccessControl.PolicyCombine = 'and',
  onPolicyError?: (err: Error, policy: AccessControl.IPolicy) => void,
  signals?: IEvalSignals,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): AccessControl.IDecision {
  const start = performance.now()

  if (policies.length === 0) {
    if (signals && defaultEffect === 'allow') signals.failOpen = true
    return {
      allowed: defaultEffect === 'allow',
      effect: defaultEffect,
      reason: 'No policies configured',
      duration: performance.now() - start,
      timestamp: Date.now(),
    }
  }

  /**
   * Same fail-skip contract as {@link evaluateFast}: one rotten policy must
   * not break the whole evaluation. Synthesise a NotApplicable decision so
   * the combiner skips it cleanly.
   */
  const safeEval = (policy: AccessControl.IPolicy): AccessControl.IDecision => {
    try {
      return evaluatePolicy(policy, request, defaultEffect, caches)
    } catch (err) {
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), policy)
      return {
        allowed: defaultEffect === 'allow',
        effect: defaultEffect,
        reason: 'Policy evaluation error - skipped',
        applicable: false,
        duration: 0,
        timestamp: Date.now(),
      }
    }
  }

  if (combine === 'and') {
    let lastAllow: AccessControl.IDecision | null = null
    for (const policy of policies) {
      const decision = safeEval(policy)
      if (decision.applicable === false) continue
      if (!decision.allowed) return { ...decision, duration: performance.now() - start }
      lastAllow = decision
    }
    if (lastAllow === null) {
      if (signals && defaultEffect === 'allow') signals.failOpen = true
      return {
        allowed: defaultEffect === 'allow',
        effect: defaultEffect,
        reason: `No policy applicable. Defaulted to ${defaultEffect}`,
        duration: performance.now() - start,
        timestamp: Date.now(),
      }
    }
    return { ...lastAllow, duration: performance.now() - start }
  }

  if (combine === 'allow-overrides') {
    let lastDeny: AccessControl.IDecision | null = null
    for (const policy of policies) {
      const decision = safeEval(policy)
      if (decision.applicable === false) continue
      if (decision.allowed) return { ...decision, duration: performance.now() - start }
      lastDeny = decision
    }
    if (lastDeny === null) {
      if (signals && defaultEffect === 'allow') signals.failOpen = true
      return {
        allowed: defaultEffect === 'allow',
        effect: defaultEffect,
        reason: `No policy applicable. Defaulted to ${defaultEffect}`,
        duration: performance.now() - start,
        timestamp: Date.now(),
      }
    }
    return { ...lastDeny, duration: performance.now() - start }
  }

  for (const policy of policies) {
    const decision = safeEval(policy)
    if (decision.applicable === false) continue
    if (decision.rule !== undefined) return { ...decision, duration: performance.now() - start }
  }
  if (signals && defaultEffect === 'allow') signals.failOpen = true
  return {
    allowed: defaultEffect === 'allow',
    effect: defaultEffect,
    reason: `No policy was applicable. Defaulted to ${defaultEffect}`,
    duration: performance.now() - start,
    timestamp: Date.now(),
  }
}

/**
 * Fast (production-mode) single-policy evaluation.
 *
 * Returns `true` / `false` when the policy applies; returns `null` when the
 * policy's targets don't match the request (NotApplicable - the cross-policy
 * combine treats it as neutral, not as the default effect).
 *
 * Avoids the trace path's per-call allocations (no `matched[]`, no
 * `{ rule, effect }` objects, no intermediate arrays). Condition evaluation
 * itself can still allocate; "zero-allocation" applies to the combiner shell.
 *
 * @param policy        The policy to evaluate.
 * @param request       The access request.
 * @param defaultEffect Effect to use when no rules match (defaults to `'deny'`).
 * @returns `true` / `false` for an applicable allow / deny, `null` when the
 *   policy is NotApplicable for this request.
 */
export function evaluatePolicyFast(
  policy: AccessControl.IPolicy,
  request: Request.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean | null {
  // Inline policyApplies - avoid function call overhead
  const targets = policy.targets
  if (targets) {
    if (targets.actions?.length && !targets.actions.some((a) => matchesAction(a, request.action))) return null
    if (targets.resources?.length && !targets.resources.some((r) => matchesResource(r, request.resource.type))) {
      return null
    }
    if (targets.roles?.length) {
      const subjectRoles = Array.isArray(request.subject.roles) ? request.subject.roles : []
      if (!targets.roles.some((role) => subjectRoles.includes(role))) return null
    }
  }

  const idx = indexPolicy(policy)
  const action = request.action
  const resType = request.resource.type

  // Fastest path: pre-computed result for unconditional rules (CASL-like O(1)).
  // Literal resource patterns match only the exact resource type - do NOT
  // probe parent prefixes here.
  const actionMap = idx.precomputed.get(action)
  if (actionMap) {
    const precomputed = actionMap.get(resType)
    if (precomputed !== undefined) return precomputed
  }

  // Literal buckets are matched by exact key only. Rules with `:*` / `.*`
  // suffixes live in `wildcardAny` and are checked there via `matchCandidate`
  // -> `matchesResource(Hierarchical)`.
  const literalBuckets: Evaluate.IIndexedRule[][] = []
  const exactAR = idx.byActionResource.get(`${action}\0${resType}`)
  if (exactAR) literalBuckets.push(exactAR)
  const wildcardAny = idx.wildcardAny
  const resHasDot = resType.includes('.')
  const algo = policy.algorithm

  if (algo === 'deny-overrides') {
    let hasAllow = false
    for (let bi = 0; bi < literalBuckets.length; bi++) {
      const bucket = literalBuckets[bi]!
      for (let i = 0; i < bucket.length; i++) {
        const entry = bucket[i]!
        if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
        if (entry.rule.effect === 'deny') return false
        hasAllow = true
      }
    }
    for (let i = 0; i < wildcardAny.length; i++) {
      const entry = wildcardAny[i]!
      if (!matchCandidate(entry, action, resType, resHasDot, request, caches)) continue
      if (entry.rule.effect === 'deny') return false
      hasAllow = true
    }
    return hasAllow ? true : defaultEffect === 'allow'
  }

  if (algo === 'allow-overrides') {
    let hasDeny = false
    for (let bi = 0; bi < literalBuckets.length; bi++) {
      const bucket = literalBuckets[bi]!
      for (let i = 0; i < bucket.length; i++) {
        const entry = bucket[i]!
        if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
        if (entry.rule.effect === 'allow') return true
        hasDeny = true
      }
    }
    for (let i = 0; i < wildcardAny.length; i++) {
      const entry = wildcardAny[i]!
      if (!matchCandidate(entry, action, resType, resHasDot, request, caches)) continue
      if (entry.rule.effect === 'allow') return true
      hasDeny = true
    }
    return hasDeny ? false : defaultEffect === 'allow'
  }

  // first-match (priority-aware) + highest-priority share the scan loop.
  let bestPriority = -Infinity
  let bestEffect: AccessControl.Effect | null = null
  for (let bi = 0; bi < literalBuckets.length; bi++) {
    const bucket = literalBuckets[bi]!
    for (let i = 0; i < bucket.length; i++) {
      const entry = bucket[i]!
      if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions)) continue
      if (entry.rule.priority > bestPriority) {
        bestPriority = entry.rule.priority
        bestEffect = entry.rule.effect
      }
    }
  }
  for (let i = 0; i < wildcardAny.length; i++) {
    const entry = wildcardAny[i]!
    if (!matchCandidate(entry, action, resType, resHasDot, request)) continue
    if (entry.rule.priority > bestPriority) {
      bestPriority = entry.rule.priority
      bestEffect = entry.rule.effect
    }
  }
  return bestEffect !== null ? bestEffect === 'allow' : defaultEffect === 'allow'
}

/**
 * Fast multi-policy evaluation - returns a plain boolean.
 *
 * Mirrors {@link evaluate}'s `combine` modes. `'first-applicable'` is not
 * supported here (the policy-fast path returns a tri-state but cannot
 * distinguish "rule fired" from "default applied" - the `Engine` constructor
 * refuses the combination at boot).
 *
 * @param policies      All policies to evaluate.
 * @param request       The access request.
 * @param defaultEffect Effect to use when no rules fire (defaults to `'deny'`).
 * @param combine       Cross-policy combine strategy (defaults to `'and'`).
 * @param onPolicyError Invoked when a single policy throws; the offending policy
 *   is treated as NotApplicable so the rest still evaluate.
 * @returns `true` when the final verdict is allow, `false` otherwise.
 */
export function evaluateFast(
  policies: AccessControl.IPolicy[],
  request: Request.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  combine: AccessControl.PolicyCombine = 'and',
  onPolicyError?: (err: Error, policy: AccessControl.IPolicy) => void,
  signals?: IEvalSignals,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (policies.length === 0) {
    const allowed = defaultEffect === 'allow'
    if (signals && allowed) signals.failOpen = true
    return allowed
  }

  /**
   * A single rotten row (NaN priority, malformed condition, etc.) must not
   * poison the whole evaluation - treat the offending policy as NotApplicable
   * and route the error to `onPolicyError` so the operator can alert.
   */
  const safeEval = (policy: AccessControl.IPolicy): boolean | null => {
    try {
      return evaluatePolicyFast(policy, request, defaultEffect, caches)
    } catch (err) {
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), policy)
      return null
    }
  }

  if (combine === 'allow-overrides') {
    let anyApplicable = false
    for (const policy of policies) {
      const r = safeEval(policy)
      if (r === null) continue
      anyApplicable = true
      if (r) return true
    }
    if (!anyApplicable) {
      const allowed = defaultEffect === 'allow'
      if (signals && allowed) signals.failOpen = true
      return allowed
    }
    return false
  }

  // 'and' (and 'first-applicable' fall-through, which Engine ctor blocks for prod).
  let anyApplicable = false
  for (const policy of policies) {
    const r = safeEval(policy)
    if (r === null) continue
    anyApplicable = true
    if (!r) return false
  }
  if (!anyApplicable) {
    const allowed = defaultEffect === 'allow'
    if (signals && allowed) signals.failOpen = true
    return allowed
  }
  return true
}

/**
 * Out-parameter shape for {@link evaluateFast}. Callers pass an empty object;
 * the evaluator mutates fields as side-effects are observed. Useful for
 * metrics that need details the boolean return cannot carry.
 */
export interface IEvalSignals {
  /**
   * Set to `true` only when the engine returned `allow` because the
   * `defaultEffect` fallback was triggered - i.e. no applicable policy fired.
   * Never set when an explicit allow rule matched. Operators chart this to
   * detect silent failures of the policy set (broken adapter, mass deletion,
   * etc.) that the boolean verdict alone hides.
   */
  failOpen?: boolean
}
