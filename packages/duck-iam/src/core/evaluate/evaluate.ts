/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */

import { evalConditionGroup } from '../conditions'
import { matchesAction, matchesResource, matchesResourceHierarchical } from '../resolve'
import type { AccessControl, IamRequest } from '../types'
import {
  combiners,
  indexPolicy,
  policyApplies,
  policyHasDenyRule,
  ruleApplies,
  rulePriority,
  ruleTargetsMatch,
} from './evaluate.libs'
import type { Evaluate } from './evaluate.types'

/**
 * Action+resource shape only, no conditions - same distinction as
 * `ruleTargetsMatch`, inlined for the indexed hot path.
 */
function candidateShapeMatches(
  entry: Evaluate.IIndexedRule,
  action: string,
  resType: string,
  resHasDot: boolean,
): boolean {
  // Action - `entry.actions.has(action)` is a fast path for an exact literal
  // match; a wildcard entry never skips the `matchesAction` prefix check.
  if (!entry.actions.has(action)) {
    let ok = false
    for (const a of entry.rule.actions) {
      if (matchesAction(a, action)) {
        ok = true
        break
      }
    }
    if (!ok) return false
  }

  // Resource - always verified; a wildcard entry never skips this check.
  for (const r of entry.rule.resources) {
    if (resHasDot || r.includes('.')) {
      if (matchesResourceHierarchical(r, resType)) return true
    } else {
      if (matchesResource(r, resType)) return true
    }
  }
  return false
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
 * @param caches        - Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @returns An {@link AccessControl.IDecision} with the evaluation result
 */
export function evaluatePolicy(
  policy: AccessControl.IPolicy,
  request: IamRequest.IAccessRequest,
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

  // Also NotApplicable when no rule's action/resource shape matches at all -
  // a policy about `update` has nothing to say about `read` and must not
  // fold in as a defaultEffect vote just because its `targets` were silent.
  if (!policy.rules.some((rule) => ruleTargetsMatch(rule, request))) {
    return {
      allowed: defaultEffect === 'allow',
      effect: defaultEffect,
      policy: policy.id,
      reason: `Policy "${policy.id}" has no rule for this action/resource. Not applicable.`,
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
 * Combine decisions across multiple policies per `combine` (`'and'` | `'allow-overrides'` | `'first-applicable'`).
 *
 * @param policies      All policies to evaluate.
 * @param request       The access request.
 * @param defaultEffect Effect when no rule fires within a policy.
 * @param combine       Cross-policy combine strategy (defaults to `'and'`).
 * @param onPolicyError Invoked when a single policy throws; offender treated as NotApplicable.
 * @param signals       Optional {@link IEvalSignals} out-parameter; `failOpen` is set on a default-effect allow.
 * @param caches        Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @returns The merged {@link AccessControl.IDecision} across all policies.
 */
export function evaluate(
  policies: AccessControl.IPolicy[],
  request: IamRequest.IAccessRequest,
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
   * One rotten policy must not break the whole evaluation, but an error is
   * Indeterminate rather than NotApplicable: skipping a policy that could have
   * denied lets an attacker disable it by making evaluation throw (padding the
   * field a `matches` rule reads). So a policy carrying any deny rule fails
   * closed; an allow-only policy stays skippable.
   */
  const safeEval = (policy: AccessControl.IPolicy): AccessControl.IDecision => {
    try {
      return evaluatePolicy(policy, request, defaultEffect, caches)
    } catch (err) {
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), policy)
      if (policyHasDenyRule(policy)) {
        return {
          allowed: false,
          effect: 'deny',
          reason: 'Policy evaluation error - denied (indeterminate)',
          duration: 0,
          timestamp: Date.now(),
        }
      }
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
 * Fast (production-mode) single-policy evaluation; allocation-light combiner shell.
 *
 * @param policy        The policy to evaluate.
 * @param request       The access request.
 * @param defaultEffect Effect to use when no rules match (defaults to `'deny'`).
 * @param caches        Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @returns `true` / `false` for an applicable allow / deny, `null` when NotApplicable.
 */
export function evaluatePolicyFast(
  policy: AccessControl.IPolicy,
  request: IamRequest.IAccessRequest,
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
  // suffixes are bucketed by whichever side of them is still literal and
  // checked there via `candidateShapeMatches` -> `matchesResource(Hierarchical)`.
  const literalBuckets: Evaluate.IIndexedRule[][] = []
  const exactAR = idx.byActionResource.get(`${action}\0${resType}`)
  if (exactAR) literalBuckets.push(exactAR)
  const resHasDot = resType.includes('.')
  const algo = policy.algorithm

  // Narrow the "every expansive rule" scan down to the (usually small, often
  // empty) subset whose literal side already matches this request - entries
  // keyed by this exact action still need a resource check, entries keyed by
  // this exact resource still need an action check, wildcardBoth needs both.
  const wildcardBuckets: Evaluate.IIndexedRule[][] = []
  const byAction = idx.byActionWildcardResource.get(action)
  if (byAction) wildcardBuckets.push(byAction)
  const byResource = idx.byResourceWildcardAction.get(resType)
  if (byResource) wildcardBuckets.push(byResource)
  if (idx.wildcardBoth.length > 0) wildcardBuckets.push(idx.wildcardBoth)

  // hasCandidate: at least one rule's action/resource shape matches, regardless
  // of whether its condition ultimately holds. A literal bucket is an exact-key
  // hit, so its mere presence already is a shape match. Distinguishes "this
  // policy has nothing to do with the request" (null, abstain) from "it does,
  // and here's its answer" (a real vote, possibly the defaultEffect fallback).

  if (algo === 'deny-overrides') {
    let hasAllow = false
    let hasCandidate = literalBuckets.length > 0
    for (let bi = 0; bi < literalBuckets.length; bi++) {
      const bucket = literalBuckets[bi]!
      for (let i = 0; i < bucket.length; i++) {
        const entry = bucket[i]!
        if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
        if (entry.rule.effect === 'deny') return false
        hasAllow = true
      }
    }
    for (let bi = 0; bi < wildcardBuckets.length; bi++) {
      const bucket = wildcardBuckets[bi]!
      for (let i = 0; i < bucket.length; i++) {
        const entry = bucket[i]!
        if (!candidateShapeMatches(entry, action, resType, resHasDot)) continue
        hasCandidate = true
        if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
        if (entry.rule.effect === 'deny') return false
        hasAllow = true
      }
    }
    if (hasAllow) return true
    return hasCandidate ? defaultEffect === 'allow' : null
  }

  if (algo === 'allow-overrides') {
    let hasDeny = false
    let hasCandidate = literalBuckets.length > 0
    for (let bi = 0; bi < literalBuckets.length; bi++) {
      const bucket = literalBuckets[bi]!
      for (let i = 0; i < bucket.length; i++) {
        const entry = bucket[i]!
        if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
        if (entry.rule.effect === 'allow') return true
        hasDeny = true
      }
    }
    for (let bi = 0; bi < wildcardBuckets.length; bi++) {
      const bucket = wildcardBuckets[bi]!
      for (let i = 0; i < bucket.length; i++) {
        const entry = bucket[i]!
        if (!candidateShapeMatches(entry, action, resType, resHasDot)) continue
        hasCandidate = true
        if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
        if (entry.rule.effect === 'allow') return true
        hasDeny = true
      }
    }
    if (hasDeny) return false
    return hasCandidate ? defaultEffect === 'allow' : null
  }

  // first-match (priority-aware) + highest-priority share the scan loop.
  // Both resolve equal priorities by source order. This scan walks literal
  // buckets before wildcard ones, which is not source order, so a plain
  // `p > bestPriority` would let a later literal rule outrank an earlier
  // wildcard one on a tie and disagree with the interpreter. Compare the
  // recorded `order` whenever the priorities are equal.
  let bestPriority = -Infinity
  let bestOrder = Infinity
  let bestEffect: AccessControl.Effect | null = null
  let hasCandidate = literalBuckets.length > 0
  for (let bi = 0; bi < literalBuckets.length; bi++) {
    const bucket = literalBuckets[bi]!
    for (let i = 0; i < bucket.length; i++) {
      const entry = bucket[i]!
      if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
      const p = rulePriority(entry.rule)
      if (p > bestPriority || (p === bestPriority && entry.order < bestOrder)) {
        bestPriority = p
        bestOrder = entry.order
        bestEffect = entry.rule.effect
      }
    }
  }
  for (let bi = 0; bi < wildcardBuckets.length; bi++) {
    const bucket = wildcardBuckets[bi]!
    for (let i = 0; i < bucket.length; i++) {
      const entry = bucket[i]!
      if (!candidateShapeMatches(entry, action, resType, resHasDot)) continue
      hasCandidate = true
      if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
      const p = rulePriority(entry.rule)
      if (p > bestPriority || (p === bestPriority && entry.order < bestOrder)) {
        bestPriority = p
        bestOrder = entry.order
        bestEffect = entry.rule.effect
      }
    }
  }
  if (bestEffect !== null) return bestEffect === 'allow'
  return hasCandidate ? defaultEffect === 'allow' : null
}

/**
 * Fast multi-policy evaluation returning a boolean; mirrors {@link evaluate}'s `combine` modes (no `first-applicable`).
 *
 * @param policies      All policies to evaluate.
 * @param request       The access request.
 * @param defaultEffect Effect to use when no rules fire (defaults to `'deny'`).
 * @param combine       Cross-policy combine strategy (defaults to `'and'`).
 * @param onPolicyError Invoked when a single policy throws; offender treated as NotApplicable.
 * @param signals       Optional {@link IEvalSignals} out-parameter; `failOpen` is set on a default-effect allow.
 * @param caches        Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @returns `true` when the final verdict is allow, `false` otherwise.
 */
export function evaluateFast(
  policies: AccessControl.IPolicy[],
  request: IamRequest.IAccessRequest,
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
   * A single rotten row (malformed condition, etc.) must not poison the whole
   * evaluation, but a policy that could have denied fails closed rather than
   * being skipped; the error is routed to `onPolicyError` either way. (A
   * non-finite `priority` does not throw; `rulePriority` ranks it as 0.)
   */
  const safeEval = (policy: AccessControl.IPolicy): boolean | null => {
    try {
      return evaluatePolicyFast(policy, request, defaultEffect, caches)
    } catch (err) {
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), policy)
      // Indeterminate, not NotApplicable - see the slow path's `safeEval`.
      return policyHasDenyRule(policy) ? false : null
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
