/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */

import { evalConditionGroup } from '../conditions/conditions'
import { IAM_RBAC_POLICY_ID } from '../rbac/rbac'
import { matchesAction, matchesResource } from '../resolve'
import type { AccessControl, IamRequest } from '../types'
import {
  combiners,
  indexPolicy,
  isRuleEffect,
  policyApplies,
  policyHasDenyRule,
  ranksByPriority,
  ruleApplies,
  rulePriority,
  ruleTargetsMatch,
  safeErrorReport,
} from './evaluate.libs'
import type { Evaluate } from './evaluate.types'

/** Action+resource shape only, no conditions: `ruleTargetsMatch` inlined for the indexed hot path. */
function candidateShapeMatches(entry: Evaluate.IIndexedRule, action: string, resType: string): boolean {
  // PERF: `entry.actions.has` is the exact-literal fast path; a wildcard entry still runs `matchesAction`.
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
    if (matchesResource(r, resType)) return true
  }
  return false
}

/**
 * Evaluates one policy: targets first, then the matching rules under the policy's combining algorithm.
 * @param policy - The policy to evaluate.
 * @param request - The access request to evaluate against.
 * @param defaultEffect - Effect to use when no rule matches.
 * @param caches - Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @param onRuleError - Reports a rule that threw and abstained; see `rulesAbstainOnThrow`.
 * @returns An {@link AccessControl.IDecision} with the evaluation result.
 */
export function evaluatePolicy(
  policy: AccessControl.IPolicy,
  request: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
  onRuleError?: AccessControl.PolicyErrorHandler,
): AccessControl.IDecision {
  const start = performance.now()

  if (!policyApplies(policy, request)) {
    // NotApplicable: the cross-policy combine skips it rather than folding in a `defaultEffect` vote.
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

  // Also NotApplicable when no rule's shape matches: a policy about `update` has nothing to say about `read`,
  // even when its `targets` were silent.
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

  // SECURITY: a non-finite priority is Indeterminate under the two ranking algorithms. Checked at policy level,
  // after the NotApplicable tests, so the fast path and the interpreter refuse the same requests.
  if (ranksByPriority(policy.algorithm) && policy.rules.some((rule) => !Number.isFinite(rule.priority))) {
    throw new Error(`[@gentleduck/iam:evaluate] Rule priority must be a finite number in policy "${policy.id}"`)
  }

  const matched: Array<{ rule: AccessControl.IRule; effect: AccessControl.Effect }> = []

  /**
   * A throwing rule abstains only in the allow-only RBAC union, whose rules are independent per-role grants.
   * SECURITY: skipping one there can only lose access; anywhere else it would disagree with the compiled table.
   */
  const rulesAbstainOnThrow = policy.id === IAM_RBAC_POLICY_ID && !policyHasDenyRule(policy)

  for (const rule of policy.rules) {
    let applies: boolean
    try {
      applies = ruleApplies(rule, request, caches)
    } catch (err) {
      if (!rulesAbstainOnThrow) throw err
      safeErrorReport(onRuleError, err, policy)
      continue
    }
    if (applies) {
      // SECURITY: an unrecognised effect is Indeterminate, not an abstention. Under `deny-overrides` a mistyped
      // deny votes for neither arm, so a sibling allow wins and the deny is silently lost.
      if (!isRuleEffect(rule.effect)) {
        throw new Error(`[@gentleduck/iam:evaluate] Unknown effect ${JSON.stringify(rule.effect)} on rule "${rule.id}"`)
      }
      matched.push({ rule, effect: rule.effect })
    }
  }

  // SECURITY: own properties only, and Indeterminate rather than a verdict, as the fast path already is. An
  // inherited `constructor` is a function and answered a decision object with no `effect` at all.
  if (!Object.hasOwn(combiners, policy.algorithm)) {
    throw new Error(`[@gentleduck/iam:evaluate] Unknown combining algorithm "${String(policy.algorithm)}"`)
  }
  const result = combiners[policy.algorithm](matched, defaultEffect)

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
 * Whether an allow came from `defaultEffect` rather than from a rule of an applicable policy.
 * That is the condition {@link IEvalSignals.failOpen} reports, and it is not visible from `allowed` alone.
 */
function allowedByDefaultEffect(decision: AccessControl.IDecision): boolean {
  return decision.allowed && decision.rule === undefined && decision.applicable !== false
}

/**
 * Combine decisions across multiple policies per `combine` (`'and'` | `'allow-overrides'` | `'first-applicable'`).
 *
 * @param policies - All policies to evaluate.
 * @param request - The access request.
 * @param defaultEffect - Effect when no rule fires within a policy.
 * @param combine - Cross-policy combine strategy.
 * @param onPolicyError - Invoked when a single policy throws; the offender is Indeterminate, never NotApplicable.
 * @param signals - Optional {@link IEvalSignals} out-parameter; `failOpen` is set on a default-effect allow.
 * @param caches - Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @returns The merged {@link AccessControl.IDecision} across all policies.
 */
export function evaluate(
  policies: AccessControl.IPolicy[],
  request: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  combine: AccessControl.PolicyCombine = 'and',
  onPolicyError?: AccessControl.PolicyErrorHandler,
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
   * Evaluates one policy; a throw is Indeterminate, never NotApplicable, so a forced throw cannot delete a vote.
   * SECURITY: a deny-bearing policy votes deny; an allow-only one votes `defaultEffect` and stays applicable.
   */
  const safeEval = (policy: AccessControl.IPolicy): AccessControl.IDecision => {
    try {
      return evaluatePolicy(policy, request, defaultEffect, caches, onPolicyError)
    } catch (err) {
      safeErrorReport(onPolicyError, err, policy)
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
        reason: `Policy evaluation error - defaulted to ${defaultEffect} (indeterminate)`,
        duration: 0,
        timestamp: Date.now(),
      }
    }
  }

  if (combine === 'and') {
    let lastAllow: AccessControl.IDecision | null = null
    let defaultSourced = false
    for (const policy of policies) {
      const decision = safeEval(policy)
      if (decision.applicable === false) continue
      if (!decision.allowed) return { ...decision, duration: performance.now() - start }
      if (allowedByDefaultEffect(decision)) defaultSourced = true
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
    // Every applicable policy contributed, so one that allowed only through `defaultEffect` is the `failOpen` shape.
    if (signals && defaultSourced) signals.failOpen = true
    return { ...lastAllow, duration: performance.now() - start }
  }

  if (combine === 'allow-overrides') {
    let lastDeny: AccessControl.IDecision | null = null
    for (const policy of policies) {
      const decision = safeEval(policy)
      if (decision.applicable === false) continue
      if (decision.allowed) {
        if (signals && allowedByDefaultEffect(decision)) signals.failOpen = true
        return { ...decision, duration: performance.now() - start }
      }
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

  // XACML `first-applicable`: the first result that is not NotApplicable wins, whether or not it names a rule.
  // NOTE: a default-effect vote and `safeEval`'s Indeterminate deny both carry no rule, so only `applicable` counts.
  for (const policy of policies) {
    const decision = safeEval(policy)
    if (decision.applicable === false) continue
    if (signals && allowedByDefaultEffect(decision)) signals.failOpen = true
    return { ...decision, duration: performance.now() - start }
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
 * Per-policy out-parameter: `true` when the vote came from the `defaultEffect` fallback rather than from a rule.
 * The boolean return cannot carry it, and {@link IEvalSignals.failOpen} needs it. Callers reuse one object per loop.
 */
export interface IVoteSource {
  fromDefault: boolean
}

/**
 * Fast (production-mode) single-policy evaluation against the policy's cached rule index.
 *
 * @param policy - The policy to evaluate.
 * @param request - The access request.
 * @param defaultEffect - Effect to use when no rule matches.
 * @param caches - Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @param voteSource - Optional {@link IVoteSource}; reset on entry, set when the vote is the `defaultEffect` fallback.
 * @param onRuleError - Forwarded to {@link evaluatePolicy} when the policy is handed over.
 * @returns `true` / `false` for an applicable allow / deny, `null` when NotApplicable.
 */
export function evaluatePolicyFast(
  policy: AccessControl.IPolicy,
  request: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
  voteSource?: IVoteSource,
  onRuleError?: AccessControl.PolicyErrorHandler,
): boolean | null {
  if (voteSource) voteSource.fromDefault = false

  // PERF: `policyApplies` inlined.
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

  // SECURITY: an unknown algorithm throws (Indeterminate) instead of falling through to the first-match scan,
  // which would let this path allow what the interpreter denies. Mirror the interpreter's NotApplicable test first.
  if (!Object.hasOwn(combiners, policy.algorithm)) {
    if (!policy.rules.some((rule) => ruleTargetsMatch(rule, request))) return null
    throw new Error(`[@gentleduck/iam:evaluate] Unknown combining algorithm "${String(policy.algorithm)}"`)
  }

  if (ranksByPriority(policy.algorithm) && policy.rules.some((rule) => !Number.isFinite(rule.priority))) {
    if (!policy.rules.some((rule) => ruleTargetsMatch(rule, request))) return null
    throw new Error(`[@gentleduck/iam:evaluate] Rule priority must be a finite number in policy "${policy.id}"`)
  }

  const idx = indexPolicy(policy)

  // SECURITY: a policy with a throwable condition goes to the interpreter, since the early returns below can reach
  // a verdict before the throwing rule runs and the two modes must agree. `mayThrow` is cached with the index.
  if (idx.mayThrow) {
    const decision = evaluatePolicy(policy, request, defaultEffect, caches, onRuleError)
    return decision.applicable === false ? null : decision.allowed
  }

  const action = request.action
  const resType = request.resource.type

  // PERF: pre-computed answer for unconditional rules. A literal resource pattern matches the exact type only,
  // so parent prefixes must not be probed here.
  const actionMap = idx.precomputed.get(action)
  if (actionMap) {
    const precomputed = actionMap.get(resType)
    if (precomputed !== undefined) return precomputed
  }

  // Literal buckets match by exact key; a `:*` / `.*` rule is bucketed by its literal side and shape-checked below.
  const literalBuckets: Evaluate.IIndexedRule[][] = []
  const exactAR = idx.byActionResource.get(action)?.get(resType)
  if (exactAR) literalBuckets.push(exactAR)
  const algo = policy.algorithm

  // PERF: narrows the expansive scan to rules whose literal side already matches. Each still needs its other
  // side checked, and `wildcardBoth` needs both.
  const wildcardBuckets: Evaluate.IIndexedRule[][] = []
  const byAction = idx.byActionWildcardResource.get(action)
  if (byAction) wildcardBuckets.push(byAction)
  const byResource = idx.byResourceWildcardAction.get(resType)
  if (byResource) wildcardBuckets.push(byResource)
  if (idx.wildcardBoth.length > 0) wildcardBuckets.push(idx.wildcardBoth)

  // `hasCandidate` separates "no match" (null) from an answer; a literal bucket is an exact-key hit, so it counts.
  // SECURITY: the `effect` tests below are positive, so a row with an unrecognised effect would vote for neither
  // arm. `indexPolicy` sets `mayThrow` for one, which sends the policy to the interpreter to be refused instead.
  if (algo === 'deny-overrides') {
    let hasAllow = false
    let hasCandidate = literalBuckets.length > 0
    for (let bi = 0; bi < literalBuckets.length; bi++) {
      const bucket = literalBuckets[bi]!
      for (let i = 0; i < bucket.length; i++) {
        const entry = bucket[i]!
        if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
        if (entry.rule.effect === 'deny') return false
        if (entry.rule.effect === 'allow') hasAllow = true
      }
    }
    for (let bi = 0; bi < wildcardBuckets.length; bi++) {
      const bucket = wildcardBuckets[bi]!
      for (let i = 0; i < bucket.length; i++) {
        const entry = bucket[i]!
        if (!candidateShapeMatches(entry, action, resType)) continue
        hasCandidate = true
        if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
        if (entry.rule.effect === 'deny') return false
        if (entry.rule.effect === 'allow') hasAllow = true
      }
    }
    if (hasAllow) return true
    if (!hasCandidate) return null
    if (voteSource) voteSource.fromDefault = true
    return defaultEffect === 'allow'
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
        if (entry.rule.effect === 'deny') hasDeny = true
      }
    }
    for (let bi = 0; bi < wildcardBuckets.length; bi++) {
      const bucket = wildcardBuckets[bi]!
      for (let i = 0; i < bucket.length; i++) {
        const entry = bucket[i]!
        if (!candidateShapeMatches(entry, action, resType)) continue
        hasCandidate = true
        if (entry.hasConditions && !evalConditionGroup(request, entry.rule.conditions, 0, caches)) continue
        if (entry.rule.effect === 'allow') return true
        if (entry.rule.effect === 'deny') hasDeny = true
      }
    }
    if (hasDeny) return false
    if (!hasCandidate) return null
    if (voteSource) voteSource.fromDefault = true
    return defaultEffect === 'allow'
  }

  // first-match (priority-aware) and highest-priority share this scan; both resolve equal priorities by source order.
  // NOTE: bucket order is not source order, so a tie compares the recorded `order` or the interpreter disagrees.
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
      if (!candidateShapeMatches(entry, action, resType)) continue
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
  if (!hasCandidate) return null
  if (voteSource) voteSource.fromDefault = true
  return defaultEffect === 'allow'
}

/**
 * Fast multi-policy evaluation returning a boolean; mirrors {@link evaluate}'s `combine` modes (no `first-applicable`).
 *
 * @param policies - All policies to evaluate.
 * @param request - The access request.
 * @param defaultEffect - Effect to use when no rule fires.
 * @param combine - Cross-policy combine strategy.
 * @param onPolicyError - Invoked when a single policy throws; the offender is Indeterminate, never NotApplicable.
 * @param signals - Optional {@link IEvalSignals} out-parameter; `failOpen` is set on a default-effect allow.
 * @param caches - Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @returns `true` when the final verdict is allow, `false` otherwise.
 */
export function evaluateFast(
  policies: AccessControl.IPolicy[],
  request: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  combine: AccessControl.PolicyCombine = 'and',
  onPolicyError?: AccessControl.PolicyErrorHandler,
  signals?: IEvalSignals,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (policies.length === 0) {
    const allowed = defaultEffect === 'allow'
    if (signals && allowed) signals.failOpen = true
    return allowed
  }

  /**
   * Mirrors the slow path's `safeEval`; see it for the Indeterminate contract.
   * SECURITY: neither vote is skippable, and returning `null` here would skip it.
   */
  const voteSource: IVoteSource = { fromDefault: false }
  const safeEval = (policy: AccessControl.IPolicy): boolean | null => {
    try {
      return evaluatePolicyFast(policy, request, defaultEffect, caches, voteSource, onPolicyError)
    } catch (err) {
      safeErrorReport(onPolicyError, err, policy)
      voteSource.fromDefault = false
      if (policyHasDenyRule(policy)) return false
      voteSource.fromDefault = true
      return defaultEffect === 'allow'
    }
  }

  if (combine === 'allow-overrides') {
    let anyApplicable = false
    for (const policy of policies) {
      const r = safeEval(policy)
      if (r === null) continue
      anyApplicable = true
      if (r) {
        // The policy that allowed is the only contributor under this combine.
        if (signals && voteSource.fromDefault) signals.failOpen = true
        return true
      }
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
  let defaultSourced = false
  for (const policy of policies) {
    const r = safeEval(policy)
    if (r === null) continue
    anyApplicable = true
    if (!r) return false
    if (voteSource.fromDefault) defaultSourced = true
  }
  if (!anyApplicable) {
    const allowed = defaultEffect === 'allow'
    if (signals && allowed) signals.failOpen = true
    return allowed
  }
  // Mirrors the interpreter: every applicable policy contributed, so one resting on `defaultEffect` is fail-open.
  if (signals && defaultSourced) signals.failOpen = true
  return true
}

/**
 * Out-parameter for {@link evaluate} and {@link evaluateFast}: callers pass an empty object and read it after.
 * Carries the detail a verdict cannot, for metrics.
 */
export interface IEvalSignals {
  /**
   * `true` when an allow rests on the `defaultEffect` fallback: no applicable policy, or an applicable policy whose
   * every rule evaluated false. Never set on a deny, nor when an allow rule fired.
   */
  failOpen?: boolean
}
