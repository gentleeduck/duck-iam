/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */

import { evalConditionGroup } from '../conditions/conditions'
import { IAM_RBAC_POLICY_ID } from '../rbac/rbac'
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
  onRuleError?: AccessControl.PolicyErrorHandler,
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

  /**
   * A rule that throws abstains, but only in a policy that carries no deny
   * rule.
   *
   * The distinction is what makes this safe, and it is not the same as the
   * policy-level rule `safeEval` documents. Dropping a whole *policy* is
   * unsafe because the vote it would have cast may have been a deny, and
   * deleting that vote turns a throw into an allow under `combine: 'and'`.
   * Skipping one *rule* inside an allow-only policy deletes no such vote: no
   * rule there can deny, so the policy's only outcomes are "some rule allowed"
   * and "none matched, so `defaultEffect`". Skipping can move the result from
   * the first to the second - a loss of access, fail-closed - and never the
   * other way, because the allow it might land on is one another rule granted
   * on its own. An attacker padding an attribute to force the throw gains
   * nothing they did not already hold.
   *
   * Restricted to the generated RBAC union, and that restriction is the point.
   * `rolesToPolicy` folds *every* role permission into one allow-only
   * `__rbac__` policy, but they are independent grants from separate roles that
   * the compiled table evaluates first-match-wins - not one authored unit whose
   * rules an operator meant to be read together. An operator's own allow-only
   * policy is such a unit, the compiled table's `evaluateDynamicCell` treats it
   * as one, and widening this to every allow-only policy makes the interpreter
   * disagree with the table in the opposite direction.
   *
   * Without this, one rotten permission poisoned every unrelated grant in the
   * union: a conditional permission that threw on request data denied a subject
   * their own unconditional grant from another role, while the compiled table
   * answered allow. Production allowed what development denied, on identical
   * data, with no malformed catalog anywhere - an oversized *request* attribute
   * is enough, and no validator sees those.
   */
  const rulesAbstainOnThrow = policy.id === IAM_RBAC_POLICY_ID && !policyHasDenyRule(policy)

  for (const rule of policy.rules) {
    let applies: boolean
    try {
      applies = ruleApplies(rule, request, caches)
    } catch (err) {
      if (!rulesAbstainOnThrow) throw err
      onRuleError?.(err instanceof Error ? err : new Error(String(err)), policy)
      continue
    }
    if (applies) {
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
 * `true` when this verdict is an allow that no rule produced: the policy was
 * applicable, every rule of it evaluated false, and `defaultEffect` supplied
 * the allow. That is exactly the condition {@link IEvalSignals.failOpen}
 * reports, and it is not visible from `allowed` alone.
 */
function allowedByDefaultEffect(decision: AccessControl.IDecision): boolean {
  return decision.allowed && decision.rule === undefined && decision.applicable !== false
}

/**
 * Combine decisions across multiple policies per `combine` (`'and'` | `'allow-overrides'` | `'first-applicable'`).
 *
 * @param policies      All policies to evaluate.
 * @param request       The access request.
 * @param defaultEffect Effect when no rule fires within a policy.
 * @param combine       Cross-policy combine strategy (defaults to `'and'`).
 * @param onPolicyError Invoked when a single policy throws; the offender is Indeterminate, never NotApplicable.
 * @param signals       Optional {@link IEvalSignals} out-parameter; `failOpen` is set on a default-effect allow.
 * @param caches        Optional per-Engine regex / path caches; falls back to the module-global ones.
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
   * One rotten policy must not break the whole evaluation, but an error is
   * Indeterminate, never NotApplicable: skipping a policy that could have
   * denied lets an attacker disable it by making evaluation throw (padding the
   * field a `matches` rule reads).
   *
   * A policy carrying any deny rule resolves to deny. An allow-only policy
   * would have returned either an allow or `defaultEffect`, so Indeterminate
   * covers both and it votes the more restrictive of the two - `defaultEffect`
   * - while staying *applicable*. It is not skippable: under
   * `defaultEffect: 'deny'` the vote it would have cast is itself a deny, and
   * dropping it is what turns a throw into an allow under `combine: 'and'`.
   */
  const safeEval = (policy: AccessControl.IPolicy): AccessControl.IDecision => {
    try {
      return evaluatePolicy(policy, request, defaultEffect, caches, onPolicyError)
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
    // Every applicable policy allowed, so all of them contributed. If any did so
    // only through `defaultEffect`, its rules said nothing and the allow rests
    // on the fallback - the silent-failure shape `failOpen` exists to surface.
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

  // XACML `first-applicable`: the first result that is not NotApplicable wins.
  // This used to gate on `decision.rule !== undefined` - "the first policy that
  // names a rule" - which drops two real votes. An applicable policy whose rules
  // all evaluate false votes `defaultEffect` with no rule, and the Indeterminate
  // deny built by `safeEval` carries no rule either, so a padded header disabled
  // the first deny policy. `applicable === false` above is the whole test.
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
 * Per-policy out-parameter telling the caller *where* a vote came from: `true`
 * when the boolean returned was produced by the `defaultEffect` fallback rather
 * than by a rule. The boolean return cannot carry it, and without it the fast
 * path cannot raise {@link IEvalSignals.failOpen} on the commonest fail-open
 * shape - a policy that is applicable but whose every rule evaluated false.
 *
 * Callers reuse one object across a loop; every entry point resets it.
 */
export interface IVoteSource {
  fromDefault: boolean
}

/**
 * Fast (production-mode) single-policy evaluation against the policy's cached rule index.
 *
 * @param policy        The policy to evaluate.
 * @param request       The access request.
 * @param defaultEffect Effect to use when no rules match (defaults to `'deny'`).
 * @param caches        Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @param voteSource    Optional {@link IVoteSource} out-parameter; reset on entry, set when the vote is the `defaultEffect` fallback.
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

  // An algorithm outside `combiners` is invalid data - `validatePolicy` rejects
  // it - but adapter reads are not re-validated, so a hand-edited row gets here.
  // The interpreter reaches `combiners[policy.algorithm]`, finds `undefined` and
  // throws, which the caller routes to Indeterminate; falling through to the
  // first-match scan below made production allow what development denied on the
  // same row. The interpreter only reaches that line for a policy that is
  // applicable at all, so mirror its NotApplicable test before throwing.
  if (!Object.hasOwn(combiners, policy.algorithm)) {
    if (!policy.rules.some((rule) => ruleTargetsMatch(rule, request))) return null
    throw new Error(`[@gentleduck/iam:evaluate] Unknown combining algorithm "${String(policy.algorithm)}"`)
  }

  const idx = indexPolicy(policy)

  // A policy carrying a throwable condition is Indeterminate as a whole, and
  // every branch below can reach a verdict without ever evaluating the throwing
  // rule - `allow-overrides` returns on its first unconditional allow, and the
  // precomputed map answers before any condition runs. Production then allowed
  // what development denied on the same policy. Hand it to the interpreter so
  // the two modes agree by construction rather than by two implementations
  // being kept in step. Costs the fast path only for policies that use
  // `matches` or an unrecognised operator; `mayThrow` is computed once per
  // policy and cached with the index.
  if (idx.mayThrow) {
    const decision = evaluatePolicy(policy, request, defaultEffect, caches, onRuleError)
    return decision.applicable === false ? null : decision.allowed
  }

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
  const exactAR = idx.byActionResource.get(action)?.get(resType)
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

  // Every branch below tracks `hasCandidate`: at least one rule's action/resource
  // shape matched, whatever its condition then decided. A literal bucket is an
  // exact-key hit, so its presence alone is a shape match. It separates "this
  // policy has nothing to do with the request" (null, abstain) from "it does,
  // and this is its answer" - possibly the `defaultEffect` fallback.
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
    if (!hasCandidate) return null
    if (voteSource) voteSource.fromDefault = true
    return defaultEffect === 'allow'
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
  if (!hasCandidate) return null
  if (voteSource) voteSource.fromDefault = true
  return defaultEffect === 'allow'
}

/**
 * Fast multi-policy evaluation returning a boolean; mirrors {@link evaluate}'s `combine` modes (no `first-applicable`).
 *
 * @param policies      All policies to evaluate.
 * @param request       The access request.
 * @param defaultEffect Effect to use when no rules fire (defaults to `'deny'`).
 * @param combine       Cross-policy combine strategy (defaults to `'and'`).
 * @param onPolicyError Invoked when a single policy throws; the offender is Indeterminate, never NotApplicable.
 * @param signals       Optional {@link IEvalSignals} out-parameter; `failOpen` is set on a default-effect allow.
 * @param caches        Optional per-Engine regex / path caches; falls back to the module-global ones.
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
   * Must mirror the slow path's `safeEval` exactly - see its doc for the
   * Indeterminate contract. A deny-bearing policy resolves to deny; an
   * allow-only one casts its `defaultEffect` vote. Neither is skippable, and
   * returning `null` here would skip it. (A non-finite `priority` does not
   * throw; `rulePriority` ranks it as 0.)
   */
  const voteSource: IVoteSource = { fromDefault: false }
  const safeEval = (policy: AccessControl.IPolicy): boolean | null => {
    try {
      return evaluatePolicyFast(policy, request, defaultEffect, caches, voteSource, onPolicyError)
    } catch (err) {
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), policy)
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
  // Mirrors the interpreter: every applicable policy allowed, so all of them
  // contributed, and one resting on `defaultEffect` is the fail-open shape.
  if (signals && defaultSourced) signals.failOpen = true
  return true
}

/**
 * Out-parameter shape for {@link evaluateFast}. Callers pass an empty object;
 * the evaluator mutates fields as side-effects are observed. Useful for
 * metrics that need details the boolean return cannot carry.
 */
export interface IEvalSignals {
  /**
   * Set to `true` only when the verdict is `allow` and a vote carrying that
   * allow came from the `defaultEffect` fallback rather than from a rule -
   * whether no policy was applicable at all, or a policy *was* applicable and
   * every one of its rules evaluated false. The second shape is the common one
   * and used to go uncounted: an attribute rename, an adapter returning empty
   * conditions or a condition dropped for being oversized makes every deny rule
   * stop matching, the system opens up, and the boolean verdict hides it.
   *
   * Never set on a deny verdict, and never when an explicit allow rule fired.
   */
  failOpen?: boolean
}
