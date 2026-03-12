import type { AccessRequest, Decision, Effect, Policy, Rule } from '../types'
import { combiners, policyApplies, ruleApplies } from './evaluate.libs'

/**
 * Evaluates a single policy against an access request.
 *
 * Pure function with no side effects. Checks policy targets first, then
 * evaluates matching rules using the policy's combining algorithm.
 *
 * @param policy        - The policy to evaluate
 * @param request       - The access request to evaluate against
 * @param defaultEffect - Effect to use when no rules match (defaults to `'deny'`)
 * @returns A {@link Decision} with the evaluation result
 */
export function evaluatePolicy(policy: Policy, request: AccessRequest, defaultEffect: Effect = 'deny'): Decision {
  const start = performance.now()

  if (!policyApplies(policy, request)) {
    return {
      allowed: defaultEffect === 'allow',
      effect: defaultEffect,
      policy: policy.id,
      reason: `Policy "${policy.id}" targets don't match -> ${defaultEffect}`,
      duration: performance.now() - start,
      timestamp: Date.now(),
    }
  }

  const matched: Array<{ rule: Rule; effect: Effect }> = []

  for (const rule of policy.rules) {
    if (ruleApplies(rule, request)) {
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
 * Evaluates multiple policies against an access request using AND-combination.
 *
 * A deny from any single policy is final (defense in depth). Policies are
 * evaluated in order; the first non-allow result short-circuits.
 *
 * @param policies      - All policies to evaluate
 * @param request       - The access request to evaluate against
 * @param defaultEffect - Effect to use when no rules match (defaults to `'deny'`)
 * @returns A {@link Decision} with the overall evaluation result
 */
export function evaluate(policies: Policy[], request: AccessRequest, defaultEffect: Effect = 'deny'): Decision {
  const start = performance.now()

  if (policies.length === 0) {
    return {
      allowed: defaultEffect === 'allow',
      effect: defaultEffect,
      reason: 'No policies configured',
      duration: performance.now() - start,
      timestamp: Date.now(),
    }
  }

  let lastAllow: Decision | null = null

  for (const policy of policies) {
    const decision = evaluatePolicy(policy, request, defaultEffect)

    if (!decision.allowed) {
      return {
        ...decision,
        duration: performance.now() - start,
      }
    }
    lastAllow = decision
  }

  return {
    ...(lastAllow ?? {
      allowed: true,
      effect: 'allow' as const,
      reason: 'All policies allowed',
      timestamp: Date.now(),
    }),
    duration: performance.now() - start,
  }
}
