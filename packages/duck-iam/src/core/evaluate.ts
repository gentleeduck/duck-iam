import { evalConditionGroup } from './conditions'
import { matchesAction, matchesResource, matchesResourceHierarchical } from './resolve'
import type { AccessRequest, CombiningAlgorithm, Decision, Effect, Policy, Rule } from './types'

// --- Rule matching ---

function ruleApplies(rule: Rule, req: AccessRequest): boolean {
  const actionMatch = rule.actions.some((a) => matchesAction(a, req.action))
  if (!actionMatch) return false

  const resourceMatch = rule.resources.some((r) => {
    // Use dot-based matching if either pattern or resource type contains a dot
    if (r.includes('.') || req.resource.type.includes('.')) {
      return matchesResourceHierarchical(r, req.resource.type)
    }
    return matchesResource(r, req.resource.type)
  })
  if (!resourceMatch) return false

  return evalConditionGroup(req, rule.conditions)
}

// --- Policy-level target check (skip entire policy if targets don't match) ---

function policyApplies(policy: Policy, req: AccessRequest): boolean {
  if (!policy.targets) return true

  const { actions, resources, roles } = policy.targets

  if (actions?.length && !actions.some((a) => matchesAction(a, req.action))) {
    return false
  }

  if (resources?.length && !resources.some((r) => matchesResource(r, req.resource.type))) {
    return false
  }

  if (roles?.length && !roles.some((role) => req.subject.roles.includes(role))) {
    return false
  }

  return true
}

// --- Combining algorithms ---

type Combiner = (
  matched: Array<{ rule: Rule; effect: Effect }>,
  defaultEffect: Effect,
) => { rule?: Rule; effect: Effect; reason: string }

const combiners: Record<CombiningAlgorithm, Combiner> = {
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
    return { effect: defaultEffect, reason: `No matching rules -> ${defaultEffect}` }
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
    return { effect: defaultEffect, reason: `No matching rules -> ${defaultEffect}` }
  },

  'first-match': (matched, defaultEffect) => {
    const first = matched[0]
    if (first) {
      return {
        rule: first.rule,
        effect: first.effect,
        reason: `First match: rule "${first.rule.id}" (${first.effect})`,
      }
    }
    return { effect: defaultEffect, reason: `No matching rules -> ${defaultEffect}` }
  },

  'highest-priority': (matched, defaultEffect) => {
    if (matched.length > 0) {
      const sorted = [...matched].sort((a, b) => b.rule.priority - a.rule.priority)
      const top = sorted[0]!
      return {
        rule: top.rule,
        effect: top.effect,
        reason: `Highest priority: rule "${top.rule.id}" (p=${top.rule.priority})`,
      }
    }
    return { effect: defaultEffect, reason: `No matching rules -> ${defaultEffect}` }
  },
}

// --- Public evaluation functions ---

/**
 * Evaluate a single policy against a request. Pure function, no side effects.
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
 * Evaluate multiple policies. Deny from any policy = overall deny.
 * This is the AND-combination across policies (defense in depth).
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
