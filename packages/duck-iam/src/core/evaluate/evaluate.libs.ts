import { evalConditionGroup } from '../conditions'
import { matchesAction, matchesResource, matchesResourceHierarchical } from '../resolve'
import type { AccessRequest, CombiningAlgorithm, Policy, Rule } from '../types'
import type { Combiner } from './evaluate.types'

/**
 * Checks whether a single rule applies to the given access request.
 *
 * A rule applies when its action patterns match the requested action,
 * its resource patterns match the requested resource type, and all
 * conditions (if any) evaluate to true.
 *
 * @param rule - The rule to test
 * @param req  - The incoming access request
 * @returns `true` if the rule matches the request
 */
export function ruleApplies(rule: Rule, req: AccessRequest): boolean {
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

/**
 * Checks whether a policy's target constraints match the given access request.
 *
 * If the policy has no targets defined, it applies to all requests.
 * Otherwise, each target dimension (actions, resources, roles) is checked
 * independently — all specified dimensions must match.
 *
 * @param policy - The policy whose targets to check
 * @param req    - The incoming access request
 * @returns `true` if the policy should be evaluated for this request
 */
export function policyApplies(policy: Policy, req: AccessRequest): boolean {
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

/**
 * Record of all supported combining algorithm implementations.
 *
 * Each algorithm determines how multiple matching rules within a policy
 * are combined into a single decision:
 *
 * - `deny-overrides`   — Any deny wins; otherwise first allow wins.
 * - `allow-overrides`  — Any allow wins; otherwise first deny wins.
 * - `first-match`      — The first matching rule wins regardless of effect.
 * - `highest-priority`  — The rule with the highest priority value wins.
 */
export const combiners: Record<CombiningAlgorithm, Combiner> = {
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
