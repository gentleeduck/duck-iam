import { evalConditionGroup } from '../conditions'
import { matchesAction, matchesResource, matchesResourceHierarchical } from '../resolve'
import type { AccessRequest, CombiningAlgorithm, Effect, Policy, Rule } from '../types'
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

  // Hoist the dot check — compute once before the .some() loop
  const resourceHasDot = req.resource.type.includes('.')

  const resourceMatch = rule.resources.some((r) => {
    // Use dot-based matching if either pattern or resource type contains a dot
    if (resourceHasDot || r.includes('.')) {
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
      const top = matched.reduce((best, cur) => (cur.rule.priority > best.rule.priority ? cur : best))
      return {
        rule: top.rule,
        effect: top.effect,
        reason: `Highest priority: rule "${top.rule.id}" (p=${top.rule.priority})`,
      }
    }
    return { effect: defaultEffect, reason: `No matching rules -> ${defaultEffect}` }
  },
}

// ---------------------------------------------------------------------------
// Rule indexing — pre-index rules by action for fast lookup
// ---------------------------------------------------------------------------

/**
 * A single rule entry within a {@link PolicyRuleIndex}.
 */
export interface IndexedRule {
  readonly rule: Rule
  readonly actions: Set<string>
  readonly resources: Set<string>
  readonly hasWildcardAction: boolean
  readonly hasWildcardResource: boolean
}

/**
 * Pre-computed index over a policy's rules for O(1) candidate lookup.
 */
export interface PolicyRuleIndex {
  readonly byAction: Map<string, IndexedRule[]>
  readonly wildcardRules: IndexedRule[]
  /** Combined action\0resource key for O(1) exact-match lookup (fast path). */
  readonly byActionResource: Map<string, IndexedRule[]>
  /** Rules with wildcard action OR wildcard resource (need full matching). */
  readonly wildcardAny: IndexedRule[]
}

/** WeakMap so indexes are GC'd when the policy is no longer referenced. */
const indexCache = new WeakMap<Policy, PolicyRuleIndex>()

/**
 * Build (or retrieve from cache) a rule index for a policy.
 */
export function indexPolicy(policy: Policy): PolicyRuleIndex {
  const cached = indexCache.get(policy)
  if (cached) return cached

  const byAction = new Map<string, IndexedRule[]>()
  const byActionResource = new Map<string, IndexedRule[]>()
  const wildcardRules: IndexedRule[] = []
  const wildcardAny: IndexedRule[] = []

  for (const rule of policy.rules) {
    const actions = new Set(rule.actions as string[])
    const resources = new Set(rule.resources as string[])
    const hasWildcardAction = actions.has('*')
    const hasWildcardResource = resources.has('*')

    const entry: IndexedRule = { rule, actions, resources, hasWildcardAction, hasWildcardResource }

    if (hasWildcardAction || hasWildcardResource) {
      wildcardAny.push(entry)
      if (hasWildcardAction) wildcardRules.push(entry)
    }

    // Populate action-only index (existing)
    if (!hasWildcardAction) {
      for (const a of actions) {
        let bucket = byAction.get(a)
        if (!bucket) {
          bucket = []
          byAction.set(a, bucket)
        }
        bucket.push(entry)
      }
    }

    // Populate combined action+resource index (new fast path)
    if (!hasWildcardAction && !hasWildcardResource) {
      for (const a of actions) {
        for (const r of resources) {
          const key = `${a}\0${r}`
          let bucket = byActionResource.get(key)
          if (!bucket) {
            bucket = []
            byActionResource.set(key, bucket)
          }
          bucket.push(entry)
        }
      }
    }
  }

  const idx: PolicyRuleIndex = { byAction, wildcardRules, byActionResource, wildcardAny }
  indexCache.set(policy, idx)
  return idx
}

/**
 * Get candidate indexed rules that could match a given action.
 */
export function getIndexedCandidates(idx: PolicyRuleIndex, action: string): IndexedRule[] {
  const exact = idx.byAction.get(action)
  if (exact) {
    return idx.wildcardRules.length > 0 ? [...exact, ...idx.wildcardRules] : exact
  }
  return idx.wildcardRules
}

/**
 * Get all indexed rules that fully match a request (action + resource + conditions).
 */
export function getIndexedMatches(idx: PolicyRuleIndex, req: AccessRequest): Array<{ rule: Rule; effect: Effect }> {
  const candidates = getIndexedCandidates(idx, req.action)
  const matched: Array<{ rule: Rule; effect: Effect }> = []
  const resourceHasDot = req.resource.type.includes('.')

  for (const entry of candidates) {
    // Action match — already narrowed by index, but check prefix patterns
    if (!entry.hasWildcardAction && !entry.actions.has(req.action)) {
      // Could be a prefix pattern like "posts:*"
      const actionMatch = entry.rule.actions.some((a) => matchesAction(a, req.action))
      if (!actionMatch) continue
    }

    // Resource match
    if (!entry.hasWildcardResource) {
      const resourceMatch = entry.rule.resources.some((r) => {
        if (resourceHasDot || r.includes('.')) {
          return matchesResourceHierarchical(r, req.resource.type)
        }
        return matchesResource(r, req.resource.type)
      })
      if (!resourceMatch) continue
    }

    // Condition match
    if (!evalConditionGroup(req, entry.rule.conditions)) continue

    matched.push({ rule: entry.rule, effect: entry.rule.effect })
  }

  return matched
}
