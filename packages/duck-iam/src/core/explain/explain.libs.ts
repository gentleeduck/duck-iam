/** biome-ignore-all lint/style/noNonNullAssertion: index iteration guarded by length check. */

import { evalConditionGroup, resolveConditionValue } from '../conditions/conditions'
import { evalCondition, IamConditionGroupError } from '../conditions/conditions.libs'
import { policyHasDenyRule, rulePriority } from '../evaluate/evaluate.libs'
import { matchesAction, matchesResource, matchesResourceHierarchical, resolve } from '../resolve'
import type { AccessControl, IamRequest } from '../types'
import type { Explain } from './explain.types'

/** Maximum nesting depth for traced condition groups. */
const MAX_TRACE_DEPTH = 10

/** Distinguishes a flat {@link AccessControl.ICondition} from a nested {@link AccessControl.IConditionGroup}. */
function isCondition(item: AccessControl.ICondition | AccessControl.IConditionGroup): item is AccessControl.ICondition {
  return 'field' in item
}

/**
 * Trace a single leaf condition, capturing actual vs expected values and the result.
 * NOTE: `result` comes from `evalCondition`, the function the engine decides with, never the raw operator table,
 * which skips refusals. `actual` and `expected` are resolved again only because they are display values.
 */
function traceLeaf(req: IamRequest.IAccessRequest, cond: AccessControl.ICondition): Explain.ILeafTrace {
  const actual = resolve(req, cond.field)
  const expected = resolveConditionValue(req, cond.value ?? null)
  const result = evalCondition(req, cond)
  return { type: 'condition', field: cond.field, operator: cond.operator, expected, actual, result }
}

/** Trace a single condition item, dispatching to leaf or group tracer. */
function traceItem(
  req: IamRequest.IAccessRequest,
  item: AccessControl.ICondition | AccessControl.IConditionGroup,
  depth: number,
): Explain.Trace {
  return isCondition(item) ? traceLeaf(req, item) : traceGroup(req, item, depth)
}

/** Recursively trace a condition group, producing child traces for each item. */
function traceGroup(
  req: IamRequest.IAccessRequest,
  group: AccessControl.IConditionGroup,
  depth = 0,
): Explain.IGroupTrace {
  if (depth >= MAX_TRACE_DEPTH) {
    // SECURITY: same contract as `evalConditionGroup` - too deep is Indeterminate, not `false`. `traceRule` records
    // it as a `conditionError` so the trace casts the vote the decision path casts.
    throw new IamConditionGroupError('depth', `condition nesting exceeds ${MAX_TRACE_DEPTH}`)
  }

  if ('all' in group) {
    const children = group.all.map((item) => traceItem(req, item, depth + 1))
    return { type: 'group', logic: 'all', result: children.every((c) => c.result), children }
  }

  if ('any' in group) {
    const children = group.any.map((item) => traceItem(req, item, depth + 1))
    return { type: 'group', logic: 'any', result: children.some((c) => c.result), children }
  }

  if ('none' in group) {
    const children = group.none.map((item) => traceItem(req, item, depth + 1))
    return { type: 'group', logic: 'none', result: children.every((c) => !c.result), children }
  }

  // No `all`/`any`/`none`: `{}` is unconditionally true while an unrecognised key is false. Delegated rather than
  // reimplemented, since there are no children to trace and a hand-copy would drift from the decision path.
  return { type: 'group', logic: 'all', result: evalConditionGroup(req, group, depth), children: [] }
}

/** Trace a single rule evaluation: action match, resource match, and condition tree. */
function traceRule(rule: AccessControl.IRule, req: IamRequest.IAccessRequest): Explain.IRuleTrace {
  const actionMatch = rule.actions.some((a) => matchesAction(a, req.action))

  const resourceMatch = rule.resources.some((r) => {
    if (r.includes('.') || req.resource.type.includes('.')) {
      return matchesResourceHierarchical(r, req.resource.type)
    }
    return matchesResource(r, req.resource.type)
  })

  // `evalConditionGroup` throws on an unknown operator, a non-group `conditions` and an oversized regex input -
  // exactly the cases `explain()` exists for. Record the failure so `tracePolicy` can cast the Indeterminate vote.
  let conditions: Explain.IGroupTrace
  let conditionError: string | undefined
  try {
    conditions = traceGroup(req, rule.conditions)
  } catch (err) {
    conditionError = err instanceof Error ? err.message : String(err)
    conditions = { type: 'group', logic: 'all', result: false, children: [] }
  }

  return {
    ruleId: rule.id,
    description: rule.description,
    effect: rule.effect,
    priority: rule.priority,
    actionMatch,
    resourceMatch,
    conditionsMet: conditions.result,
    conditions,
    matched: actionMatch && resourceMatch && conditions.result,
    ...(conditionError === undefined ? {} : { conditionError }),
  }
}

/** Apply a combining algorithm to matched rule traces, mirroring the evaluate module. */
function applyCombiner(
  algorithm: AccessControl.CombiningAlgorithm,
  matched: readonly Explain.IRuleTrace[],
  defaultEffect: AccessControl.Effect,
): { effect: AccessControl.Effect; reason: string; decidingRuleId?: string } {
  switch (algorithm) {
    case 'deny-overrides': {
      const deny = matched.find((r) => r.effect === 'deny')
      if (deny) return { effect: 'deny', reason: `Denied by rule "${deny.ruleId}"`, decidingRuleId: deny.ruleId }
      const allow = matched.find((r) => r.effect === 'allow')
      if (allow) return { effect: 'allow', reason: `Allowed by rule "${allow.ruleId}"`, decidingRuleId: allow.ruleId }
      return { effect: defaultEffect, reason: `No matching rules. Defaulted to ${defaultEffect}` }
    }
    case 'allow-overrides': {
      const allow = matched.find((r) => r.effect === 'allow')
      if (allow) return { effect: 'allow', reason: `Allowed by rule "${allow.ruleId}"`, decidingRuleId: allow.ruleId }
      const deny = matched.find((r) => r.effect === 'deny')
      if (deny) return { effect: 'deny', reason: `Denied by rule "${deny.ruleId}"`, decidingRuleId: deny.ruleId }
      return { effect: defaultEffect, reason: `No matching rules. Defaulted to ${defaultEffect}` }
    }
    case 'first-match': {
      if (matched.length === 0)
        return { effect: defaultEffect, reason: `No matching rules. Defaulted to ${defaultEffect}` }
      let first = matched[0]!
      for (let i = 1; i < matched.length; i++) {
        const cur = matched[i]!
        if (rulePriority(cur) > rulePriority(first)) first = cur
      }
      return {
        effect: first.effect,
        reason: `First match: rule "${first.ruleId}" (${first.effect})`,
        decidingRuleId: first.ruleId,
      }
    }
    case 'highest-priority': {
      let top: (typeof matched)[number] | undefined
      for (const cur of matched) {
        if (top === undefined || rulePriority(cur) > rulePriority(top)) top = cur
      }
      if (top !== undefined) {
        return {
          effect: top.effect,
          reason: `Highest priority: rule "${top.ruleId}" (p=${top.priority})`,
          decidingRuleId: top.ruleId,
        }
      }
      return { effect: defaultEffect, reason: `No matching rules. Defaulted to ${defaultEffect}` }
    }
  }
}

/** Check whether a policy's target constraints match the request. */
function policyTargetsMatch(policy: AccessControl.IPolicy, req: IamRequest.IAccessRequest): boolean {
  if (!policy.targets) return true
  const { actions, resources, roles } = policy.targets
  if (actions?.length && !actions.some((a) => matchesAction(a, req.action))) return false
  if (resources?.length && !resources.some((r) => matchesResource(r, req.resource.type))) return false
  if (roles?.length) {
    const subjectRoles = Array.isArray(req.subject.roles) ? req.subject.roles : []
    if (!roles.some((role) => subjectRoles.includes(role))) return false
  }
  return true
}

/**
 * Trace a full policy evaluation: target matching, rule traces, and the combining algorithm's result.
 *
 * @param defaultEffect - Effect to record when no rule fires.
 * @returns An {@link Explain.IPolicyTrace} describing the policy's outcome.
 */
export function tracePolicy(
  policy: AccessControl.IPolicy,
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
): Explain.IPolicyTrace {
  const targetMatch = policyTargetsMatch(policy, req)

  if (!targetMatch) {
    return {
      policyId: policy.id,
      policyName: policy.name,
      algorithm: policy.algorithm,
      targetMatch: false,
      rules: [],
      result: defaultEffect,
      reason: `Policy "${policy.id}" targets do not match. Defaulted to ${defaultEffect}`,
    }
  }

  const ruleTraces = policy.rules.map((rule) => traceRule(rule, req))

  // SECURITY: a rule that threw is Indeterminate, not "did not match", so combining the survivors would report an
  // allow the decision path never gives. Uses `evaluate`'s own `policyHasDenyRule` so the two cannot drift.
  if (ruleTraces.some((r) => r.conditionError !== undefined)) {
    const hasDeny = policyHasDenyRule(policy)
    return {
      policyId: policy.id,
      policyName: policy.name,
      algorithm: policy.algorithm,
      targetMatch: true,
      rules: ruleTraces,
      result: hasDeny ? 'deny' : defaultEffect,
      reason: hasDeny
        ? 'Policy evaluation error - denied (indeterminate)'
        : `Policy evaluation error - defaulted to ${defaultEffect} (indeterminate)`,
    }
  }

  const matched = ruleTraces.filter((r) => r.matched)
  const { effect, reason, decidingRuleId } = applyCombiner(policy.algorithm, matched, defaultEffect)
  const decidingRule = decidingRuleId ? policy.rules.find((r) => r.id === decidingRuleId) : undefined

  return {
    policyId: policy.id,
    policyName: policy.name,
    algorithm: policy.algorithm,
    targetMatch: true,
    rules: ruleTraces,
    result: effect,
    reason,
    decidingRuleId,
    decidingRule,
  }
}
