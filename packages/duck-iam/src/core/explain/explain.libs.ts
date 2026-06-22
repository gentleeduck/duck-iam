/** biome-ignore-all lint/style/noNonNullAssertion: index iteration guarded by length check. */

import { iamEvaluateOperator, iamResolveConditionValue } from '../conditions'
import { iamResolve, iamMatchesAction, iamMatchesResource, iamMatchesResourceHierarchical } from '../resolve'
import type { IamAccessControl, IamRequest } from '../types'
import type { IamExplain } from './explain.types'

/** Maximum nesting depth for traced condition groups. */
const MAX_TRACE_DEPTH = 10

/** Type guard that distinguishes a flat {@link IamAccessControl.ICondition} from a nested {@link IamAccessControl.IConditionGroup}. */
function iamIsCondition(item: IamAccessControl.ICondition | IamAccessControl.IConditionGroup): item is IamAccessControl.ICondition {
  return 'field' in item
}

/** Trace a single leaf condition, capturing actual vs expected values and the result. */
function traceLeaf(req: IamRequest.IAccessRequest, cond: IamAccessControl.ICondition): IamExplain.ILeafTrace {
  const actual = iamResolve(req, cond.field)
  const expected = iamResolveConditionValue(req, cond.value ?? null)
  const result = iamEvaluateOperator(cond.operator, actual, expected)
  return { type: 'condition', field: cond.field, operator: cond.operator, expected, actual, result }
}

/** Trace a single condition item, dispatching to leaf or group tracer. */
function traceItem(
  req: IamRequest.IAccessRequest,
  item: IamAccessControl.ICondition | IamAccessControl.IConditionGroup,
  depth: number,
): IamExplain.Trace {
  return iamIsCondition(item) ? traceLeaf(req, item) : traceGroup(req, item, depth)
}

/** Recursively trace a condition group, producing child traces for each item. */
function traceGroup(req: IamRequest.IAccessRequest, group: IamAccessControl.IConditionGroup, depth = 0): IamExplain.IGroupTrace {
  if (depth >= MAX_TRACE_DEPTH) {
    return { type: 'group', logic: 'all', result: false, children: [] }
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

  return { type: 'group', logic: 'all', result: false, children: [] }
}

/** Trace a single rule evaluation: action match, resource match, and condition tree. */
function traceRule(rule: IamAccessControl.IRule, req: IamRequest.IAccessRequest): IamExplain.IRuleTrace {
  const actionMatch = rule.actions.some((a) => iamMatchesAction(a, req.action))

  const resourceMatch = rule.resources.some((r) => {
    if (r.includes('.') || req.resource.type.includes('.')) {
      return iamMatchesResourceHierarchical(r, req.resource.type)
    }
    return iamMatchesResource(r, req.resource.type)
  })

  const conditions = traceGroup(req, rule.conditions)

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
  }
}

/** Apply a combining algorithm to matched rule traces, mirroring the iamEvaluate module logic. */
function applyCombiner(
  algorithm: IamAccessControl.CombiningAlgorithm,
  matched: readonly IamExplain.IRuleTrace[],
  defaultEffect: IamAccessControl.Effect,
): { effect: IamAccessControl.Effect; reason: string; decidingRuleId?: string } {
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
        if (cur.priority > first.priority) first = cur
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
        if (top === undefined || cur.priority > top.priority) top = cur
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
function policyTargetsMatch(policy: IamAccessControl.IPolicy, req: IamRequest.IAccessRequest): boolean {
  if (!policy.targets) return true
  const { actions, resources, roles } = policy.targets
  if (actions?.length && !actions.some((a) => iamMatchesAction(a, req.action))) return false
  if (resources?.length && !resources.some((r) => iamMatchesResource(r, req.resource.type))) return false
  if (roles?.length) {
    const subjectRoles = Array.isArray(req.subject.roles) ? req.subject.roles : []
    if (!roles.some((role) => subjectRoles.includes(role))) return false
  }
  return true
}

/**
 * Trace a full policy evaluation: target matching, rule traces, and combining
 * algorithm result.
 *
 * @param policy        - The policy to trace.
 * @param req           - The access request being evaluated.
 * @param defaultEffect - Effect to record when no rule fires.
 * @returns An {@link IamExplain.IPolicyTrace} describing the policy's outcome.
 */
export function tracePolicy(
  policy: IamAccessControl.IPolicy,
  req: IamRequest.IAccessRequest,
  defaultEffect: IamAccessControl.Effect,
): IamExplain.IPolicyTrace {
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
