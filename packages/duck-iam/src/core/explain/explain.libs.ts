/** biome-ignore-all lint/style/noNonNullAssertion: index iteration guarded by length check. */

import { evalConditionGroup, resolveConditionValue } from '../conditions/conditions'
import { evalCondition } from '../conditions/conditions.libs'
import { policyHasDenyRule, rulePriority } from '../evaluate/evaluate.libs'
import { matchesAction, matchesResource, matchesResourceHierarchical, resolve } from '../resolve'
import type { AccessControl, IamRequest } from '../types'
import type { Explain } from './explain.types'

/** Maximum nesting depth for traced condition groups. */
const MAX_TRACE_DEPTH = 10

/** Type guard that distinguishes a flat {@link AccessControl.ICondition} from a nested {@link AccessControl.IConditionGroup}. */
function isCondition(item: AccessControl.ICondition | AccessControl.IConditionGroup): item is AccessControl.ICondition {
  return 'field' in item
}

/**
 * Trace a single leaf condition, capturing actual vs expected values and the result.
 *
 * `result` comes from `evalCondition` - the function the engine decides with -
 * not from a second evaluation of the same condition. This used to call
 * `evaluateOperator`, which is the raw operator table: it skips the refusal of
 * `matches` against a `$`-sourced operand, so a trace reported a leaf as
 * satisfied that the engine had refused outright, and an operator asking why a
 * request was denied was shown the condition that supposedly passed. The
 * sibling parity test records two earlier drifts of the same kind one level up,
 * at the cross-policy combine; sourcing the verdict from the decision path is
 * what stops a third.
 *
 * `actual` and `expected` stay separately resolved because they are display
 * values - the trace has to show what the operand resolved *to*, including for
 * a condition whose verdict is a refusal. The duplicate resolve costs a walk of
 * the request on a diagnostic path, never on the decision path.
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

  // No `all`/`any`/`none`. The decision path draws a distinction here that this
  // fallback used to flatten: `{}` is "no conditions", which is unconditionally
  // true, while a group with keys we do not recognise (a typo'd `all`, a row
  // from a hand-edited store) is false, because reading it as "no conditions"
  // would turn a conditional allow into an unconditional one. Returning a flat
  // `false` made `explain()` report a denial for a rule `can()` allowed.
  //
  // Delegated rather than reimplemented. This branch has no children to trace,
  // so there is nothing to duplicate, and asking the decision path itself is
  // the only version that cannot drift from it again - which is the third time
  // a hand-copy of this logic has drifted.
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

  // `evalConditionGroup` throws on an unknown operator, on a `conditions` field
  // that is not a group, and on an oversized regex input. `explain()` is the
  // tool you reach for when a decision looks wrong, so raising out of it on
  // exactly those inputs meant it failed on the cases it exists to explain. The
  // decision path absorbs them as Indeterminate; this records the failure and
  // lets `explainPolicy` cast the same vote.
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

/** Apply a combining algorithm to matched rule traces, mirroring the evaluate module logic. */
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
 * Trace a full policy evaluation: target matching, rule traces, and combining
 * algorithm result.
 *
 * @param policy        - The policy to trace.
 * @param req           - The access request being evaluated.
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

  // A rule that threw is Indeterminate, not "did not match". Running the
  // combiner over the rules that survived would report an allow the decision
  // path never gives: `safeEval` in `evaluate.ts` votes deny whenever the
  // policy carries any deny rule - failing to evaluate it could have hidden
  // that deny - and otherwise casts `defaultEffect`, staying applicable either
  // way. `policyHasDenyRule` is the same helper that decision uses rather than
  // a second reading of the rule list; three of the four drifts between these
  // two paths were hand-copies that fell out of step.
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
