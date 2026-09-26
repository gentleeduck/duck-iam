import { evalConditionGroup, resolveConditionValue } from '../conditions/conditions'
import { evalCondition } from '../conditions/conditions.libs'
import { throwIamError } from '../errors'
import {
  combiners,
  isRuleEffect,
  policyApplies,
  policyHasDenyRule,
  ranksByPriority,
  rulePriority,
} from '../evaluate/evaluate.libs'
import { IAM_RBAC_POLICY_ID } from '../rbac/rbac'
import { matchesAction, matchesResource, resolve } from '../resolve'
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
    throwIamError('IAM_CONDITION_GROUP_INVALID', {
      reason: 'depth',
      detail: `condition nesting exceeds ${MAX_TRACE_DEPTH}`,
    })
  }

  // `in` raises a bare TypeError on a non-object, so hand that case to the function that names it.
  if (group === null || typeof group !== 'object') {
    return { type: 'group', logic: 'all', result: evalConditionGroup(req, group, depth), children: [] }
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

  // No `all`/`any`/`none`: `{}` is unconditionally true and an unrecognised key is refused. Delegated rather than
  // reimplemented, since there are no children to trace and a hand-copy would drift from the decision path.
  return { type: 'group', logic: 'all', result: evalConditionGroup(req, group, depth), children: [] }
}

/** Trace a single rule evaluation: action match, resource match, and condition tree. */
function traceRule(rule: AccessControl.IRule, req: IamRequest.IAccessRequest): Explain.IRuleTrace {
  const actionMatch = rule.actions.some((a) => matchesAction(a, req.action))

  const resourceMatch = rule.resources.some((r) => matchesResource(r, req.resource.type))

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

/** No rule in the matched set decided the policy; every combiner reports this the same way. */
function noMatchResult(defaultEffect: AccessControl.Effect): { effect: AccessControl.Effect; reason: string } {
  return { effect: defaultEffect, reason: `No matching rules. Defaulted to ${defaultEffect}` }
}

/**
 * `deny-overrides`/`allow-overrides` share one shape: prefer a rule with `primary`'s effect, else `secondary`'s,
 * else the algorithm's default. Only which effect is preferred first differs between the two.
 */
function overrideResult(
  matched: readonly Explain.IRuleTrace[],
  primary: AccessControl.Effect,
  secondary: AccessControl.Effect,
  defaultEffect: AccessControl.Effect,
): { effect: AccessControl.Effect; reason: string; decidingRuleId?: string } {
  const rule = matched.find((r) => r.effect === primary) ?? matched.find((r) => r.effect === secondary)
  if (rule === undefined) return noMatchResult(defaultEffect)
  const verb = rule.effect === 'deny' ? 'Denied' : 'Allowed'
  return { effect: rule.effect, reason: `${verb} by rule "${rule.ruleId}"`, decidingRuleId: rule.ruleId }
}

/**
 * The matched rule with the highest {@link rulePriority}; the earliest rule wins a tie.
 * NOTE: `first-match` and `highest-priority` resolve to this same rule - only the reported reason differs.
 */
function highestPriorityRule(matched: readonly Explain.IRuleTrace[]): Explain.IRuleTrace | undefined {
  let top: Explain.IRuleTrace | undefined
  for (const cur of matched) {
    if (top === undefined || rulePriority(cur) > rulePriority(top)) top = cur
  }
  return top
}

/** Apply a combining algorithm to matched rule traces, mirroring the evaluate module. */
function applyCombiner(
  algorithm: AccessControl.CombiningAlgorithm,
  matched: readonly Explain.IRuleTrace[],
  defaultEffect: AccessControl.Effect,
): { effect: AccessControl.Effect; reason: string; decidingRuleId?: string } {
  switch (algorithm) {
    case 'deny-overrides':
      return overrideResult(matched, 'deny', 'allow', defaultEffect)
    case 'allow-overrides':
      return overrideResult(matched, 'allow', 'deny', defaultEffect)
    case 'first-match': {
      const first = highestPriorityRule(matched)
      if (first === undefined) return noMatchResult(defaultEffect)
      return {
        effect: first.effect,
        reason: `First match: rule "${first.ruleId}" (${first.effect})`,
        decidingRuleId: first.ruleId,
      }
    }
    case 'highest-priority': {
      const top = highestPriorityRule(matched)
      if (top === undefined) return noMatchResult(defaultEffect)
      return {
        effect: top.effect,
        reason: `Highest priority: rule "${top.ruleId}" (p=${top.priority})`,
        decidingRuleId: top.ruleId,
      }
    }
  }
}

/**
 * The decision path's policy-level refusals, in the order `evaluate` applies them; `undefined` when it would answer.
 * SECURITY: without these the trace reports an allow for a policy the engine refuses, which is what `explain()` is
 * read to understand. Gated on the rule-target test both evaluators run first, so it refuses the same requests.
 */
function policyRefusal(
  policy: AccessControl.IPolicy,
  matched: readonly Explain.IRuleTrace[],
  targeted: boolean,
): string | undefined {
  if (!targeted) return undefined
  if (!Object.hasOwn(combiners, policy.algorithm)) {
    return `unknown combining algorithm "${String(policy.algorithm)}"`
  }
  if (ranksByPriority(policy.algorithm) && policy.rules.some((rule) => !Number.isFinite(rule.priority))) {
    return 'a rule priority is not a finite number'
  }
  const badEffect = matched.find((rule) => !isRuleEffect(rule.effect))
  return badEffect === undefined ? undefined : `unknown effect on rule "${badEffect.ruleId}"`
}

/** The 3 fields every {@link Explain.IPolicyTrace} carries regardless of outcome. */
function policyTraceHeader(
  policy: AccessControl.IPolicy,
): Pick<Explain.IPolicyTrace, 'policyId' | 'policyName' | 'algorithm'> {
  return { policyId: policy.id, policyName: policy.name, algorithm: policy.algorithm }
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
  const targetMatch = policyApplies(policy, req)

  if (!targetMatch) {
    return {
      ...policyTraceHeader(policy),
      targetMatch: false,
      rules: [],
      result: defaultEffect,
      reason: `Policy "${policy.id}" targets do not match. Defaulted to ${defaultEffect}`,
    }
  }

  const ruleTraces = policy.rules.map((rule) => traceRule(rule, req))
  const matched = ruleTraces.filter((r) => r.matched)

  // SECURITY: a rule that threw, or a policy the decision path refuses, is Indeterminate rather than "did not
  // match"; combining the survivors would report an allow the decision path never gives. Uses `evaluate`'s own
  // `policyHasDenyRule` so the two cannot drift.
  // Only a rule whose targets match: `ruleApplies` never evaluates the conditions of one that does not, so an
  // unrelated rule's throwing condition must not poison the policy here either. The allow-only RBAC union lets a
  // throwing rule abstain, as `evaluatePolicy` does, since skipping one there can only lose access.
  const abstainOnThrow = policy.id === IAM_RBAC_POLICY_ID && !policyHasDenyRule(policy)
  const threw =
    !abstainOnThrow && ruleTraces.some((r) => r.conditionError !== undefined && r.actionMatch && r.resourceMatch)
  const cause = threw
    ? undefined
    : policyRefusal(
        policy,
        matched,
        ruleTraces.some((r) => r.actionMatch && r.resourceMatch),
      )
  if (threw || cause !== undefined) {
    const hasDeny = policyHasDenyRule(policy)
    const detail = cause === undefined ? '' : `: ${cause}`
    return {
      ...policyTraceHeader(policy),
      targetMatch: true,
      rules: ruleTraces,
      result: hasDeny ? 'deny' : defaultEffect,
      reason: hasDeny
        ? `Policy evaluation error${detail} - denied (indeterminate)`
        : `Policy evaluation error${detail} - defaulted to ${defaultEffect} (indeterminate)`,
    }
  }
  // Every combiner answers `defaultEffect` for an empty set, and a policy that matched no rule is NotApplicable to
  // the cross-policy combine, so the algorithm is never consulted - an unvalidated one would have no arm here.
  if (matched.length === 0) {
    return {
      ...policyTraceHeader(policy),
      targetMatch: true,
      rules: ruleTraces,
      result: defaultEffect,
      reason: `No matching rules. Defaulted to ${defaultEffect}`,
    }
  }

  const { effect, reason, decidingRuleId } = applyCombiner(policy.algorithm, matched, defaultEffect)
  const decidingRule = decidingRuleId ? policy.rules.find((r) => r.id === decidingRuleId) : undefined

  return {
    ...policyTraceHeader(policy),
    targetMatch: true,
    rules: ruleTraces,
    result: effect,
    reason,
    decidingRuleId,
    decidingRule,
  }
}
