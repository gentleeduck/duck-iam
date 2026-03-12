import { evaluateOperator, resolveConditionValue } from './conditions'
import { matchesAction, matchesResource, matchesResourceHierarchical, resolve } from './resolve'
import type {
  AccessRequest,
  AttributeValue,
  CombiningAlgorithm,
  Condition,
  ConditionGroup,
  Decision,
  Effect,
  Operator,
  Policy,
  Rule,
} from './types'

// ------------------------------------------------------------
// Trace types
// ------------------------------------------------------------

/**
 * Trace of a single leaf condition evaluation.
 *
 * Shows the field that was tested, the operator, what value was expected,
 * what value was actually found on the request, and whether the condition passed.
 */
export interface ConditionLeafTrace {
  /** Discriminator for condition trace nodes. */
  readonly type: 'condition'
  /** The dot-path field that was evaluated. */
  readonly field: string
  /** The operator that was applied. */
  readonly operator: Operator
  /** The value the condition expected (right-hand side). */
  readonly expected: AttributeValue
  /** The value actually found on the request (left-hand side). */
  readonly actual: AttributeValue
  /** Whether this condition passed. */
  readonly result: boolean
}

/**
 * Trace of a condition group (`all`, `any`, or `none`) evaluation.
 *
 * Contains the child traces and the group's overall result.
 */
export interface ConditionGroupTrace {
  /** Discriminator for condition trace nodes. */
  readonly type: 'group'
  /** The boolean logic used to combine children. */
  readonly logic: 'all' | 'any' | 'none'
  /** Whether this group as a whole passed. */
  readonly result: boolean
  /** Traces of each child condition or nested group. */
  readonly children: ReadonlyArray<ConditionLeafTrace | ConditionGroupTrace>
}

/**
 * A union of leaf and group condition traces.
 * Used as the recursive element type in explain output.
 */
export type ConditionTrace = ConditionLeafTrace | ConditionGroupTrace

/**
 * Trace of a single rule evaluation within a policy.
 *
 * Shows whether the rule's action and resource matchers fired, whether
 * its conditions were met, and whether it ultimately matched.
 */
export interface RuleTrace {
  /** The rule's unique ID. */
  readonly ruleId: string
  /** The rule's description, if set. */
  readonly description?: string
  /** The rule's effect (`'allow'` or `'deny'`). */
  readonly effect: Effect
  /** The rule's priority value. */
  readonly priority: number
  /** Whether the request's action matched the rule's action list. */
  readonly actionMatch: boolean
  /** Whether the request's resource matched the rule's resource list. */
  readonly resourceMatch: boolean
  /** Whether all conditions in the rule's condition tree were met. */
  readonly conditionsMet: boolean
  /** Full trace of the rule's condition tree evaluation. */
  readonly conditions: ConditionGroupTrace
  /** Whether this rule matched overall (action + resource + conditions all true). */
  readonly matched: boolean
}

/**
 * Trace of a single policy evaluation.
 *
 * Shows whether the policy's targets matched, traces for each rule,
 * and the final result produced by the policy's combining algorithm.
 */
export interface PolicyTrace {
  /** The policy's unique ID. */
  readonly policyId: string
  /** The policy's display name. */
  readonly policyName: string
  /** The combining algorithm used to resolve rule conflicts. */
  readonly algorithm: CombiningAlgorithm
  /** Whether the request matched the policy's target constraints. */
  readonly targetMatch: boolean
  /** Traces for every rule in the policy (not just matching ones). */
  readonly rules: readonly RuleTrace[]
  /** The final effect produced by this policy. */
  readonly result: Effect
  /** Human-readable explanation of why this result was produced. */
  readonly reason: string
  /** The ID of the rule that decided the outcome (if any). */
  readonly decidingRuleId?: string
}

/**
 * Complete evaluation trace returned by `engine.explain()`.
 *
 * Provides a full picture of how an authorization decision was reached:
 * the final decision, the request that was evaluated, the subject's roles
 * and attributes, traces for every policy, and a human-readable summary.
 */
export interface ExplainResult {
  /** The final authorization decision. */
  readonly decision: Decision
  /** Summary of the request that was evaluated. */
  readonly request: {
    /** The action that was checked. */
    readonly action: string
    /** The resource type that was checked. */
    readonly resourceType: string
    /** The specific resource ID, if provided. */
    readonly resourceId?: string
    /** The scope, if provided. */
    readonly scope?: string
  }
  /** Information about the subject whose access was evaluated. */
  readonly subject: {
    /** The subject's ID. */
    readonly id: string
    /** The subject's effective roles (after inheritance resolution). */
    readonly roles: readonly string[]
    /** Additional roles applied from scoped assignments for this request. */
    readonly scopedRolesApplied: readonly string[]
    /** The subject's attributes at evaluation time. */
    readonly attributes: Readonly<Record<string, AttributeValue>>
  }
  /** Traces for every policy that was evaluated (including non-matching ones). */
  readonly policies: readonly PolicyTrace[]
  /** Human-readable summary of the evaluation (multi-line). */
  readonly summary: string
}

// ------------------------------------------------------------
// Traced condition evaluation (non-short-circuiting)
// ------------------------------------------------------------

const MAX_TRACE_DEPTH = 10

function isCondition(item: Condition | ConditionGroup): item is Condition {
  return 'field' in item
}

function traceLeaf(req: AccessRequest, cond: Condition): ConditionLeafTrace {
  const actual = resolve(req, cond.field)
  const expected = resolveConditionValue(req, cond.value ?? null)
  const result = evaluateOperator(cond.operator, actual, expected)
  return { type: 'condition', field: cond.field, operator: cond.operator, expected, actual, result }
}

function traceItem(req: AccessRequest, item: Condition | ConditionGroup, depth: number): ConditionTrace {
  return isCondition(item) ? traceLeaf(req, item) : traceGroup(req, item, depth)
}

function traceGroup(req: AccessRequest, group: ConditionGroup, depth = 0): ConditionGroupTrace {
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

// ------------------------------------------------------------
// Traced rule evaluation
// ------------------------------------------------------------

function traceRule(rule: Rule, req: AccessRequest): RuleTrace {
  const actionMatch = rule.actions.some((a) => matchesAction(a, req.action))

  const resourceMatch = rule.resources.some((r) => {
    if (r.includes('.') || req.resource.type.includes('.')) {
      return matchesResourceHierarchical(r, req.resource.type)
    }
    return matchesResource(r, req.resource.type)
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

// ------------------------------------------------------------
// Combining algorithms (mirrors evaluate.ts)
// ------------------------------------------------------------

function applyCombiner(
  algorithm: CombiningAlgorithm,
  matched: readonly RuleTrace[],
  defaultEffect: Effect,
): { effect: Effect; reason: string; decidingRuleId?: string } {
  switch (algorithm) {
    case 'deny-overrides': {
      const deny = matched.find((r) => r.effect === 'deny')
      if (deny) return { effect: 'deny', reason: `Denied by rule "${deny.ruleId}"`, decidingRuleId: deny.ruleId }
      const allow = matched.find((r) => r.effect === 'allow')
      if (allow) return { effect: 'allow', reason: `Allowed by rule "${allow.ruleId}"`, decidingRuleId: allow.ruleId }
      return { effect: defaultEffect, reason: `No matching rules -> ${defaultEffect}` }
    }
    case 'allow-overrides': {
      const allow = matched.find((r) => r.effect === 'allow')
      if (allow) return { effect: 'allow', reason: `Allowed by rule "${allow.ruleId}"`, decidingRuleId: allow.ruleId }
      const deny = matched.find((r) => r.effect === 'deny')
      if (deny) return { effect: 'deny', reason: `Denied by rule "${deny.ruleId}"`, decidingRuleId: deny.ruleId }
      return { effect: defaultEffect, reason: `No matching rules -> ${defaultEffect}` }
    }
    case 'first-match': {
      const first = matched[0]
      if (first) {
        return {
          effect: first.effect,
          reason: `First match: rule "${first.ruleId}" (${first.effect})`,
          decidingRuleId: first.ruleId,
        }
      }
      return { effect: defaultEffect, reason: `No matching rules -> ${defaultEffect}` }
    }
    case 'highest-priority': {
      if (matched.length > 0) {
        const sorted = [...matched].sort((a, b) => b.priority - a.priority)
        const top = sorted[0]!
        return {
          effect: top.effect,
          reason: `Highest priority: rule "${top.ruleId}" (p=${top.priority})`,
          decidingRuleId: top.ruleId,
        }
      }
      return { effect: defaultEffect, reason: `No matching rules -> ${defaultEffect}` }
    }
  }
}

// ------------------------------------------------------------
// Traced policy evaluation
// ------------------------------------------------------------

function policyTargetsMatch(policy: Policy, req: AccessRequest): boolean {
  if (!policy.targets) return true
  const { actions, resources, roles } = policy.targets
  if (actions?.length && !actions.some((a) => matchesAction(a, req.action))) return false
  if (resources?.length && !resources.some((r) => matchesResource(r, req.resource.type))) return false
  if (roles?.length && !roles.some((role) => req.subject.roles.includes(role))) return false
  return true
}

function tracePolicy(policy: Policy, req: AccessRequest, defaultEffect: Effect): PolicyTrace {
  const targetMatch = policyTargetsMatch(policy, req)

  if (!targetMatch) {
    return {
      policyId: policy.id,
      policyName: policy.name,
      algorithm: policy.algorithm,
      targetMatch: false,
      rules: [],
      result: defaultEffect,
      reason: `Policy "${policy.id}" targets don't match -> ${defaultEffect}`,
    }
  }

  const ruleTraces = policy.rules.map((rule) => traceRule(rule, req))
  const matched = ruleTraces.filter((r) => r.matched)
  const { effect, reason, decidingRuleId } = applyCombiner(policy.algorithm, matched, defaultEffect)

  return {
    policyId: policy.id,
    policyName: policy.name,
    algorithm: policy.algorithm,
    targetMatch: true,
    rules: ruleTraces,
    result: effect,
    reason,
    decidingRuleId,
  }
}

// ------------------------------------------------------------
// Main explain function
// ------------------------------------------------------------

/**
 * Subject metadata passed to {@link explainEvaluation} for building the explain trace.
 *
 * Separates original roles from scoped roles so the trace can show
 * which roles were applied due to scope matching.
 */
export interface ExplainSubjectInfo {
  /** The subject's unique ID. */
  subjectId: string
  /** The subject's base roles (before scope enrichment). */
  originalRoles: readonly string[]
  /** Additional roles applied from scoped assignments for this request. */
  scopedRolesApplied: readonly string[]
}

export function explainEvaluation(
  policies: Policy[],
  request: AccessRequest,
  defaultEffect: Effect,
  subjectInfo: ExplainSubjectInfo,
): ExplainResult {
  const start = performance.now()

  // Trace ALL policies (no short-circuit -- show everything)
  const policyTraces = policies.map((p) => tracePolicy(p, request, defaultEffect))

  // Determine final decision using same AND-combination as evaluate():
  // walk policies in order, first non-allow result = overall deny
  let finalEffect: Effect = defaultEffect
  let finalReason = 'No policies configured'
  let finalPolicy: string | undefined
  let finalRule: Rule | undefined

  if (policies.length > 0) {
    let lastAllow: PolicyTrace | null = null
    let denyingTrace: PolicyTrace | null = null

    for (const pt of policyTraces) {
      if (pt.result !== 'allow') {
        denyingTrace = pt
        break
      }
      lastAllow = pt
    }

    if (denyingTrace) {
      finalEffect = 'deny'
      finalReason = denyingTrace.reason
      finalPolicy = denyingTrace.policyId
    } else if (lastAllow) {
      finalEffect = 'allow'
      finalReason = lastAllow.reason
      finalPolicy = lastAllow.policyId
    } else {
      finalEffect = defaultEffect
      finalReason = `No matching rules across ${policies.length} policies -> ${defaultEffect}`
    }
  }

  const decision: Decision = {
    allowed: finalEffect === 'allow',
    effect: finalEffect,
    rule: finalRule,
    policy: finalPolicy,
    reason: finalReason,
    duration: performance.now() - start,
    timestamp: Date.now(),
  }

  const summary = buildSummary(decision, policyTraces, subjectInfo, request)

  return {
    decision,
    request: {
      action: request.action,
      resourceType: request.resource.type,
      resourceId: request.resource.id,
      scope: request.scope,
    },
    subject: {
      id: subjectInfo.subjectId,
      roles: subjectInfo.originalRoles,
      scopedRolesApplied: subjectInfo.scopedRolesApplied,
      attributes: request.subject.attributes,
    },
    policies: policyTraces,
    summary,
  }
}

// ------------------------------------------------------------
// Summary builder
// ------------------------------------------------------------

function buildSummary(
  decision: Decision,
  policyTraces: PolicyTrace[],
  info: ExplainSubjectInfo,
  req: AccessRequest,
): string {
  const verb = decision.allowed ? 'ALLOWED' : 'DENIED'
  const parts: string[] = []

  // Header
  parts.push(
    `${verb}: "${info.subjectId}" -> ${req.action} on ${req.resource.type}${req.scope ? ` [scope: ${req.scope}]` : ''}`,
  )

  // Roles
  const roles = [...info.originalRoles]
  if (info.scopedRolesApplied.length > 0) {
    parts.push(`  Roles: [${roles.join(', ')}] + scoped: [${info.scopedRolesApplied.join(', ')}]`)
  } else {
    parts.push(`  Roles: [${roles.join(', ')}]`)
  }

  // Per-policy summary
  for (const pt of policyTraces) {
    const matched = pt.rules.filter((r) => r.matched).length
    const total = pt.rules.length

    if (!pt.targetMatch) {
      parts.push(`  ${pt.policyId}: targets don't match (${pt.result})`)
    } else if (pt.decidingRuleId) {
      parts.push(`  ${pt.policyId} [${pt.algorithm}]: ${pt.reason} (${matched}/${total} rules matched)`)
    } else {
      parts.push(`  ${pt.policyId} [${pt.algorithm}]: no matching rules -> ${pt.result} (0/${total} rules evaluated)`)
    }
  }

  // Final
  parts.push(`  Result: ${decision.reason}`)

  return parts.join('\n')
}
