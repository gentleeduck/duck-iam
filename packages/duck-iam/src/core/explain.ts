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

export interface ConditionLeafTrace {
  readonly type: 'condition'
  readonly field: string
  readonly operator: Operator
  readonly expected: AttributeValue
  readonly actual: AttributeValue
  readonly result: boolean
}

export interface ConditionGroupTrace {
  readonly type: 'group'
  readonly logic: 'all' | 'any' | 'none'
  readonly result: boolean
  readonly children: ReadonlyArray<ConditionLeafTrace | ConditionGroupTrace>
}

export type ConditionTrace = ConditionLeafTrace | ConditionGroupTrace

export interface RuleTrace {
  readonly ruleId: string
  readonly description?: string
  readonly effect: Effect
  readonly priority: number
  readonly actionMatch: boolean
  readonly resourceMatch: boolean
  readonly conditionsMet: boolean
  readonly conditions: ConditionGroupTrace
  readonly matched: boolean
}

export interface PolicyTrace {
  readonly policyId: string
  readonly policyName: string
  readonly algorithm: CombiningAlgorithm
  readonly targetMatch: boolean
  readonly rules: readonly RuleTrace[]
  readonly result: Effect
  readonly reason: string
  readonly decidingRuleId?: string
}

export interface ExplainResult {
  readonly decision: Decision
  readonly request: {
    readonly action: string
    readonly resourceType: string
    readonly resourceId?: string
    readonly scope?: string
  }
  readonly subject: {
    readonly id: string
    readonly roles: readonly string[]
    readonly scopedRolesApplied: readonly string[]
    readonly attributes: Readonly<Record<string, AttributeValue>>
  }
  readonly policies: readonly PolicyTrace[]
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

export interface ExplainSubjectInfo {
  subjectId: string
  originalRoles: readonly string[]
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
