import { iamIsReservedRefusal } from '../../shared/reserved'
import type { AccessControl, IamRequest } from '../types'
import { tracePolicy } from './explain.libs'
import type { Explain } from './explain.types'
/**
 * Produce a detailed evaluation trace for debugging authorization decisions.
 * NOTE: every policy is traced without short-circuiting; `combine` only decides which trace yields the final decision.
 *
 * @param defaultEffect Effect when no rule fires inside any policy.
 * @param subjectInfo   Subject metadata (id, roles, scoped roles applied).
 * @param combine       Cross-policy combine strategy (defaults to `'and'`).
 * @returns A full {@link Explain.IResult} describing every policy trace and the final decision.
 */
export function explainEvaluation(
  policies: AccessControl.IPolicy[],
  request: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
  subjectInfo: Explain.ISubjectInfo,
  combine: AccessControl.PolicyCombine = 'and',
): Explain.IResult {
  const start = performance.now()

  const policyTraces = policies.map((p) => tracePolicy(p, request, defaultEffect))

  let finalEffect: AccessControl.Effect = defaultEffect
  let finalReason = 'No policies configured'
  let finalPolicy: string | undefined
  let finalRule: AccessControl.IRule | undefined

  if (policies.length > 0) {
    const decided = decideFinal(policyTraces, defaultEffect, combine)
    finalEffect = decided.effect
    finalReason = decided.reason
    finalPolicy = decided.policy
    finalRule = decided.rule
  }

  // SECURITY: the reserved refusal token is denied before any policy is consulted, so the summary must say deny even
  // when a wildcard grant would have matched. Calls the decision path's own predicate, never a hand-copy of it.
  if (iamIsReservedRefusal(request.action) || iamIsReservedRefusal(request.resource.type)) {
    finalEffect = 'deny'
    finalReason = 'Denied: the request names the reserved refusal token, which no policy can grant'
    finalPolicy = undefined
    finalRule = undefined
  }

  const decision: AccessControl.IDecision = {
    allowed: finalEffect === 'allow',
    effect: finalEffect,
    rule: finalRule,
    policy: finalPolicy,
    reason: finalReason,
    // The same `failure` tag `_reservedRefusalDecision` carries, so a caller branching on it reads one value.
    ...(iamIsReservedRefusal(request.action) || iamIsReservedRefusal(request.resource.type)
      ? { failure: 'input' as const }
      : {}),
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

/**
 * Whether a traced policy takes part in the cross-policy combine.
 * NOTE: mirrors both of `evaluate`'s NotApplicable tests; on one alone the explanation contradicts the decision.
 */
function traceIsApplicable(trace: Explain.IPolicyTrace): boolean {
  return trace.targetMatch && trace.rules.some((rule) => rule.actionMatch && rule.resourceMatch)
}

/** Resolve the final decision across all policy traces under the given combine mode. */
function decideFinal(
  traces: readonly Explain.IPolicyTrace[],
  defaultEffect: AccessControl.Effect,
  combine: AccessControl.PolicyCombine,
): { effect: AccessControl.Effect; reason: string; policy?: string; rule?: AccessControl.IRule } {
  const applicable = traces.filter(traceIsApplicable)

  if (combine === 'and') {
    let lastAllow: Explain.IPolicyTrace | null = null
    for (const pt of applicable) {
      if (pt.result !== 'allow') {
        return { effect: 'deny', reason: pt.reason, policy: pt.policyId, rule: pt.decidingRule }
      }
      lastAllow = pt
    }
    if (lastAllow) {
      return { effect: 'allow', reason: lastAllow.reason, policy: lastAllow.policyId, rule: lastAllow.decidingRule }
    }
  } else if (combine === 'allow-overrides') {
    let lastDeny: Explain.IPolicyTrace | null = null
    for (const pt of applicable) {
      if (pt.result === 'allow') {
        return { effect: 'allow', reason: pt.reason, policy: pt.policyId, rule: pt.decidingRule }
      }
      lastDeny = pt
    }
    if (lastDeny) {
      return { effect: 'deny', reason: lastDeny.reason, policy: lastDeny.policyId, rule: lastDeny.decidingRule }
    }
  } else {
    // first-applicable: the first applicable trace wins, rule or not. Gating on `decidingRule` would skip a policy
    // that voted its `defaultEffect`, which `evaluate` counts.
    const first = applicable[0]
    if (first !== undefined) {
      return { effect: first.result, policy: first.policyId, reason: first.reason, rule: first.decidingRule }
    }
  }
  return {
    effect: defaultEffect,
    reason:
      applicable.length === 0
        ? `No applicable policy across ${traces.length} policies. Defaulted to ${defaultEffect}`
        : `No matching rules across ${applicable.length} applicable policies. Defaulted to ${defaultEffect}`,
  }
}

/** Build a human-readable multi-line summary of the evaluation trace. */
function buildSummary(
  decision: AccessControl.IDecision,
  policyTraces: Explain.IPolicyTrace[],
  info: Explain.ISubjectInfo,
  req: IamRequest.IAccessRequest,
): string {
  const verb = decision.allowed ? 'ALLOWED' : 'DENIED'
  const parts: string[] = []

  parts.push(
    `${verb}: "${info.subjectId}" attempting ${req.action} on ${req.resource.type}${req.scope ? ` [scope: ${req.scope}]` : ''}`,
  )

  const roles = [...info.originalRoles]
  if (info.scopedRolesApplied.length > 0) {
    parts.push(`  Roles: [${roles.join(', ')}] + scoped: [${info.scopedRolesApplied.join(', ')}]`)
  } else {
    parts.push(`  Roles: [${roles.join(', ')}]`)
  }

  for (const pt of policyTraces) {
    const matched = pt.rules.filter((r) => r.matched).length
    const total = pt.rules.length

    if (!traceIsApplicable(pt)) {
      parts.push(`  ${pt.policyId}: not applicable to this request`)
    } else if (pt.decidingRuleId) {
      parts.push(`  ${pt.policyId} [${pt.algorithm}]: ${pt.reason} (${matched}/${total} rules matched)`)
    } else {
      parts.push(
        `  ${pt.policyId} [${pt.algorithm}]: no matching rules. Defaulted to ${pt.result} (0/${total} rules evaluated)`,
      )
    }
  }

  parts.push(`  Result: ${decision.reason}`)

  return parts.join('\n')
}
