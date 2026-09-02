import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { explainEvaluation } from '../explain'

function makeReq(overrides: Partial<IamRequest.IAccessRequest> = {}): IamRequest.IAccessRequest {
  return {
    action: 'read',
    resource: { attributes: {}, id: 'post-1', type: 'post' },
    subject: { attributes: { department: 'engineering' }, id: 'user-1', roles: ['editor'] },
    ...overrides,
  }
}

const subjectInfo = {
  originalRoles: ['editor'],
  scopedRolesApplied: [],
  subjectId: 'user-1',
}

function rule(
  id: string,
  effect: AccessControl.Effect,
  priority: number,
  overrides: Partial<AccessControl.IRule> = {},
): AccessControl.IRule {
  return {
    actions: ['read'],
    conditions: { all: [] },
    effect,
    id,
    priority,
    resources: ['post'],
    ...overrides,
  }
}

function policy(algorithm: AccessControl.CombiningAlgorithm, rules: AccessControl.IRule[]): AccessControl.IPolicy {
  return { algorithm, id: 'p', name: 'P', rules }
}

const traceOf = (p: AccessControl.IPolicy, req = makeReq()) =>
  explainEvaluation([p], req, 'deny', subjectInfo).policies[0]!

describe('tracePolicy() combining algorithms', () => {
  it('deny-overrides picks the deny even when an allow also matched', () => {
    const trace = traceOf(policy('deny-overrides', [rule('r-allow', 'allow', 10), rule('r-deny', 'deny', 1)]))
    expect(trace.result).toBe('deny')
    expect(trace.decidingRuleId).toBe('r-deny')
    expect(trace.decidingRule?.id).toBe('r-deny')
  })

  it('allow-overrides picks the allow even when a higher-priority deny also matched', () => {
    const trace = traceOf(policy('allow-overrides', [rule('r-deny', 'deny', 100), rule('r-allow', 'allow', 1)]))
    expect(trace.result).toBe('allow')
    expect(trace.decidingRuleId).toBe('r-allow')
  })

  it('allow-overrides falls back to the deny when nothing allows', () => {
    const trace = traceOf(policy('allow-overrides', [rule('r-deny', 'deny', 1)]))
    expect(trace.result).toBe('deny')
    expect(trace.decidingRuleId).toBe('r-deny')
  })

  it('first-match ranks by priority, mirroring the evaluate combiner', () => {
    const trace = traceOf(policy('first-match', [rule('r-low', 'allow', 1), rule('r-high', 'deny', 99)]))
    expect(trace.result).toBe('deny')
    expect(trace.decidingRuleId).toBe('r-high')
    expect(trace.reason).toContain('First match')
  })

  it('first-match keeps source order on a priority tie', () => {
    const trace = traceOf(policy('first-match', [rule('r-first', 'allow', 5), rule('r-second', 'deny', 5)]))
    expect(trace.decidingRuleId).toBe('r-first')
  })

  it('highest-priority picks the top-priority matched rule', () => {
    const trace = traceOf(policy('highest-priority', [rule('r-low', 'deny', 1), rule('r-high', 'allow', 50)]))
    expect(trace.result).toBe('allow')
    expect(trace.decidingRuleId).toBe('r-high')
    expect(trace.reason).toContain('p=50')
  })

  it.each(['deny-overrides', 'allow-overrides', 'first-match', 'highest-priority'] as const)(
    '%s falls back to the default effect with no matched rule',
    (algorithm) => {
      const trace = traceOf(policy(algorithm, [rule('r', 'allow', 10, { actions: ['write'] })]))
      expect(trace.result).toBe('deny')
      expect(trace.decidingRuleId).toBeUndefined()
      expect(trace.decidingRule).toBeUndefined()
      expect(trace.reason).toContain('No matching rules')
    },
  )
})

describe('tracePolicy() target matching', () => {
  it('skips a policy whose target roles the subject does not hold', () => {
    const p: AccessControl.IPolicy = {
      ...policy('deny-overrides', [rule('r', 'allow', 1)]),
      targets: { roles: ['admin'] },
    }
    const trace = traceOf(p)
    expect(trace.targetMatch).toBe(false)
    expect(trace.rules).toEqual([])
  })

  it('applies a policy whose target roles the subject holds', () => {
    const p: AccessControl.IPolicy = {
      ...policy('deny-overrides', [rule('r', 'allow', 1)]),
      targets: { roles: ['editor'] },
    }
    expect(traceOf(p).targetMatch).toBe(true)
  })

  it('treats an empty target list as no constraint', () => {
    const p: AccessControl.IPolicy = {
      ...policy('deny-overrides', [rule('r', 'allow', 1)]),
      targets: { actions: [], resources: [], roles: [] },
    }
    expect(traceOf(p).targetMatch).toBe(true)
  })

  it('reports "No applicable policy" when every policy target misses', () => {
    const p: AccessControl.IPolicy = {
      ...policy('deny-overrides', [rule('r', 'allow', 1)]),
      targets: { roles: ['admin'] },
    }
    const result = explainEvaluation([p], makeReq(), 'deny', subjectInfo)
    expect(result.decision.reason).toContain('No applicable policy across 1 policies')
  })
})

describe('traceRule() resource matching', () => {
  it('matches a dotted descendant through an explicit `.*` pattern', () => {
    const p = policy('deny-overrides', [rule('r', 'allow', 1, { resources: ['docs.*'] })])
    const trace = traceOf(p, makeReq({ resource: { attributes: {}, type: 'docs.internal.secret' } }))
    expect(trace.rules[0]!.resourceMatch).toBe(true)
  })

  it('does not treat a dotted prefix without `.*` as covering descendants', () => {
    const p = policy('deny-overrides', [rule('r', 'allow', 1, { resources: ['docs.internal'] })])
    const trace = traceOf(p, makeReq({ resource: { attributes: {}, type: 'docs.internal.secret' } }))
    expect(trace.rules[0]!.resourceMatch).toBe(false)
    expect(trace.rules[0]!.matched).toBe(false)
  })

  it('routes a dotted resource type to the dot-only matcher, so a `:*` pattern misses', () => {
    const p = policy('deny-overrides', [rule('r', 'allow', 1, { resources: ['docs:*'] })])
    const trace = traceOf(p, makeReq({ resource: { attributes: {}, type: 'docs:internal.secret' } }))
    expect(trace.rules[0]!.resourceMatch).toBe(false)
  })
})

describe('traceGroup() logic', () => {
  const eqDept = (value: string): AccessControl.ICondition => ({
    field: 'subject.attributes.department',
    operator: 'eq',
    value,
  })

  it('"any" is true when a single child passes', () => {
    const p = policy('deny-overrides', [
      rule('r', 'allow', 1, { conditions: { any: [eqDept('sales'), eqDept('engineering')] } }),
    ])
    const conditions = traceOf(p).rules[0]!.conditions
    expect(conditions.logic).toBe('any')
    expect(conditions.result).toBe(true)
    expect(conditions.children.map((c) => c.result)).toEqual([false, true])
  })

  it('"any" is false when every child fails', () => {
    const p = policy('deny-overrides', [rule('r', 'allow', 1, { conditions: { any: [eqDept('sales')] } })])
    expect(traceOf(p).rules[0]!.conditions.result).toBe(false)
  })

  it('"none" is true only when every child fails', () => {
    const passing = policy('deny-overrides', [rule('r', 'allow', 1, { conditions: { none: [eqDept('sales')] } })])
    expect(traceOf(passing).rules[0]!.conditions.result).toBe(true)

    const failing = policy('deny-overrides', [rule('r', 'allow', 1, { conditions: { none: [eqDept('engineering')] } })])
    expect(traceOf(failing).rules[0]!.conditions.result).toBe(false)
  })

  it('truncates past the trace depth cap instead of recursing without bound', () => {
    const nest = (depth: number): AccessControl.IConditionGroup =>
      depth === 0 ? { all: [eqDept('engineering')] } : { all: [nest(depth - 1)] }

    const shallow = policy('deny-overrides', [rule('r', 'allow', 1, { conditions: nest(5) })])
    expect(traceOf(shallow).rules[0]!.conditionsMet).toBe(true)

    // 12 nested groups sits past MAX_TRACE_DEPTH: the innermost trace is replaced
    // by an empty failing group, so the rule reports as not matched.
    const deep = policy('deny-overrides', [rule('r', 'allow', 1, { conditions: nest(12) })])
    const deepTrace = traceOf(deep).rules[0]!
    expect(deepTrace.conditionsMet).toBe(false)
    expect(deepTrace.matched).toBe(false)
  })
})
