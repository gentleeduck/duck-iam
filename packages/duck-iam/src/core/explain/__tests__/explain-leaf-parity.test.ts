import { describe, expect, it } from 'vitest'
import { evalCondition } from '../../conditions/conditions.libs'
import type { AccessControl, IamPrimitives, IamRequest } from '../../types'
import { explainEvaluation } from '../explain'
import type { Explain } from '../explain.types'

// SECURITY: the same parity one level down, at the leaf. `evalCondition` refuses `matches` on a `$`-sourced operand
// (a ReDoS pin), so a trace built on the raw operator table would show a leaf as satisfied that the engine refused.
const subjectInfo: Explain.ISubjectInfo = { subjectId: 'u1', originalRoles: [], scopedRolesApplied: [] }

function requestWith(attributes: Record<string, IamPrimitives.AttributeValue>): IamRequest.IAccessRequest {
  return {
    subject: { id: 'u1', roles: [], attributes },
    action: 'read',
    resource: { type: 'post', attributes: {} },
    environment: {},
  }
}

function policyWith(cond: AccessControl.ICondition): AccessControl.IPolicy {
  return {
    id: 'p1',
    name: 'p1',
    algorithm: 'first-match',
    rules: [
      { id: 'r1', effect: 'allow', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [cond] } },
    ],
  }
}

/** Pull every leaf result out of a trace, depth-first. */
function leafResults(trace: Explain.Trace): boolean[] {
  if (trace.type === 'condition') return [trace.result]
  return trace.children.flatMap(leafResults)
}

function tracedLeaves(cond: AccessControl.ICondition, req: IamRequest.IAccessRequest): boolean[] {
  const result = explainEvaluation([policyWith(cond)], req, 'deny', subjectInfo, 'and')
  return result.policies.flatMap((p) => p.rules.flatMap((r) => leafResults(r.conditions)))
}

/** Did the trace record that it could not evaluate the rule's conditions? */
function tracedRefusal(cond: AccessControl.ICondition, req: IamRequest.IAccessRequest): boolean {
  const result = explainEvaluation([policyWith(cond)], req, 'deny', subjectInfo, 'and')
  return result.policies.some((p) => p.rules.some((r) => r.conditionError !== undefined))
}

describe('a traced leaf agrees with the leaf the engine decided on', () => {
  const cases: { name: string; cond: AccessControl.ICondition; attrs: Record<string, IamPrimitives.AttributeValue> }[] =
    [
      {
        name: 'matches with a $-sourced pattern is refused by both',
        cond: { field: 'subject.attributes.name', operator: 'matches', value: '$subject.attributes.pattern' },
        attrs: { name: 'admin', pattern: '^admin$' },
      },
      {
        name: 'matches with a literal pattern is honoured by both',
        cond: { field: 'subject.attributes.name', operator: 'matches', value: '^admin$' },
        attrs: { name: 'admin' },
      },
    ]

  // Tri-state: a boolean cannot tell "did not match" from "refused to answer", and refusals are where the two drift.
  for (const { name, cond, attrs } of cases) {
    it(name, () => {
      const req = requestWith(attrs)
      let decided: boolean | 'refused'
      try {
        decided = evalCondition(req, cond)
      } catch {
        decided = 'refused'
      }
      if (decided === 'refused') {
        // The trace records the refusal on the rule and emits no leaf; both are asserted so a tracer that silently
        // drops the leaf cannot pass.
        expect(tracedRefusal(cond, req)).toBe(true)
        expect(tracedLeaves(cond, req)).toEqual([])
        return
      }
      expect(tracedLeaves(cond, req)).toEqual([decided])
      expect(tracedRefusal(cond, req)).toBe(false)
    })
  }
})
