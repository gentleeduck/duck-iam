import { describe, expect, it } from 'vitest'
import { evalCondition } from '../../conditions/conditions.libs'
import type { AccessControl, IamPrimitives, IamRequest } from '../../types'
import { explainEvaluation } from '../explain'
import type { Explain } from '../explain.types'

/**
 * `explain-evaluate-parity.test.ts` pins the two implementations against each
 * other at the *policy combine* level, and its own docblock records that they
 * had drifted twice there. They had drifted a third time one level down, at the
 * leaf: `traceLeaf` called `evaluateOperator`, which is the raw operator table,
 * while the decision path goes through `evalCondition`.
 *
 * `evalCondition` refuses `matches` when the operand is `$`-sourced, because
 * resolving it lets anyone who controls a subject/resource/environment
 * attribute choose the pattern that gets compiled - a ReDoS pin. The trace
 * resolved the `$` and compiled the result, so `explain()` reported a leaf as
 * satisfied that the engine had refused outright. An operator asking "why was
 * this denied?" was shown the condition that supposedly passed.
 */
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

  for (const { name, cond, attrs } of cases) {
    it(name, () => {
      const req = requestWith(attrs)
      const decided = evalCondition(req, cond)
      expect(tracedLeaves(cond, req)).toEqual([decided])
    })
  }
})
