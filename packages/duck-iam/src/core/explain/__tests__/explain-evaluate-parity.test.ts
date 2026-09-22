import { describe, expect, it } from 'vitest'
import { evaluate } from '../../evaluate/evaluate'
import type { AccessControl, IamRequest } from '../../types'
import { explainEvaluation } from '../explain'
import type { Explain } from '../explain.types'

// `explainEvaluation` recomputes the cross-policy combine rather than calling `evaluate`, so only a test keeps the
// two in agreement; a drift shows an operator the opposite of what the engine decided.
const subjectInfo: Explain.ISubjectInfo = {
  subjectId: 'u1',
  originalRoles: [],
  scopedRolesApplied: [],
}

const request: IamRequest.IAccessRequest = {
  subject: { id: 'u1', roles: [], attributes: { status: 'suspended' } },
  action: 'delete',
  resource: { type: 'org', attributes: {} },
  environment: {},
}

/** Applicable for this action/resource, but its condition is false. */
const conditionFalse: AccessControl.IPolicy = {
  id: 'p-condition-false',
  name: 'condition false',
  algorithm: 'deny-overrides',
  rules: [
    {
      id: 'r-deny',
      effect: 'deny',
      priority: 0,
      actions: ['*'],
      resources: ['org'],
      conditions: { all: [{ field: 'subject.attributes.status', operator: 'eq', value: 'pending' }] },
    },
  ],
}

const allowAll: AccessControl.IPolicy = {
  id: 'p-allow',
  name: 'allow',
  algorithm: 'first-match',
  rules: [
    { id: 'r-allow', effect: 'allow', priority: -1, actions: ['*'], resources: ['org'], conditions: { all: [] } },
  ],
}

const otherAction: AccessControl.IPolicy = {
  id: 'p-other',
  name: 'other action',
  algorithm: 'first-match',
  rules: [
    { id: 'r-w', effect: 'allow', priority: 1, actions: ['write'], resources: ['post'], conditions: { all: [] } },
  ],
}

const SETS: ReadonlyArray<readonly [string, AccessControl.IPolicy[]]> = [
  ['a policy voting its default, then an allow', [conditionFalse, allowAll]],
  ['an allow, then a policy voting its default', [allowAll, conditionFalse]],
  ['a NotApplicable policy, then an allow', [otherAction, allowAll]],
  ['a NotApplicable policy, then a policy voting its default', [otherAction, conditionFalse]],
  ['only NotApplicable policies', [otherAction]],
]

const COMBINES: AccessControl.PolicyCombine[] = ['first-applicable', 'and', 'allow-overrides']

// Applicability is not specific to `first-applicable` - evaluate also requires a rule shaped for the request - so
// every combine mode is covered.
describe.each(COMBINES)('explain and evaluate agree under combine=%s', (combine) => {
  describe.each(SETS)('%s', (_label, policies) => {
    it.each(['deny', 'allow'] as const)('under defaultEffect %s', (defaultEffect) => {
      const explained = explainEvaluation(policies, request, defaultEffect, subjectInfo, combine)
      const evaluated = evaluate(policies, request, defaultEffect, combine)
      expect(explained.decision.allowed).toBe(evaluated.allowed)
      expect(explained.decision.policy).toBe(evaluated.policy)
    })
  })
})
