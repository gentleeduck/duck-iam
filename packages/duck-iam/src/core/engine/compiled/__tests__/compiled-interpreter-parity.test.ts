import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../../adapters/memory'
import { evaluate } from '../../../evaluate/evaluate'
import { rolesToPolicy } from '../../../rbac'
import type { AccessControl, IamRequest } from '../../../types'
import { IamEngine } from '../../engine'
import { compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'
import type { CompiledTable } from '../compiled.types'

// The table is the verdict in both modes, so a table/interpreter divergence ships unseen by development runs.
// Each case asserts agreement AND the agreed value, so agreeing on the wrong answer still fails.
function maskFromRoles(table: CompiledTable, roles: readonly string[]): number {
  let mask = 0
  for (const name of roles) {
    const bit = table.roleId.get(name)
    if (bit !== undefined) mask |= 1 << bit
  }
  return mask
}

function both(
  roles: AccessControl.IRole[],
  policies: AccessControl.IPolicy[],
  request: IamRequest.IAccessRequest,
  combine: AccessControl.PolicyCombine = 'and',
  defaultEffect: AccessControl.Effect = 'deny',
): { interpreted: boolean; compiled: boolean } {
  const table = compileTable(roles, policies, combine, 'flat')
  const compiled = lookup(
    table,
    maskFromRoles(table, request.subject.roles),
    request.action,
    request.resource.type,
    request,
    defaultEffect,
  )
  const rbac = rolesToPolicy(roles, 'flat')
  const all = rbac.rules.length === 0 ? policies : [rbac, ...policies]
  const interpreted = evaluate(all, request, defaultEffect, combine).allowed
  return { interpreted, compiled }
}

const REQUEST: IamRequest.IAccessRequest = {
  action: 'read',
  environment: { now: 1 },
  resource: { attributes: { min: 'not-a-number' }, type: 'post' },
  subject: { attributes: { lvl: 9 }, id: 'u', roles: ['admin'] },
}

/** A `$`-reference whose resolved operand is a string, so `gte` throws IamError with code IAM_CONDITION_OPERAND_TYPE. */
const THROWING_CONDITION: AccessControl.IConditionGroup = {
  all: [{ field: 'subject.attributes.lvl', operator: 'gte', value: '$resource.attributes.min' }],
}

describe('compiled table / interpreter parity (round 13)', () => {
  describe("A-F1 policyCombine 'first-applicable'", () => {
    const POLICIES: AccessControl.IPolicy[] = [
      {
        algorithm: 'deny-overrides',
        id: 'p0',
        name: 'p0',
        rules: [
          { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 0, resources: ['post'] },
        ],
      },
      {
        algorithm: 'deny-overrides',
        id: 'p1',
        name: 'p1',
        rules: [
          { actions: ['read'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 0, resources: ['post'] },
        ],
      },
    ]

    it("lookup() folds 'first-applicable' as 'and', so it must never receive it", () => {
      // Why the engine keeps this combine off the compiled path. The `every` fold under-allows rather than over-allows.
      expect(both([], POLICIES, REQUEST, 'first-applicable')).toEqual({ compiled: false, interpreted: true })
    })

    it('the engine answers through the interpreter, not an Evaluation error', async () => {
      const onError = vi.spyOn(console, 'error').mockImplementation(() => {})
      const engine = new IamEngine({
        adapter: new IamMemoryAdapter({ policies: POLICIES }),
        mode: 'development',
        policyCombine: 'first-applicable',
      })
      const decision = await engine.authorize(REQUEST)
      // The first applicable policy allows; XACML first-applicable stops there.
      expect({ allowed: decision.allowed, consoleErrors: onError.mock.calls.length }).toEqual({
        allowed: true,
        consoleErrors: 0,
      })
      onError.mockRestore()
    })
  })

  describe('A-F2 a throwable condition the fast path never reaches', () => {
    const policyWith = (conditions: AccessControl.IConditionGroup): AccessControl.IPolicy => ({
      algorithm: 'allow-overrides',
      id: 'p0',
      name: 'p0',
      rules: [
        {
          actions: ['read'],
          conditions: { all: [] },
          effect: 'allow',
          id: 'allow-literal',
          priority: 0,
          resources: ['post'],
        },
        { actions: ['*'], conditions, effect: 'deny', id: 'deny-wildcard', priority: 0, resources: ['post'] },
      ],
    })

    it('a $-resolved operand of the wrong type makes the policy Indeterminate in both engines', () => {
      expect(both([], [policyWith(THROWING_CONDITION)], REQUEST)).toEqual({ compiled: false, interpreted: false })
    })

    it('an omitted `value` key (type-valid: ICondition.value is optional) does too', () => {
      const conditions: AccessControl.IConditionGroup = {
        all: [{ field: 'subject.attributes.lvl', operator: 'gte' }],
      }
      expect(both([], [policyWith(conditions)], REQUEST)).toEqual({ compiled: false, interpreted: false })
    })

    it('a non-array group body, on which assertItems throws, does too', () => {
      // Deliberately malformed: a row that reached the store without validation.
      const conditions = { all: 'x' } as unknown as AccessControl.IConditionGroup
      expect(both([], [policyWith(conditions)], REQUEST)).toEqual({ compiled: false, interpreted: false })
    })

    it('a well-typed literal operand still takes the fast path (no blanket fallback)', () => {
      const conditions: AccessControl.IConditionGroup = {
        all: [{ field: 'subject.attributes.lvl', operator: 'gte', value: 5 }],
      }
      // Nothing can throw, so `mayThrow` stays false and the fast path's allow-overrides short-circuit is correct.
      // In the cases above that short-circuit would return before reaching the throw.
      expect(both([], [policyWith(conditions)], REQUEST)).toEqual({ compiled: true, interpreted: true })
    })
  })

  describe('A-F3 one rotten role permission must not poison unrelated grants', () => {
    it('rbacDynamic abstains per grant, matching rulesAbstainOnThrow', () => {
      const roles: AccessControl.IRole[] = [
        {
          id: 'admin',
          name: 'admin',
          permissions: [
            { action: 'read', conditions: THROWING_CONDITION, resource: 'post' },
            { action: 'read', resource: 'post', scope: 'org1' },
          ],
        },
      ]
      expect(both(roles, [], { ...REQUEST, scope: 'org1' })).toEqual({ compiled: true, interpreted: true })
    })

    it('rbacResidual (wildcard permissions) abstains per grant too', () => {
      const roles: AccessControl.IRole[] = [
        {
          id: 'admin',
          name: 'admin',
          permissions: [
            { action: '*', conditions: THROWING_CONDITION, resource: 'post' },
            { action: '*', resource: '*' },
          ],
        },
      ]
      expect(both(roles, [], REQUEST)).toEqual({ compiled: true, interpreted: true })
    })
  })

  describe('A-F4 a duplicate role id casts no phantom RBAC vote', () => {
    // `compileTable` reads permissions positionally from the array, but roleId is
    // last-wins - so the middle entry's grant is held by nobody (roleMask 0).
    const ROLES: AccessControl.IRole[] = [
      { id: 'real', name: 'Real', permissions: [{ action: 'write', resource: 'doc' }] },
      { id: 'dup', name: 'Shadowed', permissions: [{ action: 'read', resource: 'post', scope: 'org1' }] },
      { id: 'dup', name: 'Survivor', permissions: [] },
    ]
    const request: IamRequest.IAccessRequest = { ...REQUEST, subject: { ...REQUEST.subject, roles: ['dup'] } }

    it("availability: the ABAC allow is not cancelled by a grant nobody holds (defaultEffect 'deny')", () => {
      const policies: AccessControl.IPolicy[] = [
        {
          algorithm: 'deny-overrides',
          id: 'p0',
          name: 'p0',
          rules: [
            { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 0, resources: ['post'] },
          ],
        },
      ]
      expect(both(ROLES, policies, request, 'and', 'deny')).toEqual({ compiled: true, interpreted: true })
    })

    it("security: the phantom vote does not fail open under defaultEffect 'allow'", () => {
      const policies: AccessControl.IPolicy[] = [
        {
          algorithm: 'deny-overrides',
          id: 'p0',
          name: 'p0',
          rules: [
            { actions: ['read'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 0, resources: ['post'] },
          ],
        },
      ]
      expect(both(ROLES, policies, request, 'allow-overrides', 'allow')).toEqual({
        compiled: false,
        interpreted: false,
      })
    })
  })
})
