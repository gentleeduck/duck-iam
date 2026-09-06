/**
 * Minimized reproductions of the two table/interpreter divergences the
 * generated sweep in `e2e-verdict-differential.e2e.test.ts` found.
 *
 * Both are the shape `docs/engine-rewrite.md` says can no longer happen: the
 * compiled table (the verdict in BOTH modes) answers **allow**, the interpreter
 * (run only in development, for provenance) answers **deny**, so production
 * grants access that a development run of the same catalog refuses. Both are
 * reached with zero ABAC policies - RBAC role permissions alone.
 *
 * These assert the *correct* behaviour (the two paths agree), so they fail
 * against the current code. That is deliberate: a test edited to match the
 * broken behaviour certifies the break.
 *
 * They differ in reachability, and the difference matters:
 *
 *  - The throwing-condition case needs NO malformed data. `validateRole`
 *    passes the catalog clean; what throws is an oversized *request* attribute,
 *    which no validator sees. It is reproduced again from real Postgres through
 *    `IamDrizzleAdapter` in `e2e-verdict-pg-fallback.e2e.test.ts`, so it is not
 *    a memory-adapter artefact.
 *  - The condition-depth case needs a catalog `validateRole` rejects.
 *    `IamDrizzleAdapter` re-validates on read and drops the row, so that store
 *    contains it; `IamMemoryAdapter` does not, so that one does not.
 */
import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl, IamPrimitives } from '../../types'
import { validateRole } from '../../validate'
import { IamEngine } from '../engine'

const DISAGREE_MARKER = 'compiled table and interpreter disagree'

interface IVerdicts {
  production: boolean
  development: boolean
  developmentReason: string
  disagreements: string[]
}

/** Run one request through a production engine and a development engine over identical data. */
async function bothModes(
  roles: AccessControl.IRole[],
  policies: AccessControl.IPolicy[],
  assignments: Record<string, string[]>,
  attributes: Record<string, IamPrimitives.Attributes>,
  request: { subjectId: string; action: string; resource: string },
): Promise<IVerdicts> {
  const init = { assignments, attributes, policies, roles }
  const production = new IamEngine({ adapter: new IamMemoryAdapter(init), mode: 'production' })
  const disagreements: string[] = []
  const development = new IamEngine({
    adapter: new IamMemoryAdapter(init),
    hooks: {
      onError: (err) => {
        if (err.message.includes(DISAGREE_MARKER)) disagreements.push(err.message)
      },
    },
    mode: 'development',
  })

  const realError = console.error
  console.error = (...args: unknown[]) => {
    if (
      !args
        .map((a) => String(a))
        .join(' ')
        .includes(DISAGREE_MARKER)
    )
      realError(...args)
  }
  try {
    const prod = await production.can(request.subjectId, request.action, { attributes: {}, type: request.resource })
    const dev = await development.check(request.subjectId, request.action, { attributes: {}, type: request.resource })
    return { development: dev.allowed, developmentReason: dev.reason, disagreements, production: prod }
  } finally {
    console.error = realError
    production.dispose()
    development.dispose()
  }
}

/** `depth` nested `all` groups wrapped around one always-true leaf condition. */
function nestedAlwaysTrue(depth: number): AccessControl.IConditionGroup {
  let group: AccessControl.IConditionGroup = {
    all: [{ field: 'subject.attributes.level', operator: 'gte', value: 0 }],
  }
  for (let i = 1; i < depth; i++) group = { all: [group] }
  return group
}

describe('E2E verdict divergence: RBAC role permissions', () => {
  it('a VALID role permission whose condition throws on request data must not be short-circuited by an inherited grant', async () => {
    // The strongest form of the finding: nothing here is malformed.
    // `validateRole` reports zero issues on both roles (asserted below), the
    // `matches` operator is legal, and the pattern is not catastrophic. What
    // throws is the *request*: `subject.attributes.blob` is 3000 UTF-16 units,
    // over `MAX_REGEX_INPUT_LENGTH` (2048), so `ops.matches` raises
    // `IamRegexInputTooLargeError`. No validator can prevent that, because the
    // input is not in the catalog - and the codebase's own comments describe
    // padding an attribute as the attack this Indeterminate contract exists to
    // stop.
    //
    // Table:       `rbacVote()` tests the plain grant mask FIRST. `clean`'s
    //              unconditional permission set that bit and inheritance widened
    //              it to `rotten`'s holders, so it returns true before
    //              `rbacDynamic` - where the throwing permission lives, and whose
    //              catch resolves to `defaultEffect` = deny - is ever read.
    // Interpreter: `rolesToPolicy` folds every role permission into ONE
    //              `__rbac__` policy; `evaluatePolicy` walks all its rules, the
    //              throwing one raises, and `safeEval` resolves the whole policy
    //              Indeterminate -> `defaultEffect` = deny.
    const roles: AccessControl.IRole[] = [
      { id: 'clean', name: 'clean', permissions: [{ action: 'read', resource: 'doc' }] },
      {
        id: 'rotten',
        inherits: ['clean'],
        name: 'rotten',
        permissions: [
          {
            action: 'read',
            conditions: { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+b' }] },
            resource: 'doc',
          },
        ],
      },
    ]
    for (const role of roles) expect(validateRole(role).issues, `${role.id} must be a valid catalog`).toEqual([])

    const v = await bothModes(
      roles,
      [],
      { u1: ['rotten'] },
      { u1: { blob: 'a'.repeat(3000) } },
      {
        action: 'read',
        resource: 'doc',
        subjectId: 'u1',
      },
    )

    expect(v.disagreements, `table/interpreter disagreement: ${v.disagreements[0] ?? ''}`).toEqual([])
    expect(v.production, 'production and development must reach the same verdict').toBe(v.development)
  })

  it('a role permission whose condition THROWS must not be short-circuited by an inherited clean grant', async () => {
    // `rotten` inherits `clean`. Both declare `read doc`; `rotten`'s carries an
    // operator no `ops` entry answers to, so evaluating it throws.
    //
    // Table:       `rbacVote()` tests the plain grant mask FIRST. `clean`'s
    //              unconditional permission set that bit, and inheritance widened
    //              it to `rotten`'s holders, so the mask hits and returns true
    //              before `rbacDynamic` (where the rotten permission lives, and
    //              whose catch resolves to `defaultEffect` = deny) is ever read.
    // Interpreter: `rolesToPolicy` folds every role permission into ONE
    //              `__rbac__` policy, `evaluatePolicy` walks all its rules, the
    //              rotten one throws, and `safeEval` resolves the whole policy
    //              Indeterminate -> `defaultEffect` = deny.
    //
    // The two disagree, and production is the permissive side.
    const badOperator = 'no-such-operator' as AccessControl.Operator // deliberately malformed, as a store row can be
    const roles: AccessControl.IRole[] = [
      { id: 'clean', name: 'clean', permissions: [{ action: 'read', resource: 'doc' }] },
      {
        id: 'rotten',
        inherits: ['clean'],
        name: 'rotten',
        permissions: [
          {
            action: 'read',
            conditions: { all: [{ field: 'subject.attributes.level', operator: badOperator, value: 1 }] },
            resource: 'doc',
          },
        ],
      },
    ]

    const v = await bothModes(
      roles,
      [],
      { u1: ['rotten'] },
      { u1: { level: 3 } },
      {
        action: 'read',
        resource: 'doc',
        subjectId: 'u1',
      },
    )

    expect(v.disagreements, `table/interpreter disagreement: ${v.disagreements[0] ?? ''}`).toEqual([])
    expect(v.production, 'production and development must reach the same verdict').toBe(v.development)
  })

  it('a role permission condition nested exactly at MAX_CONDITION_DEPTH must mean the same thing to both paths', async () => {
    // `MAX_CONDITION_DEPTH` is 10 and `evalConditionGroup` fails closed at
    // `depth >= 10`. The two paths hand it the SAME group at DIFFERENT depths:
    //
    //   table:       `rbacVote()` -> evalConditionGroup(perm.conditions, 0)
    //   interpreter: `rolesToPolicy` wraps it as
    //                `{ all: [{ all: baseConditions }, perm.conditions] }`,
    //                so `ruleApplies` reaches the author's group at depth 1.
    //
    // The author therefore gets ten usable levels in production and nine in
    // development. At exactly ten the table allows and the interpreter denies.
    // Depths 8 and 9 agree (allow), depth 11 agrees (deny) - only the boundary
    // splits, which is why nothing hand-written caught it.
    //
    // Reachability, stated honestly: `validateRole` rejects ten nested groups,
    // and `IamDrizzleAdapter` re-runs that validator on every read and drops the
    // row (asserted in `e2e-verdict-pg-fallback.e2e.test.ts`). So this needs a
    // catalog that never went through the validator - which `IamMemoryAdapter`,
    // used here and shipped, accepts without complaint.
    for (const depth of [8, 9, 10, 11]) {
      const roles: AccessControl.IRole[] = [
        { id: 'r', name: 'r', permissions: [{ action: 'read', conditions: nestedAlwaysTrue(depth), resource: 'doc' }] },
      ]
      const v = await bothModes(
        roles,
        [],
        { u1: ['r'] },
        { u1: { level: 3 } },
        {
          action: 'read',
          resource: 'doc',
          subjectId: 'u1',
        },
      )
      expect(v.disagreements, `depth ${depth}: ${v.disagreements[0] ?? ''}`).toEqual([])
      expect(v.production, `depth ${depth}: production and development must agree`).toBe(v.development)
    }
  })

  it('the same throw inside an ABAC policy rule does NOT diverge (scoping the finding to RBAC)', async () => {
    // Control case. An identical rotten condition on a flat ABAC policy rule
    // lands in a DYNAMIC cell, and `evaluateDynamicCell`'s catch mirrors
    // `safeEval` exactly, so the two paths agree. That is what makes the two
    // failures above specific to the RBAC vote rather than to throwing
    // conditions in general - and it is the reason a fix belongs in
    // `rbacVote()` / `rolesToPolicy`, not in the condition evaluator.
    const badOperator = 'no-such-operator' as AccessControl.Operator // deliberately malformed
    const policies: AccessControl.IPolicy[] = [
      {
        algorithm: 'allow-overrides',
        id: 'p0',
        name: 'p0',
        rules: [
          { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r-ok', priority: 1, resources: ['doc'] },
          {
            actions: ['read'],
            conditions: { all: [{ field: 'subject.attributes.level', operator: badOperator, value: 1 }] },
            effect: 'allow',
            id: 'r-rotten',
            priority: 1,
            resources: ['doc'],
          },
        ],
      },
    ]
    const v = await bothModes(
      [],
      policies,
      { u1: [] },
      { u1: { level: 3 } },
      {
        action: 'read',
        resource: 'doc',
        subjectId: 'u1',
      },
    )
    expect(v.disagreements).toEqual([])
    expect(v.production).toBe(v.development)
  })
})
