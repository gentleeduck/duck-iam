// Table/interpreter parity on RBAC role permissions: both paths must agree, and on a named verdict.
// An unevaluable RBAC grant contributes nothing; the ABAC control denies because that policy is Indeterminate.
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

/** Asserts the two paths agree and on `expected`, since two deny-everything engines would also agree. */
function expectAgreedVerdict(v: IVerdicts, expected: boolean, label: string): void {
  expect(v.disagreements, `${label}: table/interpreter disagreement: ${v.disagreements[0] ?? ''}`).toEqual([])
  expect(v.production, `${label}: production and development must reach the same verdict`).toBe(v.development)
  expect(v.production, `${label}: the agreed verdict itself`).toBe(expected)
}

describe('E2E verdict divergence: RBAC role permissions', () => {
  it('a VALID role permission whose condition throws on request data must not be short-circuited by an inherited grant', async () => {
    // The catalog is valid; the request throws, because a 3000-unit `blob` exceeds `MAX_REGEX_INPUT_LENGTH` (2048).
    // SECURITY: no validator sees request data, and padding an attribute is attacker-reachable.
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

    // RBAC grants are additive, so the unevaluable grant adds nothing and cannot cancel the inherited `clean` grant.
    // SECURITY: denying here would let anyone revoke access by padding an attribute past the regex cap.
    expectAgreedVerdict(v, true, 'oversized request attribute')
  })

  it('a role permission whose condition THROWS must not be short-circuited by an inherited clean grant', async () => {
    // `rotten` inherits `clean`; its own `read doc` uses an operator no `ops` entry answers to, so it throws.
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

    // Allow, as above: an unevaluable grant cannot revoke the unconditional inherited one.
    expectAgreedVerdict(v, true, 'unknown operator')
  })

  it('a role permission condition nested exactly at MAX_CONDITION_DEPTH must mean the same thing to both paths', async () => {
    // `evalConditionGroup` fails closed at `depth >= MAX_CONDITION_DEPTH` (10); both paths must reach it equally.
    // `validateRole` rejects ten nested groups, but `IamMemoryAdapter` accepts an unvalidated catalog.
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
      // Under the cap the always-true leaf grants; at or over it the permission cannot apply.
      expectAgreedVerdict(v, depth < 10, `depth ${depth}`)
    }
  })

  it('the same throw inside an ABAC policy rule does NOT diverge (scoping the finding to RBAC)', async () => {
    // Control: an ABAC policy may carry deny rules, so a throwing rule leaves it Indeterminate on both paths - deny.
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
    expectAgreedVerdict(v, false, 'ABAC control')
  })
})
