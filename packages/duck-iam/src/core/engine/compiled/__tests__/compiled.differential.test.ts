import { describe, expect, it } from 'vitest'
import { evaluate, evaluateFast } from '../../../evaluate'
import { rolesToPolicy } from '../../../rbac'
import type { AccessControl, IamPrimitives, IamRequest } from '../../../types'
import { CellKind, compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'

function req(
  subjectRoles: string[],
  action: string,
  resource: string,
  attributes: IamPrimitives.Attributes = {},
): IamRequest.IAccessRequest {
  return {
    subject: { id: 'u1', roles: subjectRoles, attributes: {} },
    action,
    resource: { type: resource, attributes },
    environment: { now: 1 },
  }
}

function maskOf(table: ReturnType<typeof compileTable>, roleIds: string[]): number {
  let m = 0
  for (const id of roleIds) {
    const i = table.roleId.get(id)
    if (i !== undefined) m |= 1 << i
  }
  return m
}

describe('differential: isWildcard fix - action/resource prefix patterns are not silently inert', () => {
  const policies: AccessControl.IPolicy[] = [
    {
      id: 'post-admin',
      name: 'Post Admin',
      algorithm: 'deny-overrides',
      rules: [
        { id: 'r', effect: 'allow', priority: 0, actions: ['post:*'], resources: ['thing'], conditions: { all: [] } },
      ],
    },
  ]

  it('routes to residual (not inert): matching action votes allow, matching evaluate()', () => {
    const t = compileTable([], policies, 'and')
    expect(t.residualPolicies.map((p) => p.id)).toContain('post-admin')

    const matching = req([], 'post:create', 'thing')
    const got = lookup(t, 0, 'post:create', 'thing', matching, 'deny')
    expect(got).toBe(true)
    expect(got).toBe(evaluate(policies, matching, 'deny', 'and').allowed)
  })

  // `evaluatePolicyFast`'s `matchCandidate` (packages/duck-iam/src/core/evaluate/evaluate.ts,
  // out of scope for this task) skips the action-match check entirely whenever the rule's own
  // action pattern is expansive (`hasWildcardAction`), instead of verifying the `:*` prefix -
  // so a wildcard-action rule matches ANY action there, not just the declared prefix. This is
  // a pre-existing bug independent of this task (`evaluate()` gets it right; `evaluateFast()` /
  // `evaluatePolicyFast()` do not), so the residual path - which the brief mandates delegating
  // to `evaluatePolicyFast` - inherits it. Oracle here is `evaluateFast()`, which is what
  // `lookup()` is actually built on for residual votes; see the task report for detail.
  it('non-matching action still routes through the residual policy (not silently inert), matching evaluateFast()', () => {
    const t = compileTable([], policies, 'and')
    const nonMatching = req([], 'comment:create', 'thing')
    const got = lookup(t, 0, 'comment:create', 'thing', nonMatching, 'deny')
    expect(got).toBe(evaluateFast(policies, nonMatching, 'deny', 'and'))
  })

  it('resource prefix pattern (org.*) also routes to residual; matching request agrees with evaluate()', () => {
    const resPolicies: AccessControl.IPolicy[] = [
      {
        id: 'org-admin',
        name: 'Org Admin',
        algorithm: 'deny-overrides',
        rules: [
          { id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['org.*'], conditions: { all: [] } },
        ],
      },
    ]
    const t = compileTable([], resPolicies, 'and')
    expect(t.residualPolicies.map((p) => p.id)).toContain('org-admin')

    const matching = req([], 'read', 'org.team')
    expect(lookup(t, 0, 'read', 'org.team', matching, 'deny')).toBe(true)
    expect(lookup(t, 0, 'read', 'org.team', matching, 'deny')).toBe(
      evaluate(resPolicies, matching, 'deny', 'and').allowed,
    )

    // Same pre-existing evaluatePolicyFast quirk as above, this time for a resource pattern -
    // oracle is evaluateFast(), not evaluate().
    const nonMatching = req([], 'read', 'billing')
    const got = lookup(t, 0, 'read', 'billing', nonMatching, 'deny')
    expect(got).toBe(evaluateFast(resPolicies, nonMatching, 'deny', 'and'))
  })
})

describe('differential: role scope/conditions fix - not unconditionally granted', () => {
  it('a permission with conditions is denied when the condition fails, allowed when it passes', () => {
    const roles: AccessControl.IRole[] = [
      {
        id: 'owner',
        name: 'Owner',
        permissions: [
          {
            action: 'update',
            resource: 'post',
            conditions: { all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }] },
          },
        ],
      },
    ]
    const t = compileTable(roles, [], 'and')
    const mask = maskOf(t, ['owner'])

    const oraclePolicies = [rolesToPolicy(roles)]
    const failing = req(['owner'], 'update', 'post', { ownerId: 'someone-else' })
    expect(lookup(t, mask, 'update', 'post', failing, 'deny')).toBe(false)
    expect(lookup(t, mask, 'update', 'post', failing, 'deny')).toBe(
      evaluate(oraclePolicies, failing, 'deny', 'and').allowed,
    )

    const passing = req(['owner'], 'update', 'post', { ownerId: 'u1' })
    expect(lookup(t, mask, 'update', 'post', passing, 'deny')).toBe(true)
    expect(lookup(t, mask, 'update', 'post', passing, 'deny')).toBe(
      evaluate(oraclePolicies, passing, 'deny', 'and').allowed,
    )
  })

  it('a permission with a scope is denied when the request scope differs, allowed when it matches', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'org-admin', name: 'Org Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-1' }] },
    ]
    const t = compileTable(roles, [], 'and')
    const mask = maskOf(t, ['org-admin'])

    const wrongScope: IamRequest.IAccessRequest = {
      subject: { id: 'u1', roles: ['org-admin'], attributes: {} },
      action: 'update',
      resource: { type: 'org', attributes: {} },
      scope: 'org-2',
      environment: { now: 1 },
    }
    expect(lookup(t, mask, 'update', 'org', wrongScope, 'deny')).toBe(false)

    const rightScope: IamRequest.IAccessRequest = { ...wrongScope, scope: 'org-1' }
    expect(lookup(t, mask, 'update', 'org', rightScope, 'deny')).toBe(true)
  })
})

describe("differential: 'and'-mode soundness - a co-located but irrelevant policy no longer wrongly grants", () => {
  // Two untargeted ABAC policies: 'grantable' has a rule at this cell, 'irrelevant' has none
  // at all. Under 'and', an absent-but-applicable policy votes defaultEffect (deny here) - so
  // the request must be denied, even though 'grantable' alone would allow it.
  const grantable: AccessControl.IPolicy = {
    id: 'grantable',
    name: 'Grantable',
    algorithm: 'allow-overrides',
    rules: [{ id: 'g', effect: 'allow', priority: 0, actions: ['read'], resources: ['doc'], conditions: { all: [] } }],
  }
  const irrelevant: AccessControl.IPolicy = {
    id: 'irrelevant',
    name: 'Irrelevant',
    algorithm: 'allow-overrides',
    rules: [
      { id: 'i', effect: 'allow', priority: 0, actions: ['write'], resources: ['other'], conditions: { all: [] } },
    ],
  }

  it("lookup() agrees with evaluate(..., 'and') - both deny, where the old flat model would have wrongly allowed", () => {
    const t = compileTable([], [grantable, irrelevant], 'and')
    const request = req([], 'read', 'doc')
    const oracle = evaluate([grantable, irrelevant], request, 'deny', 'and')
    expect(oracle.allowed).toBe(false)
    expect(lookup(t, 0, 'read', 'doc', request, 'deny')).toBe(oracle.allowed)
  })

  it('the same two policies under allow-overrides still allow (no regression)', () => {
    const t = compileTable([], [grantable, irrelevant], 'allow-overrides')
    const request = req([], 'read', 'doc')
    const oracle = evaluate([grantable, irrelevant], request, 'deny', 'allow-overrides')
    expect(oracle.allowed).toBe(true)
    expect(lookup(t, 0, 'read', 'doc', request, 'deny')).toBe(oracle.allowed)
  })

  it('RBAC-plus-one-ABAC-policy variant (foldRbacIntoAnd): role grant alone no longer bypasses the irrelevant policy', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'editor', name: 'Editor', permissions: [{ action: 'update', resource: 'post' }] },
    ]
    const t = compileTable(roles, [irrelevant], 'and')
    expect(t.foldRbacIntoAnd).toBe(true)

    const mask = maskOf(t, ['editor'])
    const request = req(['editor'], 'update', 'post')
    const oracle = evaluate([rolesToPolicy(roles), irrelevant], request, 'deny', 'and')
    // Ground truth: the RBAC-equivalent grant is mandatory-voted alongside 'irrelevant', which
    // has zero rules at this cell and votes defaultEffect ('deny') under 'and'.
    expect(oracle.allowed).toBe(false)
    expect(lookup(t, mask, 'update', 'post', request, 'deny')).toBe(oracle.allowed)
  })

  it('RBAC-plus-one-ABAC-policy: role grant DOES apply when the other policy is also applicable-and-allowing here', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'editor', name: 'Editor', permissions: [{ action: 'update', resource: 'post' }] },
    ]
    const coApplicable: AccessControl.IPolicy = {
      id: 'co',
      name: 'Co',
      algorithm: 'allow-overrides',
      rules: [
        { id: 'c', effect: 'allow', priority: 0, actions: ['update'], resources: ['post'], conditions: { all: [] } },
      ],
    }
    const t = compileTable(roles, [coApplicable], 'and')
    expect(t.foldRbacIntoAnd).toBe(true)
    const mask = maskOf(t, ['editor'])
    const request = req(['editor'], 'update', 'post')
    const oracle = evaluate([rolesToPolicy(roles), coApplicable], request, 'deny', 'and')
    expect(oracle.allowed).toBe(true)
    expect(lookup(t, mask, 'update', 'post', request, 'deny')).toBe(oracle.allowed)
  })
})

describe("differential: 'allow-overrides' mode - zero behavior change", () => {
  const roles: AccessControl.IRole[] = [
    { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
    { id: 'editor', name: 'Editor', inherits: ['viewer'], permissions: [{ action: 'update', resource: 'post' }] },
  ]
  const policies: AccessControl.IPolicy[] = [
    {
      id: 'public',
      name: 'Public',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'pub-read',
          effect: 'allow',
          priority: 0,
          actions: ['read'],
          resources: ['comment'],
          conditions: { all: [] },
        },
      ],
    },
    {
      id: 'deny-dangerous',
      name: 'Deny Dangerous',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'deny-delete-user',
          effect: 'deny',
          priority: 0,
          actions: ['delete'],
          resources: ['user'],
          conditions: { all: [] },
        },
      ],
    },
  ]
  const table = compileTable(roles, policies, 'allow-overrides')

  it('ROLE_MASK cell agrees with evaluate()', () => {
    const mask = maskOf(table, ['viewer'])
    const request = req(['viewer'], 'read', 'post')
    expect(lookup(table, mask, 'read', 'post', request, 'deny')).toBe(true)
  })

  it('CONST_ALLOW cell agrees with evaluate()', () => {
    const request = req([], 'read', 'comment')
    const got = lookup(table, 0, 'read', 'comment', request, 'deny')
    expect(got).toBe(true)
    expect(got).toBe(evaluate(policies, request, 'deny', 'allow-overrides').allowed)
  })

  it('CONST_DENY cell agrees with evaluate()', () => {
    const request = req([], 'delete', 'user')
    const got = lookup(table, 0, 'delete', 'user', request, 'deny')
    expect(got).toBe(false)
    expect(got).toBe(evaluate(policies, request, 'deny', 'allow-overrides').allowed)
  })

  it('untouched cell falls back to defaultEffect', () => {
    const request = req([], 'update', 'comment')
    const got = lookup(table, 0, 'update', 'comment', request, 'deny')
    expect(got).toBe(false)
    expect(got).toBe(evaluate(policies, request, 'deny', 'allow-overrides').allowed)
  })
})

describe('differential: residual policies (targets + wildcard rules) agree with evaluate()', () => {
  const targeted: AccessControl.IPolicy = {
    id: 'admin-only',
    name: 'Admin Only',
    algorithm: 'allow-overrides',
    targets: { roles: ['admin'] },
    rules: [
      { id: 'r', effect: 'allow', priority: 0, actions: ['purge'], resources: ['cache'], conditions: { all: [] } },
    ],
  }
  const wildcardRule: AccessControl.IPolicy = {
    id: 'wild',
    name: 'Wild',
    algorithm: 'allow-overrides',
    rules: [
      { id: 'w', effect: 'allow', priority: 0, actions: ['view:*'], resources: ['report'], conditions: { all: [] } },
    ],
  }

  it('targets-scoped policy: applies for a matching role, agrees with evaluate()', () => {
    const t = compileTable([], [targeted], 'and')
    expect(t.residualPolicies.map((p) => p.id)).toContain('admin-only')
    const request = req(['admin'], 'purge', 'cache')
    const got = lookup(t, 0, 'purge', 'cache', request, 'deny')
    expect(got).toBe(true)
    expect(got).toBe(evaluate([targeted], request, 'deny', 'and').allowed)
  })

  it("targets-scoped policy: doesn't apply for a non-matching role, agrees with evaluate()", () => {
    const t = compileTable([], [targeted], 'and')
    const request = req(['guest'], 'purge', 'cache')
    const got = lookup(t, 0, 'purge', 'cache', request, 'deny')
    expect(got).toBe(false)
    expect(got).toBe(evaluate([targeted], request, 'deny', 'and').allowed)
  })

  it('wildcard-rule policy: matching action, agrees with evaluate()', () => {
    const t = compileTable([], [wildcardRule], 'and')
    const request = req([], 'view:summary', 'report')
    const got = lookup(t, 0, 'view:summary', 'report', request, 'deny')
    expect(got).toBe(true)
    expect(got).toBe(evaluate([wildcardRule], request, 'deny', 'and').allowed)
  })

  // Same pre-existing evaluatePolicyFast wildcard-action quirk documented above - oracle is
  // evaluateFast(), which is what the residual path is actually built on.
  it('wildcard-rule policy: non-matching action, agrees with evaluateFast()', () => {
    const t = compileTable([], [wildcardRule], 'and')
    const request = req([], 'edit:summary', 'report')
    const got = lookup(t, 0, 'edit:summary', 'report', request, 'deny')
    expect(got).toBe(evaluateFast([wildcardRule], request, 'deny', 'and'))
  })
})

describe('differential: untouched/unknown-cell constant-vote behavior', () => {
  const policies: AccessControl.IPolicy[] = [
    {
      id: 'p',
      name: 'p',
      algorithm: 'allow-overrides',
      rules: [
        { id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['doc'], conditions: { all: [] } },
      ],
    },
  ]

  it('unknown action/resource votes the constant defaultEffect, matching evaluate()', () => {
    const t = compileTable([], policies, 'and')
    const denyRequest = req([], 'unknown-action', 'unknown-resource')
    expect(lookup(t, 0, 'unknown-action', 'unknown-resource', denyRequest, 'deny')).toBe(false)
    expect(lookup(t, 0, 'unknown-action', 'unknown-resource', denyRequest, 'allow')).toBe(true)
    expect(lookup(t, 0, 'unknown-action', 'unknown-resource', denyRequest, 'deny')).toBe(
      evaluate(policies, denyRequest, 'deny', 'and').allowed,
    )
  })

  it('a table with no flat source at all (only residual policies) still answers definitively', () => {
    const targetedOnly: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['read'] } }]
    const t = compileTable([], targetedOnly, 'and')
    expect(t.hasFlatSource).toBe(false)
    const request = req([], 'read', 'doc')
    const got = lookup(t, 0, 'read', 'doc', request, 'deny')
    expect(got).toBe(true)
    expect(got).toBe(evaluate(targetedOnly, request, 'deny', 'and').allowed)
  })
})

describe('CellKind sanity', () => {
  it('re-exports CellKind for direct kind assertions', () => {
    expect(CellKind.CONST_DENY).toBe(0)
    expect(CellKind.CONST_ALLOW).toBe(1)
    expect(CellKind.ROLE_MASK).toBe(2)
    expect(CellKind.DYNAMIC).toBe(3)
  })
})
