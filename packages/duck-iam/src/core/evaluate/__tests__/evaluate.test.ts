import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine'
import type { IamAccessControl, IamRequest } from '../../types'
import { iamEvaluate, iamEvaluateFast, iamEvaluatePolicy, iamEvaluatePolicyFast } from '../evaluate'

function makeReq(overrides: Partial<IamRequest.IAccessRequest> = {}): IamRequest.IAccessRequest {
  return {
    subject: {
      id: 'user-1',
      roles: ['editor'],
      attributes: {},
    },
    action: 'read',
    resource: { type: 'post', id: 'post-1', attributes: {} },
    ...overrides,
  }
}

const allowReadPolicy: IamAccessControl.IPolicy = {
  id: 'allow-read',
  name: 'Allow Read',
  algorithm: 'deny-overrides',
  rules: [
    {
      id: 'r1',
      effect: 'allow',
      priority: 10,
      actions: ['read'],
      resources: ['post'],
      conditions: { all: [] },
    },
  ],
}

const denyDeletePolicy: IamAccessControl.IPolicy = {
  id: 'deny-delete',
  name: 'Deny Delete',
  algorithm: 'deny-overrides',
  rules: [
    {
      id: 'r-deny',
      effect: 'deny',
      priority: 10,
      actions: ['delete'],
      resources: ['post'],
      conditions: { all: [] },
    },
  ],
}

describe('evaluatePolicy()', () => {
  it('allows when a matching allow rule exists', () => {
    const decision = iamEvaluatePolicy(allowReadPolicy, makeReq())
    expect(decision.allowed).toBe(true)
    expect(decision.effect).toBe('allow')
  })

  it('falls to default when no rules match', () => {
    const decision = iamEvaluatePolicy(allowReadPolicy, makeReq({ action: 'delete' }))
    expect(decision.allowed).toBe(false)
    expect(decision.effect).toBe('deny')
  })

  it('deny-overrides: deny wins over allow', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'mixed',
      name: 'Mixed',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r-allow',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [] },
        },
        { id: 'r-deny', effect: 'deny', priority: 10, actions: ['read'], resources: ['post'], conditions: { all: [] } },
      ],
    }
    const decision = iamEvaluatePolicy(policy, makeReq())
    expect(decision.allowed).toBe(false)
    expect(decision.reason).toContain('r-deny')
  })

  it('allow-overrides: allow wins over deny', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'mixed',
      name: 'Mixed',
      algorithm: 'allow-overrides',
      rules: [
        { id: 'r-deny', effect: 'deny', priority: 10, actions: ['read'], resources: ['post'], conditions: { all: [] } },
        {
          id: 'r-allow',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [] },
        },
      ],
    }
    const decision = iamEvaluatePolicy(policy, makeReq())
    expect(decision.allowed).toBe(true)
  })

  it('first-match: uses first matching rule', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'first',
      name: 'First',
      algorithm: 'first-match',
      rules: [
        { id: 'r-deny', effect: 'deny', priority: 10, actions: ['read'], resources: ['post'], conditions: { all: [] } },
        {
          id: 'r-allow',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [] },
        },
      ],
    }
    const decision = iamEvaluatePolicy(policy, makeReq())
    expect(decision.allowed).toBe(false)
    expect(decision.reason).toContain('r-deny')
  })

  it('highest-priority: uses highest priority rule', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'priority',
      name: 'Priority',
      algorithm: 'highest-priority',
      rules: [
        { id: 'r-deny', effect: 'deny', priority: 5, actions: ['read'], resources: ['post'], conditions: { all: [] } },
        {
          id: 'r-allow',
          effect: 'allow',
          priority: 100,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [] },
        },
      ],
    }
    const decision = iamEvaluatePolicy(policy, makeReq())
    expect(decision.allowed).toBe(true)
    expect(decision.reason).toContain('r-allow')
  })

  it('respects policy targets: skips policy if action does not match targets', () => {
    const policy: IamAccessControl.IPolicy = {
      ...allowReadPolicy,
      targets: { actions: ['write'] },
    }
    const decision = iamEvaluatePolicy(policy, makeReq())
    // policy doesn't apply, falls to default (deny)
    expect(decision.allowed).toBe(false)
  })

  it('respects policy targets: skips policy if resource does not match targets', () => {
    const policy: IamAccessControl.IPolicy = {
      ...allowReadPolicy,
      targets: { resources: ['comment'] },
    }
    const decision = iamEvaluatePolicy(policy, makeReq())
    expect(decision.allowed).toBe(false)
  })

  it('respects policy targets: skips policy if role does not match targets', () => {
    const policy: IamAccessControl.IPolicy = {
      ...allowReadPolicy,
      targets: { roles: ['admin'] },
    }
    const decision = iamEvaluatePolicy(policy, makeReq())
    expect(decision.allowed).toBe(false)
  })

  it('conditions must pass for rule to match', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'cond',
      name: 'Conditional',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r-conditional',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'user-999' }] },
        },
      ],
    }
    const decision = iamEvaluatePolicy(policy, makeReq())
    expect(decision.allowed).toBe(false) // condition fails
  })

  it('wildcard actions match all', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'wildcard',
      name: 'Wildcard',
      algorithm: 'deny-overrides',
      rules: [
        { id: 'r-wild', effect: 'allow', priority: 10, actions: ['*'], resources: ['post'], conditions: { all: [] } },
      ],
    }
    expect(iamEvaluatePolicy(policy, makeReq({ action: 'anything' })).allowed).toBe(true)
  })

  it('wildcard resources match all', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'wildcard',
      name: 'Wildcard',
      algorithm: 'deny-overrides',
      rules: [
        { id: 'r-wild', effect: 'allow', priority: 10, actions: ['read'], resources: ['*'], conditions: { all: [] } },
      ],
    }
    expect(iamEvaluatePolicy(policy, makeReq({ resource: { type: 'anything', attributes: {} } })).allowed).toBe(true)
  })
})

describe('evaluate() - multi-policy', () => {
  it('no policies defaults to deny', () => {
    const decision = iamEvaluate([], makeReq())
    expect(decision.allowed).toBe(false)
    expect(decision.reason).toContain('No policies configured')
  })

  it('no policies defaults to allow when defaultEffect=allow', () => {
    const decision = iamEvaluate([], makeReq(), 'allow')
    expect(decision.allowed).toBe(true)
  })

  it('single policy evaluation', () => {
    const decision = iamEvaluate([allowReadPolicy], makeReq())
    expect(decision.allowed).toBe(true)
  })

  it('deny from any policy = overall deny (defense in depth)', () => {
    const decision = iamEvaluate([allowReadPolicy, denyDeletePolicy], makeReq({ action: 'delete' }))
    expect(decision.allowed).toBe(false)
  })

  it('includes timing information', () => {
    const decision = iamEvaluate([allowReadPolicy], makeReq())
    expect(decision.duration).toBeGreaterThanOrEqual(0)
    expect(decision.timestamp).toBeGreaterThan(0)
  })
})

describe('hierarchical resources in evaluation', () => {
  it('bare "dashboard" rule does NOT match dashboard.users (require dashboard.*)', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'hierarchy',
      name: 'Hierarchy',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['dashboard'],
          conditions: { all: [] },
        },
      ],
    }
    const req = makeReq({ resource: { type: 'dashboard.users', attributes: {} } })
    // Bare literal patterns do not parent-match sub-resources.
    expect(iamEvaluatePolicy(policy, req).allowed).toBe(false)
    // Exact literal still matches.
    expect(iamEvaluatePolicy(policy, makeReq({ resource: { type: 'dashboard', attributes: {} } })).allowed).toBe(true)
  })

  it('dot-based hierarchy: dashboard.* rule matches dashboard.users but not dashboard', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'hierarchy',
      name: 'Hierarchy',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['dashboard.*'],
          conditions: { all: [] },
        },
      ],
    }
    expect(iamEvaluatePolicy(policy, makeReq({ resource: { type: 'dashboard.users', attributes: {} } })).allowed).toBe(
      true,
    )
    expect(iamEvaluatePolicy(policy, makeReq({ resource: { type: 'dashboard', attributes: {} } })).allowed).toBe(false)
  })
})

describe('first-match priority order', () => {
  // Both rules match; the high-priority rule (declared second) must win regardless of source order.
  const priorityPolicy: IamAccessControl.IPolicy = {
    id: 'first-priority',
    name: 'First Priority',
    algorithm: 'first-match',
    rules: [
      {
        id: 'r-low-allow',
        effect: 'allow',
        priority: 1,
        actions: ['read'],
        resources: ['post'],
        conditions: { all: [] },
      },
      {
        id: 'r-high-deny',
        effect: 'deny',
        priority: 100,
        actions: ['read'],
        resources: ['post'],
        conditions: { all: [] },
      },
    ],
  }

  it('trace path: highest priority wins, not source order', () => {
    const decision = iamEvaluatePolicy(priorityPolicy, makeReq())
    expect(decision.allowed).toBe(false)
    expect(decision.rule?.id).toBe('r-high-deny')
    expect(decision.reason).toContain('r-high-deny')
  })

  it('fast path: highest priority wins, not source order', () => {
    expect(iamEvaluatePolicyFast(priorityPolicy, makeReq())).toBe(false)
  })

  it('precomputed cache: highest priority wins on unconditional rules', () => {
    // Two unconditional rules -> precomputed cache fires (no wildcards, no conditions).
    // Both paths share iamIndexPolicy()'s WeakMap, so the same lookup must respect priority.
    const policy: IamAccessControl.IPolicy = {
      id: 'precomp',
      name: 'Precomp',
      algorithm: 'first-match',
      rules: [
        {
          id: 'r-low-deny',
          effect: 'deny',
          priority: 1,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [] },
        },
        {
          id: 'r-high-allow',
          effect: 'allow',
          priority: 50,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [] },
        },
      ],
    }
    expect(iamEvaluatePolicyFast(policy, makeReq())).toBe(true)
  })

  it('ties preserve source order (stable selection)', () => {
    // Equal priority -> earlier rule wins. Mirrors evaluate.test.ts:106 behavior.
    const policy: IamAccessControl.IPolicy = {
      id: 'first-tie',
      name: 'First Tie',
      algorithm: 'first-match',
      rules: [
        { id: 'r-deny', effect: 'deny', priority: 10, actions: ['read'], resources: ['post'], conditions: { all: [] } },
        {
          id: 'r-allow',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [] },
        },
      ],
    }
    expect(iamEvaluatePolicy(policy, makeReq()).rule?.id).toBe('r-deny')
    expect(iamEvaluatePolicyFast(policy, makeReq())).toBe(false)
  })
})

describe('fast path: expansive action/resource patterns route via wildcardAny', () => {
  // Colon-prefix actions like 'posts:*' must route through wildcardAny so the
  // fast path matches a request like { action: 'posts:read', resource: 'post' }.
  const colonActionPolicy: IamAccessControl.IPolicy = {
    id: 'colon-action',
    name: 'Colon Action',
    algorithm: 'deny-overrides',
    rules: [
      { id: 'r1', effect: 'allow', priority: 10, actions: ['posts:*'], resources: ['post'], conditions: { all: [] } },
    ],
  }

  it('fast path matches "posts:*" against "posts:read"', () => {
    expect(iamEvaluatePolicyFast(colonActionPolicy, makeReq({ action: 'posts:read' }))).toBe(true)
  })

  it('trace path matches "posts:*" against "posts:read"', () => {
    expect(iamEvaluatePolicy(colonActionPolicy, makeReq({ action: 'posts:read' })).allowed).toBe(true)
  })

  it('fast path matches "dashboard.*" resource against "dashboard.users"', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'dot-resource',
      name: 'Dot IamRequest.IResource',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['dashboard.*'],
          conditions: { all: [] },
        },
      ],
    }
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'dashboard.users', attributes: {} } }))).toBe(true)
  })

  it('fast path matches "org:*" resource against "org:project"', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'colon-resource',
      name: 'Colon IamRequest.IResource',
      algorithm: 'deny-overrides',
      rules: [
        { id: 'r1', effect: 'allow', priority: 10, actions: ['read'], resources: ['org:*'], conditions: { all: [] } },
      ],
    }
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'org:project', attributes: {} } }))).toBe(true)
  })
})

describe('NotApplicable semantics', () => {
  // A policy whose targets don't match the request is NotApplicable
  // (`applicable: false`) and must be skipped by the combiner, not folded as
  // the default effect.
  const allowReadAnywhere: IamAccessControl.IPolicy = {
    id: 'allow-read-anywhere',
    name: 'Allow Read Anywhere',
    algorithm: 'deny-overrides',
    rules: [{ id: 'r1', effect: 'allow', priority: 10, actions: ['read'], resources: ['*'], conditions: { all: [] } }],
  }
  const writesAuditPolicy: IamAccessControl.IPolicy = {
    id: 'audit-writes',
    name: 'Audit Writes',
    algorithm: 'deny-overrides',
    targets: { actions: ['create' as const, 'update' as const, 'delete' as const] },
    rules: [
      { id: 'r-audit', effect: 'allow', priority: 10, actions: ['*'], resources: ['*'], conditions: { all: [] } },
    ],
  }

  it('evaluate: AND combine skips NotApplicable policies', () => {
    // Read request: audit-writes targets only writes -> NotApplicable -> must NOT
    // contribute the default-deny that would have short-circuited the chain.
    expect(iamEvaluate([allowReadAnywhere, writesAuditPolicy], makeReq()).allowed).toBe(true)
  })

  it('evaluate: all NotApplicable falls through to default', () => {
    // Both policies NotApplicable (target only writes); no policy contributes -> default.
    expect(iamEvaluate([writesAuditPolicy], makeReq()).effect).toBe('deny')
    expect(iamEvaluate([writesAuditPolicy], makeReq(), 'allow').effect).toBe('allow')
  })

  it('evaluateFast: AND combine skips NotApplicable policies', () => {
    expect(iamEvaluateFast([allowReadAnywhere, writesAuditPolicy], makeReq())).toBe(true)
  })

  it('evaluatePolicy marks NotApplicable decisions', () => {
    const decision = iamEvaluatePolicy(writesAuditPolicy, makeReq())
    expect(decision.applicable).toBe(false)
  })

  it('evaluatePolicyFast returns null for NotApplicable', () => {
    expect(iamEvaluatePolicyFast(writesAuditPolicy, makeReq())).toBe(null)
  })
})

describe('cross-policy combine', () => {
  const allowPolicy: IamAccessControl.IPolicy = {
    id: 'allow',
    name: 'Allow',
    algorithm: 'deny-overrides',
    rules: [
      { id: 'r1', effect: 'allow', priority: 10, actions: ['read'], resources: ['post'], conditions: { all: [] } },
    ],
  }
  const denyPolicy: IamAccessControl.IPolicy = {
    id: 'deny',
    name: 'Deny',
    algorithm: 'deny-overrides',
    rules: [
      { id: 'r1', effect: 'deny', priority: 10, actions: ['read'], resources: ['post'], conditions: { all: [] } },
    ],
  }

  it('"and" (default): any deny denies overall', () => {
    expect(iamEvaluate([allowPolicy, denyPolicy], makeReq(), 'deny', 'and').allowed).toBe(false)
    expect(iamEvaluateFast([allowPolicy, denyPolicy], makeReq(), 'deny', 'and')).toBe(false)
  })

  it('"and": all allow -> allow', () => {
    expect(iamEvaluate([allowPolicy, allowPolicy], makeReq(), 'deny', 'and').allowed).toBe(true)
    expect(iamEvaluateFast([allowPolicy, allowPolicy], makeReq(), 'deny', 'and')).toBe(true)
  })

  it('"allow-overrides": any allow allows overall', () => {
    expect(iamEvaluate([denyPolicy, allowPolicy], makeReq(), 'deny', 'allow-overrides').allowed).toBe(true)
    expect(iamEvaluateFast([denyPolicy, allowPolicy], makeReq(), 'deny', 'allow-overrides')).toBe(true)
  })

  it('"allow-overrides": all deny -> deny', () => {
    expect(iamEvaluate([denyPolicy, denyPolicy], makeReq(), 'deny', 'allow-overrides').allowed).toBe(false)
    expect(iamEvaluateFast([denyPolicy, denyPolicy], makeReq(), 'deny', 'allow-overrides')).toBe(false)
  })

  it('"first-applicable": first decided policy wins', () => {
    // Both policies match - the first one (allow) wins under first-applicable.
    expect(iamEvaluate([allowPolicy, denyPolicy], makeReq(), 'deny', 'first-applicable').allowed).toBe(true)
    // Reverse order: deny wins.
    expect(iamEvaluate([denyPolicy, allowPolicy], makeReq(), 'deny', 'first-applicable').allowed).toBe(false)
  })

  it('"first-applicable" falls through to default when no rule fires', () => {
    const noMatchPolicy: IamAccessControl.IPolicy = {
      id: 'nomatch',
      name: 'NoMatch',
      algorithm: 'deny-overrides',
      rules: [
        { id: 'r1', effect: 'allow', priority: 10, actions: ['write'], resources: ['post'], conditions: { all: [] } },
      ],
    }
    expect(iamEvaluate([noMatchPolicy], makeReq(), 'deny', 'first-applicable').allowed).toBe(false)
    expect(iamEvaluate([noMatchPolicy], makeReq(), 'allow', 'first-applicable').allowed).toBe(true)
  })
})

describe('fast path: literal-only resource patterns', () => {
  // Bare literal patterns must NOT match sub-resources. Authors that want
  // recursive grants must use `:*` / `.*` explicitly.

  it('colon: bare "org" only matches request "org"', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'parent-colon',
      name: 'Parent Colon',
      algorithm: 'deny-overrides',
      rules: [
        { id: 'r1', effect: 'allow', priority: 10, actions: ['read'], resources: ['org'], conditions: { all: [] } },
      ],
    }
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'org:project', attributes: {} } }))).toBe(false)
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'org:project:doc', attributes: {} } }))).toBe(false)
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'org', attributes: {} } }))).toBe(true)
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'other', attributes: {} } }))).toBe(false)
  })

  it('colon: explicit "org:*" matches sub-resources', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'wild-colon',
      name: 'Wild Colon',
      algorithm: 'deny-overrides',
      rules: [
        { id: 'r1', effect: 'allow', priority: 10, actions: ['read'], resources: ['org:*'], conditions: { all: [] } },
      ],
    }
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'org:project', attributes: {} } }))).toBe(true)
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'org:project:doc', attributes: {} } }))).toBe(true)
  })

  it('dot: bare "dashboard" only matches request "dashboard"', () => {
    const policy: IamAccessControl.IPolicy = {
      id: 'parent-dot',
      name: 'Parent Dot',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['dashboard'],
          conditions: { all: [] },
        },
      ],
    }
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'dashboard.users', attributes: {} } }))).toBe(false)
    expect(
      iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'dashboard.users.settings', attributes: {} } })),
    ).toBe(false)
    expect(iamEvaluatePolicyFast(policy, makeReq({ resource: { type: 'dashboard', attributes: {} } }))).toBe(true)
  })
})

describe('policy targets: dot-pattern resources', () => {
  // Regression: when `iamMatchesResource` was tightened to literal-only for
  // bare patterns, `policyApplies` / `policyTargetsMatch` silently failed
  // for dot-wildcard targets like `dashboard.*`. `iamMatchesResource` must
  // handle both `:*` and `.*` suffixes.
  const dotTargetPolicy: IamAccessControl.IPolicy = {
    id: 'dot-targets',
    name: 'Dot Targets',
    algorithm: 'deny-overrides',
    targets: { resources: ['dashboard.*'] },
    rules: [{ id: 'r1', effect: 'allow', priority: 10, actions: ['*'], resources: ['*'], conditions: { all: [] } }],
  }

  it('policy with target "dashboard.*" applies to "dashboard.users"', () => {
    const decision = iamEvaluatePolicy(
      dotTargetPolicy,
      makeReq({ resource: { type: 'dashboard.users', id: 'u1', attributes: {} } }),
    )
    // `applicable` is left undefined on the success path; only NotApplicable
    // decisions set it to `false`.
    expect(decision.applicable).not.toBe(false)
    expect(decision.allowed).toBe(true)
  })

  it('policy with bare target "dashboard" does NOT apply to "dashboard.users"', () => {
    const policy: IamAccessControl.IPolicy = {
      ...dotTargetPolicy,
      id: 'bare-target',
      targets: { resources: ['dashboard'] },
    }
    const decision = iamEvaluatePolicy(
      policy,
      makeReq({ resource: { type: 'dashboard.users', id: 'u1', attributes: {} } }),
    )
    expect(decision.applicable).toBe(false)
  })

  it('policy with target "dashboard.*" still does not apply to bare "dashboard"', () => {
    const decision = iamEvaluatePolicy(
      dotTargetPolicy,
      makeReq({ resource: { type: 'dashboard', id: 'd', attributes: {} } }),
    )
    expect(decision.applicable).toBe(false)
  })

  it('colon-wildcard target continues to work (regression check)', () => {
    const policy: IamAccessControl.IPolicy = {
      ...dotTargetPolicy,
      id: 'colon-target',
      targets: { resources: ['org:billing:*'] },
    }
    const decision = iamEvaluatePolicy(
      policy,
      makeReq({ resource: { type: 'org:billing:invoice', id: 'i', attributes: {} } }),
    )
    expect(decision.applicable).not.toBe(false)
    expect(decision.allowed).toBe(true)
  })
})

describe('allowFailOpen enforcement (P0)', () => {
  // Regression: the engine previously refused defaultEffect: 'allow' only in
  // production. Development engines could ship with the same fail-open behavior
  // and silently mask dropped policies. Enforcement is now mode-independent.
  it("refuses defaultEffect: 'allow' in development without allowFailOpen", () => {
    const adapter = new IamMemoryAdapter()
    expect(() => new IamEngine({ adapter, mode: 'development', defaultEffect: 'allow' })).toThrow(/fail-open/i)
  })

  it("refuses defaultEffect: 'allow' in production without allowFailOpen", () => {
    const adapter = new IamMemoryAdapter()
    expect(() => new IamEngine({ adapter, mode: 'production', defaultEffect: 'allow' } as never)).toThrow(/fail-open/i)
  })

  it("accepts defaultEffect: 'allow' in any mode with allowFailOpen: true", () => {
    const adapter = new IamMemoryAdapter()
    expect(
      () => new IamEngine({ adapter, mode: 'development', defaultEffect: 'allow', allowFailOpen: true }),
    ).not.toThrow()
  })
})
