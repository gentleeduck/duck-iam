import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../../adapters/memory'
import { iamBuildPermissionKey } from '../../../../shared/keys'
import { REGEX_CACHE_MAX } from '../../../conditions/conditions.libs'
import type { AccessControl, IamPrimitives, IamRequest } from '../../../types'
import { IamEngine } from '../../engine'
import { compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'

// Boundary + error-handling-path coverage for the compiled table, additive to
// compiled.engine-wiring.test.ts / compiled.compile.test.ts / compiled.differential.test.ts.
// Does NOT re-test what those files already cover (mixed simple+residual RBAC on one
// role, >32 roles failing closed, invalidation rebuilding the table, the stale
// in-flight-table race, the RBAC-residual-abstain regression) - see each section below
// for exactly what is new.

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

/** Long enough to trip MAX_REGEX_INPUT_LENGTH (2048) and make the `matches` operator throw. */
const OVERSIZED = 'a'.repeat(4096)

// ---------------------------------------------------------------------------------------
// 1. Boundary role counts
// ---------------------------------------------------------------------------------------

describe('boundary: 0 roles - no RBAC source at all', () => {
  it('hasRbacSource is false for an empty role list (compileTable)', () => {
    const t = compileTable([], [], 'and')
    expect(t.hasRbacSource).toBe(false)
  })

  it('RBAC casts no vote at all (not even a defaultEffect vote) - distinct from voting defaultEffect', () => {
    // ABAC votes a real, unconditional `true` (CONST_ALLOW) at this exact cell. If RBAC
    // wrongly cast its own defaultEffect=false vote instead of abstaining (hasRbacSource
    // false), 'and' would flip this to false despite the ABAC allow.
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
    const t = compileTable([], policies, 'and')
    expect(t.hasRbacSource).toBe(false)
    const request = req([], 'read', 'doc')
    expect(lookup(t, 0, 'read', 'doc', request, 'deny')).toBe(true)
  })
})

describe('boundary: exactly 1 role', () => {
  it('the sole role holder is granted, a non-holder of any role is denied', async () => {
    const roles: AccessControl.IRole[] = [
      { id: 'only-role', name: 'Only Role', permissions: [{ action: 'read', resource: 'doc' }] },
    ]
    const adapter = new IamMemoryAdapter({
      roles,
      policies: [],
      assignments: { holder: ['only-role'], stranger: [] },
      attributes: { holder: {}, stranger: {} },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    const resource = { type: 'doc', attributes: {} }
    expect(await production.can('holder', 'read', resource)).toBe(true)
    expect(await production.can('stranger', 'read', resource)).toBe(false)
  })
})

describe('boundary: exactly 32 roles - role index 31 (the sign-bit case, `1 << 31` is negative in JS)', () => {
  it("role 31's grant round-trips true for its sole holder, and false for a subject holding every other role", async () => {
    const roles: AccessControl.IRole[] = Array.from({ length: 32 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: i === 31 ? [{ action: 'read', resource: 'secret31' }] : [],
    }))
    const allButLast = roles.slice(0, 31).map((r) => r.id)
    const adapter = new IamMemoryAdapter({
      roles,
      policies: [],
      assignments: { holder31: ['role-31'], holder0to30: allButLast },
      attributes: { holder31: {}, holder0to30: {} },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    const resource = { type: 'secret31', attributes: {} }
    expect(await production.can('holder31', 'read', resource)).toBe(true)
    expect(await production.can('holder0to30', 'read', resource)).toBe(false)
  })
})

// ---------------------------------------------------------------------------------------
// 2. The full fail-skip / abstain matrix.
//
// Four independent abstain paths, each must return `null` (abstain) - not vote - when a
// policy throws:
//   A: abacFlatVote's evaluateDynamicCell, when every group at a DYNAMIC cell throws.
//   B: rbacVote's catch, when the rbacResidual policy throws.
//   C: lookup()'s own residual-policy loop, when a residual (targeted/wildcard) policy throws.
//   D: rbacVote's rbacDynamic scan, when a scoped/conditioned role permission throws.
//
// For each: an "unrelated vote present" case (must decide the outcome, not get vetoed by
// the throw, under policyCombine 'and') and a "no other vote" case (falls back to
// defaultEffect, both 'allow' and 'deny'). compiled.engine-wiring.test.ts already covers
// path B's unrelated-vote-present case with defaultEffect 'deny' and the unrelated vote
// coming from a flat ABAC CONST_ALLOW policy - not duplicated here; the path-B
// unrelated-vote-present test below uses a *residual* (targeted) policy as the unrelated
// vote instead, exercising a different combine branch (lookup()'s residualPolicies loop)
// alongside the same rbacVote throw.
// ---------------------------------------------------------------------------------------

const throwingFlatPolicy: AccessControl.IPolicy = {
  id: 'throwing-flat',
  name: 'Throwing Flat',
  algorithm: 'deny-overrides',
  rules: [
    {
      id: 'r',
      effect: 'allow',
      priority: 0,
      actions: ['read'],
      resources: ['doc'],
      conditions: { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+$' }] },
    },
  ],
}

function buildPathAAdapter(): IamMemoryAdapter {
  const roles: AccessControl.IRole[] = [
    { id: 'reader', name: 'Reader', permissions: [{ action: 'read', resource: 'doc' }] },
  ]
  return new IamMemoryAdapter({
    roles,
    policies: [throwingFlatPolicy],
    assignments: { 'user-1': ['reader'] },
    attributes: { 'user-1': { blob: OVERSIZED } },
  })
}

describe('fail-skip matrix - path A: every group at an ABAC DYNAMIC cell throws (evaluateDynamicCell)', () => {
  it("unrelated-vote-present, defaultEffect 'deny': the RBAC grant decides, the throw does not veto it (regression)", async () => {
    let reported: Error | undefined
    const production = new IamEngine({
      adapter: buildPathAAdapter(),
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err) => (reported = err) },
    })
    const development = new IamEngine({ adapter: buildPathAAdapter(), defaultEffect: 'deny' })
    const resource = { type: 'doc', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toMatch(/MAX_REGEX_INPUT_LENGTH/)
  })

  it("unrelated-vote-present, defaultEffect 'allow': still decided by the RBAC grant, not the fallback", async () => {
    const production = new IamEngine({
      adapter: buildPathAAdapter(),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    const development = new IamEngine({ adapter: buildPathAAdapter(), defaultEffect: 'allow', allowFailOpen: true })
    const resource = { type: 'doc', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
  })

  it("no-other-vote, defaultEffect 'deny': falls back to deny (no RBAC source, no residual policies)", async () => {
    const adapter = new IamMemoryAdapter({
      roles: [],
      policies: [throwingFlatPolicy],
      assignments: {},
      attributes: { 'user-1': { blob: OVERSIZED } },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc', attributes: {} })).toBe(false)
  })

  it("no-other-vote, defaultEffect 'allow': falls back to allow", async () => {
    const adapter = new IamMemoryAdapter({
      roles: [],
      policies: [throwingFlatPolicy],
      assignments: {},
      attributes: { 'user-1': { blob: OVERSIZED } },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'allow', allowFailOpen: true, mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc', attributes: {} })).toBe(true)
  })
})

const complexThrowingRole: AccessControl.IRole = {
  id: 'complex-role',
  name: 'Complex Role',
  permissions: [
    {
      action: 'read',
      resource: 'doc2',
      conditions: { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+$' }] },
    },
  ],
}

const unrelatedResidualAllow: AccessControl.IPolicy = {
  id: 'unrelated-residual-allow',
  name: 'Unrelated Residual Allow',
  algorithm: 'allow-overrides',
  targets: { actions: ['read'] },
  rules: [{ id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['doc2'], conditions: { all: [] } }],
}

const unrelatedFlatAllow: AccessControl.IPolicy = {
  id: 'unrelated-flat-allow',
  name: 'Unrelated Flat Allow',
  algorithm: 'allow-overrides',
  rules: [{ id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['doc2'], conditions: { all: [] } }],
}

function buildPathBAdapter(unrelated: AccessControl.IPolicy): IamMemoryAdapter {
  return new IamMemoryAdapter({
    roles: [complexThrowingRole],
    policies: [unrelated],
    assignments: { 'user-1': ['complex-role'] },
    attributes: { 'user-1': { blob: OVERSIZED } },
  })
}

describe('fail-skip matrix - path B: the rbacResidual policy throws (rbacVote catch)', () => {
  it("unrelated-vote-present, defaultEffect 'deny', unrelated vote via a residual policy: decides, not vetoed", async () => {
    let reported: Error | undefined
    const production = new IamEngine({
      adapter: buildPathBAdapter(unrelatedResidualAllow),
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err) => (reported = err) },
    })
    const development = new IamEngine({ adapter: buildPathBAdapter(unrelatedResidualAllow), defaultEffect: 'deny' })
    const resource = { type: 'doc2', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toMatch(/MAX_REGEX_INPUT_LENGTH/)
  })

  it("unrelated-vote-present, defaultEffect 'allow', unrelated vote via a flat CONST_ALLOW policy", async () => {
    const production = new IamEngine({
      adapter: buildPathBAdapter(unrelatedFlatAllow),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    const development = new IamEngine({
      adapter: buildPathBAdapter(unrelatedFlatAllow),
      defaultEffect: 'allow',
      allowFailOpen: true,
    })
    const resource = { type: 'doc2', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
  })

  it("no-other-vote, defaultEffect 'deny': falls back to deny (no ABAC policies at all)", async () => {
    const adapter = new IamMemoryAdapter({
      roles: [complexThrowingRole],
      policies: [],
      assignments: { 'user-1': ['complex-role'] },
      attributes: { 'user-1': { blob: OVERSIZED } },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc2', attributes: {} })).toBe(false)
  })

  it("no-other-vote, defaultEffect 'allow': falls back to allow", async () => {
    const adapter = new IamMemoryAdapter({
      roles: [complexThrowingRole],
      policies: [],
      assignments: { 'user-1': ['complex-role'] },
      attributes: { 'user-1': { blob: OVERSIZED } },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'allow', allowFailOpen: true, mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc2', attributes: {} })).toBe(true)
  })
})

const throwingResidualPolicy: AccessControl.IPolicy = {
  id: 'throwing-residual',
  name: 'Throwing Residual',
  algorithm: 'deny-overrides',
  targets: { actions: ['read'] },
  rules: [
    {
      id: 'r',
      effect: 'deny',
      priority: 0,
      actions: ['read'],
      resources: ['doc3'],
      conditions: { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+$' }] },
    },
  ],
}

function buildPathCAdapter(withRbac: boolean): IamMemoryAdapter {
  const roles: AccessControl.IRole[] = withRbac
    ? [{ id: 'reader3', name: 'Reader3', permissions: [{ action: 'read', resource: 'doc3' }] }]
    : []
  return new IamMemoryAdapter({
    roles,
    policies: [throwingResidualPolicy],
    assignments: withRbac ? { 'user-1': ['reader3'] } : {},
    attributes: { 'user-1': { blob: OVERSIZED } },
  })
}

describe("fail-closed matrix - path C: lookup()'s own residual-policy loop throws", () => {
  it("unrelated-vote-present, defaultEffect 'deny': a deny rule that throws vetoes the RBAC grant", async () => {
    let reported: Error | undefined
    const production = new IamEngine({
      adapter: buildPathCAdapter(true),
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err) => (reported = err) },
    })
    const development = new IamEngine({ adapter: buildPathCAdapter(true), defaultEffect: 'deny' })
    const resource = { type: 'doc3', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(false)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toMatch(/MAX_REGEX_INPUT_LENGTH/)
  })

  it("unrelated-vote-present, defaultEffect 'allow': fail-open does not rescue a throwing deny", async () => {
    const production = new IamEngine({
      adapter: buildPathCAdapter(true),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    const development = new IamEngine({ adapter: buildPathCAdapter(true), defaultEffect: 'allow', allowFailOpen: true })
    const resource = { type: 'doc3', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(false)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
  })

  it("no-other-vote, defaultEffect 'deny': falls back to deny (no RBAC, no flat ABAC policies)", async () => {
    const production = new IamEngine({ adapter: buildPathCAdapter(false), defaultEffect: 'deny', mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc3', attributes: {} })).toBe(false)
  })

  it("no-other-vote, defaultEffect 'allow': the throwing deny still denies", async () => {
    const production = new IamEngine({
      adapter: buildPathCAdapter(false),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    expect(await production.can('user-1', 'read', { type: 'doc3', attributes: {} })).toBe(false)
  })

  it('control: an allow-only policy that throws stays skippable and does not veto the RBAC grant', async () => {
    const adapter = new IamMemoryAdapter({
      assignments: { 'user-1': ['reader3'] },
      attributes: { 'user-1': { blob: OVERSIZED } },
      policies: [{ ...throwingResidualPolicy, rules: [{ ...throwingResidualPolicy.rules[0]!, effect: 'allow' }] }],
      roles: [{ id: 'reader3', name: 'Reader3', permissions: [{ action: 'read', resource: 'doc3' }] }],
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc3', attributes: {} })).toBe(true)
  })
})
