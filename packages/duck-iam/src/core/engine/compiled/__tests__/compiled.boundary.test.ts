import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../../adapters/memory'
import { iamBuildPermissionKey } from '../../../../shared/keys'
import { REGEX_CACHE_MAX } from '../../../conditions/conditions.libs'
import type { AccessControl, IamPrimitives, IamRequest } from '../../../types'
import { IamEngine } from '../../engine'
import { compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'

// Boundary role counts and the throw-path matrix for the compiled table.
// Adds to compiled.engine-wiring / compiled.compile / compiled.differential tests without repeating them.

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

// 1. Boundary role counts

describe('boundary: 0 roles - no RBAC source at all', () => {
  it('hasRbacSource is false for an empty role list (compileTable)', () => {
    const t = compileTable([], [], 'and')
    expect(t.hasRbacSource).toBe(false)
  })

  it('RBAC casts no vote at all (not even a defaultEffect vote) - distinct from voting defaultEffect', () => {
    // ABAC votes an unconditional allow here; an RBAC defaultEffect vote instead of an abstain would flip 'and'.
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

// 2. Throw paths - A: evaluateDynamicCell, B: rbacVote's catch, C: lookup()'s residual-policy loop.
// Each gets an unrelated-vote case and a no-other-vote case, under both defaultEffects.

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
  // SECURITY: `blob` is subject-controlled, so padding it past the regex cap must not delete the policy's vote.
  // An allow-only policy that throws still votes `defaultEffect` (deny here), and 'and' vetoes.
  it("unrelated-vote-present, defaultEffect 'deny': an allow-only throw casts its deny vote and vetoes (regression)", async () => {
    let reported: Error | undefined
    const production = new IamEngine({
      adapter: buildPathAAdapter(),
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err) => (reported = err) },
    })
    const development = new IamEngine({ adapter: buildPathAAdapter(), defaultEffect: 'deny', mode: 'development' })
    const resource = { type: 'doc', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(false)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toBe('IAM_CONDITION_REGEX_INPUT_TOO_LARGE')
  })

  it("unrelated-vote-present, defaultEffect 'allow': still decided by the RBAC grant, not the fallback", async () => {
    const production = new IamEngine({
      adapter: buildPathAAdapter(),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    const development = new IamEngine({
      adapter: buildPathAAdapter(),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'development',
    })
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
  // As in path A: the residual-policy catch casts `defaultEffect` rather than abstaining.
  it("unrelated-vote-present, defaultEffect 'deny', unrelated vote via a residual policy: the throw vetoes", async () => {
    let reported: Error | undefined
    const production = new IamEngine({
      adapter: buildPathBAdapter(unrelatedResidualAllow),
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err) => (reported = err) },
    })
    const development = new IamEngine({
      adapter: buildPathBAdapter(unrelatedResidualAllow),
      defaultEffect: 'deny',
      mode: 'development',
    })
    const resource = { type: 'doc2', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(false)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toBe('IAM_CONDITION_REGEX_INPUT_TOO_LARGE')
  })

  it("unrelated-vote-present, defaultEffect 'allow', unrelated vote via a flat CONST_ALLOW policy", async () => {
    const production = new IamEngine({
      adapter: buildPathBAdapter(unrelatedFlatAllow),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    const development = new IamEngine({
      mode: 'development',
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
    const development = new IamEngine({ adapter: buildPathCAdapter(true), defaultEffect: 'deny', mode: 'development' })
    const resource = { type: 'doc3', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(false)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toBe('IAM_CONDITION_REGEX_INPUT_TOO_LARGE')
  })

  it("unrelated-vote-present, defaultEffect 'allow': fail-open does not rescue a throwing deny", async () => {
    const production = new IamEngine({
      adapter: buildPathCAdapter(true),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    const development = new IamEngine({
      adapter: buildPathCAdapter(true),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'development',
    })
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

  // As in path A: an allow-only throw is not a skip, since `blob` is subject-controlled.
  it('control: an allow-only policy that throws casts its defaultEffect vote and vetoes the RBAC grant', async () => {
    const adapter = new IamMemoryAdapter({
      assignments: { 'user-1': ['reader3'] },
      attributes: { 'user-1': { blob: OVERSIZED } },
      policies: [{ ...throwingResidualPolicy, rules: [{ ...throwingResidualPolicy.rules[0]!, effect: 'allow' }] }],
      roles: [{ id: 'reader3', name: 'Reader3', permissions: [{ action: 'read', resource: 'doc3' }] }],
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc3', attributes: {} })).toBe(false)
  })
})
