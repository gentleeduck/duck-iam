/**
 * `first-applicable` short-circuits, so the order the engine hands policies over in is the decision.
 * The synthetic `__rbac__` policy is generated, not written, and must not pre-empt the operator's own.
 */
import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine'
import { explainEvaluation } from '../../explain'
import { IAM_RBAC_POLICY_ID } from '../../rbac/rbac'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate } from '../evaluate'
import { firstApplicableOrder } from '../evaluate.libs'

/** Allows `delete` on `post`, then denies it for a locked post; the allow keeps the deny from being vacuous. */
const lockPolicy: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  id: 'p-lock',
  name: 'locked posts',
  rules: [
    { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'r-allow', priority: 0, resources: ['post'] },
    {
      actions: ['delete'],
      conditions: { all: [{ field: 'resource.attributes.locked', operator: 'eq', value: true }] },
      effect: 'deny',
      id: 'r-deny-locked',
      priority: 10,
      resources: ['post'],
    },
  ],
}

/** The trace metadata `explainEvaluation` takes; none of it reaches the verdict. */
const SUBJECT_INFO = { originalRoles: ['editor'], scopedRolesApplied: [], subjectId: 'u1' }

const locked = { attributes: { locked: true }, type: 'post' }
const unlocked = { attributes: { locked: false }, type: 'post' }

async function engineFor(policyCombine: AccessControl.PolicyCombine, withRole: boolean) {
  const adapter = new IamMemoryAdapter()
  if (withRole) {
    await adapter.saveRole({ id: 'editor', name: 'Editor', permissions: [{ action: 'delete', resource: 'post' }] })
    await adapter.assignRole('u1', 'editor')
  }
  await adapter.savePolicy(lockPolicy)
  return new IamEngine({ adapter, cacheTTL: 0, mode: 'development', policyCombine })
}

describe('a role grant no longer retires the operator’s deny', () => {
  it('first-applicable denies a locked post to a role holder', async () => {
    const iam = await engineFor('first-applicable', true)
    expect(await iam.can('u1', 'delete', locked)).toBe(false)
  })

  it('CONTROL: the same role holder may delete an unlocked post', async () => {
    const iam = await engineFor('first-applicable', true)
    expect(await iam.can('u1', 'delete', unlocked)).toBe(true)
  })

  it('CONTROL: with no role at all the deny already fired, so the role grant is what changed', async () => {
    const iam = await engineFor('first-applicable', false)
    expect({
      locked: await iam.can('u1', 'delete', locked),
      unlocked: await iam.can('u1', 'delete', unlocked),
    }).toEqual({ locked: false, unlocked: true })
  })

  it('answers what the other combines answer', async () => {
    const matrix: Record<string, boolean> = {}
    for (const combine of ['and', 'allow-overrides', 'first-applicable'] as const) {
      for (const withRole of [false, true]) {
        const iam = await engineFor(combine, withRole)
        matrix[`${combine}/role=${withRole}/locked`] = await iam.can('u1', 'delete', locked)
        matrix[`${combine}/role=${withRole}/unlocked`] = await iam.can('u1', 'delete', unlocked)
      }
    }
    expect(matrix).toEqual({
      'allow-overrides/role=false/locked': false,
      'allow-overrides/role=false/unlocked': true,
      'allow-overrides/role=true/locked': true,
      'allow-overrides/role=true/unlocked': true,
      'and/role=false/locked': false,
      'and/role=false/unlocked': true,
      'and/role=true/locked': false,
      'and/role=true/unlocked': true,
      'first-applicable/role=false/locked': false,
      'first-applicable/role=false/unlocked': true,
      'first-applicable/role=true/locked': false,
      'first-applicable/role=true/unlocked': true,
    })
  })

  it('names the policy that decided, not the generated one', async () => {
    const iam = await engineFor('first-applicable', true)
    const decision = await iam.check('u1', 'delete', locked)
    expect(typeof decision === 'boolean' ? null : { allowed: decision.allowed, policy: decision.policy }).toEqual({
      allowed: false,
      policy: 'p-lock',
    })
  })

  it('explain() reaches the same verdict and names the same policy', async () => {
    const iam = await engineFor('first-applicable', true)
    const traced = await iam.explain('u1', 'delete', locked)
    expect({ allowed: traced.decision.allowed, policy: traced.decision.policy }).toEqual({
      allowed: false,
      policy: 'p-lock',
    })
  })
})

describe('evaluate() puts the generated policy last whatever order it is handed', () => {
  const rbacLike: AccessControl.IPolicy = {
    algorithm: 'allow-overrides',
    id: IAM_RBAC_POLICY_ID,
    name: 'RBAC Policies',
    rules: [
      {
        actions: ['delete'],
        conditions: { all: [{ field: 'subject.roles', operator: 'contains', value: 'editor' }] },
        effect: 'allow',
        id: '__rbac__#0',
        priority: 10,
        resources: ['post'],
      },
    ],
  }
  const request: IamRequest.IAccessRequest = {
    action: 'delete',
    resource: { attributes: { locked: true }, type: 'post' },
    subject: { attributes: {}, id: 'u1', roles: ['editor'] },
  }

  it('denies whether the generated policy is first or last in the array', () => {
    expect({
      last: evaluate([lockPolicy, rbacLike], request, 'deny', 'first-applicable').allowed,
      first: evaluate([rbacLike, lockPolicy], request, 'deny', 'first-applicable').allowed,
    }).toEqual({ first: false, last: false })
  })

  it('CONTROL: an unlocked post is allowed from either order', () => {
    const open = { ...request, resource: { attributes: { locked: false }, type: 'post' } }
    expect({
      last: evaluate([lockPolicy, rbacLike], open, 'deny', 'first-applicable').allowed,
      first: evaluate([rbacLike, lockPolicy], open, 'deny', 'first-applicable').allowed,
    }).toEqual({ first: true, last: true })
  })

  it('CONTROL: the other combines are untouched by the reorder', () => {
    for (const combine of ['and', 'allow-overrides'] as const) {
      expect({
        combine,
        first: evaluate([rbacLike, lockPolicy], request, 'deny', combine).allowed,
        last: evaluate([lockPolicy, rbacLike], request, 'deny', combine).allowed,
      }).toEqual({ combine, first: combine === 'allow-overrides', last: combine === 'allow-overrides' })
    }
  })
})

describe('firstApplicableOrder', () => {
  const id = (v: string) => v

  it('leaves a list with no generated policy alone', () => {
    const list = ['a', 'b', 'c']
    expect(firstApplicableOrder(list, id)).toBe(list)
  })

  it('moves the generated policy to the end and keeps the rest in order', () => {
    expect(firstApplicableOrder([IAM_RBAC_POLICY_ID, 'a', 'b'], id)).toEqual(['a', 'b', IAM_RBAC_POLICY_ID])
    expect(firstApplicableOrder(['a', IAM_RBAC_POLICY_ID, 'b'], id)).toEqual(['a', 'b', IAM_RBAC_POLICY_ID])
    expect(firstApplicableOrder(['a', 'b', IAM_RBAC_POLICY_ID], id)).toEqual(['a', 'b', IAM_RBAC_POLICY_ID])
  })

  it('handles an empty list and a list that is only the generated policy', () => {
    expect(firstApplicableOrder([], id)).toEqual([])
    expect(firstApplicableOrder([IAM_RBAC_POLICY_ID], id)).toEqual([IAM_RBAC_POLICY_ID])
  })
})

/**
 * `first-applicable` is the one combine the compiled table never runs, so `evaluate` and `explain` are its only
 * two implementations. Order now matters to both, which is exactly where they can drift.
 */
describe('evaluate() and explain() agree under first-applicable', () => {
  const SEED = Number(process.env.DUCKIAM_FIRST_APPLICABLE_SEED ?? 0x0f1a5eed) >>> 0
  const CATALOGS = 400
  const ACTIONS = ['read', 'delete', 'post:create'] as const
  const RESOURCES = ['post', 'doc', 'org.team'] as const
  const ALGORITHMS = ['deny-overrides', 'allow-overrides', 'first-match', 'highest-priority'] as const

  function mulberry32(seed: number): () => number {
    let state = seed >>> 0
    return () => {
      state = (state + 0x6d2b79f5) | 0
      let t = state
      t = Math.imul(t ^ (t >>> 15), t | 1)
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296
    }
  }
  function pick<T>(rng: () => number, arr: readonly T[]): T {
    const item = arr[Math.floor(rng() * arr.length)]
    if (item === undefined) throw new Error('pick() needs a non-empty list')
    return item
  }

  function buildRule(rng: () => number, i: number): AccessControl.IRule {
    const conditioned = rng() < 0.6
    return {
      actions: [pick(rng, ACTIONS)],
      conditions: conditioned
        ? { all: [{ field: 'subject.attributes.tier', operator: 'eq', value: pick(rng, ['gold', 'bronze']) }] }
        : { all: [] },
      effect: rng() < 0.5 ? 'allow' : 'deny',
      id: `r${i}`,
      priority: Math.floor(rng() * 20),
      resources: [pick(rng, RESOURCES)],
    }
  }

  it('reaches the same verdict over generated catalogs', () => {
    const mismatches: unknown[] = []
    let comparisons = 0
    let rbacDecided = 0
    for (let c = 0; c < CATALOGS; c++) {
      const rng = mulberry32((SEED ^ (c * 0x9e3779b9)) >>> 0)
      const count = 1 + Math.floor(rng() * 4)
      const policies: AccessControl.IPolicy[] = []
      for (let p = 0; p < count; p++) {
        const isRbac = rng() < 0.4 && !policies.some((x) => x.id === IAM_RBAC_POLICY_ID)
        policies.push({
          algorithm: isRbac ? 'allow-overrides' : pick(rng, ALGORITHMS),
          id: isRbac ? IAM_RBAC_POLICY_ID : `p${p}`,
          name: `policy ${p}`,
          rules: Array.from({ length: 1 + Math.floor(rng() * 3) }, (_, i) => {
            const rule = buildRule(rng, i)
            return isRbac ? { ...rule, effect: 'allow' as const } : rule
          }),
        })
      }
      const defaultEffect: AccessControl.Effect = rng() < 0.3 ? 'allow' : 'deny'
      const request: IamRequest.IAccessRequest = {
        action: pick(rng, ACTIONS),
        resource: { attributes: {}, type: pick(rng, RESOURCES) },
        subject: { attributes: { tier: pick(rng, ['gold', 'bronze']) }, id: 'u1', roles: ['editor'] },
      }
      const decided = evaluate(policies, request, defaultEffect, 'first-applicable')
      const traced = explainEvaluation(policies, request, defaultEffect, SUBJECT_INFO, 'first-applicable')
      comparisons++
      if (decided.policy === IAM_RBAC_POLICY_ID) rbacDecided++
      if (decided.allowed !== traced.decision.allowed || decided.policy !== traced.decision.policy) {
        mismatches.push({ catalog: c, defaultEffect, evaluate: decided, explain: traced.decision, policies, request })
      }
    }
    expect({ comparisons, mismatches }).toEqual({ comparisons: CATALOGS, mismatches: [] })
    // The generator must actually reach the reordered policy, or agreement is vacuous.
    expect(rbacDecided).toBeGreaterThan(0)
  })
})
