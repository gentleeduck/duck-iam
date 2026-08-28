import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../../adapters/memory'
import { iamBuildPermissionKey } from '../../../../shared/keys'
import type { AccessControl, IamPrimitives } from '../../../types'
import { IamEngine } from '../../engine'

// Property-based / randomized differential test: a `mode: 'production'` engine
// (compiled table) and a `mode: 'development'` engine (interpreter, the ground
// truth oracle) must agree on every `can()`/`check()` verdict and every
// `permissions()` batch entry over identical `IamMemoryAdapter` data - that is
// the entire correctness contract of the compiled path (see docs/engine-rewrite.md).
//
// Randomness is a seeded mulberry32 PRNG, never bare `Math.random()`, so a
// failure is reproducible: the failure message prints both the master SEED and
// the iteration index, from which `seedFor(SEED, i)` regenerates the exact same
// roles/policies/assignments/attributes/requests deterministically.

/** mulberry32: tiny, fast, deterministic 32-bit PRNG. */
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

/** Derives an independent, deterministic per-iteration seed from a fixed master seed. */
function seedFor(base: number, i: number): number {
  let h = (base ^ Math.imul(i + 1, 0x9e3779b9)) >>> 0
  h = Math.imul(h ^ (h >>> 16), 0x45d9f3b)
  h = Math.imul(h ^ (h >>> 16), 0x45d9f3b)
  h = (h ^ (h >>> 16)) >>> 0
  return h
}

// Fixed literal, not Date.now() - re-runs must reproduce identical configurations.
const SEED = 0xc0ffee42
const CONFIG_COUNT = 160
const REQUESTS_PER_CONFIG = 10

function randInt(rng: () => number, min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1))
}

function randBool(rng: () => number, pTrue = 0.5): boolean {
  return rng() < pTrue
}

function pick<T>(rng: () => number, arr: readonly T[]): T {
  return arr[Math.floor(rng() * arr.length)]!
}

/** Sample up to `n` distinct elements from `arr`, order randomized. */
function pickN<T>(rng: () => number, arr: readonly T[], n: number): T[] {
  const pool = [...arr]
  const count = Math.min(n, pool.length)
  const result: T[] = []
  for (let k = 0; k < count; k++) {
    const idx = Math.floor(rng() * pool.length)
    result.push(pool[idx]!)
    pool.splice(idx, 1)
  }
  return result
}

const ACTIONS = [
  'read',
  'update',
  'delete',
  'create',
  'archive',
  'comment',
  'post:create',
  'post:edit',
  'view:summary',
  'view:detail',
] as const
const RESOURCES = ['post', 'comment', 'doc', 'cache', 'report', 'user', 'secret', 'billing'] as const
const ORG_SUFFIXES = ['team', 'billing', 'settings'] as const
const WILDCARD_ACTIONS = ['post:*', 'view:*'] as const
const WILDCARD_RESOURCES = ['org.*'] as const
const SCOPES = ['org-1', 'org-2', 'org-3'] as const
const DEPTS = ['eng', 'sales', 'ops'] as const
const TAGS = ['vip', 'trial', 'internal'] as const
const SUBJECT_IDS = ['u0', 'u1', 'u2', 'u3', 'u4', 'u5', 'u6', 'u7'] as const
// Role counts we must hit: none, one, a handful (3-5), and exactly the 32-bit
// mask capacity. Cycled deterministically across iterations so every count is
// exercised many times over CONFIG_COUNT runs, while every other dimension
// (policies, permission shapes, conditions, requests) stays randomized.
const ROLE_COUNT_PLAN = [0, 1, 3, 4, 5, 32] as const

function randomCondition(rng: () => number): AccessControl.IConditionGroup {
  switch (randInt(rng, 0, 6)) {
    case 0:
      return { all: [] } // unconditionally true
    case 1:
      // Ownership pattern: dynamic $-reference to the resource's owner.
      return { all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }] }
    case 2:
      return {
        all: [
          {
            field: 'subject.attributes.level',
            operator: pick(rng, ['gte', 'lt', 'eq'] as const),
            value: randInt(rng, 0, 5),
          },
        ],
      }
    case 3:
      return {
        any: [
          { field: 'subject.attributes.dept', operator: 'eq', value: pick(rng, DEPTS) },
          { field: 'subject.attributes.active', operator: 'eq', value: true },
        ],
      }
    case 4:
      return {
        all: [
          {
            field: 'resource.attributes.status',
            operator: 'eq',
            value: pick(rng, ['active', 'archived', 'pending'] as const),
          },
        ],
      }
    case 5:
      return { none: [{ field: 'subject.attributes.tags', operator: 'contains', value: pick(rng, TAGS) }] }
    default:
      return { all: [{ field: 'resource.attributes.ownerId', operator: 'exists' }] }
  }
}

function genPermission(rng: () => number): AccessControl.IPermission {
  const action = pick(rng, ACTIONS)
  const resource = pick(rng, RESOURCES)
  // Weighted so plain (mask-eligible) permissions are the common case, with
  // scoped and conditioned (residual) permissions well represented too.
  switch (pick(rng, ['plain', 'plain', 'plain', 'scoped', 'conditioned'] as const)) {
    case 'scoped':
      return { action, resource, scope: pick(rng, SCOPES) }
    case 'conditioned':
      return { action, resource, conditions: randomCondition(rng) }
    default:
      return { action, resource }
  }
}

function genRole(rng: () => number, id: string, priorIds: readonly string[]): AccessControl.IRole {
  const permissions = Array.from({ length: randInt(rng, 0, 3) }, () => genPermission(rng))
  const role: AccessControl.IRole = { id, name: id, permissions }
  // Inherit only from an already-created (lower-index) role, so chains never cycle.
  if (priorIds.length > 0 && randBool(rng, 0.3)) {
    return { ...role, inherits: [pick(rng, priorIds)] }
  }
  return role
}

function genPolicy(rng: () => number, id: string, roleIds: readonly string[]): AccessControl.IPolicy {
  const algorithm = pick(rng, ['deny-overrides', 'allow-overrides'] as const)
  const shapeRoll = rng()

  if (shapeRoll < 0.2) {
    // Wildcard action or resource pattern - forces the whole policy residual.
    const actionWildcard = randBool(rng)
    const rule: AccessControl.IRule = {
      id: `${id}-w`,
      effect: pick(rng, ['allow', 'deny'] as const),
      priority: randInt(rng, 0, 5),
      actions: actionWildcard ? [pick(rng, WILDCARD_ACTIONS)] : [pick(rng, ACTIONS)],
      resources: actionWildcard ? [pick(rng, RESOURCES)] : [pick(rng, WILDCARD_RESOURCES)],
      conditions: randomCondition(rng),
    }
    return { id, name: id, algorithm, rules: [rule] }
  }

  const rules: AccessControl.IRule[] = Array.from({ length: randInt(rng, 1, 3) }, (_, i) => ({
    id: `${id}-r${i}`,
    effect: pick(rng, ['allow', 'deny'] as const),
    priority: randInt(rng, 0, 5),
    actions: [pick(rng, ACTIONS)],
    resources: [pick(rng, RESOURCES)],
    conditions: randomCondition(rng),
  }))
  const policy: AccessControl.IPolicy = { id, name: id, algorithm, rules }

  if (shapeRoll < 0.4 && roleIds.length > 0) {
    return { ...policy, targets: { roles: pickN(rng, roleIds, randInt(rng, 1, roleIds.length)) } }
  }
  if (shapeRoll < 0.55) {
    return { ...policy, targets: { actions: pickN(rng, ACTIONS, randInt(rng, 1, 3)) } }
  }
  if (shapeRoll < 0.65) {
    return { ...policy, targets: { resources: pickN(rng, RESOURCES, randInt(rng, 1, 3)) } }
  }
  return policy // untargeted, flat-eligible
}

function genSubjectAttributes(rng: () => number): IamPrimitives.Attributes {
  return {
    level: randInt(rng, 0, 5),
    dept: pick(rng, DEPTS),
    active: randBool(rng, 0.7),
    tags: pickN(rng, TAGS, randInt(rng, 0, 2)),
  }
}

function genResourceAttributes(rng: () => number, requesterId: string): IamPrimitives.Attributes {
  // Biased mix: sometimes the requester owns the resource (conditions pass),
  // sometimes another real subject owns it, sometimes nobody does.
  const ownerId = randBool(rng, 0.4)
    ? requesterId
    : randBool(rng, 0.5)
      ? pick(rng, SUBJECT_IDS)
      : `ghost-${randInt(rng, 0, 999)}`
  return { ownerId, status: pick(rng, ['active', 'archived', 'pending'] as const) }
}

interface IGeneratedConfig {
  roles: AccessControl.IRole[]
  policies: AccessControl.IPolicy[]
  assignments: Record<string, string[]>
  attributes: Record<string, IamPrimitives.Attributes>
  roleIds: string[]
}

function genConfig(rng: () => number, iterationIndex: number): IGeneratedConfig {
  const roleCount = ROLE_COUNT_PLAN[iterationIndex % ROLE_COUNT_PLAN.length]!
  const roleIds = Array.from({ length: roleCount }, (_, idx) => `role-${idx}`)
  const roles = roleIds.map((id, idx) => genRole(rng, id, roleIds.slice(0, idx)))

  const policyCount = randInt(rng, 0, 4)
  const policies = Array.from({ length: policyCount }, (_, idx) => genPolicy(rng, `policy-${idx}`, roleIds))

  const assignments: Record<string, string[]> = {}
  const attributes: Record<string, IamPrimitives.Attributes> = {}
  for (const sid of SUBJECT_IDS) {
    const maxRoles = Math.min(3, roleIds.length)
    const n = maxRoles === 0 ? 0 : randInt(rng, 0, maxRoles)
    assignments[sid] = n === 0 ? [] : pickN(rng, roleIds, n)
    attributes[sid] = genSubjectAttributes(rng)
  }

  return { roles, policies, assignments, attributes, roleIds }
}

interface IGeneratedRequest {
  subjectId: string
  action: string
  resourceType: string
  resourceAttributes: IamPrimitives.Attributes
  resourceId?: string
  scope?: string
}

function genRequest(rng: () => number): IGeneratedRequest {
  const subjectId = pick(rng, SUBJECT_IDS)
  const action = randBool(rng, 0.85) ? pick(rng, ACTIONS) : `unknown-action-${randInt(rng, 0, 9)}`

  const resourceRoll = rng()
  const resourceType =
    resourceRoll < 0.15
      ? `org.${pick(rng, ORG_SUFFIXES)}` // exercises the org.* wildcard residual policy
      : resourceRoll < 0.25
        ? `unknown-resource-${randInt(rng, 0, 9)}` // untouched cell -> defaultEffect
        : pick(rng, RESOURCES)

  return {
    subjectId,
    action,
    resourceType,
    resourceAttributes: genResourceAttributes(rng, subjectId),
    resourceId: randBool(rng, 0.3) ? `res-${randInt(rng, 0, 5)}` : undefined,
    scope: randBool(rng, 0.4) ? pick(rng, SCOPES) : undefined,
  }
}

function reproMessage(iterationIndex: number, iterSeed: number, config: IGeneratedConfig, extra: unknown): string {
  return [
    `Mismatch at iteration ${iterationIndex} (SEED=${SEED}, iterSeed=${seedForHex(iterSeed)}).`,
    'Reproduce by regenerating iteration state from seedFor(SEED, i).',
    `roles: ${JSON.stringify(config.roles)}`,
    `policies: ${JSON.stringify(config.policies)}`,
    `assignments: ${JSON.stringify(config.assignments)}`,
    `attributes: ${JSON.stringify(config.attributes)}`,
    `case: ${JSON.stringify(extra)}`,
  ].join('\n')
}

function seedForHex(n: number): string {
  return `0x${n.toString(16)}`
}

describe('property fuzz: production (compiled table) vs development (interpreter) agree', () => {
  it(`agree on can()/check() and permissions() across ${CONFIG_COUNT} random configs x ${REQUESTS_PER_CONFIG}+ requests (SEED=${seedForHex(SEED)})`, async () => {
    const originalWarn = console.warn
    console.warn = () => {} // silence the expected defaultEffect:'allow' fail-open warning
    let totalAssertions = 0
    try {
      for (let i = 0; i < CONFIG_COUNT; i++) {
        const iterSeed = seedFor(SEED, i)
        const rng = mulberry32(iterSeed)
        const config = genConfig(rng, i)

        const policyCombine = i % 2 === 0 ? ('and' as const) : ('allow-overrides' as const)
        const defaultEffect = Math.floor(i / 2) % 2 === 0 ? ('deny' as const) : ('allow' as const)
        const allowFailOpen = defaultEffect === 'allow'

        const { roles, policies, assignments, attributes } = config

        const production = new IamEngine({
          adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
          defaultEffect,
          mode: 'production',
          policyCombine,
          allowFailOpen,
        })
        const development = new IamEngine({
          adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
          defaultEffect,
          policyCombine,
          allowFailOpen,
        })

        const requests = Array.from({ length: REQUESTS_PER_CONFIG }, () => genRequest(rng))

        for (const [ri, r] of requests.entries()) {
          const resource = { type: r.resourceType, id: r.resourceId, attributes: r.resourceAttributes }
          const prodResult = await production.can(r.subjectId, r.action, resource, undefined, r.scope)
          const devDecision = await development.check(r.subjectId, r.action, resource, undefined, r.scope)

          if (prodResult !== devDecision.allowed) {
            throw new Error(
              reproMessage(i, iterSeed, config, {
                kind: 'can/check',
                requestIndex: ri,
                policyCombine,
                defaultEffect,
                request: r,
                prodResult,
                devResult: devDecision.allowed,
              }),
            )
          }
          totalAssertions++
        }

        // permissions() batch check: a meaningful subset (first 4 generated
        // requests per config) run as one production batch vs per-item development checks.
        const batch = requests.slice(0, 4)
        const checks = batch.map((r) => ({
          action: r.action,
          resource: r.resourceType,
          resourceId: r.resourceId,
          scope: r.scope,
        }))
        const subjectId = pick(rng, SUBJECT_IDS)
        const prodMap = await production.permissions(subjectId, checks)
        for (const c of checks) {
          const devDecision = await development.check(
            subjectId,
            c.action,
            { type: c.resource, id: c.resourceId, attributes: {} },
            undefined,
            c.scope,
          )
          const key = iamBuildPermissionKey(c.action, c.resource, c.resourceId, c.scope)
          if (prodMap[key] !== devDecision.allowed) {
            throw new Error(
              reproMessage(i, iterSeed, config, {
                kind: 'permissions()',
                policyCombine,
                defaultEffect,
                subjectId,
                check: c,
                prodResult: prodMap[key],
                devResult: devDecision.allowed,
              }),
            )
          }
          totalAssertions++
        }
      }
    } finally {
      console.warn = originalWarn
    }

    expect(totalAssertions).toBeGreaterThanOrEqual(1200)
  })
})
