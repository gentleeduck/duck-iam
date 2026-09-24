import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// Every engine.admin write must leave a long-lived engine answering what a cold engine on the same store answers.
// Seeds are fixed, so a red reproduces exactly; the last case proves the comparison can see an incoherence.

function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const pick = <T>(rng: () => number, xs: readonly T[]): T => xs[Math.floor(rng() * xs.length)] as T

const SEEDS = [1, 4, 5, 6, 7, 8]
const ITERATIONS = 300
const SUBJECTS = ['u1', 'u2']
const ROLES = ['viewer', 'editor']
const ACTIONS = ['read', 'write']
const RESOURCES = ['post', 'comment']
const SCOPES: (string | undefined)[] = [undefined, 'org-1', 'org-1.team-2']
/** The adapter refuses this by design; anything else the loop swallows would make it vacuous. */
const EXPECTED_REFUSAL = /IAM_ROLE_NOT_FOUND/

function role(id: string, perms: { action: string; resource: string }[], scope?: string): AccessControl.IRole {
  return { description: '', id, inherits: [], name: id, permissions: perms, ...(scope ? { scope } : {}) }
}

function policy(id: string, effect: AccessControl.Effect, action: string, resource: string): AccessControl.IPolicy {
  return {
    algorithm: 'deny-overrides',
    description: '',
    id,
    name: id,
    rules: [
      {
        actions: [action],
        conditions: { all: [{ field: 'subject.attributes.tier', operator: 'eq', value: 'gold' }] },
        effect,
        id: `${id}-r1`,
        priority: 10,
        resources: [resource],
      },
    ],
    version: 1,
  }
}

const makeEngine = (adapter: IamMemoryAdapter) =>
  new IamEngine({ adapter, cacheTTL: 600, mode: 'production', scopeMode: 'hierarchical' })

interface IRun {
  divergences: string[]
  allows: number
  checks: number
  refusals: string[]
}

async function fuzz(seed: number, opts: { suppressRoleInvalidation?: boolean } = {}): Promise<IRun> {
  const rng = mulberry32(seed)
  const roleIds = [...ROLES, 'manager']
  const adapter = new IamMemoryAdapter()
  const hot = makeEngine(adapter)
  if (opts.suppressRoleInvalidation) hot.cache.invalidateRoles = () => {}
  await hot.admin.saveRole(role('viewer', [{ action: 'read', resource: 'post' }]))
  await hot.admin.saveRole(role('editor', [{ action: 'write', resource: 'post' }]))
  await hot.admin.savePolicy(policy('p1', 'allow', 'read', 'comment'))
  await hot.admin.setAttributes('u1', { tier: 'gold' })

  const out: IRun = { allows: 0, checks: 0, divergences: [], refusals: [] }
  for (let i = 0; i < ITERATIONS && out.divergences.length === 0; i++) {
    const s = pick(rng, SUBJECTS)
    const r = pick(rng, roleIds)
    const sc = pick(rng, SCOPES)
    const ops: { name: string; run: () => Promise<unknown> }[] = [
      { name: 'assignRole', run: () => hot.admin.assignRole(s, r, sc) },
      { name: 'revokeRole', run: () => hot.admin.revokeRole(s, r, sc) },
      {
        name: 'saveRole',
        run: () =>
          hot.admin.saveRole(
            role(
              r,
              [{ action: pick(rng, ACTIONS), resource: pick(rng, RESOURCES) }],
              rng() < 0.3 ? 'org-1' : undefined,
            ),
          ),
      },
      { name: 'deleteRole', run: () => hot.admin.deleteRole(r) },
      { name: 'savePolicy', run: () => hot.admin.savePolicy(policy('p1', 'allow', 'read', 'comment')) },
      { name: 'deletePolicy', run: () => hot.admin.deletePolicy('p1') },
      { name: 'setAttributes', run: () => hot.admin.setAttributes(s, { tier: rng() < 0.5 ? 'gold' : 'silver' }) },
      {
        name: 'assignRoles',
        run: () => hot.admin.assignRoles([{ roleId: r, subjectId: s, ...(sc ? { scope: sc } : {}) }]),
      },
      {
        name: 'revokeRoles',
        run: () => hot.admin.revokeRoles([{ roleId: r, subjectId: s, ...(sc ? { scope: sc } : {}) }]),
      },
      {
        name: 'moveRoleScopes',
        run: () =>
          hot.admin.moveRoleScopes([
            { roleId: r, subjectId: s, ...(sc ? { toScope: sc } : {}), ...(rng() < 0.5 ? { fromScope: 'org-1' } : {}) },
          ]),
      },
      { name: 'updateAssignmentScope', run: () => hot.admin.updateAssignmentScope(s, r, undefined, sc) },
      {
        name: 'saveRole(manager inherits)',
        run: () =>
          hot.admin.saveRole({
            description: '',
            id: 'manager',
            inherits: [pick(rng, ROLES)],
            name: 'manager',
            permissions: [],
          }),
      },
      { name: 'assignRole(manager)', run: () => hot.admin.assignRole(s, 'manager', sc) },
      {
        name: 'import',
        run: () =>
          hot.admin.import({
            exportedAt: new Date().toISOString(),
            policies: [policy('p1', 'allow', 'read', 'comment')],
            roles: [role('viewer', [{ action: 'read', resource: 'post' }])],
            schemaVersion: 1,
          }),
      },
    ]
    const op = ops[Math.floor(rng() * ops.length)]
    if (op === undefined) continue
    try {
      await op.run()
    } catch (err) {
      if (!(err instanceof Error) || !/not found|no such/i.test(err.message)) out.refusals.push(String(err))
    }

    const cold = makeEngine(adapter)
    for (const subject of SUBJECTS) {
      for (const action of ACTIONS) {
        for (const resource of RESOURCES) {
          for (const scope of SCOPES) {
            const a = await hot.can(subject, action, { attributes: {}, type: resource }, undefined, scope)
            const b = await cold.can(subject, action, { attributes: {}, type: resource }, undefined, scope)
            out.checks++
            if (a) out.allows++
            if (a !== b) {
              out.divergences.push(`i=${i} ${op.name} ${subject}/${action}/${resource}/${scope} hot=${a} cold=${b}`)
            }
          }
        }
      }
    }
  }
  return out
}

describe('a long-lived engine after every admin write', () => {
  it.each(SEEDS)('agrees with a cold engine reading the same store (seed %i)', async (seed) => {
    const run = await fuzz(seed)
    expect(run.divergences.slice(0, 3)).toEqual([])
    expect(run.allows, 'nothing was ever allowed, so agreement proves nothing').toBeGreaterThan(0)
    expect(run.refusals.filter((r) => !EXPECTED_REFUSAL.test(r))).toEqual([])
  })

  it('the comparison reports an incoherence when role invalidation is suppressed', async () => {
    const run = await fuzz(6, { suppressRoleInvalidation: true })
    expect(run.divergences.length, 'a stale engine went unnoticed - the agreement above is worthless').toBeGreaterThan(
      0,
    )
  })
})
