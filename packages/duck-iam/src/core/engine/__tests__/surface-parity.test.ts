import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { iamBuildPermissionKey } from '../../../shared/keys'
import type { AccessControl, IamPrimitives } from '../../types'
import { IamEngine } from '../engine'

// One verdict, five ways of asking for it: production `can`, development `can` and `check`, `explain`, and the
// batch `permissions` map. A caller that gates on one and audits with another must not be told two stories.

/** mulberry32: tiny, fast, deterministic 32-bit PRNG. */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const pick = <T>(rng: () => number, xs: readonly T[]): T => xs[Math.floor(rng() * xs.length)] as T

const SEEDS = [1, 2, 3]
const ITERATIONS = 150
const SUBJECTS = ['u1', 'u2']
const ROLE_IDS = ['viewer', 'editor', 'manager']
const ACTIONS = ['read', 'write']
const RESOURCES = ['post', 'comment']
const SCOPES: (string | undefined)[] = [undefined, 'org-1', 'org-1.team-2']

function role(id: string, perms: { action: string; resource: string }[], scope?: string, inherits: string[] = []) {
  return { description: '', id, inherits, name: id, permissions: perms, ...(scope ? { scope } : {}) }
}

function policy(
  id: string,
  effect: AccessControl.Effect,
  action: string,
  resource: string,
  on: 'subject' | 'resource' = 'subject',
): AccessControl.IPolicy {
  // A policy whose only rule is a deny answers `defaultEffect` when the rule misses, and under `policyCombine: 'and'`
  // that denies everything. The resource-conditioned one carries an allow rule so its deny is the only variable.
  const baseline: AccessControl.IRule[] =
    on === 'resource'
      ? [
          {
            actions: [action],
            conditions: { all: [{ field: 'action', operator: 'eq', value: action }] },
            effect: 'allow',
            id: `${id}-r0`,
            priority: 1,
            resources: [resource],
          },
        ]
      : []
  return {
    algorithm: 'deny-overrides',
    description: '',
    id,
    name: id,
    rules: [
      ...baseline,
      {
        actions: [action],
        conditions: {
          all: [
            on === 'subject'
              ? { field: 'subject.attributes.tier', operator: 'eq', value: 'gold' }
              : { field: 'resource.attributes.archived', operator: 'eq', value: true },
          ],
        },
        effect,
        id: `${id}-r1`,
        priority: 10,
        resources: [resource],
      },
    ],
    version: 1,
  }
}

interface IRun {
  divergences: string[]
  allows: number
}

async function parity(seed: number, devScopeMode: 'flat' | 'hierarchical'): Promise<IRun> {
  const rng = mulberry32(seed)
  const adapter = new IamMemoryAdapter()
  const cfg = { adapter, cacheTTL: 600, scopeMode: 'hierarchical' as const }
  const writer = new IamEngine({ ...cfg, mode: 'production' as const })
  const out: IRun = { allows: 0, divergences: [] }

  for (let i = 0; i < ITERATIONS && out.divergences.length === 0; i++) {
    const s = pick(rng, SUBJECTS)
    const r = pick(rng, ROLE_IDS)
    const sc = pick(rng, SCOPES)
    const perm = { action: pick(rng, ACTIONS), resource: pick(rng, RESOURCES) }
    const rscope = rng() < 0.3 ? 'org-1' : undefined
    const tier = rng() < 0.5 ? 'gold' : 'silver'
    const inheritPick = pick(rng, ROLE_IDS)
    const deletePick = rng() < 0.5 ? 'p1' : 'p2'
    // The instance the surfaces are asked about: every one must be handed the same id and attributes.
    const rid = rng() < 0.5 ? '42' : undefined
    const resAttrs: IamPrimitives.Attributes = rng() < 0.5 ? { archived: true } : {}
    const ops: { name: string; run: () => Promise<unknown> }[] = [
      { name: 'saveRole', run: () => writer.admin.saveRole(role(r, [perm], rscope, [inheritPick])) },
      { name: 'deleteRole', run: () => writer.admin.deleteRole(r) },
      { name: 'savePolicy', run: () => writer.admin.savePolicy(policy('p1', 'allow', perm.action, perm.resource)) },
      {
        name: 'savePolicy(deny)',
        run: () => writer.admin.savePolicy(policy('p2', 'deny', perm.action, perm.resource, 'resource')),
      },
      { name: 'deletePolicy', run: () => writer.admin.deletePolicy(deletePick) },
      { name: 'assignRole', run: () => writer.admin.assignRole(s, r, sc) },
      { name: 'revokeRole', run: () => writer.admin.revokeRole(s, r, sc) },
      { name: 'setAttributes', run: () => writer.admin.setAttributes(s, { tier }) },
    ]
    const op = ops[Math.floor(rng() * ops.length)]
    if (op === undefined) continue
    try {
      await op.run()
    } catch {
      /* a refused write changes nothing; the surfaces must still agree about the state that is there */
    }

    const prod = new IamEngine({ ...cfg, mode: 'production' as const })
    const dev = new IamEngine({ ...cfg, mode: 'development' as const, scopeMode: devScopeMode })
    for (const subject of SUBJECTS) {
      for (const action of ACTIONS) {
        for (const resource of RESOURCES) {
          for (const scope of SCOPES) {
            const res = { attributes: resAttrs, id: rid, type: resource }
            const viaCan = await prod.can(subject, action, res, undefined, scope)
            const viaCheck = await dev.check(subject, action, res, undefined, scope)
            const viaExplain = await dev.explain(subject, action, res, undefined, scope)
            const viaDevCan = await dev.can(subject, action, res, undefined, scope)
            const map = await prod.permissions(subject, [
              { action, attributes: resAttrs, resource, resourceId: rid, scope },
            ])
            const viaMap = map[iamBuildPermissionKey(action, resource, rid, scope)]
            if (viaCan) out.allows++
            const label = `i=${i} ${op.name} ${subject}/${action}/${resource}/${scope}/${rid}/${JSON.stringify(resAttrs)}`
            if (viaCheck.allowed !== viaCan) out.divergences.push(`${label} can=${viaCan} check=${viaCheck.allowed}`)
            if (viaExplain.decision.allowed !== viaCan)
              out.divergences.push(`${label} can=${viaCan} explain=${viaExplain.decision.allowed}`)
            if (viaDevCan !== viaCan) out.divergences.push(`${label} can=${viaCan} devCan=${viaDevCan}`)
            if (viaMap !== viaCan) out.divergences.push(`${label} can=${viaCan} map=${String(viaMap)}`)
          }
        }
      }
    }
  }
  return out
}

describe('every way of asking for a verdict', () => {
  it.each(SEEDS)('gives the same answer (seed %i)', async (seed) => {
    const run = await parity(seed, 'hierarchical')
    expect(run.divergences.slice(0, 3)).toEqual([])
    expect(run.allows, 'nothing was ever allowed, so agreement proves nothing').toBeGreaterThan(0)
  })

  it('the comparison reports a development engine configured differently', async () => {
    const run = await parity(1, 'flat')
    expect(run.divergences.length, 'two engines that must disagree went unnoticed').toBeGreaterThan(0)
  })
})
