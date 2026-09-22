import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl, IamAdapter } from '../../types'
import { IamEngine } from '../engine'

// Past the compiled table's 32-role mask the engine drops to the interpreter for every check. Padding a store with
// roles nobody holds must not move a single verdict: a tenant that grows past the limit changes evaluator, not
// answers. `verdict-differential` compares the two evaluators on synthetic requests; this one compares them
// through the engine, with real role resolution behind the verdict.

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
const PAD = 40
const SUBJECTS = ['u1', 'u2']
const ROLE_IDS = ['viewer', 'editor', 'manager']
const ACTIONS = ['read', 'write']
const RESOURCES = ['post', 'comment']
const SCOPES: (string | undefined)[] = [undefined, 'org-1', 'org-1.team-2']
const ALGORITHMS = ['deny-overrides', 'allow-overrides', 'first-match', 'highest-priority'] as const

function role(
  id: string,
  perms: AccessControl.IPermission[],
  scope?: string,
  inherits: string[] = [],
): AccessControl.IRole {
  return { description: '', id, inherits, name: id, permissions: perms, ...(scope ? { scope } : {}) }
}

function policy(
  id: string,
  effect: AccessControl.Effect,
  action: string,
  resource: string,
  algorithm: AccessControl.CombiningAlgorithm,
  targets?: AccessControl.IPolicy['targets'],
): AccessControl.IPolicy {
  return {
    algorithm,
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
    ...(targets ? { targets } : {}),
    version: 1,
  }
}

const engineOn = (a: IamAdapter.IAdapter) =>
  new IamEngine({ adapter: a, cacheTTL: 600, mode: 'production', scopeMode: 'hierarchical' })

interface IRun {
  divergences: string[]
  allows: number
}

async function compare(seed: number, pad: number, starveSecond = false): Promise<IRun> {
  const rng = mulberry32(seed)
  const lean = new IamMemoryAdapter()
  const padded = new IamMemoryAdapter()
  for (let n = 0; n < pad; n++) await padded.saveRole(role(`pad-${n}`, []))
  const out: IRun = { allows: 0, divergences: [] }

  for (let i = 0; i < ITERATIONS && out.divergences.length === 0; i++) {
    const s = pick(rng, SUBJECTS)
    const r = pick(rng, ROLE_IDS)
    const sc = pick(rng, SCOPES)
    const perm = { action: pick(rng, ACTIONS), resource: pick(rng, RESOURCES) }
    const permScope = rng() < 0.3 ? 'org-1' : undefined
    const rscope = rng() < 0.3 ? 'org-1' : undefined
    const tier = rng() < 0.5 ? 'gold' : 'silver'
    const inheritPick = pick(rng, ROLE_IDS)
    const algorithm = pick(rng, ALGORITHMS)
    const targets = rng() < 0.3 ? { roles: [pick(rng, ROLE_IDS)] } : undefined
    // Drawn here, not inside an op: each op runs once per store and both must be handed the same value.
    const deletePick = rng() < 0.5 ? 'p1' : 'p2'
    const ops: { name: string; run: (e: IamEngine) => Promise<unknown> }[] = [
      {
        name: 'saveRole',
        run: (e) =>
          e.admin.saveRole(role(r, [{ ...perm, ...(permScope ? { scope: permScope } : {}) }], rscope, [inheritPick])),
      },
      { name: 'deleteRole', run: (e) => e.admin.deleteRole(r) },
      {
        name: 'savePolicy',
        run: (e) => e.admin.savePolicy(policy('p1', 'allow', perm.action, perm.resource, algorithm, targets)),
      },
      {
        name: 'savePolicy(deny)',
        run: (e) => e.admin.savePolicy(policy('p2', 'deny', perm.action, perm.resource, algorithm, targets)),
      },
      { name: 'deletePolicy', run: (e) => e.admin.deletePolicy(deletePick) },
      { name: 'assignRole', run: (e) => e.admin.assignRole(s, r, sc) },
      { name: 'revokeRole', run: (e) => e.admin.revokeRole(s, r, sc) },
      { name: 'setAttributes', run: (e) => e.admin.setAttributes(s, { tier }) },
    ]
    const opIndex = Math.floor(rng() * ops.length)
    for (const adapter of [lean, padded] as const) {
      const op = ops[opIndex]
      if (op === undefined) continue
      if (starveSecond && adapter === padded && op.name === 'setAttributes') continue
      try {
        await op.run(engineOn(adapter))
      } catch {
        /* both stores hold the same non-pad rows, so both refuse the same writes */
      }
    }

    const leanEngine = engineOn(lean)
    const paddedEngine = engineOn(padded)
    for (const subject of SUBJECTS) {
      for (const action of ACTIONS) {
        for (const resource of RESOURCES) {
          for (const scope of SCOPES) {
            const res = { attributes: {}, type: resource }
            const compiled = await leanEngine.can(subject, action, res, undefined, scope)
            const interpreted = await paddedEngine.can(subject, action, res, undefined, scope)
            if (compiled) out.allows++
            if (compiled !== interpreted) {
              out.divergences.push(
                `i=${i} ${ops[opIndex]?.name} ${subject}/${action}/${resource}/${scope} compiled=${compiled} interpreter=${interpreted}`,
              )
            }
          }
        }
      }
    }

    const health = await paddedEngine.healthCheck()
    if (health.compiledTable?.reason !== 'role-limit-exceeded') {
      out.divergences.push(`i=${i} the second engine is not on the role-limit fallback`)
    }
  }
  return out
}

describe('the compiled table and the interpreter it falls back to', () => {
  it.each(SEEDS)('answer the same through the engine (seed %i)', async (seed) => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const run = await compare(seed, PAD)
    expect(run.divergences.slice(0, 3)).toEqual([])
    expect(run.allows, 'nothing was ever allowed, so agreement proves nothing').toBeGreaterThan(0)
  })

  it('the decision matrix reports a store the writes did not reach', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const run = await compare(1, PAD, true)
    expect(run.divergences[0], 'a store that missed every attribute write still agreed').toMatch(/compiled=/)
  })

  it('it is the padding that puts the second engine on the fallback', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const run = await compare(1, 0)
    expect(run.divergences[0], 'an unpadded store claimed the role-limit fallback').toMatch(/not on the role-limit/)
  })
})
