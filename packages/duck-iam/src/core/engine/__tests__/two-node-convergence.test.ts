import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

// Two engines on one store, joined by an invalidator. Whichever one takes the write, the other must answer what a
// cold engine reading the same store answers - a write that invalidates locally but publishes nothing looks fine
// from one node and is stale on every other.

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
const ITERATIONS = 200
const SUBJECTS = ['u1', 'u2']
const ROLE_IDS = ['viewer', 'editor', 'manager']
const ACTIONS = ['read', 'write']
const RESOURCES = ['post', 'comment']
const SCOPES: (string | undefined)[] = [undefined, 'org-1', 'org-1.team-2']

function role(id: string, perms: { action: string; resource: string }[], scope?: string, inherits: string[] = []) {
  return { description: '', id, inherits, name: id, permissions: perms, ...(scope ? { scope } : {}) }
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

/** In-process bus: publish reaches every other subscriber before the write returns. */
function makeBus(deliver = true) {
  const handlers = new Set<(e: IamEngineTypes.IInvalidateEvent) => void>()
  let published = 0
  const port = (): IamEngineTypes.IInvalidator => {
    let own: ((e: IamEngineTypes.IInvalidateEvent) => void) | null = null
    return {
      publish(event) {
        published++
        for (const h of handlers) if (h !== own) h(event)
      },
      subscribe(handler) {
        own = handler
        if (deliver) handlers.add(handler)
        return () => {
          handlers.delete(handler)
        }
      },
    }
  }
  return {
    port,
    get published() {
      return published
    },
  }
}

interface IRun {
  divergences: string[]
  allows: number
  published: number
}

async function converge(seed: number, deliver: boolean): Promise<IRun> {
  const rng = mulberry32(seed)
  const adapter = new IamMemoryAdapter()
  const bus = makeBus(deliver)
  const cfg = { adapter, cacheTTL: 600, mode: 'production' as const, scopeMode: 'hierarchical' as const }
  const a = new IamEngine({ ...cfg, invalidator: bus.port() })
  const b = new IamEngine({ ...cfg, invalidator: bus.port() })
  const out: IRun = { allows: 0, divergences: [], published: 0 }

  for (let i = 0; i < ITERATIONS && out.divergences.length === 0; i++) {
    const s = pick(rng, SUBJECTS)
    const r = pick(rng, ROLE_IDS)
    const sc = pick(rng, SCOPES)
    const perm = { action: pick(rng, ACTIONS), resource: pick(rng, RESOURCES) }
    const rscope = rng() < 0.3 ? 'org-1' : undefined
    const tier = rng() < 0.5 ? 'gold' : 'silver'
    const inheritPick = pick(rng, ROLE_IDS)
    const writer = rng() < 0.5 ? a : b
    const ops: { name: string; run: () => Promise<unknown> }[] = [
      { name: 'saveRole', run: () => writer.admin.saveRole(role(r, [perm], rscope)) },
      { name: 'saveRole(inherits)', run: () => writer.admin.saveRole(role(r, [perm], rscope, [inheritPick])) },
      { name: 'deleteRole', run: () => writer.admin.deleteRole(r) },
      { name: 'savePolicy', run: () => writer.admin.savePolicy(policy('p1', 'allow', perm.action, perm.resource)) },
      { name: 'deletePolicy', run: () => writer.admin.deletePolicy('p1') },
      { name: 'assignRole', run: () => writer.admin.assignRole(s, r, sc) },
      { name: 'revokeRole', run: () => writer.admin.revokeRole(s, r, sc) },
      { name: 'setAttributes', run: () => writer.admin.setAttributes(s, { tier }) },
      {
        name: 'assignRoles',
        run: () => writer.admin.assignRoles([{ roleId: r, subjectId: s, ...(sc ? { scope: sc } : {}) }]),
      },
      {
        name: 'revokeRoles',
        run: () => writer.admin.revokeRoles([{ roleId: r, subjectId: s, ...(sc ? { scope: sc } : {}) }]),
      },
      { name: 'updateAssignmentScope', run: () => writer.admin.updateAssignmentScope(s, r, undefined, sc) },
      {
        name: 'moveRoleScopes',
        run: () => writer.admin.moveRoleScopes([{ roleId: r, subjectId: s, ...(sc ? { toScope: sc } : {}) }]),
      },
    ]
    const op = ops[Math.floor(rng() * ops.length)]
    if (op === undefined) continue
    try {
      await op.run()
    } catch {
      /* a refused write leaves the store as it was; the nodes must still agree about it */
    }

    const cold = new IamEngine(cfg)
    for (const subject of SUBJECTS) {
      for (const action of ACTIONS) {
        for (const resource of RESOURCES) {
          for (const scope of SCOPES) {
            const res = { attributes: {}, type: resource }
            const truth = await cold.can(subject, action, res, undefined, scope)
            const fromA = await a.can(subject, action, res, undefined, scope)
            const fromB = await b.can(subject, action, res, undefined, scope)
            if (truth) out.allows++
            const stale = fromA !== truth ? 'A' : fromB !== truth ? 'B' : null
            if (stale) {
              out.divergences.push(
                `i=${i} ${op.name} writer=${writer === a ? 'A' : 'B'} ${subject}/${action}/${resource}/${scope} stale=${stale} a=${fromA} b=${fromB} cold=${truth}`,
              )
            }
          }
        }
      }
    }
  }
  out.published = bus.published
  return out
}

describe('two nodes on one store', () => {
  it.each(SEEDS)('both answer what a cold engine answers after every write (seed %i)', async (seed) => {
    const run = await converge(seed, true)
    expect(run.divergences.slice(0, 2)).toEqual([])
    expect(run.allows, 'nothing was ever allowed, so agreement proves nothing').toBeGreaterThan(0)
    expect(run.published, 'no event was published, so delivery was never exercised').toBeGreaterThan(0)
  })

  it('the comparison reports a node that stopped receiving events', async () => {
    const run = await converge(1, false)
    expect(run.divergences.length, 'a deaf node went unnoticed - the agreement above is worthless').toBeGreaterThan(0)
  })
})
