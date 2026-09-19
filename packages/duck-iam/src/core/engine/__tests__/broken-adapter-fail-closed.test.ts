import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl, IamAdapter } from '../../types'
import { IamEngine } from '../engine'

// A store that throws, or answers with something that is not what it promised, may cost an allow. It may never
// buy one: every answer under a broken read must also be an answer the healthy store gives.

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
const TRIALS = 120
const SUBJECTS = ['u1', 'u2']
const ACTIONS = ['read', 'write']
const RESOURCES = ['post', 'comment']
const SCOPES: (string | undefined)[] = [undefined, 'org-1', 'org-1.team-2']
const METHODS = [
  'getSubjectRoles',
  'getSubjectAttributes',
  'getSubjectScopedRoles',
  'listRoles',
  'listPolicies',
  'getSubjectGrantBoundary',
] as const
const BREAKAGES = ['throw', 'null', 'undefined', 'string', 'object', 'number'] as const

function brokenValue(kind: (typeof BREAKAGES)[number]): unknown {
  if (kind === 'null') return null
  if (kind === 'undefined') return undefined
  if (kind === 'string') return 'admin'
  if (kind === 'object') return { admin: true }
  return 7
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

const engineOn = (a: IamAdapter.IAdapter) =>
  new IamEngine({ adapter: a, cacheTTL: 600, mode: 'production', scopeMode: 'hierarchical' })

async function seedStore(): Promise<IamMemoryAdapter> {
  const adapter = new IamMemoryAdapter()
  const seed = engineOn(adapter)
  await seed.admin.saveRole({
    description: '',
    id: 'viewer',
    inherits: [],
    name: 'viewer',
    permissions: [{ action: 'read', resource: 'post' }],
  })
  await seed.admin.saveRole({
    description: '',
    id: 'editor',
    inherits: ['viewer'],
    name: 'editor',
    permissions: [{ action: 'write', resource: 'comment' }],
    scope: 'org-1',
  })
  await seed.admin.savePolicy(policy('p1', 'allow', 'read', 'comment'))
  await seed.admin.setAttributes('u1', { tier: 'gold' })
  await seed.admin.assignRole('u1', 'viewer')
  await seed.admin.assignRole('u2', 'editor', 'org-1')
  return adapter
}

interface IRun {
  escalations: string[]
  healthyAllows: number
}

async function underFailure(seed: number, liar: boolean): Promise<IRun> {
  const rng = mulberry32(seed)
  const adapter = await seedStore()
  const truth = new Map<string, boolean>()
  const healthy = engineOn(adapter)
  for (const s of SUBJECTS)
    for (const action of ACTIONS)
      for (const resource of RESOURCES)
        for (const scope of SCOPES) {
          const key = `${s}/${action}/${resource}/${scope}`
          truth.set(key, await healthy.can(s, action, { attributes: {}, type: resource }, undefined, scope))
        }

  const out: IRun = { escalations: [], healthyAllows: [...truth.values()].filter(Boolean).length }
  for (let i = 0; i < TRIALS && out.escalations.length === 0; i++) {
    const method = pick(rng, METHODS)
    const kind = pick(rng, BREAKAGES)
    const broken = new Proxy(adapter, {
      get(target, prop, receiver) {
        if (prop !== method) return Reflect.get(target, prop, receiver)
        // The control: a store that answers plausibly but wrongly, which must register as an escalation.
        if (liar && prop === 'getSubjectRoles') return async () => ['editor']
        if (kind === 'throw') {
          return async () => {
            throw new Error(`[test] ${String(prop)} is down`)
          }
        }
        return async () => brokenValue(kind)
      },
    })
    const engine = engineOn(broken)
    for (const s of SUBJECTS)
      for (const action of ACTIONS)
        for (const resource of RESOURCES)
          for (const scope of SCOPES) {
            const key = `${s}/${action}/${resource}/${scope}`
            let answer: boolean
            try {
              answer = await engine.can(s, action, { attributes: {}, type: resource }, undefined, scope)
            } catch (err) {
              out.escalations.push(`i=${i} ${method}/${kind} ${key} threw instead of denying: ${String(err)}`)
              continue
            }
            if (answer && truth.get(key) === false) {
              out.escalations.push(`i=${i} ${method}/${kind} ${key} broken=true healthy=false`)
            }
          }
  }
  return out
}

describe('a broken store read', () => {
  it.each(SEEDS)('never turns a deny into an allow, and never throws out (seed %i)', async (seed) => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const run = await underFailure(seed, false)
    expect(run.escalations.slice(0, 3)).toEqual([])
    expect(run.healthyAllows, 'the healthy store allowed nothing, so no escalation was reachable').toBeGreaterThan(0)
  })

  it('the comparison reports a store that answers with roles the subject does not hold', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const run = await underFailure(1, true)
    expect(run.escalations.length, 'an over-granting store went unnoticed').toBeGreaterThan(0)
  })

  it('cannot drop the deny that is the only thing stopping a role grant', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const adapter = new IamMemoryAdapter()
    const seed = engineOn(adapter)
    await seed.admin.saveRole({
      description: '',
      id: 'viewer',
      inherits: [],
      name: 'viewer',
      permissions: [{ action: 'read', resource: 'post' }],
    })
    await seed.admin.assignRole('u1', 'viewer')
    expect(await engineOn(adapter).can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)

    await seed.admin.savePolicy({
      algorithm: 'deny-overrides',
      description: '',
      id: 'p-deny',
      name: 'p-deny',
      rules: [
        {
          actions: ['read'],
          conditions: { all: [{ field: 'action', operator: 'eq', value: 'read' }] },
          effect: 'deny',
          id: 'r1',
          priority: 100,
          resources: ['post'],
        },
      ],
      version: 1,
    })
    expect(await engineOn(adapter).can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)

    const malformed: [string, () => unknown][] = [
      [
        'throws',
        () => {
          throw new Error('[test] listPolicies is down')
        },
      ],
      ['null', () => null],
      ['undefined', () => undefined],
      ['a string', () => 'policies'],
      ['a number', () => 7],
      ['a plain object', () => ({})],
      ['junk rows', () => [null, 'x', 7]],
      ['a policy with no rules', () => [{ algorithm: 'deny-overrides', id: 'p-deny', name: 'p-deny' }]],
    ]
    const answers: string[] = []
    for (const [name, value] of malformed) {
      const broken = new Proxy(adapter, {
        get(target, prop, receiver) {
          if (prop !== 'listPolicies') return Reflect.get(target, prop, receiver)
          return async () => value()
        },
      })
      try {
        answers.push(`${name} -> ${await engineOn(broken).can('u1', 'read', { attributes: {}, type: 'post' })}`)
      } catch (err) {
        answers.push(`${name} -> threw ${err instanceof Error ? err.message : String(err)}`)
      }
    }
    expect(answers.filter((a) => a.endsWith('-> true'))).toEqual([])

    // An empty list is the one answer that is indistinguishable from a store that genuinely holds no policies, so
    // the engine cannot refuse it. Keeping the deny is the adapter's job (see the file adapter's `_rootField`).
    const empty = new Proxy(adapter, {
      get(target, prop, receiver) {
        if (prop !== 'listPolicies') return Reflect.get(target, prop, receiver)
        return async () => []
      },
    })
    expect(await engineOn(empty).can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)
  })
})
