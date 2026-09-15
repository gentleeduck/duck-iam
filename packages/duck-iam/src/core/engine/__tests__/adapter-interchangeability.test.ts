import { describe, expect, it, vi } from 'vitest'
import { IamFileAdapter } from '../../../adapters/file'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl, IamAdapter } from '../../types'
import { IamEngine } from '../engine'

// The two adapters that need no infrastructure, driven through the same random op sequence: the store they end up
// holding and the answers built from it must not depend on which one is configured.

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

const SEEDS = [1, 2, 3, 4]
const ITERATIONS = 150
const SUBJECTS = ['u1', 'u2']
const ROLE_IDS = ['viewer', 'editor', 'manager']
const ACTIONS = ['read', 'write']
const RESOURCES = ['post', 'comment']
const SCOPES: (string | undefined)[] = [undefined, 'org-1', 'org-1.team-2']

function makeFakeFS() {
  const files = new Map<string, string>()
  const dirs = new Set<string>(['/data'])
  const enoent = (): NodeJS.ErrnoException => {
    const err = new Error('ENOENT') as NodeJS.ErrnoException
    err.code = 'ENOENT'
    return err
  }
  return {
    async mkdir(path: string) {
      if (dirs.has(path)) {
        const err = new Error('EEXIST') as NodeJS.ErrnoException
        err.code = 'EEXIST'
        throw err
      }
      dirs.add(path)
    },
    async readFile(path: string) {
      const v = files.get(path)
      if (v == null) throw enoent()
      return v
    },
    async realpath(path: string) {
      if (files.has(path) || dirs.has(path)) return path
      throw enoent()
    },
    async rename(from: string, to: string) {
      const data = files.get(from)
      if (data == null) throw enoent()
      files.set(to, data)
      files.delete(from)
    },
    async writeFile(path: string, data: string) {
      files.set(path, data)
    },
  }
}

function role(
  id: string,
  perms: { action: string; resource: string }[],
  scope?: string,
  inherits: string[] = [],
): AccessControl.IRole {
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

const engineOn = (a: IamAdapter.IAdapter) =>
  new IamEngine({ adapter: a, cacheTTL: 600, mode: 'production', scopeMode: 'hierarchical' })

/** The tag identifies the adapter, not the disagreement, so it is removed before comparing refusals. */
const norm = (err: unknown): string =>
  String(err instanceof Error ? err.message : err).replace(/\[@gentleduck\/iam:[a-z]+\]/g, '[adapter]')

async function readBack(a: IamAdapter.IAdapter): Promise<string> {
  const roles = [...(await a.listRoles())].sort((x, y) => x.id.localeCompare(y.id))
  const policies = [...(await a.listPolicies())].sort((x, y) => x.id.localeCompare(y.id))
  const subjects: Record<string, unknown> = {}
  for (const s of SUBJECTS) {
    const scoped = a.getSubjectScopedRoles ? await a.getSubjectScopedRoles(s) : []
    subjects[s] = {
      attributes: await a.getSubjectAttributes(s),
      roles: [...(await a.getSubjectRoles(s))].sort(),
      scoped: [...scoped].sort((x, y) => `${x.role}${x.scope}`.localeCompare(`${y.role}${y.scope}`)),
    }
  }
  // Keys are sorted: which order an adapter happens to store a bag in is not a contract.
  return JSON.stringify({ policies, roles, subjects }, (_k, v) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as Record<string, unknown>).sort(([x], [y]) => x.localeCompare(y)))
      : v,
  )
}

interface IRun {
  divergences: string[]
  allows: number
}

async function differential(seed: number, second: IamAdapter.IAdapter): Promise<IRun> {
  const rng = mulberry32(seed)
  const first = new IamMemoryAdapter()
  const pair = [first, second] as const
  const out: IRun = { allows: 0, divergences: [] }

  for (let i = 0; i < ITERATIONS && out.divergences.length === 0; i++) {
    const s = pick(rng, SUBJECTS)
    const r = pick(rng, ROLE_IDS)
    const sc = pick(rng, SCOPES)
    const perm = { action: pick(rng, ACTIONS), resource: pick(rng, RESOURCES) }
    const rscope = rng() < 0.3 ? 'org-1' : undefined
    const tier = rng() < 0.5 ? 'gold' : 'silver'
    // Every random value is drawn here: each op runs once per adapter and both must be handed the same one.
    const inheritPick = pick(rng, ROLE_IDS)
    const importMode = rng() < 0.5 ? ('replace' as const) : ('merge' as const)
    const ops: { name: string; run: (e: IamEngine) => Promise<unknown> }[] = [
      { name: 'saveRole', run: (e) => e.admin.saveRole(role(r, [perm], rscope)) },
      { name: 'saveRole(inherits)', run: (e) => e.admin.saveRole(role(r, [perm], rscope, [inheritPick])) },
      { name: 'deleteRole', run: (e) => e.admin.deleteRole(r) },
      { name: 'savePolicy', run: (e) => e.admin.savePolicy(policy('p1', 'allow', perm.action, perm.resource)) },
      { name: 'deletePolicy', run: (e) => e.admin.deletePolicy('p1') },
      { name: 'assignRole', run: (e) => e.admin.assignRole(s, r, sc) },
      { name: 'revokeRole', run: (e) => e.admin.revokeRole(s, r, sc) },
      { name: 'setAttributes', run: (e) => e.admin.setAttributes(s, { tier }) },
      {
        name: 'assignRoles',
        run: (e) => e.admin.assignRoles([{ roleId: r, subjectId: s, ...(sc ? { scope: sc } : {}) }]),
      },
      {
        name: 'revokeRoles',
        run: (e) => e.admin.revokeRoles([{ roleId: r, subjectId: s, ...(sc ? { scope: sc } : {}) }]),
      },
      { name: 'updateAssignmentScope', run: (e) => e.admin.updateAssignmentScope(s, r, undefined, sc) },
      {
        name: 'moveRoleScopes',
        run: (e) => e.admin.moveRoleScopes([{ roleId: r, subjectId: s, ...(sc ? { toScope: sc } : {}) }]),
      },
      {
        name: 'import',
        run: (e) =>
          e.admin.import(
            {
              exportedAt: new Date(0).toISOString(),
              policies: [policy('p1', 'allow', perm.action, perm.resource)],
              roles: [role('viewer', [perm])],
              schemaVersion: 1,
            },
            { mode: importMode },
          ),
      },
      {
        name: 'saveRole then mutate the argument',
        run: async (e) => {
          const mutable = { description: '', id: r, inherits: [] as string[], name: r, permissions: [perm] }
          await e.admin.saveRole(mutable)
          mutable.permissions.push({ action: 'write', resource: 'post' })
          mutable.inherits.push('editor')
          return null
        },
      },
      {
        name: 'setAttributes then mutate the bag',
        run: async (e) => {
          const groups = ['a']
          await e.admin.setAttributes(s, { groups, tier })
          groups.push('admins')
          return null
        },
      },
    ]
    const op = ops[Math.floor(rng() * ops.length)]
    if (op === undefined) continue

    const outcomes: string[] = []
    for (const adapter of pair) {
      try {
        outcomes.push(`ok:${JSON.stringify((await op.run(engineOn(adapter))) ?? null)}`)
      } catch (err) {
        outcomes.push(`err:${norm(err)}`)
      }
    }
    if (outcomes[0] !== outcomes[1]) {
      out.divergences.push(`i=${i} ${op.name} outcome first=${outcomes[0]} second=${outcomes[1]}`)
      continue
    }

    const [firstState, secondState] = await Promise.all([readBack(first), readBack(second)])
    if (firstState !== secondState) {
      out.divergences.push(`i=${i} ${op.name} state\n  first=${firstState}\n  second=${secondState}`)
      continue
    }

    const engines = [engineOn(first), engineOn(second)] as const
    for (const subject of SUBJECTS) {
      for (const action of ACTIONS) {
        for (const resource of RESOURCES) {
          for (const scope of SCOPES) {
            const res = { attributes: {}, type: resource }
            const a = await engines[0].can(subject, action, res, undefined, scope)
            const b = await engines[1].can(subject, action, res, undefined, scope)
            if (a) out.allows++
            if (a !== b) {
              out.divergences.push(`i=${i} ${op.name} ${subject}/${action}/${resource}/${scope} first=${a} second=${b}`)
            }
          }
        }
      }
    }
  }
  return out
}

const fileAdapter = () => new IamFileAdapter({ fs: makeFakeFS(), path: '/data/store.json', rootDir: '/data' })

describe('the memory and file adapters', () => {
  it.each(SEEDS)('hold the same store and answer the same after every write (seed %i)', async (seed) => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const run = await differential(seed, fileAdapter())
    expect(run.divergences.slice(0, 2)).toEqual([])
    expect(run.allows, 'nothing was ever allowed, so agreement proves nothing').toBeGreaterThan(0)
  })

  it('the comparison reports an adapter that drops a role scope', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const lossy = fileAdapter()
    const saveRole = lossy.saveRole.bind(lossy)
    lossy.saveRole = async (r) => {
      const { scope: _dropped, ...withoutScope } = r
      return saveRole(withoutScope)
    }
    const run = await differential(1, lossy)
    expect(run.divergences.length, 'a lossy adapter went unnoticed - the agreement above is worthless').toBeGreaterThan(
      0,
    )
  })
})
