import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine'
import { evaluate } from '../../evaluate/evaluate'
import type { AccessControl, IamPrimitives, IamRequest } from '../../types'
import { validatePolicy } from '../../validate'
import { defineRule } from '../rule'
import type { When } from '../when'

// Random condition trees go through the builder; validator, interpreter and compiled table must match a reference
// model. The seed is fixed so a failure replays.

/** mulberry32: the same tiny deterministic PRNG the other fuzzers here use. */
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

const SEED = Number(process.env.DUCKIAM_BUILDER_SEED ?? 0xb0117e5) >>> 0
const TREES = Number(process.env.DUCKIAM_BUILDER_TREES ?? 600)
const REQUESTS_PER_TREE = 6
/** How many of the generated trees also go through both engines. */
const ENGINE_TREES = 30

const ROLES = ['admin', 'editor', 'viewer', 'auditor'] as const
const TIERS = ['free', 'pro', 'enterprise'] as const
const ATTR_KEYS = ['tier', 'level', 'department', 'region'] as const
const DEPARTMENTS = ['engineering', 'sales', 'legal'] as const
const REGIONS = ['eu', 'us', 'apac'] as const

/** The generated tree as data. The builder chain and the reference model each walk it, never each other. */
type Leaf =
  | { kind: 'role'; role: string }
  | { kind: 'tier'; tier: string }
  | { kind: 'levelGte'; level: number }
  | { kind: 'levelLt'; level: number }
  | { kind: 'departmentIn'; departments: string[] }
  | { kind: 'regionNeq'; region: string }
  | { kind: 'exists'; key: string }
type Node =
  | Leaf
  | { kind: 'all'; children: Node[] }
  | { kind: 'any'; children: Node[] }
  | { kind: 'none'; children: Node[] }

function pick<T>(rng: () => number, xs: readonly T[]): T {
  const x = xs[Math.floor(rng() * xs.length)]
  if (x === undefined) throw new Error('empty choice list')
  return x
}

function randomLeaf(rng: () => number): Leaf {
  switch (Math.floor(rng() * 7)) {
    case 0:
      return { kind: 'role', role: pick(rng, ROLES) }
    case 1:
      return { kind: 'tier', tier: pick(rng, TIERS) }
    case 2:
      return { kind: 'levelGte', level: Math.floor(rng() * 10) }
    case 3:
      return { kind: 'levelLt', level: Math.floor(rng() * 10) }
    case 4:
      return { departments: [pick(rng, DEPARTMENTS), pick(rng, DEPARTMENTS)], kind: 'departmentIn' }
    case 5:
      return { kind: 'regionNeq', region: pick(rng, REGIONS) }
    default:
      return { key: pick(rng, ATTR_KEYS), kind: 'exists' }
  }
}

/** Depth is capped well inside the validator's limit; the cap has its own tests. */
function randomNode(rng: () => number, depth: number): Node {
  if (depth >= 3 || rng() < 0.45) return randomLeaf(rng)
  const width = 1 + Math.floor(rng() * 2)
  const children = Array.from({ length: width }, () => randomNode(rng, depth + 1))
  const roll = rng()
  if (roll < 0.45) return { children, kind: 'all' }
  if (roll < 0.85) return { children, kind: 'any' }
  return { children, kind: 'none' }
}

/** Emit the tree through the builder. */
function emit(node: Node, w: When): When {
  switch (node.kind) {
    case 'role':
      return w.role(node.role)
    case 'tier':
      return w.attr('tier', 'eq', node.tier)
    case 'levelGte':
      return w.attr('level', 'gte', node.level)
    case 'levelLt':
      return w.attr('level', 'lt', node.level)
    case 'departmentIn':
      return w.in('subject.attributes.department', node.departments)
    case 'regionNeq':
      return w.attr('region', 'neq', node.region)
    case 'exists':
      return w.exists(`subject.attributes.${node.key}`)
    case 'all':
      return w.and((inner) => node.children.reduce((acc, c) => emit(c, acc), inner))
    case 'any':
      return w.or((inner) => node.children.reduce((acc, c) => emit(c, acc), inner))
    case 'none':
      return w.not((inner) => node.children.reduce((acc, c) => emit(c, acc), inner))
  }
}

interface ISubjectState {
  readonly roles: string[]
  readonly attributes: IamPrimitives.Attributes
}

/** The reference reading of the same tree, written against the request directly. */
function holds(node: Node, s: ISubjectState): boolean {
  switch (node.kind) {
    case 'role':
      return s.roles.includes(node.role)
    case 'tier':
      return s.attributes.tier === node.tier
    case 'levelGte':
      return typeof s.attributes.level === 'number' && s.attributes.level >= node.level
    case 'levelLt':
      return typeof s.attributes.level === 'number' && s.attributes.level < node.level
    case 'departmentIn':
      return typeof s.attributes.department === 'string' && node.departments.includes(s.attributes.department)
    case 'regionNeq':
      return s.attributes.region !== node.region
    case 'exists':
      return s.attributes[node.key] !== undefined && s.attributes[node.key] !== null
    case 'all':
      return node.children.every((c) => holds(c, s))
    case 'any':
      return node.children.some((c) => holds(c, s))
    case 'none':
      return !node.children.some((c) => holds(c, s))
  }
}

function randomSubject(rng: () => number): ISubjectState {
  const attributes: IamPrimitives.Attributes = {}
  if (rng() < 0.85) attributes.tier = pick(rng, TIERS)
  if (rng() < 0.85) attributes.level = Math.floor(rng() * 10)
  if (rng() < 0.75) attributes.department = pick(rng, DEPARTMENTS)
  if (rng() < 0.75) attributes.region = pick(rng, REGIONS)
  const roles = ROLES.filter(() => rng() < 0.4)
  return { attributes, roles: [...roles] }
}

function requestFor(s: ISubjectState): IamRequest.IAccessRequest {
  return {
    action: 'update',
    resource: { attributes: {}, type: 'post' },
    subject: { attributes: s.attributes, id: 'u1', roles: s.roles },
  }
}

function ruleFor(node: Node, id: string): AccessControl.IRule {
  return defineRule(id)
    .allow()
    .on('update')
    .of('post')
    .when((w) => emit(node, w))
    .build()
}

describe('a random condition tree means the same thing to everyone who reads it', () => {
  it('the interpreter agrees with the reference model on every generated tree', () => {
    const rng = mulberry32(SEED)
    let allowed = 0
    let denied = 0

    for (let i = 0; i < TREES; i++) {
      const node = randomNode(rng, 0)
      const rule = ruleFor(node, `r${i}`)
      const policy: AccessControl.IPolicy = { algorithm: 'deny-overrides', id: 'p', name: 'p', rules: [rule] }

      const report = validatePolicy(policy)
      expect(
        report.issues.filter((issue) => issue.type === 'error'),
        `tree ${i} did not validate`,
      ).toEqual([])

      for (let r = 0; r < REQUESTS_PER_TREE; r++) {
        const subject = randomSubject(rng)
        const expected = holds(node, subject)
        const actual = evaluate([policy], requestFor(subject), 'deny', 'and').allowed
        expect(
          actual,
          `seed ${SEED}, tree ${i}, request ${r}\ntree: ${JSON.stringify(node)}\nsubject: ${JSON.stringify(subject)}`,
        ).toBe(expected)
        if (expected) allowed++
        else denied++
      }
    }

    // Guard against a sweep that only exercises one arm passing vacuously.
    expect(allowed, 'the generator never produced an allow').toBeGreaterThan(TREES)
    expect(denied, 'the generator never produced a deny').toBeGreaterThan(TREES)
  })

  it('both engines agree with the reference model, and so with each other', async () => {
    const rng = mulberry32(SEED ^ 0x9e3779b9)

    for (let i = 0; i < ENGINE_TREES; i++) {
      const node = randomNode(rng, 0)
      const policy: AccessControl.IPolicy = {
        algorithm: 'deny-overrides',
        id: `p${i}`,
        name: 'p',
        rules: [ruleFor(node, `r${i}`)],
      }
      const subject = randomSubject(rng)
      const expected = holds(node, subject)
      const detail = `seed ${SEED}, tree ${i}\ntree: ${JSON.stringify(node)}\nsubject: ${JSON.stringify(subject)}`

      // A fresh adapter per engine: both cache, so a shared one would let one engine answer for the other.
      const ask = async (mode: 'development' | 'production'): Promise<boolean> => {
        const adapter = new IamMemoryAdapter({ policies: [policy] })
        await adapter.setSubjectAttributes('u1', subject.attributes)
        for (const role of subject.roles) {
          await adapter.saveRole({ id: role, name: role, permissions: [] })
          await adapter.assignRole('u1', role)
        }
        return await new IamEngine({ adapter, defaultEffect: 'deny', mode }).can('u1', 'update', {
          attributes: {},
          type: 'post',
        })
      }

      expect(await ask('production'), `production: ${detail}`).toBe(expected)
      // Development also cross-checks interpreter against table and fails closed, so a mismatch shows as a deny.
      expect(await ask('development'), `development: ${detail}`).toBe(expected)
    }
  }, 60_000)
})
