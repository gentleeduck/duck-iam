/**
 * The compiled table vs the interpreter, over catalogs nobody hand-wrote.
 *
 * Deliberately NOT named `*.e2e.test.ts`, despite being a sweep. It imports
 * `IamMemoryAdapter` and nothing else - no Postgres, no Redis, no container -
 * and finishes in about thirteen seconds. Under the old name it was excluded
 * from `bun run test` by the `--exclude` glob in `package.json` that drops
 * every `.e2e.test.ts` file, and
 * no CI workflow invokes `test:e2e`, so the one detector in this package that
 * can catch an under-granting compiled table ran in no lane at all: a mutation
 * to `compiled.lookup.ts` that denies where the interpreter allows shipped
 * green through every job. The manifesto's rule is "prove the harness runs";
 * a suite that executes nowhere is further from that than a skipped one, which
 * at least reports itself. The `.e2e.` suffix is for tests that need external
 * infrastructure, and this needs none.
 *
 * As of Batch 52 BOTH modes take their verdict from the compiled table;
 * development additionally runs the interpreter for provenance and
 * `console.error`s + throws when the two disagree (see
 * `docs/engine-rewrite.md`, "Both modes evaluate through the table"). That
 * design only pays off if a disagreement actually exists somewhere and is
 * findable, so this file generates catalogs and hunts for one.
 *
 * Two independent detectors, because neither alone is sufficient:
 *
 *  1. `production.can()` vs `development.check().allowed`. This catches the
 *     "table allows, interpreter denies" direction only - the other direction
 *     is MASKED, because the dev disagreement throw is swallowed by
 *     `authorize()`'s fail-closed catch and reported as `allowed: false`,
 *     which happens to equal the table's deny. A suite comparing only the two
 *     booleans would report green on half of all possible divergences.
 *  2. The dev engine's `onError` hook plus a `console.error` spy, both keyed on
 *     the literal "compiled table and interpreter disagree" message. This is
 *     direction-agnostic and is the authoritative detector here.
 *
 * Randomness is a seeded mulberry32 PRNG. `DUCKIAM_VERDICT_SEED` overrides the
 * master seed and `DUCKIAM_VERDICT_CONFIGS` the catalog count, so a reported
 * failure is replayable and a sweep can be widened without editing the file.
 */
import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { iamBuildPermissionKey } from '../../../shared/keys'
import type { AccessControl, IamPrimitives } from '../../types'
import { CellKind, compileTable } from '../compiled/compiled.compile'
import { IamEngine } from '../engine'

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

/** Independent, deterministic per-iteration seed derived from the master seed. */
function seedFor(base: number, i: number): number {
  let h = (base ^ Math.imul(i + 1, 0x9e3779b9)) >>> 0
  h = Math.imul(h ^ (h >>> 16), 0x45d9f3b)
  h = Math.imul(h ^ (h >>> 16), 0x45d9f3b)
  h = (h ^ (h >>> 16)) >>> 0
  return h
}

function hex(n: number): string {
  return `0x${(n >>> 0).toString(16)}`
}

const SEED = Number(process.env.DUCKIAM_VERDICT_SEED ?? 0x51ded00d) >>> 0
// 6000 catalogs x 16 comparisons ~= 96k verdict pairs in a few seconds. Sized
// so the two known divergences (iterations 1369 and 4710 under the default
// seed) are inside the sweep - a count that misses them would report green on a
// live Critical bug.
const CONFIG_COUNT = Number(process.env.DUCKIAM_VERDICT_CONFIGS ?? 6000)
const REQUESTS_PER_CONFIG = 12

function randInt(rng: () => number, min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1))
}
function randBool(rng: () => number, pTrue = 0.5): boolean {
  return rng() < pTrue
}
function pick<T>(rng: () => number, arr: readonly T[]): T {
  return arr[Math.floor(rng() * arr.length)]!
}
function pickN<T>(rng: () => number, arr: readonly T[], n: number): T[] {
  const pool = [...arr]
  const count = Math.min(n, pool.length)
  const out: T[] = []
  for (let k = 0; k < count; k++) {
    const idx = Math.floor(rng() * pool.length)
    out.push(pool[idx]!)
    pool.splice(idx, 1)
  }
  return out
}

const ACTIONS = ['read', 'update', 'delete', 'post:create', 'post:edit', 'view:summary', 'admin.reset'] as const
const RESOURCES = ['post', 'comment', 'doc', 'secret', 'org.team', 'org.team.a', 'billing'] as const
const WILDCARD_ACTIONS = ['*', 'post:*', 'view:*', 'admin.*'] as const
const WILDCARD_RESOURCES = ['*', 'org.*', 'org:*'] as const
const SCOPES = ['org-1', 'org-2', 'org-1.team-a', 'org-1.team-a.sub', ''] as const
const DEPTS = ['eng', 'sales', 'ops'] as const
const TAGS = ['vip', 'trial', 'internal'] as const
const SUBJECT_IDS = ['u0', 'u1', 'u2', 'u3', 'u4', 'u5'] as const
const ALGORITHMS = ['deny-overrides', 'allow-overrides', 'first-match', 'highest-priority'] as const

/**
 * Role counts to hit, cycled deterministically. 31/32 straddle the 32-bit grant
 * mask capacity; 33/64/65 are the interpreter-fallback side of that boundary
 * (`compileTable` throws `IamRoleLimitExceededError` past 32 and both modes drop
 * to the interpreter, so those iterations exercise the fallback, not the table).
 */
const ROLE_COUNT_PLAN = [0, 1, 2, 3, 5, 8, 31, 32, 33, 64, 65] as const

/** Every counter the distribution assertions read. A generator that emits one trivial catalog N times fails these, not the differential. */
interface IStats {
  comparisons: number
  allow: number
  deny: number
  roleCounts: Map<number, number>
  tableUnavailable: number
  wildcardPerm: number
  scopedPerm: number
  roleLevelScope: number
  conditionedPerm: number
  cyclicInherits: number
  diamondInherits: number
  emptyAnyCondition: number
  deepCondition: number
  unknownGroupKey: number
  throwingOperator: number
  unknownOperator: number
  unknownAlgorithm: number
  roleTargetedPolicy: number
  literalTargetedPolicy: number
  wildcardTargetedPolicy: number
  wildcardRulePattern: number
  scopedAssignment: number
  hierarchicalMode: number
  defaultAllow: number
  combineAllowOverrides: number
  constAllowCells: number
  constDenyCells: number
  dynamicCells: number
  rbacDynamicCells: number
  residualPolicies: number
  nonFinitePriority: number
}

function newStats(): IStats {
  return {
    allow: 0,
    combineAllowOverrides: 0,
    comparisons: 0,
    conditionedPerm: 0,
    constAllowCells: 0,
    constDenyCells: 0,
    cyclicInherits: 0,
    deepCondition: 0,
    defaultAllow: 0,
    deny: 0,
    diamondInherits: 0,
    dynamicCells: 0,
    emptyAnyCondition: 0,
    hierarchicalMode: 0,
    literalTargetedPolicy: 0,
    nonFinitePriority: 0,
    rbacDynamicCells: 0,
    residualPolicies: 0,
    roleCounts: new Map<number, number>(),
    roleLevelScope: 0,
    roleTargetedPolicy: 0,
    scopedAssignment: 0,
    scopedPerm: 0,
    tableUnavailable: 0,
    throwingOperator: 0,
    unknownAlgorithm: 0,
    unknownGroupKey: 0,
    unknownOperator: 0,
    wildcardPerm: 0,
    wildcardRulePattern: 0,
    wildcardTargetedPolicy: 0,
  }
}

/** Nest `{all:[...]}` `depth` levels deep around a leaf condition. `MAX_CONDITION_DEPTH` is 10, so 8..12 straddles the fail-closed cut. */
function nestedCondition(depth: number, leaf: AccessControl.ICondition): AccessControl.IConditionGroup {
  let group: AccessControl.IConditionGroup = { all: [leaf] }
  for (let i = 1; i < depth; i++) group = { all: [group] }
  return group
}

function randomCondition(rng: () => number, stats: IStats): AccessControl.IConditionGroup {
  // Weighted, not uniform: unconditional rules are the only thing that lowers a
  // cell to CONST_ALLOW / CONST_DENY, and a uniform draw left the two constant
  // cell kinds unrepresented - the differential would then only ever have
  // exercised DYNAMIC cells.
  if (randBool(rng, 0.3)) return { all: [] }
  switch (randInt(rng, 0, 11)) {
    case 0:
      return { all: [] } // unconditionally true - lowers into a CONST cell
    case 1:
      stats.emptyAnyCondition++
      // Request-independently FALSE. `matchesUnconditionally` deliberately
      // refuses to lower this, so it must land in a DYNAMIC cell.
      return { any: [] }
    case 2:
      return { all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }] }
    case 3:
      return {
        all: [
          {
            field: 'subject.attributes.level',
            operator: pick(rng, ['gte', 'lt', 'eq'] as const),
            value: randInt(rng, 0, 5),
          },
        ],
      }
    case 4:
      return {
        any: [
          { field: 'subject.attributes.dept', operator: 'eq', value: pick(rng, DEPTS) },
          { field: 'subject.attributes.active', operator: 'eq', value: true },
        ],
      }
    case 5:
      return { none: [{ field: 'subject.attributes.tags', operator: 'contains', value: pick(rng, TAGS) }] }
    case 6:
      return { all: [{ field: 'scope', operator: 'starts_with', value: pick(rng, ['org-1', 'org-2']) }] }
    case 7: {
      stats.deepCondition++
      return nestedCondition(randInt(rng, 8, 12), {
        field: 'subject.attributes.level',
        operator: 'gte',
        value: randInt(rng, 0, 5),
      })
    }
    case 8: {
      stats.throwingOperator++
      // `subject.attributes.blob` is 3000 UTF-16 units, over MAX_REGEX_INPUT_LENGTH
      // (2048), so `matches` throws IamRegexInputTooLargeError - the "operator that
      // throws" lever, which both evaluators must resolve to Indeterminate identically.
      return { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+b' }] }
    }
    case 9: {
      stats.unknownOperator++
      // Deliberately malformed: an operator no `ops` entry answers to. Reaches
      // `evalCondition`'s unknown-operator throw. The cast manufactures the bad
      // value on purpose - a store row or hand-edited config can carry one.
      const op = 'no-such-operator' as AccessControl.Operator
      return { all: [{ field: 'subject.attributes.level', operator: op, value: 1 }] }
    }
    case 10: {
      stats.unknownGroupKey++
      // Deliberately malformed group key (a typo'd `all`, a hand-edited row).
      // `evalConditionGroup` reads it as false; `matchesUnconditionally` refuses
      // to lower it. The cast is what makes the malformed shape expressible.
      const bad = { alll: [{ field: 'subject.id', operator: 'exists' }] } as unknown as AccessControl.IConditionGroup
      return bad
    }
    default:
      return { all: [{ field: 'resource.attributes.ownerId', operator: 'exists' }] }
  }
}

function genPermission(rng: () => number, stats: IStats): AccessControl.IPermission {
  const roll = rng()
  if (roll < 0.15) {
    stats.wildcardPerm++
    return randBool(rng)
      ? { action: pick(rng, WILDCARD_ACTIONS), resource: pick(rng, RESOURCES) }
      : { action: pick(rng, ACTIONS), resource: pick(rng, WILDCARD_RESOURCES) }
  }
  const base = { action: pick(rng, ACTIONS), resource: pick(rng, RESOURCES) }
  if (roll < 0.35) {
    stats.scopedPerm++
    return { ...base, scope: pick(rng, SCOPES) }
  }
  if (roll < 0.5) {
    stats.conditionedPerm++
    return { ...base, conditions: randomCondition(rng, stats) }
  }
  if (roll < 0.56) {
    stats.scopedPerm++
    stats.conditionedPerm++
    return { ...base, conditions: randomCondition(rng, stats), scope: pick(rng, SCOPES) }
  }
  return base
}

/**
 * Roles with a real inheritance graph: chains, diamonds, and (10% of catalogs)
 * a deliberate cycle, which the compiler's `seen` map and `collectPermissions`'
 * are both meant to cut identically.
 */
function genRoles(rng: () => number, count: number, stats: IStats): AccessControl.IRole[] {
  const ids = Array.from({ length: count }, (_, i) => `role-${i}`)
  const roles: AccessControl.IRole[] = ids.map((id, idx) => {
    const permissions = Array.from({ length: randInt(rng, 0, 3) }, () => genPermission(rng, stats))
    const role: AccessControl.IRole = { id, name: id, permissions }
    const priors = ids.slice(0, idx)
    let out = role
    if (priors.length >= 2 && randBool(rng, 0.25)) {
      stats.diamondInherits++
      out = { ...out, inherits: pickN(rng, priors, 2) }
    } else if (priors.length > 0 && randBool(rng, 0.35)) {
      out = { ...out, inherits: [pick(rng, priors)] }
    }
    if (randBool(rng, 0.12)) {
      stats.roleLevelScope++
      out = { ...out, scope: pick(rng, SCOPES) }
    }
    return out
  })

  // 10% of catalogs get a genuine cycle: role-0 inherits the last role, which
  // already reaches role-0. The validator is not in this path - an adapter can
  // return exactly this - so both walkers must terminate and agree.
  if (count >= 2 && randBool(rng, 0.1)) {
    stats.cyclicInherits++
    const last = roles[count - 1]!
    roles[0] = { ...roles[0]!, inherits: [last.id] }
    roles[count - 1] = { ...last, inherits: [...(last.inherits ?? []), roles[0]!.id] }
  }
  return roles
}

function genRule(rng: () => number, id: string, stats: IStats): AccessControl.IRule {
  const wildcard = randBool(rng, 0.22)
  if (wildcard) stats.wildcardRulePattern++
  const priorityRoll = rng()
  let priority = randInt(rng, 0, 5)
  if (priorityRoll < 0.05) {
    stats.nonFinitePriority++
    priority = Number.NaN
  }
  return {
    actions: wildcard && randBool(rng) ? [pick(rng, WILDCARD_ACTIONS)] : pickN(rng, ACTIONS, randInt(rng, 1, 2)),
    conditions: randomCondition(rng, stats),
    effect: pick(rng, ['allow', 'deny'] as const),
    id,
    priority,
    resources: wildcard && randBool(rng) ? [pick(rng, WILDCARD_RESOURCES)] : pickN(rng, RESOURCES, randInt(rng, 1, 2)),
  }
}

function genPolicy(rng: () => number, id: string, roleIds: readonly string[], stats: IStats): AccessControl.IPolicy {
  let algorithm: AccessControl.CombiningAlgorithm = pick(rng, ALGORITHMS)
  if (randBool(rng, 0.06)) {
    stats.unknownAlgorithm++
    // Deliberately malformed: an algorithm outside `combiners`. Both paths must
    // treat it as Indeterminate, never fall through to a permissive default.
    algorithm = 'bogus-algorithm' as AccessControl.CombiningAlgorithm
  }
  const rules = Array.from({ length: randInt(rng, 1, 3) }, (_, i) => genRule(rng, `${id}-r${i}`, stats))
  const policy: AccessControl.IPolicy = { algorithm, id, name: id, rules }

  const shape = rng()
  if (shape < 0.18 && roleIds.length > 0) {
    stats.roleTargetedPolicy++
    return { ...policy, targets: { roles: pickN(rng, roleIds, randInt(rng, 1, Math.min(3, roleIds.length))) } }
  }
  if (shape < 0.3) {
    stats.literalTargetedPolicy++
    return { ...policy, targets: { actions: pickN(rng, ACTIONS, randInt(rng, 1, 3)) } }
  }
  if (shape < 0.4) {
    stats.literalTargetedPolicy++
    return { ...policy, targets: { resources: pickN(rng, RESOURCES, randInt(rng, 1, 3)) } }
  }
  if (shape < 0.5) {
    stats.wildcardTargetedPolicy++
    // A wildcard in `targets` forces the whole policy residual - the branch a
    // literal target restriction deliberately does NOT take.
    return randBool(rng)
      ? { ...policy, targets: { actions: [pick(rng, WILDCARD_ACTIONS)] } }
      : { ...policy, targets: { resources: [pick(rng, WILDCARD_RESOURCES)] } }
  }
  if (shape < 0.58 && roleIds.length > 0) {
    stats.roleTargetedPolicy++
    stats.literalTargetedPolicy++
    return {
      ...policy,
      targets: {
        actions: pickN(rng, ACTIONS, 2),
        roles: pickN(rng, roleIds, 1),
      },
    }
  }
  return policy
}

interface IGeneratedConfig {
  roles: AccessControl.IRole[]
  policies: AccessControl.IPolicy[]
  assignments: Record<string, string[]>
  scopedAssignments: Array<{ subjectId: string; role: string; scope: string }>
  attributes: Record<string, IamPrimitives.Attributes>
  policyCombine: AccessControl.PolicyCombine
  defaultEffect: AccessControl.Effect
  scopeMode: 'flat' | 'hierarchical'
  scopeCombine: 'union' | 'override'
  roleCount: number
}

function genConfig(rng: () => number, i: number, stats: IStats): IGeneratedConfig {
  const roleCount = ROLE_COUNT_PLAN[i % ROLE_COUNT_PLAN.length]!
  stats.roleCounts.set(roleCount, (stats.roleCounts.get(roleCount) ?? 0) + 1)
  const roles = genRoles(rng, roleCount, stats)
  const roleIds = roles.map((r) => r.id)

  const policies = Array.from({ length: randInt(rng, 0, 4) }, (_, idx) =>
    genPolicy(rng, `policy-${idx}`, roleIds, stats),
  )

  const assignments: Record<string, string[]> = {}
  const scopedAssignments: Array<{ subjectId: string; role: string; scope: string }> = []
  const attributes: Record<string, IamPrimitives.Attributes> = {}
  for (const sid of SUBJECT_IDS) {
    const n = roleIds.length === 0 ? 0 : randInt(rng, 0, Math.min(3, roleIds.length))
    assignments[sid] = n === 0 ? [] : pickN(rng, roleIds, n)
    if (roleIds.length > 0 && randBool(rng, 0.3)) {
      stats.scopedAssignment++
      // `''` is excluded here only: the store schema forbids a blank assignment
      // scope, and this generator's catalogs are replayed into Postgres by the
      // sibling suite.
      const scope = pick(
        rng,
        SCOPES.filter((s) => s.length > 0),
      )
      scopedAssignments.push({ role: pick(rng, roleIds), scope, subjectId: sid })
    }
    attributes[sid] = {
      active: randBool(rng, 0.7),
      // Oversized on purpose: the `matches` operator throws above 2048 units.
      blob: 'a'.repeat(3000),
      dept: pick(rng, DEPTS),
      level: randInt(rng, 0, 5),
      tags: pickN(rng, TAGS, randInt(rng, 0, 2)),
    }
  }

  const policyCombine: AccessControl.PolicyCombine = randBool(rng) ? 'and' : 'allow-overrides'
  if (policyCombine === 'allow-overrides') stats.combineAllowOverrides++
  const defaultEffect: AccessControl.Effect = randBool(rng, 0.3) ? 'allow' : 'deny'
  if (defaultEffect === 'allow') stats.defaultAllow++
  const scopeMode = randBool(rng, 0.4) ? 'hierarchical' : 'flat'
  if (scopeMode === 'hierarchical') stats.hierarchicalMode++

  return {
    assignments,
    attributes,
    defaultEffect,
    policies,
    policyCombine,
    roleCount,
    roles,
    scopeCombine: randBool(rng, 0.25) ? 'override' : 'union',
    scopedAssignments,
    scopeMode,
  }
}

interface IGeneratedRequest {
  subjectId: string
  action: string
  resourceType: string
  resourceId?: string
  resourceAttributes: IamPrimitives.Attributes
  scope?: string
}

function genRequest(rng: () => number): IGeneratedRequest {
  const subjectId = pick(rng, SUBJECT_IDS)
  const action = randBool(rng, 0.85) ? pick(rng, ACTIONS) : `unknown-action-${randInt(rng, 0, 5)}`
  const resourceRoll = rng()
  const resourceType =
    resourceRoll < 0.12
      ? `org.team.${randInt(rng, 0, 3)}` // deeper than any literal - exercises hierarchical matching
      : resourceRoll < 0.22
        ? `unknown-resource-${randInt(rng, 0, 5)}`
        : pick(rng, RESOURCES)
  const ownerId = randBool(rng, 0.4) ? subjectId : pick(rng, SUBJECT_IDS)
  return {
    action,
    resourceAttributes: { ownerId, status: pick(rng, ['active', 'archived'] as const) },
    resourceId: randBool(rng, 0.3) ? `res-${randInt(rng, 0, 4)}` : undefined,
    resourceType,
    scope: randBool(rng, 0.45) ? pick(rng, SCOPES) : undefined,
    subjectId,
  }
}

async function buildAdapter(cfg: IGeneratedConfig): Promise<IamMemoryAdapter> {
  const adapter = new IamMemoryAdapter({
    assignments: cfg.assignments,
    attributes: cfg.attributes,
    policies: cfg.policies,
    roles: cfg.roles,
  })
  for (const a of cfg.scopedAssignments) await adapter.assignRole(a.subjectId, a.role, a.scope)
  return adapter
}

/** Record the compiled table's own shape, so "the generator varied the catalog" is asserted on structure, not on generator intent. */
function recordTableShape(cfg: IGeneratedConfig, stats: IStats): void {
  let table: ReturnType<typeof compileTable>
  try {
    table = compileTable(cfg.roles, cfg.policies, cfg.policyCombine, cfg.scopeMode)
  } catch {
    // Past 32 roles compileTable throws and both modes fall back to the
    // interpreter; that is a shape too, counted separately.
    stats.tableUnavailable++
    return
  }
  for (let i = 0; i < table.kind.length; i++) {
    if (table.touched[i] === 0) continue
    if (table.kind[i] === CellKind.CONST_ALLOW) stats.constAllowCells++
    else if (table.kind[i] === CellKind.CONST_DENY) stats.constDenyCells++
    else stats.dynamicCells++
  }
  for (const g of table.rbacDynamic) if (g !== undefined) stats.rbacDynamicCells += g.length
  stats.residualPolicies += table.residualPolicies.length
}

function repro(i: number, iterSeed: number, cfg: IGeneratedConfig, extra: unknown): string {
  return [
    `VERDICT MISMATCH at iteration ${i} (SEED=${hex(SEED)}, iterSeed=${hex(iterSeed)}).`,
    `Replay with DUCKIAM_VERDICT_SEED=${SEED} and read iteration ${i}.`,
    `policyCombine=${cfg.policyCombine} defaultEffect=${cfg.defaultEffect} scopeMode=${cfg.scopeMode} scopeCombine=${cfg.scopeCombine}`,
    `roles: ${JSON.stringify(cfg.roles)}`,
    `policies: ${JSON.stringify(cfg.policies)}`,
    `assignments: ${JSON.stringify(cfg.assignments)}`,
    `scopedAssignments: ${JSON.stringify(cfg.scopedAssignments)}`,
    `attributes: ${JSON.stringify(cfg.attributes, (k, v) => (k === 'blob' ? '<3000 chars>' : v))}`,
    `case: ${JSON.stringify(extra)}`,
  ].join('\n')
}

const DISAGREE_MARKER = 'compiled table and interpreter disagree'

describe('E2E verdict parity: compiled table vs interpreter over generated catalogs', () => {
  it(`finds no table/interpreter disagreement across ${CONFIG_COUNT} generated catalogs (SEED=${hex(SEED)})`, {
    timeout: 600_000,
  }, async () => {
    const stats = newStats()
    const disagreements: string[] = []
    const mismatches: string[] = []
    // Set before every evaluated request so a disagreement - which surfaces
    // out-of-band, via console.error and the onError hook - can be reported
    // with the catalog and request that produced it rather than as a bare
    // message with no reproduction.
    let context = () => 'no request in flight'

    const realWarn = console.warn
    const realError = console.error
    let warnCount = 0
    console.warn = () => {
      warnCount++
    }
    console.error = (...args: unknown[]) => {
      const text = args.map((a) => String(a)).join(' ')
      if (text.includes(DISAGREE_MARKER)) disagreements.push(`${text}\n${context()}`)
      else realError(...args)
    }

    try {
      for (let i = 0; i < CONFIG_COUNT; i++) {
        const iterSeed = seedFor(SEED, i)
        const rng = mulberry32(iterSeed)
        const cfg = genConfig(rng, i, stats)
        recordTableShape(cfg, stats)

        const common = {
          allowFailOpen: cfg.defaultEffect === 'allow',
          defaultEffect: cfg.defaultEffect,
          policyCombine: cfg.policyCombine,
          scopeCombine: cfg.scopeCombine,
          scopeMode: cfg.scopeMode,
        }
        const production = new IamEngine({ adapter: await buildAdapter(cfg), ...common, mode: 'production' })
        const development = new IamEngine({
          adapter: await buildAdapter(cfg),
          ...common,
          hooks: {
            onError: (err) => {
              if (err.message.includes(DISAGREE_MARKER)) disagreements.push(`${err.message}\n${context()}`)
            },
          },
          mode: 'development',
        })

        const requests = Array.from({ length: REQUESTS_PER_CONFIG }, () => genRequest(rng))
        for (const [ri, r] of requests.entries()) {
          const resource = { attributes: r.resourceAttributes, id: r.resourceId, type: r.resourceType }
          context = () => repro(i, iterSeed, cfg, { kind: 'can/check', request: r, requestIndex: ri })
          const prod = await production.can(r.subjectId, r.action, resource, undefined, r.scope)
          const dev = await development.check(r.subjectId, r.action, resource, undefined, r.scope)
          stats.comparisons++
          if (prod) stats.allow++
          else stats.deny++

          // `failure: 'evaluation'` is what a swallowed disagreement throw
          // looks like from outside; record it even when the two booleans
          // happen to line up.
          if (dev.failure === 'evaluation') {
            mismatches.push(repro(i, iterSeed, cfg, { kind: 'dev-evaluation-failure', request: r, requestIndex: ri }))
          }
          if (prod !== dev.allowed) {
            mismatches.push(
              repro(i, iterSeed, cfg, {
                devReason: dev.reason,
                devResult: dev.allowed,
                kind: 'can/check',
                prodResult: prod,
                request: r,
                requestIndex: ri,
              }),
            )
          }
        }

        // permissions() batch: same catalog, the other public entry point.
        const batch = requests.slice(0, 4).map((r) => ({
          action: r.action,
          resource: r.resourceType,
          resourceId: r.resourceId,
          scope: r.scope,
        }))
        const subjectId = pick(rng, SUBJECT_IDS)
        const prodMap = await production.permissions(subjectId, batch)
        for (const c of batch) {
          context = () => repro(i, iterSeed, cfg, { check: c, kind: 'permissions()', subjectId })
          const devDecision = await development.check(
            subjectId,
            c.action,
            { attributes: {}, id: c.resourceId, type: c.resource },
            undefined,
            c.scope,
          )
          const key = iamBuildPermissionKey(c.action, c.resource, c.resourceId, c.scope)
          stats.comparisons++
          if (prodMap[key]) stats.allow++
          else stats.deny++
          if (prodMap[key] !== devDecision.allowed) {
            mismatches.push(
              repro(i, iterSeed, cfg, {
                check: c,
                devResult: devDecision.allowed,
                kind: 'permissions()',
                prodResult: prodMap[key],
                subjectId,
              }),
            )
          }
        }

        production.dispose()
        development.dispose()
      }
    } finally {
      console.warn = realWarn
      console.error = realError
    }

    // The generator has to have produced varied catalogs, or a green
    // differential means nothing. These assert on the compiled table's own
    // structure and on the observed verdict spread, not on generator intent.
    expect(stats.comparisons).toBeGreaterThanOrEqual(CONFIG_COUNT * (REQUESTS_PER_CONFIG + 4))
    expect(stats.allow).toBeGreaterThan(stats.comparisons * 0.05)
    expect(stats.deny).toBeGreaterThan(stats.comparisons * 0.05)
    for (const count of ROLE_COUNT_PLAN) expect(stats.roleCounts.get(count) ?? 0).toBeGreaterThan(0)
    const mustBeNonZero: Array<keyof IStats> = [
      'combineAllowOverrides',
      'conditionedPerm',
      'constAllowCells',
      'constDenyCells',
      'cyclicInherits',
      'deepCondition',
      'defaultAllow',
      'diamondInherits',
      'dynamicCells',
      'emptyAnyCondition',
      'hierarchicalMode',
      'literalTargetedPolicy',
      'nonFinitePriority',
      'rbacDynamicCells',
      'residualPolicies',
      'roleLevelScope',
      'roleTargetedPolicy',
      'scopedAssignment',
      'scopedPerm',
      'tableUnavailable',
      'throwingOperator',
      'unknownAlgorithm',
      'unknownGroupKey',
      'unknownOperator',
      'wildcardPerm',
      'wildcardRulePattern',
      'wildcardTargetedPolicy',
    ]
    for (const key of mustBeNonZero) {
      const value = stats[key]
      expect(typeof value === 'number' ? value : 0, `generator never produced "${key}"`).toBeGreaterThan(0)
    }
    // The role-limit fallback warns; the fail-open defaultEffect warns. Both
    // are expected, so a zero here would mean the stub never ran.
    expect(warnCount).toBeGreaterThan(0)

    // The finding, if there is one. Reported one sample per distinct shape
    // rather than the first N raw hits: a single frequent divergence would
    // otherwise fill the output and hide a rarer, different one behind it.
    const byShape = new Map<string, { count: number; sample: string }>()
    for (const d of disagreements) {
      const m = /table=(\w+), interpreter=(\w+) \(interpreter reason: ([^)]*)/.exec(d)
      const shape = m ? `table=${m[1]} interpreter=${m[2]} :: ${m[3]!.replace(/"[^"]*"/g, '"X"')}` : d.slice(0, 120)
      const seen = byShape.get(shape)
      if (seen) seen.count++
      else byShape.set(shape, { count: 1, sample: d })
    }
    const report = [...byShape]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 3)
      .map(([shape, v]) => `### ${v.count}x ${shape}\n${v.sample}`)
      .join('\n\n')
    expect(report, `table/interpreter disagreement (${disagreements.length} hits, ${byShape.size} shapes)`).toEqual('')
    expect(mismatches.slice(0, 3).join('\n===\n'), 'production/development verdict mismatch').toEqual('')
  })

  it("production still refuses policyCombine 'first-applicable' at construction", () => {
    // Documents why the sweep above only varies 'and' / 'allow-overrides': the
    // third combine cannot be compared, because production rejects it outright.
    expect(
      () =>
        new IamEngine({
          adapter: new IamMemoryAdapter({}),
          mode: 'production',
          policyCombine: 'first-applicable',
        }),
    ).toThrow(/first-applicable/)
  })
})
