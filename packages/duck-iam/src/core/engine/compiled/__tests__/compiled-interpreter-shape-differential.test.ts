import { describe, expect, it } from 'vitest'
import { evaluate } from '../../../evaluate/evaluate'
import { rolesToPolicy } from '../../../rbac'
import type { AccessControl, IamRequest } from '../../../types'
import { compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'

// `compiled-interpreter-parity.test.ts` pins named cases one at a time. This one sweeps instead: every rule and
// condition shape recent audit rounds named, crossed with the axes that decide how a lost vote lands. The table is
// the verdict in both modes, so a shape the two paths read differently ships without a development run seeing it.

const ROLES: AccessControl.IRole[] = [
  { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
  { id: 'other', name: 'O', permissions: [] },
]

const REQ: IamRequest.IAccessRequest = {
  action: 'delete',
  environment: { now: 1 },
  resource: { attributes: { tags: ['x'] }, id: 'p1', type: 'post' },
  subject: { attributes: { lvl: 3 }, id: 'u1', roles: ['writer'] },
}

const COMBINES: AccessControl.PolicyCombine[] = ['allow-overrides', 'and', 'first-applicable']
const EFFECTS: AccessControl.Effect[] = ['deny', 'allow']

function maskOf(table: ReturnType<typeof compileTable>, roles: readonly string[]): number {
  let mask = 0
  for (const r of roles) {
    const bit = table.roleId.get(r)
    if (bit !== undefined) mask |= 1 << bit
  }
  return mask
}

/** The compiled side of the comparison, injectable so the sweep can be run against a saboteur and shown to fail. */
type SecondOpinion = (
  policy: AccessControl.IPolicy,
  req: IamRequest.IAccessRequest,
  combine: AccessControl.PolicyCombine,
  def: AccessControl.Effect,
  mode: 'flat' | 'hierarchical',
) => string

const compiledVerdict: SecondOpinion = (policy, req, combine, def, mode) => {
  try {
    const table = compileTable(ROLES, [policy], combine, mode)
    return String(lookup(table, maskOf(table, req.subject.roles), req.action, req.resource.type, req, def))
  } catch (err) {
    return `throw:${(err as Error).constructor.name}`
  }
}

/** Both verdicts for one configuration; a throw is folded in by name so the two paths must also agree on failing. */
function verdicts(
  policy: AccessControl.IPolicy,
  req: IamRequest.IAccessRequest,
  combine: AccessControl.PolicyCombine,
  def: AccessControl.Effect,
  mode: 'flat' | 'hierarchical',
  second: SecondOpinion = compiledVerdict,
): { compiled: string; interpreted: string } {
  let interpreted: string
  try {
    interpreted = String(evaluate([rolesToPolicy(ROLES, mode), policy], req, def, combine).allowed)
  } catch (err) {
    interpreted = `throw:${(err as Error).constructor.name}`
  }
  return { compiled: second(policy, req, combine, def, mode), interpreted }
}

const deepGroup = (n: number): AccessControl.IConditionGroup => {
  let node: AccessControl.IConditionGroup = { all: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] }
  for (let i = 0; i < n; i++) node = { all: [node] }
  return node
}
const C = (conditions: AccessControl.IConditionGroup): Partial<AccessControl.IRule> => ({ conditions })

/** Shapes the audit has touched: dead rules, vacuous groups, operand faults, pattern forms, malformed rows. */
const SHAPES: Record<string, Partial<AccessControl.IRule>> = {
  absent_attribute: C({ all: [{ field: 'subject.attributes.nope', operator: 'eq', value: 1 }] }),
  action_shorthand: C({ all: [{ field: 'action', operator: 'eq', value: 'delete' }] }),
  all_empty: C({ all: [] }),
  any_empty: C({ any: [] }),
  both_all_and_any: C({ all: [], any: [{ field: 'subject.id', operator: 'eq', value: 'zzz' }] }),
  condition_depth_exceeded: C(deepGroup(20)),
  condition_depth_ok: C(deepGroup(6)),
  contains_on_scalar_field: C({ all: [{ field: 'subject.id', operator: 'contains', value: 'u1' }] }),
  dead_path_root: C({ all: [{ field: 'user.banned', operator: 'eq', value: true }] }),
  empty_actions: { actions: [] },
  empty_resources: { resources: [] },
  exists_on_absent: C({ all: [{ field: 'subject.attributes.nope', operator: 'exists' }] }),
  in_empty_list: C({ all: [{ field: 'subject.id', operator: 'in', value: [] }] }),
  matches_with_reference: C({ all: [{ field: 'subject.id', operator: 'matches', value: '$subject.id' }] }),
  missing_value_key: C({ all: [{ field: 'subject.id', operator: 'eq' }] }),
  nin_empty_list: C({ all: [{ field: 'subject.id', operator: 'nin', value: [] }] }),
  none_empty: C({ none: [] }),
  none_holding_tautology: C({ none: [{ all: [] }] }),
  not_exists_on_absent: C({ all: [{ field: 'subject.attributes.nope', operator: 'not_exists' }] }),
  nothing_wrong: {},
  null_value: C({ all: [{ field: 'subject.attributes.nope', operator: 'eq', value: null }] }),
  prefix_action: { actions: ['delete:*'] },
  prototype_path: C({ all: [{ field: 'subject.__proto__.x', operator: 'eq', value: 1 }] }),
  reference_resolves_to_null: C({ all: [{ field: 'subject.id', operator: 'eq', value: '$subject.nope' }] }),
  resource_dot_wildcard: { resources: ['post.*'] },
  resource_colon_wildcard: { resources: ['post:*'] },
  scope_field: C({ all: [{ field: 'scope', operator: 'eq', value: 'org-1' }] }),
  subset_of_empty: C({ all: [{ field: 'resource.attributes.tags', operator: 'subset_of', value: [] }] }),
  superset_of_empty: C({ all: [{ field: 'resource.attributes.tags', operator: 'superset_of', value: [] }] }),
  unknown_effect: { effect: 'nope' as AccessControl.Effect },
  unknown_group_key: C({ nope: [] } as unknown as AccessControl.IConditionGroup),
  unknown_operator: C({ all: [{ field: 'subject.id', operator: 'nope' as AccessControl.Operator, value: 1 }] }),
  wildcard_action: { actions: ['*'] },
  wrong_operand_type: C({ all: [{ field: 'subject.attributes.lvl', operator: 'gt', value: 'x' }] }),
  nonfinite_priority: { priority: Number.NaN },
}

/** The shape sits on one rule; the companion carries the opposite effect so the verdict says which one fired. */
function shapePolicy(shape: Partial<AccessControl.IRule>, victim: AccessControl.Effect): AccessControl.IPolicy {
  const other: AccessControl.Effect = victim === 'deny' ? 'allow' : 'deny'
  return {
    algorithm: 'deny-overrides',
    id: 'p',
    name: 'P',
    rules: [
      {
        actions: ['delete'],
        conditions: { all: [] },
        effect: other,
        id: 'companion',
        priority: victim === 'deny' ? 1 : 10,
        resources: ['post'],
      },
      {
        actions: ['delete'],
        conditions: { all: [] },
        effect: victim,
        id: 'victim',
        priority: victim === 'deny' ? 10 : 1,
        resources: ['post'],
        ...shape,
      },
    ],
  }
}

const TARGETS: Record<string, AccessControl.IPolicy['targets']> = {
  action_hit: { actions: ['delete'] },
  action_hit_resource_miss: { actions: ['delete'], resources: ['page'] },
  action_miss: { actions: ['read'] },
  action_prefix: { actions: ['delete:*'] },
  action_star: { actions: ['*'] },
  actions_empty: { actions: [] },
  all_three: { actions: ['delete'], resources: ['post'], roles: ['writer'] },
  none: undefined,
  resource_colon: { resources: ['post:*'] },
  resource_dot: { resources: ['post.*'] },
  resource_hit: { resources: ['post'] },
  resource_miss: { resources: ['page'] },
  resource_star: { resources: ['*'] },
  resources_empty: { resources: [] },
  roles_empty: { roles: [] },
  roles_hit: { roles: ['writer'] },
  roles_hit_action_miss: { actions: ['read'], roles: ['writer'] },
  roles_miss: { roles: ['other'] },
}

const REQUESTS: Record<string, IamRequest.IAccessRequest> = {
  plain: REQ,
  sub_action: { ...REQ, action: 'delete:hard' },
  sub_resource_colon: { ...REQ, resource: { attributes: {}, id: 'p1', type: 'post:draft' } },
  sub_resource_dot: { ...REQ, resource: { attributes: {}, id: 'p1', type: 'post.draft' } },
  two_roles: { ...REQ, subject: { attributes: {}, id: 'u1', roles: ['writer', 'other'] } },
}

const TARGET_RULES: Record<string, AccessControl.IRule[]> = {
  allow_only: [
    { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 1, resources: ['post'] },
  ],
  both: [
    { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 1, resources: ['post'] },
    { actions: ['delete'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 10, resources: ['post'] },
  ],
  conditional_deny: [
    { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 1, resources: ['post'] },
    {
      actions: ['delete'],
      conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] },
      effect: 'deny',
      id: 'd',
      priority: 10,
      resources: ['post'],
    },
  ],
  deny_only: [
    { actions: ['delete'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 1, resources: ['post'] },
  ],
  wildcard_rule: [
    { actions: ['delete:*'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 1, resources: ['post:*'] },
  ],
}

interface Sweep {
  cells: number
  disagreements: string[]
  seen: Set<string>
}

function sweepShapes(second?: SecondOpinion): Sweep {
  const out: Sweep = { cells: 0, disagreements: [], seen: new Set() }
  for (const combine of COMBINES) {
    for (const def of EFFECTS) {
      for (const mode of ['flat', 'hierarchical'] as const) {
        for (const victim of EFFECTS) {
          for (const [name, shape] of Object.entries(SHAPES)) {
            out.cells++
            const { compiled, interpreted } = verdicts(shapePolicy(shape, victim), REQ, combine, def, mode, second)
            out.seen.add(interpreted)
            if (compiled !== interpreted) {
              out.disagreements.push(`${name}|${combine}|default=${def}|${mode}|victim=${victim}`)
            }
          }
        }
      }
    }
  }
  return out
}

function sweepTargets(): Sweep {
  const out: Sweep = { cells: 0, disagreements: [], seen: new Set() }
  for (const [tn, targets] of Object.entries(TARGETS)) {
    for (const [rn, rules] of Object.entries(TARGET_RULES)) {
      for (const [qn, req] of Object.entries(REQUESTS)) {
        for (const combine of COMBINES) {
          for (const def of EFFECTS) {
            out.cells++
            const policy: AccessControl.IPolicy = { algorithm: 'deny-overrides', id: 'p', name: 'P', rules, targets }
            const { compiled, interpreted } = verdicts(policy, req, combine, def, 'flat')
            out.seen.add(interpreted)
            if (compiled !== interpreted) {
              out.disagreements.push(`${tn}|${rn}|${qn}|${combine}|default=${def}`)
            }
          }
        }
      }
    }
  }
  return out
}

describe('the compiled table and the interpreter answer every shape the same', () => {
  it('agrees on every rule and condition shape, across combine, default effect, scope mode and rule effect', () => {
    const sweep = sweepShapes()
    expect(sweep.disagreements).toEqual([])
    // Exact, so an axis quietly dropped from the loops fails here instead of shrinking the sweep in silence.
    expect(sweep.cells).toBe(COMBINES.length * EFFECTS.length * 2 * EFFECTS.length * Object.keys(SHAPES).length)
    // Non-vacuity: a sweep whose every cell answers the same way would agree for the wrong reason.
    expect([...sweep.seen].sort()).toEqual(['false', 'true'])
  })

  it('agrees on every policy target, rule set and request shape', () => {
    const sweep = sweepTargets()
    expect(sweep.disagreements).toEqual([])
    expect(sweep.cells).toBe(
      Object.keys(TARGETS).length *
        Object.keys(TARGET_RULES).length *
        Object.keys(REQUESTS).length *
        COMBINES.length *
        EFFECTS.length,
    )
    expect([...sweep.seen].sort()).toEqual(['false', 'true'])
  })

  it('agrees on a policyCombine that is not one of the three, which neither path should invent a meaning for', () => {
    const unknown = 'nope' as AccessControl.PolicyCombine
    const disagreements: string[] = []
    for (const [name, shape] of Object.entries(SHAPES)) {
      for (const def of EFFECTS) {
        const { compiled, interpreted } = verdicts(shapePolicy(shape, 'deny'), REQ, unknown, def, 'flat')
        if (compiled !== interpreted) disagreements.push(`${name}|default=${def}`)
      }
    }
    expect(disagreements).toEqual([])
  })

  it('reports a divergence when the second opinion is wrong, so the greens above mean something', () => {
    // The same sweep, run against a saboteur that answers one shape the other way. Without this, "no
    // disagreements" is also what a sweep that compares nothing prints.
    const saboteur: SecondOpinion = (policy, req, combine, def, mode) => {
      const honest = compiledVerdict(policy, req, combine, def, mode)
      const victim = policy.rules.find((rule) => rule.id === 'victim')
      if (victim?.actions.length === 0) return honest === 'true' ? 'false' : 'true'
      return honest
    }
    const sabotaged = sweepShapes(saboteur)
    expect(sabotaged.disagreements.length).toBeGreaterThan(0)
    // Only the shape the saboteur touches, and every configuration of it - the sweep misses none of them.
    expect(new Set(sabotaged.disagreements.map((d) => d.split('|')[0]))).toEqual(new Set(['empty_actions']))
    expect(sabotaged.disagreements).toHaveLength(COMBINES.length * EFFECTS.length * 2 * EFFECTS.length)
  })
})
