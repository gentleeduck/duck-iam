import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { evalConditionGroup, matchesUnconditionally } from '../../conditions/conditions'
import { IamEngine } from '../../engine/engine'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast } from '../evaluate'
import { indexPolicy } from '../evaluate.libs'

// `matchesUnconditionally` answers "may this rule match without evaluating it" for both fast paths,
// and must agree with `evalConditionGroup`, the authority.
const request: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
}

/** Built through JSON, the way an adapter row arrives, so shapes outside `IConditionGroup` need no cast. */
function policyWith(conditions: unknown, effect: AccessControl.Effect = 'allow'): AccessControl.IPolicy {
  const rule: Record<string, unknown> = {
    actions: ['read'],
    effect,
    id: 'r',
    priority: 1,
    resources: ['post'],
  }
  if (conditions !== undefined) rule.conditions = conditions
  return JSON.parse(JSON.stringify({ algorithm: 'deny-overrides', id: 'p', name: 'p', rules: [rule] }))
}

function groupOf(policy: AccessControl.IPolicy): AccessControl.IConditionGroup | undefined {
  return policy.rules[0]?.conditions
}

/** `true` / `false` when the evaluator answers, `'throws'` when it cannot. */
function evaluatorVerdict(group: AccessControl.IConditionGroup | undefined): boolean | 'throws' {
  try {
    if (group === undefined) return evalConditionGroup(request, JSON.parse('null'))
    return evalConditionGroup(request, group)
  } catch {
    return 'throws'
  }
}

/** Shapes the fast paths classify, including the malformed ones. */
const SHAPES: Array<{ conditions: unknown; label: string; unconditional: boolean }> = [
  { conditions: {}, label: '{}', unconditional: true },
  { conditions: { all: [] }, label: '{ all: [] }', unconditional: true },
  { conditions: { none: [] }, label: '{ none: [] }', unconditional: true },
  { conditions: { any: [] }, label: '{ any: [] }', unconditional: false },
  { conditions: { typo: 1 }, label: '{ typo: 1 }', unconditional: false },
  { conditions: { al: [] }, label: "{ al: [] } (misspelled 'all')", unconditional: false },
  {
    conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] },
    label: 'a real `all`',
    unconditional: false,
  },
  {
    conditions: { all: [], any: [{ field: 'subject.id', operator: 'eq', value: 'nobody' }] },
    label: 'empty `all` beside a real `any`',
    unconditional: true,
  },
  {
    conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'nobody' }], any: [] },
    label: 'real `all` beside an empty `any`',
    unconditional: false,
  },
  { conditions: { all: 'not-an-array' }, label: 'a non-array `all`', unconditional: false },
  { conditions: undefined, label: 'no `conditions` key at all', unconditional: false },
]

describe('matchesUnconditionally agrees with evalConditionGroup', () => {
  it.each(SHAPES)('$label', ({ conditions, unconditional }) => {
    const group = groupOf(policyWith(conditions))
    expect(matchesUnconditionally(group)).toBe(unconditional)
    // The contract is one-directional: `true` promises the evaluator answers
    // `true`. `false` promises nothing beyond "ask the evaluator".
    if (unconditional) expect(evaluatorVerdict(group)).toBe(true)
  })

  // Positive control: the implication above is vacuous if everything answers `false`.
  it('says true for at least three of them', () => {
    expect(SHAPES.filter((s) => s.unconditional).length).toBeGreaterThanOrEqual(3)
  })
})

describe('both engines reach the same verdict for every shape', () => {
  it.each(SHAPES)('$label', ({ conditions }) => {
    const policy = policyWith(conditions)
    const slow = evaluate([policy], request, 'deny', 'and', vi.fn()).allowed
    const fast = evaluateFast([policy], request, 'deny', 'and', vi.fn())
    expect(fast).toBe(slow)
  })

  // A precomputed cell is a third answer to the same question and must agree too.
  it.each(SHAPES)('$label, precomputed', ({ conditions }) => {
    const policy = policyWith(conditions)
    const precomputed = indexPolicy(policy).precomputed.get('read')?.get('post')
    if (precomputed === undefined) return
    expect(precomputed).toBe(evaluate([policy], request, 'deny', 'and', vi.fn()).allowed)
  })

  // Control: the `undefined` skip above is not quietly skipping everything.
  it('populates the table for the unconditional shapes', () => {
    const populated = SHAPES.filter(
      ({ conditions }) => indexPolicy(policyWith(conditions)).precomputed.get('read')?.get('post') !== undefined,
    )
    expect(populated.map((s) => s.label).sort()).toEqual(
      SHAPES.filter((s) => s.unconditional)
        .map((s) => s.label)
        .sort(),
    )
  })
})

/** `check()` returns a decision in development and a bare boolean in production. */
function allowedOf(result: unknown): boolean {
  if (typeof result === 'boolean') return result
  if (result !== null && typeof result === 'object' && 'allowed' in result) return result.allowed === true
  throw new Error(`unrecognised check() result: ${JSON.stringify(result)}`)
}

const target = { attributes: {}, type: 'post' }

async function checkIn(mode: 'development' | 'production', policy: AccessControl.IPolicy): Promise<boolean> {
  const engine = new IamEngine({ adapter: adapterWith(policy), hooks: { onError: vi.fn() }, mode })
  return allowedOf(await engine.check('u1', 'read', target))
}

describe('the compiled table agrees with the interpreter', () => {
  it.each(SHAPES)('$label', async ({ conditions }) => {
    const policy = policyWith(conditions)
    expect(await checkIn('production', policy)).toBe(await checkIn('development', policy))
  })

  // Control: the agreement above is not "everything denies".
  it('control: an unconditional shape allows in both modes', async () => {
    const policy = policyWith({ all: [] })
    expect(await checkIn('development', policy)).toBe(true)
    expect(await checkIn('production', policy)).toBe(true)
  })
})

function adapterWith(policy: AccessControl.IPolicy): IamMemoryAdapter {
  return new IamMemoryAdapter({ assignments: {}, policies: [policy], roles: [] })
}
