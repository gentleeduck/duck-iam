import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine'
import { compileTable } from '../../engine/compiled/compiled.compile'
import { lookup } from '../../engine/compiled/compiled.lookup'
import { IamError, metaOf } from '../../errors'
import { evaluatePolicy } from '../../evaluate/evaluate'
import { combiners } from '../../evaluate/evaluate.libs'
import { evaluateOperator } from '../conditions'
import { evalCondition, ops } from '../conditions.libs'

const POST = { attributes: {}, type: 'post' } as const

/** Every function reachable on an object literal's prototype chain; `ops` and `combiners` are object literals. */
const INHERITED = ['constructor', 'toString', 'toLocaleString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf']

const REQ = {
  action: 'delete',
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: { tier: 'bronze' }, id: 'u1', roles: [] },
}

class Planted extends IamMemoryAdapter {
  readonly extra: AccessControlPolicy[] = []
  override async listPolicies() {
    return [...(await super.listPolicies()), ...this.extra]
  }
}

type AccessControlPolicy = Awaited<ReturnType<IamMemoryAdapter['listPolicies']>>[number]

/** Builds a stored row the write path refuses, the way a seed or a migration would. */
const planted = (id: string, operator: string, effect: 'allow' | 'deny', group: 'all' | 'none') =>
  ({
    algorithm: 'deny-overrides',
    description: '',
    id,
    name: id,
    rules: [
      {
        actions: ['delete'],
        conditions: { [group]: [{ field: 'subject.attributes.tier', operator, value: 'gold' }] },
        effect,
        id: 'r1',
        priority: 0,
        resources: ['post'],
      },
    ],
    version: 1,
  }) as unknown as AccessControlPolicy

async function engines(policies: AccessControlPolicy[], attributes?: Record<string, string>) {
  const adapter = new Planted()
  adapter.extra.push(...policies)
  if (attributes) await adapter.setSubjectAttributes('u1', attributes)
  return {
    dev: new IamEngine({ adapter, cacheTTL: 0, mode: 'development' }),
    prod: new IamEngine({ adapter, cacheTTL: 0, mode: 'production' }),
  }
}

describe('an inherited name is not an operator', () => {
  it('CONTROL: every inherited name really is a function on the tables', () => {
    for (const name of INHERITED) {
      expect(typeof (ops as unknown as Record<string, unknown>)[name]).toBe('function')
      expect(typeof (combiners as unknown as Record<string, unknown>)[name]).toBe('function')
      expect(Object.hasOwn(ops, name)).toBe(false)
      expect(Object.hasOwn(combiners, name)).toBe(false)
    }
  })

  it.each(INHERITED)('evalCondition refuses operator %s instead of answering truthy', (name) => {
    try {
      evalCondition(REQ as never, { field: 'subject.attributes.tier', operator: name, value: 'gold' } as never)
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_CONDITION_OPERATOR_UNKNOWN'>, 'IAM_CONDITION_OPERATOR_UNKNOWN')
      expect(meta.operator).toBe(name)
    }
  })

  it.each(INHERITED)('the public iamEvaluateOperator refuses %s too', (name) => {
    try {
      evaluateOperator(name as never, 'bronze', 'gold')
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_CONDITION_OPERATOR_UNKNOWN'>, 'IAM_CONDITION_OPERATOR_UNKNOWN')
      expect(meta.operator).toBe(name)
    }
  })

  it('CONTROL: iamEvaluateOperator still applies a real operator', () => {
    expect(evaluateOperator('eq', 'gold', 'gold')).toBe(true)
    expect(evaluateOperator('eq', 'bronze', 'gold')).toBe(false)
  })

  it('CONTROL: a real operator that misses answers false, it does not throw', () => {
    expect(
      evalCondition(REQ as never, { field: 'subject.attributes.tier', operator: 'eq', value: 'gold' } as never),
    ).toBe(false)
  })

  it.each(['constructor', 'toString'])(
    'an allow rule conditioned on %s no longer fires in production',
    async (name) => {
      const { prod } = await engines([planted('a', name, 'allow', 'all')])
      expect(await prod.can('u1', 'delete', POST)).toBe(false)
    },
  )

  /** A deny the `none` group retires, plus the companion allow without which `defaultEffect` answers either way. */
  const guardedDeny = (operator: string) => {
    const policy = planted('d', operator, 'deny', 'none')
    const rules = [{ ...policy.rules[0], conditions: { all: [] }, effect: 'allow', id: 'r0' }, policy.rules[0]]
    return { ...policy, rules } as unknown as AccessControlPolicy
  }

  it('CONTROL: a true `none` condition really does retire the deny', async () => {
    const { prod } = await engines([guardedDeny('eq')], { tier: 'gold' })
    expect(await prod.can('u1', 'delete', POST)).toBe(true)
  })

  it.each(['constructor', 'toString'])('a deny guarded by `none` on %s is no longer retired', async (name) => {
    const { prod } = await engines([guardedDeny(name)], { tier: 'gold' })
    expect(await prod.can('u1', 'delete', POST)).toBe(false)
  })

  it('CONTROL: the same policy with a matching condition does allow', async () => {
    const adapter = new IamMemoryAdapter()
    await adapter.savePolicy(planted('ok', 'eq', 'allow', 'all'))
    await adapter.setSubjectAttributes('u1', { tier: 'gold' })
    const engine = new IamEngine({ adapter, cacheTTL: 0, mode: 'production' })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
  })

  it('reports the refusal as Indeterminate, naming the operator', async () => {
    const { dev } = await engines([planted('a', 'constructor', 'allow', 'all')])
    const decision = await dev.check('u1', 'delete', POST)
    expect(decision.allowed).toBe(false)
    expect(decision.reason).toMatch(/error|indeterminate/i)
  })

  it('the write path already refused these, so only a seeded row could carry one', async () => {
    const adapter = new IamMemoryAdapter()
    await expect(adapter.savePolicy(planted('w', 'constructor', 'allow', 'all'))).rejects.toThrow(
      'IAM_VALIDATION_FAILED',
    )
  })

  // An inherited combiner name answers an object with no `effect`, so it denies either way. What the guard adds is
  // that the policy is reported as failed instead of silently voting deny with a malformed decision.
  it.each(INHERITED)('an inherited combining algorithm %s is reported, in production', async (name) => {
    const seen: string[] = []
    const policy = { ...planted('c', 'eq', 'allow', 'all'), algorithm: name } as unknown as AccessControlPolicy
    const adapter = new Planted()
    adapter.extra.push(policy)
    const engine = new IamEngine({
      adapter,
      cacheTTL: 0,
      hooks: { onPolicyError: (err) => seen.push(err.message) },
      mode: 'production',
    })
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(seen.join(' | ')).toMatch(new RegExp(`Unknown combining algorithm "${name}"`))
  })

  it.each(INHERITED)('an inherited combining algorithm %s is Indeterminate in the interpreter too', async (name) => {
    const policy = { ...planted('c', 'eq', 'allow', 'all'), algorithm: name } as unknown as AccessControlPolicy
    expect(() => evaluatePolicy(policy, REQ as never, 'deny')).toThrow(
      new RegExp(`Unknown combining algorithm "${name}"`),
    )
  })

  // The compiled table never holds one: `isResidualPolicy` forces it out, and `evaluatePolicyFast` refuses it.
  // That is what keeps `combiners[group.algorithm]` in the DYNAMIC cell from ever seeing an inherited name.
  it.each(INHERITED)('a compiled table keeps algorithm %s residual and reports it', (name) => {
    const seen: string[] = []
    const policy = { ...planted('c', 'eq', 'allow', 'all'), algorithm: name } as unknown as AccessControlPolicy
    const table = compileTable([], [policy], 'and')
    expect(table.residualPolicies.map((p) => p.id)).toEqual(['c'])
    const req = { ...REQ, subject: { ...REQ.subject, attributes: { tier: 'gold' } } }
    const allowed = lookup(table, 0, 'delete', 'post', req as never, 'deny', (err) => seen.push(err.message))
    expect(allowed).toBe(false)
    expect(seen.join(' | ')).toMatch(new RegExp(`Unknown combining algorithm "${name}"`))
  })

  it('CONTROL: the same policy with a real algorithm compiles into the table and allows', () => {
    const seen: string[] = []
    const table = compileTable([], [planted('c', 'eq', 'allow', 'all')], 'and')
    expect(table.residualPolicies).toEqual([])
    const req = { ...REQ, subject: { ...REQ.subject, attributes: { tier: 'gold' } } }
    expect(lookup(table, 0, 'delete', 'post', req as never, 'deny', (err) => seen.push(err.message))).toBe(true)
    expect(seen).toEqual([])
  })

  it('CONTROL: a real algorithm reports nothing and still allows', async () => {
    const seen: string[] = []
    const adapter = new Planted()
    adapter.extra.push(planted('c', 'eq', 'allow', 'all'))
    await adapter.setSubjectAttributes('u1', { tier: 'gold' })
    const engine = new IamEngine({
      adapter,
      cacheTTL: 0,
      hooks: { onPolicyError: (err) => seen.push(err.message) },
      mode: 'production',
    })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(seen).toEqual([])
  })
})
