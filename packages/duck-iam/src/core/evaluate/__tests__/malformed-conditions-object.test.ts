import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { evalConditionGroup } from '../../conditions/conditions'
import { IamEngine } from '../../engine'
import { IamError, metaOf } from '../../errors'
import { evaluatePolicy, evaluatePolicyFast } from '../evaluate'

class Planted extends IamMemoryAdapter {
  readonly extra: AccessControlPolicy[] = []
  override async listPolicies() {
    return [...(await super.listPolicies()), ...this.extra]
  }
}
type AccessControlPolicy = Awaited<ReturnType<IamMemoryAdapter['listPolicies']>>[number]

const REQ = {
  action: 'read',
  resource: { attributes: {}, type: 'doc' },
  subject: { attributes: {}, id: 'u1', roles: [] },
} as never

/** Shapes the write path refuses and a seed, a migration or a direct write can still store. */
const NON_OBJECT: Array<[string, unknown]> = [
  ['undefined', undefined],
  ['null', null],
  ['a string', 'all'],
  ['a number', 7],
  ['a boolean', true],
]

const ALGOS = ['allow-overrides', 'deny-overrides', 'first-match', 'highest-priority'] as const

/** `deny` carries the shape under test; the companion allow is what a lost deny shows up as. */
const policy = (algorithm: string, denyConditions: unknown, denyResources: string[] = ['doc']) =>
  ({
    algorithm,
    description: '',
    id: 'p1',
    name: 'p1',
    rules: [
      { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r-allow', priority: 1, resources: ['doc'] },
      {
        actions: ['read'],
        conditions: denyConditions,
        effect: 'deny',
        id: 'r-deny',
        priority: 0,
        resources: denyResources,
      },
    ],
    version: 1,
  }) as unknown as AccessControlPolicy

async function engines(p: AccessControlPolicy, attributes?: Record<string, string>) {
  const adapter = new Planted()
  adapter.extra.push(p)
  if (attributes) await adapter.setSubjectAttributes('u1', attributes)
  return {
    dev: new IamEngine({ adapter, cacheTTL: 0, mode: 'development' }),
    prod: new IamEngine({ adapter, cacheTTL: 0, mode: 'production' }),
  }
}

const RESOURCE = { attributes: {}, id: 'd1', type: 'doc' } as never

describe('a condition group that is not an object', () => {
  describe('evalConditionGroup refuses it by name', () => {
    for (const [name, group] of NON_OBJECT) {
      it(`${name} throws IAM_CONDITION_GROUP_INVALID, not a bare TypeError`, () => {
        expect(() => evalConditionGroup(REQ, group as never)).toThrow('IAM_CONDITION_GROUP_INVALID')
        try {
          evalConditionGroup(REQ, group as never)
          expect.unreachable()
        } catch (err) {
          expect(err).toBeInstanceOf(IamError)
          expect(metaOf(err as IamError<'IAM_CONDITION_GROUP_INVALID'>, 'IAM_CONDITION_GROUP_INVALID').detail).toMatch(
            /is not an object/,
          )
        }
      })
    }

    it('CONTROL: an empty group is still unconditionally true', () => {
      expect(evalConditionGroup(REQ, {} as never)).toBe(true)
    })

    it('CONTROL: an unknown key is still reported by name', () => {
      try {
        evalConditionGroup(REQ, { alll: [] } as never)
        expect.unreachable()
      } catch (err) {
        expect(metaOf(err as IamError<'IAM_CONDITION_GROUP_INVALID'>, 'IAM_CONDITION_GROUP_INVALID').detail).toMatch(
          /no recognised key \(saw alll\)/,
        )
      }
    })
  })

  describe('both evaluators refuse the same rule', () => {
    for (const algorithm of ALGOS) {
      for (const [name, group] of NON_OBJECT) {
        it(`${algorithm}: ${name}`, () => {
          const p = policy(algorithm, group)
          expect(() => evaluatePolicy(p as never, REQ, 'deny')).toThrow()
          expect(() => evaluatePolicyFast(p as never, REQ, 'deny')).toThrow()
        })
      }
    }

    it('CONTROL: a well-formed rule is answered, not refused', () => {
      const p = policy('deny-overrides', { all: [] })
      expect(evaluatePolicy(p as never, REQ, 'deny').allowed).toBe(false)
      expect(evaluatePolicyFast(p as never, REQ, 'deny')).toBe(false)
    })
  })

  describe('a residual policy: production used to allow what development denied', () => {
    for (const [name, group] of NON_OBJECT) {
      it(`${name}: both modes deny`, async () => {
        // `resources: ['*']` is what makes the policy residual, so `evaluatePolicyFast` is the path under test.
        const { dev, prod } = await engines(policy('allow-overrides', group, ['*']))
        expect(await dev.can('u1', 'read' as never, RESOURCE)).toBe(false)
        expect(await prod.can('u1', 'read' as never, RESOURCE)).toBe(false)
      })
    }

    it('CONTROL: the same residual policy still allows when the deny is well-formed', async () => {
      const { dev, prod } = await engines(policy('allow-overrides', { all: [] }, ['*']))
      expect(await dev.can('u1', 'read' as never, RESOURCE)).toBe(true)
      expect(await prod.can('u1', 'read' as never, RESOURCE)).toBe(true)
    })
  })

  describe('CONTROL: the deny under test can decide, so `false` is not vacuous', () => {
    const gold = { all: [{ field: 'subject.attributes.tier', operator: 'eq', value: 'gold' }] }

    it('the deny fires when its condition holds', async () => {
      const { dev, prod } = await engines(policy('deny-overrides', gold, ['*']), { tier: 'gold' })
      expect(await dev.can('u1', 'read' as never, RESOURCE)).toBe(false)
      expect(await prod.can('u1', 'read' as never, RESOURCE)).toBe(false)
    })

    it('the same policy allows when its condition does not hold', async () => {
      const { dev, prod } = await engines(policy('deny-overrides', gold, ['*']), { tier: 'bronze' })
      expect(await dev.can('u1', 'read' as never, RESOURCE)).toBe(true)
      expect(await prod.can('u1', 'read' as never, RESOURCE)).toBe(true)
    })

    it('and refuses when the same deny carries a non-object group', async () => {
      const { dev, prod } = await engines(policy('deny-overrides', null, ['*']), { tier: 'bronze' })
      expect(await dev.can('u1', 'read' as never, RESOURCE)).toBe(false)
      expect(await prod.can('u1', 'read' as never, RESOURCE)).toBe(false)
    })
  })

  describe('a non-object nested inside a group body', () => {
    for (const [name, child] of NON_OBJECT) {
      it(`{ all: [${name}] } is refused by both evaluators`, () => {
        const p = policy('allow-overrides', { all: [child] }, ['*'])
        expect(() => evaluatePolicy(p as never, REQ, 'deny')).toThrow()
        expect(() => evaluatePolicyFast(p as never, REQ, 'deny')).toThrow()
      })
    }

    it('CONTROL: a real condition in the same position is evaluated', () => {
      const p = policy(
        'allow-overrides',
        { all: [{ field: 'subject.attributes.tier', operator: 'eq', value: 'gold' }] },
        ['*'],
      )
      expect(evaluatePolicyFast(p as never, REQ, 'deny')).toBe(true)
    })
  })
})
