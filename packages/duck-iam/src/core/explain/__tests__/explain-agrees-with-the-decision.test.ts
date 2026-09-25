import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine'

type Policy = Awaited<ReturnType<IamMemoryAdapter['listPolicies']>>[number]
type Role = Awaited<ReturnType<IamMemoryAdapter['listRoles']>>[number]

/** Lists rows past the write gate, the way a seed or a migration would. */
class Planted extends IamMemoryAdapter {
  readonly policies: Policy[] = []
  readonly roles: Role[] = []
  readonly assigned = new Map<string, string[]>()
  override async listPolicies() {
    return [...(await super.listPolicies()), ...this.policies]
  }
  override async listRoles() {
    return [...(await super.listRoles()), ...this.roles]
  }
  override async getSubjectRoles(id: string) {
    return [...(await super.getSubjectRoles(id)), ...(this.assigned.get(id) ?? [])] as never
  }
}

const RESOURCE = { attributes: {}, id: 'd1', type: 'doc' } as never
const BAD_OPERATOR = { all: [{ field: 'subject.id', operator: 'no-such-operator', value: 1 }] }

const policy = (algorithm: string, rules: Array<Record<string, unknown>>) =>
  ({ algorithm, description: '', id: 'p1', name: 'p1', rules, version: 1 }) as unknown as Policy

const allow = (extra: Record<string, unknown> = {}) => ({
  actions: ['read'],
  conditions: { all: [] },
  effect: 'allow',
  id: 'r-allow',
  priority: 5,
  resources: ['doc'],
  ...extra,
})
const deny = (extra: Record<string, unknown> = {}) => ({
  actions: ['read'],
  conditions: { all: [] },
  effect: 'deny',
  id: 'r-deny',
  priority: 0,
  resources: ['doc'],
  ...extra,
})

async function ask(adapter: Planted) {
  const dev = new IamEngine({ adapter, cacheTTL: 0, mode: 'development' })
  const can = await dev.can('u1', 'read' as never, RESOURCE)
  const explained = await dev.explain('u1', 'read' as never, RESOURCE)
  return { can, explained: explained.decision.allowed, reason: explained.decision.reason }
}

const withPolicy = (p: Policy) => {
  const adapter = new Planted()
  adapter.policies.push(p)
  return adapter
}

describe('explain() agrees with the decision path', () => {
  describe('a rule the decision path refuses', () => {
    it('an unrecognised effect: both deny, and the trace says why', async () => {
      const r = await ask(withPolicy(policy('deny-overrides', [allow(), deny({ effect: 'DENY' })])))
      expect(r.can).toBe(false)
      expect(r.explained).toBe(false)
      expect(r.reason).toMatch(/unknown effect on rule "r-deny"/)
    })

    it('a non-finite priority, on a rule that matched: both deny', async () => {
      const r = await ask(withPolicy(policy('highest-priority', [allow(), deny({ priority: null })])))
      expect(r.can).toBe(false)
      expect(r.explained).toBe(false)
      expect(r.reason).toMatch(/priority is not a finite number/)
    })

    it('a non-finite priority, on a rule whose condition is false: still both deny', async () => {
      const bad = deny({
        conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'nobody' }] },
        priority: null,
      })
      const r = await ask(withPolicy(policy('first-match', [allow(), bad])))
      expect(r.can).toBe(false)
      expect(r.explained).toBe(false)
    })

    it('an unknown algorithm: both deny, and explain does not crash', async () => {
      const r = await ask(withPolicy(policy('bogus', [allow(), deny()])))
      expect(r.can).toBe(false)
      expect(r.explained).toBe(false)
      expect(r.reason).toMatch(/unknown combining algorithm "bogus"/)
    })

    it('an unknown algorithm on a policy no rule targets: NotApplicable, not a crash', async () => {
      const p = policy('bogus', [allow({ actions: ['delete'] })])
      const adapter = withPolicy(p)
      const dev = new IamEngine({
        adapter,
        allowFailOpen: true,
        cacheTTL: 0,
        defaultEffect: 'allow',
        mode: 'development',
      })
      await expect(dev.explain('u1', 'read' as never, RESOURCE)).resolves.toBeDefined()
      const r = await ask(adapter)
      expect(r.explained).toBe(r.can)
    })

    it('CONTROL: the same policies decide normally when well-formed', async () => {
      const r = await ask(withPolicy(policy('deny-overrides', [allow(), deny()])))
      expect(r.can).toBe(false)
      expect(r.explained).toBe(false)
      expect(r.reason).toBe('Denied by rule "r-deny"')
    })

    it('CONTROL: an allow-only policy is still allowed by both', async () => {
      const r = await ask(withPolicy(policy('deny-overrides', [allow()])))
      expect(r.can).toBe(true)
      expect(r.explained).toBe(true)
    })
  })

  describe('a throwing condition on a rule that does not target the request', () => {
    it('does not poison the policy in either path', async () => {
      const unrelated = deny({ actions: ['delete'], conditions: BAD_OPERATOR, resources: ['other'] })
      const r = await ask(withPolicy(policy('deny-overrides', [allow(), unrelated])))
      expect(r.can).toBe(true)
      expect(r.explained).toBe(true)
    })

    it('CONTROL: the same condition on a rule that does target is Indeterminate in both', async () => {
      const targeting = deny({ conditions: BAD_OPERATOR })
      const r = await ask(withPolicy(policy('deny-overrides', [allow(), targeting])))
      expect(r.can).toBe(false)
      expect(r.explained).toBe(false)
    })
  })

  describe('the allow-only RBAC union lets a throwing permission abstain', () => {
    const roleWith = (permissions: Array<Record<string, unknown>>) => {
      const adapter = new Planted()
      adapter.roles.push({ id: 'r1', name: 'r1', permissions } as unknown as Role)
      adapter.assigned.set('u1', ['r1'])
      return adapter
    }

    it('another permission still grants, in both paths', async () => {
      const r = await ask(
        roleWith([
          { action: 'read', conditions: BAD_OPERATOR, resource: 'doc' },
          { action: 'read', conditions: { all: [] }, resource: 'doc' },
        ]),
      )
      expect(r.can).toBe(true)
      expect(r.explained).toBe(true)
    })

    it('CONTROL: with only the throwing permission, both refuse', async () => {
      const r = await ask(roleWith([{ action: 'read', conditions: BAD_OPERATOR, resource: 'doc' }]))
      expect(r.can).toBe(false)
      expect(r.explained).toBe(false)
    })

    it('CONTROL: with only the good permission, both allow', async () => {
      const r = await ask(roleWith([{ action: 'read', conditions: { all: [] }, resource: 'doc' }]))
      expect(r.can).toBe(true)
      expect(r.explained).toBe(true)
    })
  })

  describe('a condition group that is not an object', () => {
    it('is reported by name in the trace, not as a bare TypeError', async () => {
      const adapter = withPolicy(policy('deny-overrides', [allow(), deny({ conditions: null })]))
      const dev = new IamEngine({ adapter, cacheTTL: 0, mode: 'development' })
      const result = await dev.explain('u1', 'read' as never, RESOURCE)
      const trace = result.policies.find((p) => p.policyId === 'p1')
      const errors = trace?.rules.map((r) => r.conditionError).filter(Boolean) ?? []
      expect(errors).toHaveLength(1)
      expect(errors[0]).toBe('IAM_CONDITION_GROUP_INVALID')
      expect(result.decision.allowed).toBe(false)
    })
  })
})
