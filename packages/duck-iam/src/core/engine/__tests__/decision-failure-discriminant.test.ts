import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

const denyAll: AccessControl.IPolicy = {
  algorithm: 'first-match',
  id: 'p',
  name: 'deny all',
  rules: [{ actions: ['*'], conditions: { all: [] }, effect: 'deny', id: 'r', priority: 1, resources: ['*'] }],
}

const resource = { attributes: {}, type: 'post' }

async function engineWith(policies: AccessControl.IPolicy[]) {
  const adapter = new IamMemoryAdapter()
  for (const p of policies) await adapter.savePolicy(p)
  return new IamEngine({ adapter, mode: 'development' })
}

// Lets a caller answer 403 for a deny and 503 for an outage; `onError` is engine-scoped, not per call.
describe('IDecision distinguishes a policy deny from a broken engine', () => {
  it('an ordinary deny carries no failure', async () => {
    const engine = await engineWith([denyAll])
    const decision = await engine.check('u1', 'read', resource)
    expect(decision.allowed).toBe(false)
    expect(decision.failure).toBeUndefined()
  })

  it('an ordinary allow carries no failure', async () => {
    const engine = await engineWith([
      {
        algorithm: 'first-match',
        id: 'a',
        name: 'allow',
        rules: [
          { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 1, resources: ['post'] },
        ],
      },
    ])
    const decision = await engine.check('u1', 'read', resource)
    expect(decision.allowed).toBe(true)
    expect(decision.failure).toBeUndefined()
  })

  it("reports 'input' for a malformed subjectId", async () => {
    const engine = await engineWith([denyAll])
    const decision = await engine.check('', 'read', resource)
    expect(decision.allowed).toBe(false)
    expect(decision.failure).toBe('input')
  })

  it("reports 'resolution' when the adapter is down", async () => {
    const adapter = new IamMemoryAdapter()
    vi.spyOn(adapter, 'getSubjectRoles').mockRejectedValue(new Error('adapter down'))
    const onError = vi.fn()
    const engine = new IamEngine({ adapter, hooks: { onError }, mode: 'development' })

    const decision = await engine.check('u1', 'read', resource)
    expect(decision.allowed).toBe(false)
    expect(decision.failure).toBe('resolution')
    expect(onError).toHaveBeenCalledOnce()
  })

  it('the failure kind is what separates the two identical-looking denies', async () => {
    const adapter = new IamMemoryAdapter()
    await adapter.savePolicy(denyAll)
    const engine = new IamEngine({ adapter, mode: 'development' })
    const byPolicy = await engine.check('u1', 'read', resource)

    const broken = new IamMemoryAdapter()
    vi.spyOn(broken, 'getSubjectRoles').mockRejectedValue(new Error('adapter down'))
    const brokenEngine = new IamEngine({ adapter: broken, hooks: { onError: vi.fn() }, mode: 'development' })
    const byOutage = await brokenEngine.check('u1', 'read', resource)

    expect(byPolicy.allowed).toBe(byOutage.allowed)
    expect(byPolicy.failure).not.toBe(byOutage.failure)
  })
})

// Production has no object to carry the discriminant, so `onError` stays the channel there.
describe('production mode still answers with a bare boolean', () => {
  it('an adapter outage is false, and onError is the only signal', async () => {
    const adapter = new IamMemoryAdapter()
    vi.spyOn(adapter, 'getSubjectRoles').mockRejectedValue(new Error('adapter down'))
    const onError = vi.fn()
    const engine = new IamEngine({ adapter, hooks: { onError }, mode: 'production' })

    expect(await engine.check('u1', 'read', resource)).toBe(false)
    expect(onError).toHaveBeenCalledOnce()
  })
})
