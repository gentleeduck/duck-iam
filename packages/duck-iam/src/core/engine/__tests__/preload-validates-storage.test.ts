import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { type IamError, metaOf } from '../../errors'
import type { AccessControl } from '../../types'
import { IamEngine } from '../index'

function preloadFailure(promise: Promise<unknown>): Promise<IamError<'IAM_ENGINE_PRELOAD_VALIDATION_FAILED'>> {
  return promise.then(
    () => {
      throw new Error('expected preload() to throw')
    },
    (err: unknown) => err as IamError<'IAM_ENGINE_PRELOAD_VALIDATION_FAILED'>,
  )
}

/** Rows the write gate never saw: a migration, a seed script, a restore, another service writing the same table. */
class Planted extends IamMemoryAdapter {
  readonly extraPolicies: AccessControl.IPolicy[] = []
  readonly extraRoles: AccessControl.IRole[] = []
  override async listPolicies() {
    return [...(await super.listPolicies()), ...this.extraPolicies]
  }
  override async listRoles() {
    return [...(await super.listRoles()), ...this.extraRoles]
  }
}

const ALLOW_READ: AccessControl.IRule = {
  actions: ['read'],
  conditions: { all: [] },
  effect: 'allow',
  id: 'allow-read',
  priority: 1,
  resources: ['post'],
}

const deny = (action: string): AccessControl.IRule => ({
  actions: [action],
  conditions: { all: [] },
  effect: 'deny',
  id: 'deny-read',
  priority: 100,
  resources: ['post'],
})

const policy = (id: string, denyAction: string): AccessControl.IPolicy => ({
  algorithm: 'deny-overrides',
  description: '',
  id,
  name: id,
  rules: [ALLOW_READ, deny(denyAction)],
  version: 1,
})

/** A trailing newline on the action, the shape a seed script or a CSV import leaves behind. */
const INVALID = policy('planted', 'read\n')
/** The same policy, minus the newline: the write path accepts it and the deny fires. */
const VALID = policy('control', 'read')

const INVALID_ROLE: AccessControl.IRole = {
  description: '',
  id: 'bad',
  inherits: [],
  name: 'bad',
  permissions: [{ action: 'read\n', resource: 'post' }],
}

const engineOn = (adapter: Planted) => new IamEngine({ adapter, cacheTTL: 0, mode: 'production' })

describe('preload is the only check on rows the write path never saw', () => {
  it('the write path refuses the invalid policy outright', async () => {
    await expect(new Planted().savePolicy(INVALID)).rejects.toThrow('IAM_VALIDATION_FAILED')
  })

  it('CONTROL: without the newline the same deny fires', async () => {
    const adapter = new Planted()
    await adapter.savePolicy(VALID)
    expect(await engineOn(adapter).can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })

  it('read from storage the invalid policy evaluates, and its deny silently never fires', async () => {
    const adapter = new Planted()
    adapter.extraPolicies.push(INVALID)
    expect(await engineOn(adapter).can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)
  })

  it('preload() without the flag does not notice', async () => {
    const adapter = new Planted()
    adapter.extraPolicies.push(INVALID)
    await expect(engineOn(adapter).preload()).resolves.toBeUndefined()
  })

  it('preload({ validator: true }) throws, naming the policy and the reason', async () => {
    const adapter = new Planted()
    adapter.extraPolicies.push(INVALID)
    const err = await preloadFailure(engineOn(adapter).preload({ validator: true }))
    const meta = metaOf(err, 'IAM_ENGINE_PRELOAD_VALIDATION_FAILED')
    expect(meta.count).toBe(1)
    expect(meta.problems[0]).toMatch(/policy "planted": .*control characters/)
  })

  it('a planted role is checked too', async () => {
    const adapter = new Planted()
    adapter.extraRoles.push(INVALID_ROLE)
    const err = await preloadFailure(engineOn(adapter).preload({ validator: true }))
    const meta = metaOf(err, 'IAM_ENGINE_PRELOAD_VALIDATION_FAILED')
    expect(meta.problems.some((p) => p.includes('role "bad"'))).toBe(true)
  })

  it('counts every offender exactly and names at most ten', async () => {
    const adapter = new Planted()
    for (let i = 0; i < 12; i++) adapter.extraPolicies.push(policy(`planted-${i}`, 'read\n'))
    const err = await preloadFailure(engineOn(adapter).preload({ validator: true }))
    const meta = metaOf(err, 'IAM_ENGINE_PRELOAD_VALIDATION_FAILED')
    expect(meta.count).toBe(12)
    expect(meta.problems).toHaveLength(10)
    expect(meta.problems.every((p) => p.includes('policy "planted-'))).toBe(true)
  })

  it('reports the errors on an offending row, not its warnings', async () => {
    const adapter = new Planted()
    adapter.extraPolicies.push({
      ...INVALID,
      rules: [
        { actions: ['*'], conditions: { all: [] }, effect: 'allow', id: 'god', priority: 1, resources: ['*'] },
        deny('read\n'),
      ],
    })
    const err = await preloadFailure(engineOn(adapter).preload({ validator: true }))
    const meta = metaOf(err, 'IAM_ENGINE_PRELOAD_VALIDATION_FAILED')
    expect(meta.problems.some((p) => p.includes('control characters'))).toBe(true)
    expect(meta.problems.some((p) => p.includes('broadest possible grant'))).toBe(false)
  })

  it('a clean store preloads with the flag on', async () => {
    const adapter = new Planted()
    await adapter.savePolicy(VALID)
    await expect(engineOn(adapter).preload({ validator: true })).resolves.toBeUndefined()
  })
})
