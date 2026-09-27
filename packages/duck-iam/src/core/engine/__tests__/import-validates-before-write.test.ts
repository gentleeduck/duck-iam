import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { hasIamErrorCode, type IamError, metaOf } from '../../errors'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

const goodPolicy = (id: string): AccessControl.IPolicy => ({
  id,
  name: id,
  algorithm: 'deny-overrides',
  rules: [
    { id: `${id}-r`, effect: 'deny', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [] } },
  ],
})

function engineWith(policies: AccessControl.IPolicy[]) {
  const adapter = new IamMemoryAdapter({ assignments: {}, policies, roles: [] })
  return { adapter, engine: new IamEngine({ adapter }) }
}

const snapshot = (policies: unknown[], roles: unknown[] = []) => ({ schemaVersion: 1, policies, roles }) as never

describe('admin.import validates the whole snapshot before writing', () => {
  it('a bad row late in the list writes none of the earlier rows', async () => {
    const { adapter, engine } = engineWith([])
    await expect(
      engine.admin.import(snapshot([goodPolicy('p1'), goodPolicy('p2'), { id: 'broken' }])),
    ).rejects.toThrow()
    expect(await adapter.listPolicies()).toHaveLength(0)
  })

  it('replace mode does not delete the existing set when the incoming set is invalid', async () => {
    const { adapter, engine } = engineWith([goodPolicy('existing')])
    await expect(engine.admin.import(snapshot([{ id: 'broken' }]), { mode: 'replace' })).rejects.toThrow()
    const remaining = await adapter.listPolicies()
    expect(remaining.map((p) => p.id)).toEqual(['existing'])
  })

  it('a valid snapshot still applies in full', async () => {
    const { adapter, engine } = engineWith([])
    const result = await engine.admin.import(snapshot([goodPolicy('p1'), goodPolicy('p2')]))
    expect(result.policiesAdded).toBe(2)
    expect(await adapter.listPolicies()).toHaveLength(2)
  })

  it('rejects a non-array policies field before touching the adapter', async () => {
    const { adapter, engine } = engineWith([goodPolicy('existing')])
    const err = await engine.admin.import(snapshot({} as never), { mode: 'replace' }).then(
      () => {
        throw new Error('expected import() to throw')
      },
      (e: unknown) => e,
    )
    expect(hasIamErrorCode(err, 'IAM_ENGINE_SNAPSHOT_FIELD_INVALID')).toBe(true)
    expect(
      metaOf(err as IamError<'IAM_ENGINE_SNAPSHOT_FIELD_INVALID'>, 'IAM_ENGINE_SNAPSHOT_FIELD_INVALID').field,
    ).toBe('policies')
    expect(await adapter.listPolicies()).toHaveLength(1)
  })
})
