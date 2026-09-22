import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine, iamEngine } from '../engine'

describe('iamEngine factory', () => {
  it('returns a real IamEngine instance', () => {
    expect(iamEngine({ adapter: new IamMemoryAdapter() })).toBeInstanceOf(IamEngine)
  })

  it('forwards config to the constructor - the built engine evaluates against the adapter', async () => {
    const adapter = new IamMemoryAdapter<string, string, string, string>()
    await adapter.saveRole({ id: 'editor', name: 'editor', permissions: [{ action: 'read', resource: 'post' }] })
    await adapter.assignRole('user-1', 'editor')
    const engine = iamEngine({ adapter })
    expect(await engine.can('user-1', 'read', { attributes: {}, type: 'post' })).toBe(true)
    expect(await engine.can('user-1', 'delete', { attributes: {}, type: 'post' })).toBe(false)
  })

  it('propagates constructor validation errors instead of swallowing them', () => {
    expect(() => iamEngine({ adapter: new IamMemoryAdapter(), defaultEffect: 'allow' })).toThrow(/allowFailOpen/)
  })
})
