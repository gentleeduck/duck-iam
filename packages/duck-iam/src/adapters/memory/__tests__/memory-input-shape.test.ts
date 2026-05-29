import { describe, expect, it } from 'vitest'
import type { Primitives } from '../../../core/types'
import { MemoryAdapter } from '../index'

describe('MemoryAdapter direct-call input shape', () => {
  it('rejects a string attrs value (the spread-to-chars class)', async () => {
    const adapter = new MemoryAdapter<string, string, string, string>()
    await expect(
      adapter.setSubjectAttributes('user-1', 'admin=true' as unknown as Primitives.Attributes),
    ).rejects.toThrow(/attributes for "user-1" must be a plain object \(got string\)/)
  })

  it('rejects an array attrs value', async () => {
    const adapter = new MemoryAdapter<string, string, string, string>()
    await expect(adapter.setSubjectAttributes('user-1', [1, 2, 3] as unknown as Primitives.Attributes)).rejects.toThrow(
      /attributes for "user-1" must be a plain object \(got array\)/,
    )
  })

  it('rejects a null attrs value', async () => {
    const adapter = new MemoryAdapter<string, string, string, string>()
    await expect(adapter.setSubjectAttributes('user-1', null as unknown as Primitives.Attributes)).rejects.toThrow(
      /attributes for "user-1" must be a plain object \(got null\)/,
    )
  })

  it('rejects a number attrs value', async () => {
    const adapter = new MemoryAdapter<string, string, string, string>()
    await expect(adapter.setSubjectAttributes('user-1', 42 as unknown as Primitives.Attributes)).rejects.toThrow(
      /attributes for "user-1" must be a plain object \(got number\)/,
    )
  })

  it('rejects a boolean attrs value', async () => {
    const adapter = new MemoryAdapter<string, string, string, string>()
    await expect(adapter.setSubjectAttributes('user-1', true as unknown as Primitives.Attributes)).rejects.toThrow(
      /attributes for "user-1" must be a plain object \(got boolean\)/,
    )
  })

  it('accepts a valid object', async () => {
    const adapter = new MemoryAdapter<string, string, string, string>()
    await adapter.setSubjectAttributes('user-1', { tier: 'gold', verified: true })
    const attrs = await adapter.getSubjectAttributes('user-1')
    expect(attrs).toEqual({ tier: 'gold', verified: true })
  })

  it('does not corrupt existing attributes on a rejected call', async () => {
    const adapter = new MemoryAdapter<string, string, string, string>()
    await adapter.setSubjectAttributes('user-1', { tier: 'gold' })
    const before = await adapter.getSubjectAttributes('user-1')
    await expect(adapter.setSubjectAttributes('user-1', 'attack' as unknown as Primitives.Attributes)).rejects.toThrow()
    const after = await adapter.getSubjectAttributes('user-1')
    expect(after).toEqual(before)
  })

  it('accepts an empty object (legit no-op write)', async () => {
    const adapter = new MemoryAdapter<string, string, string, string>()
    await adapter.setSubjectAttributes('user-1', { tier: 'gold' })
    await adapter.setSubjectAttributes('user-1', {})
    const attrs = await adapter.getSubjectAttributes('user-1')
    expect(attrs).toEqual({ tier: 'gold' })
  })
})
