import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../index'

describe('identities store is tenant-free (global account)', () => {
  it('merge() and findByProviderSub() take no tenant argument', () => {
    const a = new MemoryAdapter()
    // Arity is the contract: identities methods no longer accept tenant.
    expect(a.identities.merge.length).toBe(2)
    expect(a.identities.findByProviderSub.length).toBe(2)
  })
})
