import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../index'

describe('identities store is tenant-free (global account)', () => {
  it('merge() and find() take no tenant argument', () => {
    const a = new MemoryAdapter()
    // Arity is the contract: identities methods no longer accept tenant.
    expect(a.identities.merge.length).toBe(2)
    expect(a.identities.find.length).toBe(1)
  })
})
