import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../index'

describe('identities store is tenant-free (global account)', () => {
  it('find() and link() take no tenant argument', () => {
    const a = new MemoryAdapter()
    // Arity is the contract: identities methods no longer accept tenant.
    expect(a.identities.find.length).toBe(1)
    expect(a.identities.link.length).toBe(2)
  })
})
