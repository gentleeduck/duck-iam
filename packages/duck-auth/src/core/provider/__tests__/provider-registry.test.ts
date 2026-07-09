import { describe, expect, it } from 'vitest'
import { Providers } from '../provider'

class FakeFacet {
  readonly id = 'fake'
  readonly kind = 'fake'
}

const signInProvider = {
  id: 'password',
  kind: 'password',
  begin: async () => [],
  complete: async () => [],
}

describe('Providers capability registry', () => {
  it('resolve() returns the entry that is instanceof the ctor', () => {
    const facet = new FakeFacet()
    const reg = new Providers([signInProvider, facet])
    expect(reg.resolve(FakeFacet)).toBe(facet)
  })

  it('resolve() returns null when no entry matches the ctor', () => {
    const reg = new Providers([signInProvider])
    expect(reg.resolve(FakeFacet)).toBeNull()
  })

  it('list() excludes non-sign-in capabilities (no complete())', () => {
    const reg = new Providers([signInProvider, new FakeFacet()])
    expect(reg.list().map((e) => e.id)).toEqual(['password'])
  })

  it('register() still rejects duplicate ids', () => {
    const reg = new Providers([signInProvider])
    expect(() => reg.register(signInProvider)).toThrow()
  })
})
