import { beforeEach, describe, expect, it } from 'vitest'
import { AuthMemoryAdapter } from '..'

describe('AuthMemoryAdapter.findByEmail - profile-shape robustness', () => {
  let adapter: AuthMemoryAdapter<Record<string, unknown>>

  beforeEach(() => {
    adapter = new AuthMemoryAdapter<Record<string, unknown>>()
  })

  it('finds an identity by well-formed string email', async () => {
    const ident = await adapter.identities.create({ profile: { email: 'ada@example.com' }, providers: [] }, {})
    const found = await adapter.identities.findByEmail('ada@example.com', {})
    expect(found?.id).toBe(ident.id)
  })

  it('does NOT match an identity whose profile.email is a number', async () => {
    await adapter.identities.create({ profile: { email: 42 }, providers: [] }, {})
    const found = await adapter.identities.findByEmail('42', {})
    expect(found).toBeNull()
  })

  it('does NOT match an identity whose profile.email is an array', async () => {
    await adapter.identities.create({ profile: { email: ['a@x.com', 'b@x.com'] }, providers: [] }, {})
    const found = await adapter.identities.findByEmail('a@x.com', {})
    expect(found).toBeNull()
  })

  it('does NOT match an identity whose profile.email is an object', async () => {
    await adapter.identities.create({ profile: { email: { primary: 'a@x.com' } }, providers: [] }, {})
    const found = await adapter.identities.findByEmail('a@x.com', {})
    expect(found).toBeNull()
  })

  it('does NOT match an identity whose profile.email is the empty string', async () => {
    await adapter.identities.create({ profile: { email: '' }, providers: [] }, {})
    const found = await adapter.identities.findByEmail('', {})
    expect(found).toBeNull()
  })

  it('skips a malformed-email identity while still finding a well-formed one', async () => {
    await adapter.identities.create({ profile: { email: 42 }, providers: [] }, {})
    const good = await adapter.identities.create({ profile: { email: 'good@example.com' }, providers: [] }, {})
    await adapter.identities.create({ profile: { email: ['arr@example.com'] }, providers: [] }, {})
    const found = await adapter.identities.findByEmail('good@example.com', {})
    expect(found?.id).toBe(good.id)
  })

  it("handles identities with no profile.email at all (other fields don't bleed through)", async () => {
    await adapter.identities.create({ profile: { phone: '+1234567890', name: 'Ada' }, providers: [] }, {})
    const found = await adapter.identities.findByEmail('Ada', {})
    expect(found).toBeNull()
  })
})
