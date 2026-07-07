import { beforeEach, describe, expect, it } from 'vitest'
import type { Identity } from '../../../core/types/identity'
import { MemoryAdapter } from '..'
import { identityInput } from '../../../test/store-inputs'

/**
 * These robustness tests deliberately feed malformed `profile` shapes
 * (non-string email, arrays, objects, missing email) to prove `findByEmail`
 * fails closed. The strict `ProfileMetadataBase` contract rejects those at the
 * type level, so `mal()` casts each fixture through — the runtime behaviour is
 * exactly what we are exercising.
 */
const mal = (p: Record<string, unknown>): Identity.ProfileMetadataBase => p as unknown as Identity.ProfileMetadataBase

describe('MemoryAdapter.findByEmail - profile-shape robustness', () => {
  let adapter: MemoryAdapter<Identity.ProfileMetadataBase>

  beforeEach(() => {
    adapter = new MemoryAdapter<Identity.ProfileMetadataBase>()
  })

  it('finds an identity by well-formed string email', async () => {
    const ident = await adapter.identities.create(identityInput({ profile: mal({ email: 'ada@example.com' }), providers: [] }), {})
    const found = await adapter.identities.findByEmail('ada@example.com', {})
    expect(found?.id).toBe(ident.id)
  })

  it('does NOT match an identity whose profile.email is a number', async () => {
    await adapter.identities.create(identityInput({ profile: mal({ email: 42 }), providers: [] }), {})
    const found = await adapter.identities.findByEmail('42', {})
    expect(found).toBeNull()
  })

  it('does NOT match an identity whose profile.email is an array', async () => {
    await adapter.identities.create(identityInput({ profile: mal({ email: ['a@x.com', 'b@x.com'] }), providers: [] }), {})
    const found = await adapter.identities.findByEmail('a@x.com', {})
    expect(found).toBeNull()
  })

  it('does NOT match an identity whose profile.email is an object', async () => {
    await adapter.identities.create(identityInput({ profile: mal({ email: { primary: 'a@x.com' } }), providers: [] }), {})
    const found = await adapter.identities.findByEmail('a@x.com', {})
    expect(found).toBeNull()
  })

  it('does NOT match an identity whose profile.email is the empty string', async () => {
    await adapter.identities.create(identityInput({ profile: mal({ email: '' }), providers: [] }), {})
    const found = await adapter.identities.findByEmail('', {})
    expect(found).toBeNull()
  })

  it('skips a malformed-email identity while still finding a well-formed one', async () => {
    await adapter.identities.create(identityInput({ profile: mal({ email: 42 }), providers: [] }), {})
    const good = await adapter.identities.create(identityInput({ profile: mal({ email: 'good@example.com' }), providers: [] }), {})
    await adapter.identities.create(identityInput({ profile: mal({ email: ['arr@example.com'] }), providers: [] }), {})
    const found = await adapter.identities.findByEmail('good@example.com', {})
    expect(found?.id).toBe(good.id)
  })

  it("handles identities with no profile.email at all (other fields don't bleed through)", async () => {
    await adapter.identities.create(identityInput({ profile: mal({ phone: '+1234567890', name: 'Ada' }), providers: [] }), {})
    const found = await adapter.identities.findByEmail('Ada', {})
    expect(found).toBeNull()
  })
})
