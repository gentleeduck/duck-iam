import { beforeEach, describe, expect, it } from 'vitest'
import type { Identities } from '~/core/identities/identities.types'
import { identityInput } from '~/test/store-inputs'
import { MemoryAdapter } from '..'

/**
 * `find({ email })` must answer on the address and on nothing else. The malformed *stored* profiles this
 * file used to plant — a numeric address, an array, a missing one — are refused on the way in now, the
 * store carrying the same `chk_auth_identities_profile_shape` every dialect declares; those cases live in
 * `identity-invariants-parity.test.ts`. What is left here is what a caller can still ask for.
 */
const profile = (over: Record<string, unknown> = {}): Identities.ProfileMetadataBase =>
  Object.assign({ email: 'ada@example.com', username: 'ada' }, over)

describe('MemoryAdapter find({ email }) matches the address and nothing else', () => {
  let adapter: MemoryAdapter<Identities.ProfileMetadataBase>

  beforeEach(() => {
    adapter = new MemoryAdapter<Identities.ProfileMetadataBase>()
  })

  it('finds an identity by its address', async () => {
    const ident = await adapter.identities.create(identityInput({ profile: profile(), providers: [] }))

    await expect(adapter.identities.find({ email: 'ada@example.com' })).resolves.toMatchObject({ id: ident.id })
  })

  it('does not let another profile key answer for the address', async () => {
    await adapter.identities.create(
      identityInput({ profile: profile({ name: 'Ada', phone: '+1234567890' }), providers: [] }),
    )

    await expect(adapter.identities.find({ email: 'Ada' })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
  })

  it('matches nothing on a blank address, which is now a thing no row can hold', async () => {
    // `toEmailList('')` answers `['']` on the reasoning that no dialect stores a blank one. That was true
    // of the dialects and not of this store.
    await adapter.identities.create(identityInput({ profile: profile(), providers: [] }))

    await expect(adapter.identities.find({ email: '' })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
  })

  it('finds the one identity among several that holds the address asked for', async () => {
    await adapter.identities.create(
      identityInput({ profile: profile({ email: 'other@example.com', username: 'other' }), providers: [] }),
    )
    const good = await adapter.identities.create(
      identityInput({ profile: profile({ email: 'good@example.com', username: 'good' }), providers: [] }),
    )

    await expect(adapter.identities.find({ email: 'good@example.com' })).resolves.toMatchObject({ id: good.id })
  })
})
