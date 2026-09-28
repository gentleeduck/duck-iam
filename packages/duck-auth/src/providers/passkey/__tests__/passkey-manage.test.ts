import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { credentialInput } from '~/test/store-inputs'
import { PasskeyImpl } from '../index'

const OWNER = 'user-1'
const OTHER = 'user-2'

async function setup() {
  const store = new MemoryAdapter().credentials
  const facet = new PasskeyImpl({
    rpID: 'x.test',
    rpName: 'X',
    expectedOrigins: ['https://x.test'],
    findIdentityByEmail: async () => null,
  })
  const plant = (identityId: string, kind: 'passkey' | 'password', secret: string) =>
    store.create(credentialInput({ identityId, kind, secret, metadata: { publicKey: `pk-${secret}` } }), {})
  const phone = await plant(OWNER, 'passkey', 'cred-phone')
  const laptop = await plant(OWNER, 'passkey', 'cred-laptop')
  const password = await plant(OWNER, 'password', 'hash')
  const theirs = await plant(OTHER, 'passkey', 'cred-theirs')
  return { facet, laptop, password, phone, store, theirs }
}

describe('passkey management', () => {
  it('lists the identity live passkeys without their secret', async () => {
    const { facet, laptop, phone, store } = await setup()
    await store.revoke(laptop.id, {})
    const listed = await facet.list(OWNER, store)
    expect(listed.map((c) => c.id)).toEqual([phone.id])
    expect(listed[0]).not.toHaveProperty('secret')
    expect(listed[0]?.metadata).toEqual({ publicKey: 'pk-cred-phone' })
  })

  it('revokes a passkey the identity holds, and refuses one of another identity or another kind', async () => {
    const { facet, password, phone, store, theirs } = await setup()
    const revoked = await facet.revoke(OWNER, phone.id, store)
    expect(revoked.id).toBe(phone.id)
    expect(revoked.revokedAt).toBeInstanceOf(Date)
    expect(revoked).not.toHaveProperty('secret')
    for (const id of [theirs.id, password.id]) {
      await expect(facet.revoke(OWNER, id, store)).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      expect((await store.findById(id, {})).revokedAt).toBeNull()
    }
  })

  it('revokes every live passkey the identity holds and nothing else', async () => {
    const { facet, laptop, password, phone, store, theirs } = await setup()
    const revoked = await facet.revokeAll(OWNER, store)
    expect(revoked.map((c) => c.id).sort()).toEqual([laptop.id, phone.id].sort())
    expect(revoked.every((c) => !('secret' in c))).toBe(true)
    expect(await facet.list(OWNER, store)).toEqual([])
    expect((await store.findById(password.id, {})).revokedAt).toBeNull()
    expect((await store.findById(theirs.id, {})).revokedAt).toBeNull()
  })
})
