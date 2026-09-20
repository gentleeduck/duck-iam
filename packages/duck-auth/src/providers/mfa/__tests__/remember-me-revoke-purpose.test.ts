import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials.constants'
import { randomToken, sha256 } from '~/core/crypto'
import { credentialInput, identityInput } from '~/test/store-inputs'
import { DEFAULT_REMEMBER_ME_CONFIG, RememberMeFacet } from '../internal/remember-me'

const CRYPTO = { authRandomToken: randomToken, authSha256: sha256 }

/**
 * `revoke` takes a credential id straight off a "remove this device" request. It checks the row belongs
 * to the caller and then deletes it, whatever kind of credential it turned out to be.
 */
describe('RememberMeFacet.revoke only touches trusted devices', () => {
  let adapter: MemoryAdapter
  let facet: RememberMeFacet
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    facet = new RememberMeFacet(adapter.credentials, CRYPTO)
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    identityId = ident.id
  })

  it('leaves the identity’s TOTP enrollment alone', async () => {
    const totp = await adapter.credentials.create(
      credentialInput({ identityId, kind: 'totp', metadata: { confirmed: true }, secret: 'JBSWY3DPEHPK3PXP' }),
      {},
    )
    await facet.revoke(identityId, totp.id)
    expect(await orNull(adapter.credentials.findById(totp.id, {}))).not.toBeNull()
  })

  it('leaves a pending password-reset token alone', async () => {
    const reset = await adapter.credentials.create(
      credentialInput({
        identityId,
        kind: 'recovery',
        metadata: { purpose: RECOVERY_PURPOSES.passwordReset },
        secret: sha256('reset-token'),
      }),
      {},
    )
    await facet.revoke(identityId, reset.id)
    expect(await orNull(adapter.credentials.findById(reset.id, {}))).not.toBeNull()
  })

  it('still revokes an actual trusted device', async () => {
    const { credentialId } = await facet.issue(identityId)
    await facet.revoke(identityId, credentialId)
    expect(await orNull(adapter.credentials.findById(credentialId, {}))).toBeNull()
  })
})

describe('RememberMeFacet list and revokeAll agree about what a device is', () => {
  let adapter: MemoryAdapter
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    identityId = ident.id
  })

  // A real elapsed TTL, not a negative one: the memory adapter refuses to create a row that is already
  // past its expiry, so the window has to open after the write.
  const elapsed = async () => {
    const facet = new RememberMeFacet(adapter.credentials, CRYPTO, { ...DEFAULT_REMEMBER_ME_CONFIG, ttlMs: 5 })
    const issued = await facet.issue(identityId)
    await new Promise((r) => setTimeout(r, 30))
    return { facet, issued }
  }

  it('list omits a device whose TTL has elapsed', async () => {
    const { facet } = await elapsed()
    expect(await facet.list(identityId)).toHaveLength(0)
  })

  it('revokeAll wipes an expired device too, rather than leaving the row behind', async () => {
    const { facet, issued } = await elapsed()
    await facet.revokeAll(identityId)
    expect(await orNull(adapter.credentials.findById(issued.credentialId, {}))).toBeNull()
  })
})
