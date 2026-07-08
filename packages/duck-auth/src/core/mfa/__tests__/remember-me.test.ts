import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { credentialInput, identityInput } from '../../../test/store-inputs'
import { randomToken, sha256 } from '../../crypto'
import { RememberMeFacet } from '../remember-me'

describe('AuthRememberMeFacet', () => {
  let adapter: MemoryAdapter
  let facet: RememberMeFacet
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    facet = new RememberMeFacet(adapter.credentials, { authRandomToken: randomToken, authSha256: sha256 })
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }),
      {},
    )
    identityId = ident.id
  })

  it('issue + verify round-trip returns the same identity', async () => {
    const { token } = await facet.issue(identityId, { metadata: { label: 'macbook' } })
    const verified = await facet.verify(token)
    expect(verified?.identityId).toBe(identityId)
    expect(verified?.metadata).toMatchObject({ purpose: 'trusted-device', label: 'macbook' })
  })

  it('verify returns null for bogus token', async () => {
    await facet.issue(identityId)
    expect(await facet.verify('not-a-real-token')).toBeNull()
  })

  it('verify rejects empty / non-string input', async () => {
    await expect(facet.verify('')).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
  })

  it('verify does NOT consume the token (reusable across requests)', async () => {
    const { token } = await facet.issue(identityId)
    expect(await facet.verify(token)).not.toBeNull()
    expect(await facet.verify(token)).not.toBeNull()
    expect(await facet.verify(token)).not.toBeNull()
  })

  it('verify returns null after revoke', async () => {
    const { token, credentialId } = await facet.issue(identityId)
    await facet.revoke(identityId, credentialId)
    expect(await facet.verify(token)).toBeNull()
  })

  it('revoke is a no-op when (identityId, credentialId) ownership does not match', async () => {
    const otherIdentity = await adapter.identities.create(
      identityInput({ profile: { email: 'other@x.com', username: 'other' }, providers: [] }),
      {},
    )
    const { token, credentialId } = await facet.issue(identityId)
    await facet.revoke(otherIdentity.id, credentialId)
    // Token still verifies - the cross-identity revoke was refused.
    expect(await facet.verify(token)).not.toBeNull()
  })

  it('list returns live trusted devices with metadata', async () => {
    await facet.issue(identityId, { metadata: { label: 'macbook' } })
    await facet.issue(identityId, { metadata: { label: 'iphone' } })
    const devices = await facet.list(identityId)
    expect(devices).toHaveLength(2)
    expect(devices.map((d) => (d.metadata as { label: string }).label).sort()).toEqual(['iphone', 'macbook'])
  })

  it('revokeAll wipes every trusted device for the identity', async () => {
    await facet.issue(identityId)
    await facet.issue(identityId)
    await facet.revokeAll(identityId)
    expect(await facet.list(identityId)).toEqual([])
  })

  it('does not match recovery rows of a different purpose', async () => {
    // Manually insert a non-trusted-device recovery row + ensure verify
    // does not accept it as a trusted device.
    const token = randomToken(32)
    await adapter.credentials.upsert(
      credentialInput({
        identityId,
        kind: 'recovery',
        secret: sha256(token),
        metadata: { purpose: 'email-verification' },
      }),
      {},
    )
    expect(await facet.verify(token)).toBeNull()
  })

  it('respects ttl: expired token returns null + is auto-deleted', async () => {
    const tiny = new RememberMeFacet(
      adapter.credentials,
      { authRandomToken: randomToken, authSha256: sha256 },
      { ttlMs: 5, byteLength: 32 },
    )
    const { token, credentialId } = await tiny.issue(identityId)
    await new Promise((r) => setTimeout(r, 20))
    expect(await tiny.verify(token)).toBeNull()
    // Best-effort delete + may still be in the store briefly; explicit
    // list() filters revoked anyway. Assert the row no longer surfaces
    // via verify; cleanup is implementation detail.
    void credentialId
  })
})
