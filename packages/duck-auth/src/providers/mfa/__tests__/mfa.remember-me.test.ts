import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials.constants'
import { randomToken, sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { credentialInput, identityInput } from '~/test/store-inputs'
import { RememberMeFacet } from '../internal/remember-me'
import { MfaImpl } from '../mfa'
import { DEFAULT_MFA_CONFIG } from '../mfa.constants'

describe('RememberMeFacet', () => {
  let adapter: MemoryAdapter
  let facet: RememberMeFacet
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    facet = new RememberMeFacet(adapter.credentials, { authRandomToken: randomToken, authSha256: sha256 })
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }),
    )
    identityId = ident.id
  })

  it('issue + verify round-trip returns the same identity', async () => {
    const { token } = await facet.issue(identityId, { metadata: { label: 'macbook' } })
    const verified = await facet.verify(token)
    expect(verified.identityId).toBe(identityId)
    expect(verified.metadata).toMatchObject({ purpose: 'trusted-device', label: 'macbook' })
  })

  it('keeps its own purpose whatever metadata the caller passes', async () => {
    const { token } = await facet.issue(identityId, {
      metadata: { label: 'laptop', purpose: RECOVERY_PURPOSES.passwordReset },
    })
    await expect(facet.verify(token)).resolves.toMatchObject({
      metadata: { label: 'laptop', purpose: RECOVERY_PURPOSES.trustedDevice },
    })
    await facet.revokeAll(identityId)
    expect(await adapter.credentials.listByIdentity(identityId, 'recovery', {})).toEqual([])
  })

  it('verify rejects a token never issued', async () => {
    await facet.issue(identityId)
    await expect(facet.verify('not-a-real-token')).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })

  it('verify rejects empty / non-string input', async () => {
    await expect(facet.verify('')).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
  })

  it('verify does NOT consume the token (reusable across requests)', async () => {
    const { token } = await facet.issue(identityId)
    await expect(facet.verify(token)).resolves.toBeDefined()
    await expect(facet.verify(token)).resolves.toBeDefined()
    await expect(facet.verify(token)).resolves.toBeDefined()
  })

  it('verify rejects after revoke', async () => {
    const { token, credentialId } = await facet.issue(identityId)
    await facet.revoke(identityId, credentialId)
    await expect(facet.verify(token)).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })

  it('revoke is a no-op when (identityId, credentialId) ownership does not match', async () => {
    const otherIdentity = await adapter.identities.create(
      identityInput({ profile: { email: 'other@x.com', username: 'other' }, providers: [] }),
    )
    const { token, credentialId } = await facet.issue(identityId)
    await facet.revoke(otherIdentity.id, credentialId)
    // Token still verifies - the cross-identity revoke was refused.
    await expect(facet.verify(token)).resolves.toBeDefined()
  })

  it('list returns live trusted devices with metadata', async () => {
    await facet.issue(identityId, { metadata: { label: 'macbook' } })
    await facet.issue(identityId, { metadata: { label: 'iphone' } })
    const devices = await facet.list(identityId)
    expect(devices).toHaveLength(2)
    expect(devices.map((d) => d.metadata?.label).sort()).toEqual(['iphone', 'macbook'])
  })

  it('revokeAll wipes every trusted device for the identity', async () => {
    await facet.issue(identityId)
    await facet.issue(identityId)
    await facet.revokeAll(identityId)
    expect(await facet.list(identityId)).toEqual([])
  })

  it('does not match recovery rows of a different purpose', async () => {
    const token = randomToken(32)
    await adapter.credentials.create(
      credentialInput({
        identityId,
        kind: 'recovery',
        secret: sha256(token),
        metadata: { purpose: 'email-verification' },
      }),
      {},
    )
    await expect(facet.verify(token)).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })

  it('verify rejects a token past its ttl', async () => {
    const tiny = new RememberMeFacet(
      adapter.credentials,
      { authRandomToken: randomToken, authSha256: sha256 },
      { ttlMs: 5, byteLength: 32 },
    )
    const { token } = await tiny.issue(identityId)
    await new Promise((r) => setTimeout(r, 20))
    await expect(tiny.verify(token)).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })
})

describe('a remembered device goes with the factor it skipped', () => {
  let adapter: MemoryAdapter
  let devices: RememberMeFacet
  let mfa: MfaImpl

  beforeEach(() => {
    adapter = new MemoryAdapter()
    devices = new RememberMeFacet(adapter.credentials, { authRandomToken: randomToken, authSha256: sha256 })
    mfa = new MfaImpl(adapter.credentials, new InMemoryEvents(), DEFAULT_MFA_CONFIG)
  })

  it.each(['removeTotp', 'removeWebauthnMfa'] as const)(
    "%s revokes the identity's devices and no one else's",
    async (remove) => {
      const mine = await devices.issue('user-1')
      const theirs = await devices.issue('user-2')
      await mfa[remove]('user-1')
      await expect(devices.verify(mine.token)).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      await expect(devices.verify(theirs.token)).resolves.toMatchObject({ identityId: 'user-2' })
    },
  )

  it('removeBackupCodes keeps them: a device skips the factor, not its fallback', async () => {
    const { token } = await devices.issue('user-1')
    await mfa.regenerateBackupCodes('user-1')
    expect(await mfa.removeBackupCodes('user-1')).toEqual({ removed: DEFAULT_MFA_CONFIG.backupCodeCount })
    await expect(devices.verify(token)).resolves.toMatchObject({ identityId: 'user-1' })
  })
})
