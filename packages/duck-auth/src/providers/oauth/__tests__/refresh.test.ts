import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { Identities } from '~/core/identities'
import { credentialInput, identityInput } from '~/test/store-inputs'
import type { OAuth } from '../core/oauth.types'
import { authRefreshoauthToken, parseFamilyMetadata } from '../core/refresh'

interface Profile extends Identities.ProfileMetadataBase {}

describe('oauth refresh-token reuse detection (RFC 6749 section 10.4)', () => {
  let adapter: MemoryAdapter<Profile>
  let events: InMemoryEvents
  let identityId: string

  async function seedRefresh(refreshPlain: string, familyId = 'fam-1'): Promise<void> {
    await adapter.credentials.create(
      credentialInput({
        identityId,
        kind: 'oauth',
        secret: sha256(refreshPlain),
        metadata: {
          provider: 'oauth:fake',
          sub: 'idp-sub-1',
          familyId,
          generation: 1,
          accessToken: 'at-1',
        } satisfies OAuth.FamilyMetadata,
      }),
      {},
    )
  }

  beforeEach(async () => {
    adapter = new MemoryAdapter<Profile>()
    events = new InMemoryEvents()
    const i = await adapter.identities.create(
      identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }),
    )
    identityId = i.id
  })

  it('refuses to refresh once the identity is soft-deleted, without calling the provider', async () => {
    await seedRefresh('rt-old')
    const exchange = vi.fn(async (): Promise<OAuth.TokenResponse> => {
      throw new Error('exchange must not run for a deleted identity')
    })

    await adapter.identities.softDelete(identityId, 60_000)

    await expect(
      authRefreshoauthToken({
        credentials: adapter.credentials,
        events,
        exchange,
        identities: adapter.identities,
        presentedRefreshToken: 'rt-old',
        tenant: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })

    // Checked before the CAS and before the network call, so a refresh for a
    // dead account costs nothing and leaves the row intact for a later restore.
    expect(exchange).not.toHaveBeenCalled()
    const row = await adapter.credentials.findByHashedSecret(sha256('rt-old'), 'oauth', {})
    expect(row?.revokedAt ?? null).toBeNull()
  })

  it('still refreshes for a live identity when the probe is supplied (control)', async () => {
    await seedRefresh('rt-live')
    const exchange = vi.fn(
      async (): Promise<OAuth.TokenResponse> => ({
        access_token: 'at-2',
        expires_in: 3600,
        refresh_token: 'rt-live-2',
        token_type: 'Bearer',
      }),
    )

    // Without this the guard above would also pass if the probe simply refused
    // everything it was handed.
    const r = await authRefreshoauthToken({
      credentials: adapter.credentials,
      events,
      exchange,
      identities: adapter.identities,
      presentedRefreshToken: 'rt-live',
      tenant: {},
    })

    expect(r.identityId).toBe(identityId)
    expect(exchange).toHaveBeenCalledOnce()
  })

  it('happy path rotates the refresh token + bumps generation', async () => {
    await seedRefresh('rt-old')
    const exchange = vi.fn(
      async (): Promise<OAuth.TokenResponse> => ({
        access_token: 'at-2',
        refresh_token: 'rt-new',
        token_type: 'Bearer',
        expires_in: 3600,
      }),
    )

    const r = await authRefreshoauthToken({
      presentedRefreshToken: 'rt-old',
      tenant: {},
      credentials: adapter.credentials,
      identities: adapter.identities,
      events,
      exchange,
    })
    expect(exchange).toHaveBeenCalledOnce()
    expect(r.tokens.refresh_token).toBe('rt-new')

    // New row persists.
    const newRow = await adapter.credentials.findByHashedSecret(sha256('rt-new'), 'oauth', {})
    expect(newRow).not.toBeNull()
    expect((newRow?.metadata as OAuth.FamilyMetadata).generation).toBe(2)

    // The old token is spent: its hash resolves to nothing, because claiming the row moved the secret off
    // it. The row is still there under the hash the claim wrote, which is what the replay case below
    // finds in order to revoke the family.
    await expect(adapter.credentials.findByHashedSecret(sha256('rt-old'), 'oauth', {})).rejects.toMatchObject({
      code: 'AUTH_CREDENTIAL_NOT_FOUND',
    })
  })

  it('replay of old refresh token surfaces AUTH/oauth/REUSE_DETECTED + emits suspicious + revokes family', async () => {
    await seedRefresh('rt-old')
    const exchange = vi.fn(
      async (): Promise<OAuth.TokenResponse> => ({
        access_token: 'at-2',
        refresh_token: 'rt-new',
        token_type: 'Bearer',
        expires_in: 3600,
      }),
    )
    // First (happy) use rotates.
    await authRefreshoauthToken({
      presentedRefreshToken: 'rt-old',
      tenant: {},
      credentials: adapter.credentials,
      identities: adapter.identities,
      events,
      exchange,
    })

    const suspicious = vi.fn()
    events.on('suspicious', suspicious)

    // Replay the now-revoked old token.
    await expect(
      authRefreshoauthToken({
        presentedRefreshToken: 'rt-old',
        tenant: {},
        credentials: adapter.credentials,
        identities: adapter.identities,
        events,
        exchange: vi.fn(),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_OAUTH_REUSE_DETECTED', meta: { familyRevoked: true } })

    expect(suspicious).toHaveBeenCalledOnce()
    expect(suspicious.mock.calls[0]?.[0].signal).toBe('oauth-refresh-reuse')

    // Family revoked: the new token (rt-new) row is also marked revoked.
    const newRow = await adapter.credentials.findByHashedSecret(sha256('rt-new'), 'oauth', {})
    expect(newRow?.revokedAt).toBeTruthy()
  })

  it('a token presented after the claim, while the exchange is still in flight, gets no exchange of its own', async () => {
    // The claim is a CAS on `version`, which only stops a racer that read *before* it landed. One that
    // reads after sees a live row at the next version and wins a CAS of its own - and the window is the
    // whole outbound exchange, not a couple of adjacent writes.
    await seedRefresh('rt-old')
    let release = (): void => {}
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    let exchangeCalls = 0
    const gatedExchange = async (): Promise<OAuth.TokenResponse> => {
      exchangeCalls += 1
      // Only the winner waits, so the bug fails this test loudly instead of hanging it.
      if (exchangeCalls === 1) await held
      return { access_token: 'at-2', expires_in: 3600, refresh_token: `rt-new-${exchangeCalls}`, token_type: 'Bearer' }
    }
    const suspicious = vi.fn()
    events.on('suspicious', suspicious)

    const winner = authRefreshoauthToken({
      credentials: adapter.credentials,
      events,
      exchange: gatedExchange,
      identities: adapter.identities,
      presentedRefreshToken: 'rt-old',
      tenant: {},
    })
    await vi.waitFor(() => {
      if (exchangeCalls === 0) throw new Error('the winner has not claimed the row yet')
    })

    await expect(
      authRefreshoauthToken({
        credentials: adapter.credentials,
        events,
        exchange: gatedExchange,
        identities: adapter.identities,
        presentedRefreshToken: 'rt-old',
        tenant: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH_OAUTH_REUSE_DETECTED', meta: { familyRevoked: true } })

    // The claimed row is still found, so this is reuse against a known family rather than an unknown row:
    // that is what lets the family be revoked at all.
    expect(suspicious.mock.calls[0]?.[0].signal).toBe('oauth-refresh-reuse')
    expect(exchangeCalls).toBe(1)

    release()
    await winner
  })

  it('an exchange that fails releases the claim, so the refresh token still works', async () => {
    // Claiming the row spends the token, so a provider that is briefly unreachable would otherwise cost
    // the client its session. Nothing has been issued at that point, so the claim goes back.
    await seedRefresh('rt-flaky')
    await expect(
      authRefreshoauthToken({
        credentials: adapter.credentials,
        events,
        exchange: async () => {
          throw new Error('provider unreachable')
        },
        identities: adapter.identities,
        presentedRefreshToken: 'rt-flaky',
        tenant: {},
      }),
    ).rejects.toThrow('provider unreachable')

    const r = await authRefreshoauthToken({
      credentials: adapter.credentials,
      events,
      exchange: async () => ({
        access_token: 'at-2',
        expires_in: 3600,
        refresh_token: 'rt-flaky-2',
        token_type: 'Bearer',
      }),
      identities: adapter.identities,
      presentedRefreshToken: 'rt-flaky',
      tenant: {},
    })
    expect(r.tokens.refresh_token).toBe('rt-flaky-2')
  })

  it('unknown refresh token surfaces AUTH/oauth/REUSE_DETECTED (treat as leaked)', async () => {
    await expect(
      authRefreshoauthToken({
        presentedRefreshToken: 'never-issued',
        tenant: {},
        credentials: adapter.credentials,
        identities: adapter.identities,
        events,
        exchange: vi.fn(),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_OAUTH_REUSE_DETECTED' })
  })

  it('unknown row also emits `suspicious` (operator can page on leaked-token signal)', async () => {
    const suspicious = vi.fn()
    events.on('suspicious', suspicious)
    await expect(
      authRefreshoauthToken({
        presentedRefreshToken: 'never-issued',
        tenant: {},
        credentials: adapter.credentials,
        identities: adapter.identities,
        events,
        exchange: vi.fn(),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_OAUTH_REUSE_DETECTED', meta: { familyRevoked: false } })
    expect(suspicious).toHaveBeenCalledOnce()
    expect(suspicious.mock.calls[0]?.[0].signal).toBe('oauth-refresh-unknown-row')
  })

  it('IdP that does not rotate (no refresh_token in response) keeps the current row and stores no access token', async () => {
    await seedRefresh('rt-stable')
    const exchange = vi.fn(
      async (): Promise<OAuth.TokenResponse> => ({
        access_token: 'at-new',
        token_type: 'Bearer',
        expires_in: 60,
      }),
    )
    const r = await authRefreshoauthToken({
      presentedRefreshToken: 'rt-stable',
      tenant: {},
      credentials: adapter.credentials,
      identities: adapter.identities,
      events,
      exchange,
    })
    // The caller gets the fresh token in hand; the row must not keep a copy of it.
    expect(r.tokens.access_token).toBe('at-new')
    const row = await adapter.credentials.findByHashedSecret(sha256('rt-stable'), 'oauth', {})
    expect(row?.metadata).not.toHaveProperty('accessToken')
    expect(JSON.stringify(row?.metadata)).not.toContain('at-new')
  })

  it('concurrent refreshes with the same token - only one wins, loser revokes family', async () => {
    await seedRefresh('rt-old')
    let exchangeCalls = 0
    const slowExchange = async (): Promise<OAuth.TokenResponse> => {
      exchangeCalls++
      const which = exchangeCalls
      await new Promise((r) => setTimeout(r, 30))
      return {
        access_token: `at-${which}`,
        refresh_token: `rt-new-${which}`,
        token_type: 'Bearer',
        expires_in: 3600,
      }
    }
    const suspicious = vi.fn()
    events.on('suspicious', suspicious)

    const [a, b] = await Promise.allSettled([
      authRefreshoauthToken({
        presentedRefreshToken: 'rt-old',
        tenant: {},
        credentials: adapter.credentials,
        identities: adapter.identities,
        events,
        exchange: slowExchange,
      }),
      authRefreshoauthToken({
        presentedRefreshToken: 'rt-old',
        tenant: {},
        credentials: adapter.credentials,
        identities: adapter.identities,
        events,
        exchange: slowExchange,
      }),
    ])
    // Exactly one fulfilled, one rejected with oauth/REUSE_DETECTED.
    const fulfilled = [a, b].filter((r) => r.status === 'fulfilled')
    const rejected = [a, b].filter((r) => r.status === 'rejected')
    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)
    expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({
      code: 'AUTH_OAUTH_REUSE_DETECTED',
    })
    // Race detection emitted suspicious with the new "oauth-refresh-race" signal.
    expect(suspicious).toHaveBeenCalled()
    expect(suspicious.mock.calls[0]?.[0].signal).toBe('oauth-refresh-race')
  })

  describe('family metadata validation', () => {
    const good = { familyId: 'f', generation: 1, provider: 'oauth:fake', sub: 's' }

    it('drops a legacy accessToken instead of carrying it forward', () => {
      const parsed = parseFamilyMetadata({ ...good, accessToken: 'ya29-LIVE-BEARER', accessTokenExpiresAt: 123 })
      expect(parsed).toEqual(good)
      expect(JSON.stringify(parsed)).not.toContain('ya29-LIVE-BEARER')
    })

    it("keeps the operator's own extra fields", () => {
      expect(parseFamilyMetadata({ ...good, mine: 'keep' })).toEqual({ ...good, mine: 'keep' })
    })

    it('rejects metadata with non-numeric generation', () => {
      expect(parseFamilyMetadata({ ...good, generation: '1' })).toBeNull()
    })

    it('rejects metadata with non-string familyId (would mis-target revokeFamily)', () => {
      expect(parseFamilyMetadata({ ...good, familyId: { evil: 'object' } })).toBeNull()
    })

    it('authRefreshoauthToken throws PROVIDER_FAILED on malformed family metadata', async () => {
      // Seed a credential whose metadata is structurally broken (would
      // pass the `as` cast). Calling refresh should fail closed.
      await adapter.credentials.create(
        credentialInput({
          identityId,
          kind: 'oauth',
          secret: sha256('rt-broken'),
          metadata: {
            provider: 'oauth:fake',
            sub: 'idp-sub-1',
            familyId: 'fam-broken',
            generation: 'one', // wrong type -> string-concat bug downstream
            accessToken: 'at-broken',
          },
        }),
        {},
      )
      const exchange = vi.fn(
        async (): Promise<OAuth.TokenResponse> => ({
          access_token: 'at-x',
          token_type: 'Bearer',
        }),
      )
      await expect(
        authRefreshoauthToken({
          presentedRefreshToken: 'rt-broken',
          tenant: {},
          credentials: adapter.credentials,
          identities: adapter.identities,
          events,
          exchange,
        }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
      // Never reaches the slow exchange - the parser blocks at the front.
      expect(exchange).not.toHaveBeenCalled()
    })
  })
})
