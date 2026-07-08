import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { Identity } from '../../../core'
import { sha256 } from '../../../core/crypto'
import { InMemoryEvents } from '../../../core/events'
import { credentialInput, identityInput } from '../../../test/store-inputs'
import type { OauthClient } from '../core/client'
import { AuthoauthRefresh, authRefreshoauthToken, projectAccessToken } from '../core/refresh'

interface Profile extends Identity.ProfileMetadataBase {}

describe('oauth refresh-token reuse detection (RFC 6749 section 10.4)', () => {
  let adapter: MemoryAdapter<Profile>
  let events: InMemoryEvents
  let identityId: string

  async function seedRefresh(refreshPlain: string, familyId = 'fam-1'): Promise<void> {
    await adapter.credentials.upsert(
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
        } satisfies AuthoauthRefresh.IFamilyMetadata,
      }),
      {},
    )
  }

  beforeEach(async () => {
    adapter = new MemoryAdapter<Profile>()
    events = new InMemoryEvents()
    const i = await adapter.identities.create(
      identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }),
      {},
    )
    identityId = i.id
  })

  it('happy path rotates the refresh token + bumps generation', async () => {
    await seedRefresh('rt-old')
    const exchange = vi.fn(
      async (): Promise<OauthClient.TokenResponse> => ({
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
      events,
      exchange,
    })
    expect(exchange).toHaveBeenCalledOnce()
    expect(r.tokens.refresh_token).toBe('rt-new')

    // New row persists; old row is revoked.
    const newRow = await adapter.credentials.findByHashedSecret(sha256('rt-new'), 'oauth', {})
    expect(newRow).not.toBeNull()
    expect((newRow?.metadata as AuthoauthRefresh.IFamilyMetadata).generation).toBe(2)

    const oldRow = await adapter.credentials.findByHashedSecret(sha256('rt-old'), 'oauth', {})
    expect(oldRow?.revokedAt).toBeTruthy()
  })

  it('replay of old refresh token surfaces AUTH/oauth/REUSE_DETECTED + emits suspicious + revokes family', async () => {
    await seedRefresh('rt-old')
    const exchange = vi.fn(
      async (): Promise<OauthClient.TokenResponse> => ({
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

  it('unknown refresh token surfaces AUTH/oauth/REUSE_DETECTED (treat as leaked)', async () => {
    await expect(
      authRefreshoauthToken({
        presentedRefreshToken: 'never-issued',
        tenant: {},
        credentials: adapter.credentials,
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
        events,
        exchange: vi.fn(),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_OAUTH_REUSE_DETECTED', meta: { familyRevoked: false } })
    expect(suspicious).toHaveBeenCalledOnce()
    expect(suspicious.mock.calls[0]?.[0].signal).toBe('oauth-refresh-unknown-row')
  })

  it('IdP that does not rotate (no refresh_token in response) keeps the current row + updates access token', async () => {
    await seedRefresh('rt-stable')
    const exchange = vi.fn(
      async (): Promise<OauthClient.TokenResponse> => ({
        access_token: 'at-new',
        token_type: 'Bearer',
        expires_in: 60,
      }),
    )
    const r = await authRefreshoauthToken({
      presentedRefreshToken: 'rt-stable',
      tenant: {},
      credentials: adapter.credentials,
      events,
      exchange,
    })
    expect(r.tokens.access_token).toBe('at-new')
    // Old refresh token still resolves; access token updated.
    const row = await adapter.credentials.findByHashedSecret(sha256('rt-stable'), 'oauth', {})
    expect((row?.metadata as AuthoauthRefresh.IFamilyMetadata).accessToken).toBe('at-new')
  })

  it('concurrent refreshes with the same token - only one wins, loser revokes family', async () => {
    await seedRefresh('rt-old')
    let exchangeCalls = 0
    const slowExchange = async (): Promise<OauthClient.TokenResponse> => {
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
        events,
        exchange: slowExchange,
      }),
      authRefreshoauthToken({
        presentedRefreshToken: 'rt-old',
        tenant: {},
        credentials: adapter.credentials,
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

  it('projectAccessToken returns null when access token expired', () => {
    const expired = projectAccessToken({
      id: 'x',
      identityId,
      kind: 'oauth',
      secret: 'h',
      version: 1,
      createdAt: new Date(0),
      metadata: {
        provider: 'oauth:fake',
        sub: 's',
        familyId: 'f',
        generation: 1,
        accessToken: 'at',
        accessTokenExpiresAt: Date.now() - 1,
      } satisfies AuthoauthRefresh.IFamilyMetadata,
      tenantId: null,
      expiresAt: null,
      revokedAt: null,
      lastUsedAt: null,
    })
    expect(expired).toBeNull()
  })

  describe('family metadata validation', () => {
    function rowWithMeta(metadata: Record<string, unknown>): Parameters<typeof projectAccessToken>[0] {
      return {
        id: 'x',
        identityId,
        kind: 'oauth',
        secret: 'h',
        version: 1,
        createdAt: new Date(0),
        metadata,
        tenantId: null,
        expiresAt: null,
        revokedAt: null,
        lastUsedAt: null,
      }
    }

    it('projectAccessToken rejects metadata whose accessTokenExpiresAt is a string (would bypass expiry via NaN)', () => {
      // Previously `as IFamilyMetadata` cast passed this through; the
      // numeric-comparison check `expiresAt < Date.now()` evaluated
      // `NaN < N === false` and returned the stale access token as fresh.
      const result = projectAccessToken(
        rowWithMeta({
          provider: 'oauth:fake',
          sub: 's',
          familyId: 'f',
          generation: 1,
          accessToken: 'at',
          accessTokenExpiresAt: '9999999999',
        }),
      )
      expect(result).toBeNull()
    })

    it('projectAccessToken rejects metadata with non-numeric generation', () => {
      const result = projectAccessToken(
        rowWithMeta({
          provider: 'oauth:fake',
          sub: 's',
          familyId: 'f',
          generation: '1',
          accessToken: 'at',
        }),
      )
      expect(result).toBeNull()
    })

    it('projectAccessToken rejects metadata with non-string familyId (would mis-target revokeFamily)', () => {
      const result = projectAccessToken(
        rowWithMeta({
          provider: 'oauth:fake',
          sub: 's',
          familyId: { evil: 'object' },
          generation: 1,
          accessToken: 'at',
        }),
      )
      expect(result).toBeNull()
    })

    it('authRefreshoauthToken throws PROVIDER_FAILED on malformed family metadata', async () => {
      // Seed a credential whose metadata is structurally broken (would
      // pass the `as` cast). Calling refresh should fail closed.
      await adapter.credentials.upsert(
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
        async (): Promise<OauthClient.TokenResponse> => ({
          access_token: 'at-x',
          token_type: 'Bearer',
        }),
      )
      await expect(
        authRefreshoauthToken({
          presentedRefreshToken: 'rt-broken',
          tenant: {},
          credentials: adapter.credentials,
          events,
          exchange,
        }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
      // Never reaches the slow exchange - the parser blocks at the front.
      expect(exchange).not.toHaveBeenCalled()
    })
  })
})
