/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { sha256 } from '../../../core/crypto'
import { InMemoryEvents } from '../../../core/events'
import type { TokenResponse } from '../core/client'
import { type OAuthFamilyMetadata, projectAccessToken, refreshOauthToken } from '../core/refresh'

interface Profile {
  email: string
}

describe('OAuth refresh-token reuse detection (RFC 6749 section 10.4)', () => {
  let adapter: MemoryAuthAdapter<Profile>
  let events: InMemoryEvents
  let identityId: string

  async function seedRefresh(refreshPlain: string, familyId = 'fam-1'): Promise<void> {
    await adapter.credentials.upsert(
      {
        identityId,
        kind: 'oauth',
        secret: sha256(refreshPlain),
        metadata: {
          provider: 'oauth:fake',
          sub: 'idp-sub-1',
          familyId,
          generation: 1,
          accessToken: 'at-1',
        } satisfies OAuthFamilyMetadata,
      },
      {},
    )
  }

  beforeEach(async () => {
    adapter = new MemoryAuthAdapter<Profile>()
    events = new InMemoryEvents()
    const i = await adapter.identities.create({ profile: { email: 'a@x.com' }, providers: [] }, {})
    identityId = i.id
  })

  it('happy path rotates the refresh token + bumps generation', async () => {
    await seedRefresh('rt-old')
    const exchange = vi.fn(
      async (): Promise<TokenResponse> => ({
        access_token: 'at-2',
        refresh_token: 'rt-new',
        token_type: 'Bearer',
        expires_in: 3600,
      }),
    )

    const r = await refreshOauthToken({
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
    expect((newRow?.metadata as OAuthFamilyMetadata).generation).toBe(2)

    const oldRow = await adapter.credentials.findByHashedSecret(sha256('rt-old'), 'oauth', {})
    expect(oldRow?.revokedAt).toBeTruthy()
  })

  it('replay of old refresh token surfaces AUTH/OAUTH_REUSE_DETECTED + emits suspicious + revokes family', async () => {
    await seedRefresh('rt-old')
    const exchange = vi.fn(
      async (): Promise<TokenResponse> => ({
        access_token: 'at-2',
        refresh_token: 'rt-new',
        token_type: 'Bearer',
        expires_in: 3600,
      }),
    )
    // First (happy) use rotates.
    await refreshOauthToken({
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
      refreshOauthToken({
        presentedRefreshToken: 'rt-old',
        tenant: {},
        credentials: adapter.credentials,
        events,
        exchange: vi.fn(),
      }),
    ).rejects.toMatchObject({ code: 'AUTH/OAUTH_REUSE_DETECTED', meta: { familyRevoked: true } })

    expect(suspicious).toHaveBeenCalledOnce()
    expect(suspicious.mock.calls[0]?.[0].signal).toBe('oauth-refresh-reuse')

    // Family revoked: the new token (rt-new) row is also marked revoked.
    const newRow = await adapter.credentials.findByHashedSecret(sha256('rt-new'), 'oauth', {})
    expect(newRow?.revokedAt).toBeTruthy()
  })

  it('unknown refresh token surfaces AUTH/OAUTH_REUSE_DETECTED (treat as leaked)', async () => {
    await expect(
      refreshOauthToken({
        presentedRefreshToken: 'never-issued',
        tenant: {},
        credentials: adapter.credentials,
        events,
        exchange: vi.fn(),
      }),
    ).rejects.toMatchObject({ code: 'AUTH/OAUTH_REUSE_DETECTED' })
  })

  it('IdP that does not rotate (no refresh_token in response) keeps the current row + updates access token', async () => {
    await seedRefresh('rt-stable')
    const exchange = vi.fn(
      async (): Promise<TokenResponse> => ({
        access_token: 'at-new',
        token_type: 'Bearer',
        expires_in: 60,
      }),
    )
    const r = await refreshOauthToken({
      presentedRefreshToken: 'rt-stable',
      tenant: {},
      credentials: adapter.credentials,
      events,
      exchange,
    })
    expect(r.tokens.access_token).toBe('at-new')
    // Old refresh token still resolves; access token updated.
    const row = await adapter.credentials.findByHashedSecret(sha256('rt-stable'), 'oauth', {})
    expect((row?.metadata as OAuthFamilyMetadata).accessToken).toBe('at-new')
  })

  it('projectAccessToken returns null when access token expired', () => {
    const expired = projectAccessToken({
      id: 'x',
      identityId,
      kind: 'oauth',
      secret: 'h',
      version: 1,
      createdAt: 0,
      metadata: {
        provider: 'oauth:fake',
        sub: 's',
        familyId: 'f',
        generation: 1,
        accessToken: 'at',
        accessTokenExpiresAt: Date.now() - 1,
      } satisfies OAuthFamilyMetadata,
    })
    expect(expired).toBeNull()
  })
})
