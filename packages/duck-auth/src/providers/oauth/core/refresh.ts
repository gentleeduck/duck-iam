import { isRevoked } from '../../../core/credential-utils'
import { authSha256 } from '../../../core/crypto'
import { AuthErrorObject } from '../../../core/errors'
import type { AuthTenantContext } from '../../../core/types/context'
import type { AuthCredential } from '../../../core/types/credential'
import type { AuthEvents } from '../../../core/types/events'
import type { AuthOAuthClient } from './client'

export namespace AuthOAuthRefresh {
  /**
   * Refresh-token family metadata. Persisted under `kind: 'oauth'`
   * credentials by the OAuth provider at signin; rotated atomically by
   * {@link authRefreshOauthToken}. Reuse of an old refresh token causes a
   * `AUTH/OAUTH_REUSE_DETECTED` throw + revocation of the whole token
   * family.
   */
  export interface IFamilyMetadata {
    provider: string
    sub: string
    familyId: string
    generation: number
    accessToken: string
    accessTokenExpiresAt?: number
    /** When set, family revoked; every member rejects on lookup. */
    revokedAt?: number
    /** Index signature for AuthCredential.metadata assignment. */
    [k: string]: unknown
  }
}

/**
 * Stores the new refresh token + revokes the predecessor inside the
 * same family. RFC 6749 section 10.4 reuse detection.
 */
export async function authRefreshOauthToken(opts: {
  presentedRefreshToken: string
  tenant: AuthTenantContext
  credentials: AuthCredential.IStore
  events: AuthEvents.IBus
  exchange: () => Promise<AuthOAuthClient.ITokenResponse>
}): Promise<{ tokens: AuthOAuthClient.ITokenResponse; identityId: string; familyId: string }> {
  const presentedHash = authSha256(opts.presentedRefreshToken)
  const row = await opts.credentials.findByHashedSecret(presentedHash, 'oauth', opts.tenant)
  if (!row) {
    // Unknown row: leaked/forged OR a GC'd revoked row. We cannot
    // revoke the family without a familyId; alert via `suspicious`.
    await opts.events.emit('suspicious', {
      signal: 'oauth-refresh-unknown-row',
      score: 1,
      meta: { presentedHash },
    })
    throw new AuthErrorObject('AUTH/OAUTH_REUSE_DETECTED', { familyRevoked: false })
  }
  const meta = parseFamilyMetadata(row.metadata)
  if (!meta) {
    throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
      providerId: 'oauth',
      detail: 'refresh credential missing or malformed family metadata',
    })
  }
  // Explicit `!== undefined`: falsy chain would let `revokedAt: 0` slip past.
  if (meta.revokedAt !== undefined || isRevoked(row)) {
    await revokeFamily(opts.credentials, opts.tenant, meta.familyId)
    await opts.events.emit('suspicious', {
      ...(row.identityId && { identityId: row.identityId }),
      signal: 'oauth-refresh-reuse',
      score: 1,
      meta: { familyId: meta.familyId, provider: meta.provider, sub: meta.sub },
    })
    throw new AuthErrorObject('AUTH/OAUTH_REUSE_DETECTED', { familyRevoked: true })
  }

  // Claim the row via CAS on `version` before the (slow) exchange so
  // concurrent refreshes serialise (RFC 6749 section 10.4 reuse detection).
  try {
    await opts.credentials.rotate(row.id, row.secret, row.version, opts.tenant)
  } catch (err) {
    if (err instanceof AuthErrorObject && err.code === 'AUTH/STALE_WRITE') {
      // CAS loser still revokes the family (RFC 6749 10.4 reuse detection).
      await revokeFamily(opts.credentials, opts.tenant, meta.familyId)
      await opts.events.emit('suspicious', {
        ...(row.identityId && { identityId: row.identityId }),
        signal: 'oauth-refresh-race',
        score: 1,
        meta: { familyId: meta.familyId, provider: meta.provider, sub: meta.sub },
      })
      throw new AuthErrorObject('AUTH/OAUTH_REUSE_DETECTED', { familyRevoked: true })
    }
    throw err
  }

  const fresh = await opts.exchange()
  if (!fresh.refresh_token) {
    const updated: AuthOAuthRefresh.IFamilyMetadata = {
      ...meta,
      accessToken: fresh.access_token,
      accessTokenExpiresAt: fresh.expires_in !== undefined ? Date.now() + fresh.expires_in * 1000 : undefined,
    }
    await opts.credentials.revoke(row.id, opts.tenant)
    await opts.credentials.upsert(
      {
        identityId: row.identityId,
        kind: 'oauth',
        secret: row.secret,
        metadata: updated,
      },
      opts.tenant,
    )
    return { tokens: fresh, identityId: row.identityId, familyId: meta.familyId }
  }

  const newMeta: AuthOAuthRefresh.IFamilyMetadata = {
    ...meta,
    generation: meta.generation + 1,
    accessToken: fresh.access_token,
    accessTokenExpiresAt: fresh.expires_in !== undefined ? Date.now() + fresh.expires_in * 1000 : undefined,
  }
  await opts.credentials.upsert(
    {
      identityId: row.identityId,
      kind: 'oauth',
      secret: authSha256(fresh.refresh_token),
      metadata: newMeta,
    },
    opts.tenant,
  )
  await opts.credentials.revoke(row.id, opts.tenant)
  return { tokens: fresh, identityId: row.identityId, familyId: meta.familyId }
}

async function revokeFamily(credentials: AuthCredential.IStore, ctx: AuthTenantContext, familyId: string): Promise<void> {
  // Reflect.get + typeof: avoids a runtime-incorrect `as Store & {__familyRevoke?}` shape.
  const method: unknown = Reflect.get(credentials, '__familyRevoke')
  if (typeof method !== 'function') return
  await method.call(credentials, familyId, ctx)
}

/**
 * Convenience helper for adapters that want to project an unexpired
 * refresh row's access token (without performing a refresh round-trip).
 */
export function projectAccessToken(row: AuthCredential.ICredential | null): {
  accessToken: string
  expiresAt: number | undefined
} | null {
  if (!row) return null
  // Parser rejects bad accessTokenExpiresAt; `as` cast lets NaN slip past expiry.
  const meta = parseFamilyMetadata(row.metadata)
  if (!meta) return null
  if (meta.accessTokenExpiresAt !== undefined && meta.accessTokenExpiresAt < Date.now()) return null
  return {
    accessToken: meta.accessToken,
    expiresAt: meta.accessTokenExpiresAt,
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Runtime validator for OAuth refresh-token family metadata. */
function parseFamilyMetadata(meta: unknown): AuthOAuthRefresh.IFamilyMetadata | null {
  if (!isPlainObject(meta)) return null
  const { provider, sub, familyId, generation, accessToken, accessTokenExpiresAt, revokedAt } = meta
  if (typeof provider !== 'string' || provider.length === 0) return null
  if (typeof sub !== 'string' || sub.length === 0) return null
  if (typeof familyId !== 'string' || familyId.length === 0) return null
  if (typeof generation !== 'number' || !Number.isFinite(generation)) return null
  if (typeof accessToken !== 'string') return null
  if (
    accessTokenExpiresAt !== undefined &&
    (typeof accessTokenExpiresAt !== 'number' || !Number.isFinite(accessTokenExpiresAt))
  ) {
    return null
  }
  if (revokedAt !== undefined && (typeof revokedAt !== 'number' || !Number.isFinite(revokedAt))) {
    return null
  }
  const parsed: AuthOAuthRefresh.IFamilyMetadata = { provider, sub, familyId, generation, accessToken }
  if (accessTokenExpiresAt !== undefined) parsed.accessTokenExpiresAt = accessTokenExpiresAt
  if (revokedAt !== undefined) parsed.revokedAt = revokedAt
  // Preserve any extra index-signature fields the operator wrote.
  for (const k of Object.keys(meta)) {
    if (!(k in parsed)) parsed[k] = meta[k]
  }
  return parsed
}
