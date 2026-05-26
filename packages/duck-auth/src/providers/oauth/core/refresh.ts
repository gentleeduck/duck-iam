/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { sha256 } from '../../../core/crypto'
import { AuthErrorObject } from '../../../core/errors'
import type { TenantContext } from '../../../core/types/context'
import type { Credential } from '../../../core/types/credential'
import type { Events } from '../../../core/types/events'
import type { TokenResponse } from './client'

/**
 * OAuth refresh-token family metadata. Persisted under `kind: 'oauth'`
 * credentials by the OAuth provider at signin; rotated atomically by
 * {@link refreshOauthToken} on every refresh. Reuse of an old refresh
 * token causes a `AUTH/OAUTH_REUSE_DETECTED` throw + revocation of the
 * whole token family.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface OAuthFamilyMetadata {
  provider: string
  sub: string
  familyId: string
  generation: number
  accessToken: string
  accessTokenExpiresAt?: number
  /** When set, the family has been revoked; every member rejects on lookup. */
  revokedAt?: number
  /** Index signature so the shape is assignable to Credential.metadata's Record<string, unknown>. */
  [k: string]: unknown
}

/**
 * Stores the new refresh token + revokes the predecessor inside the
 * same family. RFC 6749 section 10.4 reuse detection: presenting a
 * previously-used refresh token (one whose hash matches a credential
 * row that has been revoked AND belongs to a family without a newer
 * unrevoked generation) revokes the whole family and surfaces
 * AUTH/OAUTH_REUSE_DETECTED.
 *
 * @param opts.presentedRefreshToken plaintext token from the client
 * @param opts.tenant tenant scope for store calls
 * @param opts.credentials store handle
 * @param opts.events bus for `suspicious` emission on reuse detection
 * @param opts.exchange callback that hits the IdP for a fresh token (provider-specific)
 * @returns the IdP's TokenResponse + the rotated row's identity id
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export async function refreshOauthToken(opts: {
  presentedRefreshToken: string
  tenant: TenantContext
  credentials: Credential.IStore
  events: Events.IBus
  exchange: () => Promise<TokenResponse>
}): Promise<{ tokens: TokenResponse; identityId: string; familyId: string }> {
  const presentedHash = sha256(opts.presentedRefreshToken)
  const row = await opts.credentials.findByHashedSecret(presentedHash, 'oauth', opts.tenant)
  if (!row) {
    throw new AuthErrorObject('AUTH/OAUTH_REUSE_DETECTED', { familyRevoked: true })
  }
  const meta = row.metadata as OAuthFamilyMetadata | undefined
  if (!meta) {
    throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
      providerId: 'oauth',
      detail: 'refresh credential missing family metadata',
    })
  }
  // Family already revoked OR this row is revoked (someone else rotated past us)
  if (meta.revokedAt || row.revokedAt) {
    await revokeFamily(opts.credentials, opts.tenant, meta.familyId)
    await opts.events.emit('suspicious', {
      ...(row.identityId && { identityId: row.identityId }),
      signal: 'oauth-refresh-reuse',
      score: 1,
      meta: { familyId: meta.familyId, provider: meta.provider, sub: meta.sub },
    })
    throw new AuthErrorObject('AUTH/OAUTH_REUSE_DETECTED', { familyRevoked: true })
  }

  // Live row + first use: rotate.
  const fresh = await opts.exchange()
  if (!fresh.refresh_token) {
    // IdP did not rotate; supersede the current row with updated access token.
    const updated: OAuthFamilyMetadata = {
      ...meta,
      accessToken: fresh.access_token,
      accessTokenExpiresAt: fresh.expires_in !== undefined ? Date.now() + fresh.expires_in * 1000 : undefined,
    }
    // Revoke + upsert so findByHashedSecret returns the new row deterministically
    // even when the underlying clock has sub-ms resolution.
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

  // Persist the new generation BEFORE revoking the old; any concurrent
  // refresh seeing both rows will pick the freshest (createdAt) live row,
  // which is the new generation, and reject the old as a reuse attempt.
  const newMeta: OAuthFamilyMetadata = {
    ...meta,
    generation: meta.generation + 1,
    accessToken: fresh.access_token,
    accessTokenExpiresAt: fresh.expires_in !== undefined ? Date.now() + fresh.expires_in * 1000 : undefined,
  }
  await opts.credentials.upsert(
    {
      identityId: row.identityId,
      kind: 'oauth',
      secret: sha256(fresh.refresh_token),
      metadata: newMeta,
    },
    opts.tenant,
  )
  // Mark the old refresh-token row as revoked so a replay sees `row.revokedAt`.
  await opts.credentials.revoke(row.id, opts.tenant)
  return { tokens: fresh, identityId: row.identityId, familyId: meta.familyId }
}

/**
 * Revoke every credential row in a token family. Called when reuse is
 * detected so the leaked branch cannot continue minting tokens.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
async function revokeFamily(credentials: Credential.IStore, ctx: TenantContext, familyId: string): Promise<void> {
  // listByIdentity is the cheapest cross-row iteration the store contract
  // exposes; the iam-side caller already knows the identity from the
  // earlier hash lookup so we use that. Adapters with a (kind, metadata.familyId)
  // index will override this with a single SQL query in v0.2.
  // Memory adapter walks every row; production adapters should add the index.
  const internal = credentials as Credential.IStore & {
    __familyRevoke?: (familyId: string, ctx: TenantContext) => Promise<void>
  }
  if (internal.__familyRevoke) {
    await internal.__familyRevoke(familyId, ctx)
  }
}

/**
 * Convenience helper for adapters that want to project an unexpired
 * refresh row's access token (without performing a refresh round-trip).
 * Returns null when the access token is expired or the row missing.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function projectAccessToken(row: Credential.ICredential | null): {
  accessToken: string
  expiresAt: number | undefined
} | null {
  if (!row) return null
  const meta = row.metadata as OAuthFamilyMetadata | undefined
  if (!meta) return null
  if (meta.accessTokenExpiresAt !== undefined && meta.accessTokenExpiresAt < Date.now()) return null
  return {
    accessToken: meta.accessToken,
    expiresAt: meta.accessTokenExpiresAt,
  }
}

/**
 * Namespace merge for `OAuthRefresh`. Co-locates the flat type exports
 * alongside the primary symbol via TS class+namespace merging.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace OAuthRefresh {
  /** Alias for the flat `OAuthFamilyMetadata` type. */
  export type IOAuthFamilyMetadata = OAuthFamilyMetadata
}
