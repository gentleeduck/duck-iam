import { orNull } from '~/core/answer'
import { isRevoked, toCredentialCreate } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { sha256 } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Events } from '~/core/events'
import type { TenantContext } from '~/core/tenant/tenant.types'
import type { OAuth } from './oauth.types'

/**
 * Stores the new refresh token and revokes its predecessor in the same family, per RFC 6749 section 10.4.
 *
 * WARN: nothing in the package imports this, and no entrypoint exports it, so no consumer can call it.
 * `OProviderImpl.complete` still writes the `familyId` + `generation` metadata it reads, and
 * `AUTH_OAUTH_REUSE_DETECTED` is in the public error catalogue, so the feature looks wired from every
 * side except the one that would run it. Exporting it means a new `./providers/oauth` entrypoint.
 */
export async function authRefreshoauthToken(opts: {
  presentedRefreshToken: string
  tenant: TenantContext
  credentials: Credential.Store
  events: Events.IBus
  exchange: () => Promise<OAuth.TokenResponse>
  /**
   * SECURITY: required, not optional. Nothing else on the credential-first path looks at the identity, so
   * without this a deleted identity keeps refreshing tokens and its id keeps reaching the caller, the same
   * gap that let an API key outlive its owner.
   */
  identities: { find(by: { id: string }): Promise<unknown> }
}): Promise<{ tokens: OAuth.TokenResponse; identityId: string; familyId: string }> {
  const presentedHash = sha256(opts.presentedRefreshToken)
  // What the claim below rotates the secret to. Derived rather than random, so the row stays findable
  // here: an unfindable row cannot revoke its own family, which is the whole of section 10.4.
  const claimedHash = sha256(`oauth-claimed:${presentedHash}`)
  const presented = await orNull(opts.credentials.findByHashedSecret(presentedHash, 'oauth', opts.tenant))
  // Found only under the claimed hash means a refresh already took this token - in flight, finished, or
  // abandoned. Whichever it was, presenting the token again is reuse.
  const claimed = presented === null
  const row = presented ?? (await orNull(opts.credentials.findByHashedSecret(claimedHash, 'oauth', opts.tenant)))
  if (!row) {
    // An unknown row is leaked, forged, or a revoked row already collected. Revoking the family needs a
    // familyId there is none of, so this reports through `suspicious` instead.
    await opts.events.emit('suspicious', {
      signal: 'oauth-refresh-unknown-row',
      score: 1,
      meta: { presentedHash },
    })
    throw new AuthError('AUTH_OAUTH_REUSE_DETECTED', { familyRevoked: false })
  }
  const meta = parseFamilyMetadata(row.metadata)
  if (!meta) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oauth',
      detail: 'refresh credential missing or malformed family metadata',
    })
  }
  // Explicit `!== undefined`: a falsy check would let `revokedAt: 0` slip past as not-revoked.
  if (claimed || meta.revokedAt !== undefined || isRevoked(row)) {
    const moved = await opts.credentials.revokeFamily(meta.familyId, opts.tenant)
    await opts.events.emit('suspicious', {
      ...(row.identityId && { identityId: row.identityId }),
      signal: 'oauth-refresh-reuse',
      score: 1,
      meta: { familyId: meta.familyId, provider: meta.provider, sub: meta.sub },
    })
    throw new AuthError('AUTH_OAUTH_REUSE_DETECTED', { familyRevoked: moved > 0 })
  }

  // Checked before the CAS and before the exchange, so a refresh for a deleted account neither burns the row
  // nor calls the provider. The family is left alone rather than revoked, because a soft delete is reversible
  // and the tokens should work again if the account comes back inside its grace window.
  if (row.identityId && !(await orNull(opts.identities.find({ id: row.identityId })))) {
    throw new AuthError('AUTH_UNAUTHENTICATED')
  }

  // Claims the row before the slow exchange, so concurrent refreshes serialise into the reuse detection
  // rather than racing past it. The CAS on `version` only stops a racer that read before this landed;
  // moving the secret off `presentedHash` in the same write is what stops one that reads after, which
  // would otherwise see a live row at the next version and win a CAS of its own.
  let claimedRow: Credential.Me
  try {
    claimedRow = await opts.credentials.rotate(row.id, claimedHash, row.version, opts.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
      // The CAS loser still revokes the family: losing the race is indistinguishable from a replay.
      const moved = await opts.credentials.revokeFamily(meta.familyId, opts.tenant)
      await opts.events.emit('suspicious', {
        ...(row.identityId && { identityId: row.identityId }),
        signal: 'oauth-refresh-race',
        score: 1,
        meta: { familyId: meta.familyId, provider: meta.provider, sub: meta.sub },
      })
      throw new AuthError('AUTH_OAUTH_REUSE_DETECTED', { familyRevoked: moved > 0 })
    }
    throw err
  }

  let fresh: OAuth.TokenResponse
  try {
    fresh = await opts.exchange()
  } catch (err) {
    // Released, not kept: a provider that is briefly unreachable should not cost the client its refresh
    // token, and nothing has been issued yet.
    await opts.credentials.rotate(row.id, row.secret, claimedRow.version, opts.tenant).catch(() => {})
    throw err
  }
  if (!fresh.refresh_token) {
    const updated: OAuth.FamilyMetadata = { ...meta }
    await opts.credentials.revoke(row.id, opts.tenant)
    await opts.credentials.create(
      toCredentialCreate({
        identityId: row.identityId,
        kind: 'oauth',
        secret: row.secret,
        metadata: updated,
      }),
      opts.tenant,
    )
    return { tokens: fresh, identityId: row.identityId, familyId: meta.familyId }
  }

  const newMeta: OAuth.FamilyMetadata = { ...meta, generation: meta.generation + 1 }
  await opts.credentials.create(
    toCredentialCreate({
      identityId: row.identityId,
      kind: 'oauth',
      secret: sha256(fresh.refresh_token),
      metadata: newMeta,
    }),
    opts.tenant,
  )
  await opts.credentials.revoke(row.id, opts.tenant)
  return { tokens: fresh, identityId: row.identityId, familyId: meta.familyId }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Validates the refresh-token family metadata read back off a credential row. */
export function parseFamilyMetadata(meta: unknown): OAuth.FamilyMetadata | null {
  if (!isPlainObject(meta)) return null
  const { provider, sub, familyId, generation, revokedAt } = meta
  if (typeof provider !== 'string' || provider.length === 0) return null
  if (typeof sub !== 'string' || sub.length === 0) return null
  if (typeof familyId !== 'string' || familyId.length === 0) return null
  if (typeof generation !== 'number' || !Number.isFinite(generation)) return null
  if (revokedAt !== undefined && (typeof revokedAt !== 'number' || !Number.isFinite(revokedAt))) {
    return null
  }
  const parsed: OAuth.FamilyMetadata = { provider, sub, familyId, generation }
  if (revokedAt !== undefined) parsed.revokedAt = revokedAt
  // Preserves the operator's own fields.
  // SECURITY: a token from a row written before these stopped being stored is dropped here, so a rotation
  // purges it.
  for (const k of Object.keys(meta)) {
    if (k === 'accessToken' || k === 'accessTokenExpiresAt') continue
    if (!(k in parsed)) parsed[k] = meta[k]
  }
  return parsed
}
