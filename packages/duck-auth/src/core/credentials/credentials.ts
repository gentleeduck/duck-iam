import { AuthError } from '../errors'
import { isExpiredAt } from '../predicates/predicates'
import type { Provider } from '../provider/provider.types'
import type { TenantContext } from '../tenant/tenant.types'
import { PUBLIC_METADATA_KEYS } from './credentials.constants'
import type { Credential } from './credentials.types'

export function isRevoked(row: Pick<Credential.Me, 'revokedAt'>): boolean {
  return row.revokedAt != null
}

/** A `null` expiry never expires; anything unreadable fails closed as expired. */
export function isCredentialExpired(row: Pick<Credential.Me, 'expiresAt'>, now: number = Date.now()): boolean {
  return isExpiredAt(row.expiresAt, now)
}

/** Whether a credential can start a session on its own, which is what "the account is still reachable"
 *  means. A second factor (`totp`, `webauthn-mfa`) cannot; the one-shot tokens under `recovery` and
 *  `magic-link` are spent and gone; and an `oauth` row is the provider link, already counted as one.
 *  The two lockout guards each wrote their own version of this and each missed a clause the other had. */
export function isStandingFactor(row: Pick<Credential.Me, 'kind' | 'revokedAt' | 'expiresAt'>): boolean {
  if (isRevoked(row) || isCredentialExpired(row)) return false
  return row.kind === 'password' || row.kind === 'passkey' || row.kind === 'api-key'
}

/** Drops the secret, and every metadata key the kind does not declare public. */
export function toPublicCredential(row: Credential.Me): Credential.Public {
  const { secret: _secret, ...rest } = row
  if (rest.metadata == null) return rest
  const allowed = PUBLIC_METADATA_KEYS[rest.kind] ?? []
  const metadata: Record<string, unknown> = {}
  for (const key of allowed) {
    if (key in rest.metadata) metadata[key] = rest.metadata[key]
  }
  return { ...rest, metadata }
}

export function getCredentialPurpose(row: Pick<Credential.Me, 'metadata'>): string | undefined {
  const meta = row.metadata
  if (meta == null) return undefined
  const purpose = meta.purpose
  return typeof purpose === 'string' ? purpose : undefined
}

export function toCredentialCreate(
  input: Pick<Credential.CreateInput, 'identityId' | 'kind' | 'secret'> & Partial<Credential.CreateInput>,
): Credential.CreateInput {
  return {
    tenantId: null,
    metadata: null,
    lastUsedAt: null,
    expiresAt: null,
    revokedAt: null,
    ...input,
  }
}

/** Claims a single-use token by rotating its secret to one nobody holds, so the claim and the burn are one
 *  write and every loser of the race sees `AUTH_RECOVERY_TOKEN_INVALID`.
 *  SECURITY: never rotate to `row.secret` - that takes the version while leaving the row findable by hash
 *  until the caller's delete or revoke, and a read landing in that window wins its own CAS. */
export async function burnCredential(
  ctx: { crypto: Provider.Crypto; stores: { credentials: Credential.Store }; tenant: TenantContext },
  row: Pick<Credential.Me, 'id' | 'version'>,
): Promise<void> {
  const burnt = ctx.crypto.authSha256(ctx.crypto.authRandomToken(32))
  try {
    await ctx.stores.credentials.rotate(row.id, burnt, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    throw err
  }
}
