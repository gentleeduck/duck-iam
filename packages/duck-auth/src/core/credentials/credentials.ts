import { isExpiredAt } from '../predicates/predicates'
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
